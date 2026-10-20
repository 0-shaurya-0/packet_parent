import datetime as dt
import hashlib
import json
import sqlite3
import threading
from collections import Counter, defaultdict
from contextlib import closing, contextmanager
from pathlib import Path

from storage import ingest, migrate, remove_capture_events

from packets import CaptureError, clean_domain, parse_capture

# Re-export these helpers for existing callers.
from sessions import day_bounds, estimate_sessions
from rules import CATEGORIES, active, category, evaluate_rules, matches, window_contains

DEFAULT_SETTINGS = {'keep_raw_captures': False, 'retention_days': 90, 'idle_seconds': 120, 'utc_offset': 330, 'ignored_domains': ['windowsupdate.com', 'update.microsoft.com', 'time.windows.com']}


class Store:
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.parser_state = {}
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS devices(ip TEXT PRIMARY KEY, name TEXT NOT NULL, child TEXT NOT NULL DEFAULT '');
            CREATE TABLE IF NOT EXISTS captures(id INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                imported REAL NOT NULL, first REAL, last REAL, stats TEXT NOT NULL, demo INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL,
                capture_id INTEGER REFERENCES captures(id), device_ip TEXT REFERENCES devices(ip), timestamp REAL NOT NULL,
                remote_ip TEXT, domain TEXT, protocol TEXT, evidence TEXT, active INTEGER, bytes INTEGER, category TEXT);
            CREATE INDEX IF NOT EXISTS event_time ON events(timestamp);
            CREATE INDEX IF NOT EXISTS event_device_time ON events(device_ip,timestamp);
            CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '', start TEXT NOT NULL DEFAULT '', end TEXT NOT NULL DEFAULT '',
                minutes INTEGER NOT NULL DEFAULT 60, device_ip TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, rule_id INTEGER REFERENCES rules(id), device_ip TEXT,
                day TEXT, timestamp REAL, last_seen REAL, domain TEXT, title TEXT, reason TEXT, evidence TEXT,
                count INTEGER, acknowledged INTEGER NOT NULL DEFAULT 0);
            ''')
            db.execute('INSERT OR IGNORE INTO config VALUES (?,?)', ('settings', json.dumps(DEFAULT_SETTINGS)))
            if 'source' not in {r[1] for r in db.execute('PRAGMA table_info(captures)')}:
                db.execute("ALTER TABLE captures ADD COLUMN source TEXT NOT NULL DEFAULT 'import'")
                db.execute("UPDATE captures SET source='demo' WHERE demo=1")
            if 'source_ip' not in {r[1] for r in db.execute('PRAGMA table_info(events)')}:
                db.execute("ALTER TABLE events ADD COLUMN source_ip TEXT NOT NULL DEFAULT ''")
                db.execute('UPDATE events SET source_ip=device_ip')
            if 'source' not in {r[1] for r in db.execute('PRAGMA table_info(alerts)')}:
                db.execute("ALTER TABLE alerts ADD COLUMN source TEXT NOT NULL DEFAULT 'import'")
            db.execute('CREATE INDEX IF NOT EXISTS alert_source_day ON alerts(source,day)')
        self.remove_legacy_samples()
        migrate(self)

    def remove_legacy_samples(self):
        """Remove only positively marked legacy samples, keeping a recoverable backup."""
        with self.lock, self.connect() as db:
            sample_ids = [r[0] for r in db.execute("SELECT id FROM captures WHERE demo=1 OR source='demo'")]
            if not sample_ids:
                return
            backup_dir = Path(self.path).parent / 'backups'
            backup_dir.mkdir(exist_ok=True)
            backup = backup_dir / ('before-sample-cleanup-' + dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.sqlite3')
            with closing(sqlite3.connect(backup)) as destination:
                db.backup(destination)
            sample_devices = {r[0] for r in db.execute("SELECT DISTINCT device_ip FROM events WHERE capture_id IN (SELECT id FROM captures WHERE demo=1 OR source='demo')")}
            defaults = [
                (1, 'Gaming during study hours', 'category', 'Gaming', '19:00', '21:00', 60, '', 1),
                (2, 'Internet outside permitted hours', 'hours', '', '07:00', '22:00', 60, '', 1),
                (3, 'Daily internet budget', 'budget', '', '', '', 60, '', 1)]
            first_rules = [tuple(r) for r in db.execute('SELECT id,name,kind,target,start,end,minutes,device_ip,enabled FROM rules WHERE id IN (1,2,3) ORDER BY id')]
            if first_rules == defaults:
                db.execute('DELETE FROM alerts WHERE rule_id IN (1,2,3)')
                db.execute('DELETE FROM rules WHERE id IN (1,2,3)')
            if 'packets' in {r[1] for r in db.execute('PRAGMA table_info(events)')}:
                for capture_id in sample_ids:
                    remove_capture_events(db, capture_id)
            else:
                db.execute("DELETE FROM events WHERE capture_id IN (SELECT id FROM captures WHERE demo=1 OR source='demo')")
            db.execute("DELETE FROM captures WHERE demo=1 OR source='demo'")
            self.rebuild_alerts(db)
            for ip in sample_devices:
                in_use = db.execute('SELECT 1 FROM events WHERE device_ip=? UNION ALL SELECT 1 FROM rules WHERE device_ip=? LIMIT 1', (ip, ip)).fetchone()
                if not in_use:
                    db.execute('DELETE FROM devices WHERE ip=?', (ip,))
                else:
                    # A real imported device may have shared an example IP address.
                    db.execute("""UPDATE devices SET name=?,child='' WHERE ip=? AND
                        ((name='Aarav’s laptop' AND child='Aarav') OR (name='Maya’s tablet' AND child='Maya'))""", ('Device ' + ip, ip))
            db.execute('INSERT OR REPLACE INTO config VALUES (?,?)', ('sample_cleanup_backup', str(backup)))

    def register_local(self, info):
        with self.lock, self.connect() as db:
            db.execute('INSERT OR IGNORE INTO devices(ip,name) VALUES(?,?)', (info['id'], info['name']))
            db.execute('INSERT OR REPLACE INTO config VALUES (?,?)', ('local_device', json.dumps(info)))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def settings(self, db=None):
        if db is not None:
            return {**DEFAULT_SETTINGS, **json.loads(db.execute("SELECT value FROM config WHERE key='settings'").fetchone()[0])}
        with self.connect() as conn:
            return self.settings(conn)

    def purge(self, now=None):
        """Delete metadata older than the configured local-day retention boundary."""
        with self.lock, self.connect() as db:
            settings = self.settings(db)
            days = settings['retention_days']
            if not days:
                return 0
            tz = dt.timezone(dt.timedelta(minutes=settings['utc_offset']))
            today = dt.datetime.fromtimestamp(now, tz).date() if now is not None else dt.datetime.now(tz).date()
            cutoff_day = (today - dt.timedelta(days=days)).isoformat()
            cutoff, _ = day_bounds(cutoff_day, settings['utc_offset'])
            removed = db.execute('DELETE FROM events WHERE timestamp<?', (cutoff,)).rowcount
            db.execute('DELETE FROM alerts WHERE day<?', (cutoff_day,))
            if removed:
                self.rebuild_alerts(db, {('live', cutoff_day), ('import', cutoff_day)})
            return removed

    def auth_hash(self):
        with self.connect() as db:
            row = db.execute("SELECT value FROM config WHERE key='password'").fetchone()
            return row[0] if row else None

    def setup(self, password_hash, offset):
        with self.lock, self.connect() as db:
            if db.execute("SELECT 1 FROM config WHERE key='password'").fetchone():
                raise ValueError('A parent password has already been set.')
            db.execute('INSERT INTO config VALUES (?,?)', ('password', password_hash))
            settings = self.settings(db)
            settings['utc_offset'] = offset
            db.execute("UPDATE config SET value=? WHERE key='settings'", (json.dumps(settings),))

    def import_capture(self, data, name, monitored=None, source=None):
        source = source or ('live' if monitored else 'import')
        if source not in ('live', 'import'):
            raise ValueError('Only your live or imported captures are supported.')
        if source == 'live' and not monitored:
            raise ValueError('Local capture requires this PC’s identity.')
        digest = hashlib.sha256(source.encode() + b'\0' + data).hexdigest()
        with self.lock:
            with self.connect() as db:
                existing = db.execute('SELECT id FROM captures WHERE hash=?', (digest,)).fetchone()
                if existing:
                    return {'duplicate': True, 'id': existing[0], 'message': 'This capture is already imported.'}
            rows, stats = parse_capture(data, monitored, self.parser_state if source == 'live' else None)
            with self.connect() as db:
                cur = db.execute('INSERT INTO captures(hash,name,imported,first,last,stats,demo,source) VALUES(?,?,?,?,?,?,?,?)',
                                 (digest, name[:180], dt.datetime.now().timestamp(), min((r['timestamp'] for r in rows), default=None),
                                  max((r['timestamp'] for r in rows), default=None), '{}', 0, source))
                capture_id = cur.lastrowid
                inserted = ingest(db, rows, capture_id, source, category,
                                  monitored['name'] if monitored else None)
                stats['inserted'] = inserted
                stats['duplicates'] = len(rows) - inserted
                db.execute('UPDATE captures SET stats=? WHERE id=?', (json.dumps(stats), capture_id))
                if inserted:
                    settings = self.settings(db)
                    tz = dt.timezone(dt.timedelta(minutes=settings['utc_offset']))
                    touched = set()
                    for row in rows:
                        for timestamp in (row['timestamp'] - settings['idle_seconds'],
                                          row['timestamp'], row['timestamp'] + settings['idle_seconds']):
                            touched.add((source, dt.datetime.fromtimestamp(timestamp, tz).date().isoformat()))
                    self.rebuild_alerts(db, touched)
            return {'duplicate': False, 'id': capture_id, 'stats': stats, 'message': f'Imported {inserted:,} observations.'}

    def rebuild_alerts(self, db, pairs=None):
        """Rebuild all alerts, or only affected source/day partitions with boundary context."""
        if pairs is None:
            self._evaluate_alerts(db)
        else:
            for source, day in sorted(pairs):
                self._evaluate_alerts(db, source, day)

    def _evaluate_alerts(self, db, source=None, day=None):
        """Evaluate one day using adjacent activity to preserve midnight sessions."""
        condition = '' if source is None else ' WHERE source=? AND day=?'
        parameters = [] if source is None else [source, day]
        if not db.execute('SELECT 1 FROM rules WHERE enabled=1').fetchone():
            db.execute('DELETE FROM alerts' + condition, parameters)
            return
        settings = self.settings(db)
        aggregated = 'packets' in {r[1] for r in db.execute('PRAGMA table_info(events)')}
        order = 'first_ts' if aggregated else 'timestamp'
        query = 'SELECT e.*,c.source FROM events e JOIN captures c ON c.id=e.capture_id'
        values = []
        if source is not None:
            start, end = day_bounds(day, settings['utc_offset'])
            source_column = 'e.source' if aggregated else 'c.source'
            query += ' WHERE ' + source_column + '=? AND e.timestamp>=? AND e.timestamp<?'
            values = [source, start - settings['idle_seconds'], end + settings['idle_seconds']]
        rows = [dict(r) for r in db.execute(query + ' ORDER BY ' + order, values)]
        requested_day = day
        rules = [dict(r) for r in db.execute('SELECT * FROM rules WHERE enabled=1')]
        old_ack = {r['id']: r['acknowledged'] for r in db.execute('SELECT id,acknowledged FROM alerts' + condition, parameters)}
        output = evaluate_rules(rows, rules, settings)
        db.execute('DELETE FROM alerts' + condition, parameters)
        for row in output:
            if requested_day is not None and row['day'] != requested_day:
                continue
            row['acknowledged'] = old_ack.get(row['id'], 0)
            keys = list(row)
            db.execute('INSERT INTO alerts(' + ','.join(keys) + ') VALUES(' + ','.join('?' for _ in keys) + ')', list(row.values()))

    def save_rule(self, rule, rule_id=None):
        with self.lock, self.connect() as db:
            if rule['device_ip'] and not db.execute('SELECT 1 FROM devices WHERE ip=?', (rule['device_ip'],)).fetchone():
                raise ValueError('Choose an existing device.')
            if rule_id is None:
                keys = list(rule)
                db.execute(f"INSERT INTO rules({','.join(keys)}) VALUES({','.join('?' for _ in keys)})", list(rule.values()))
            else:
                if not db.execute('SELECT 1 FROM rules WHERE id=?', (rule_id,)).fetchone():
                    raise ValueError('Rule not found.')
                db.execute('UPDATE rules SET ' + ','.join(k + '=?' for k in rule) + ' WHERE id=?', list(rule.values()) + [rule_id])
            self.rebuild_alerts(db)

    def delete_rule(self, rule_id):
        with self.lock, self.connect() as db:
            db.execute('DELETE FROM alerts WHERE rule_id=?', (rule_id,))
            db.execute('DELETE FROM rules WHERE id=?', (rule_id,))

    def save_settings(self, settings):
        with self.lock, self.connect() as db:
            db.execute("UPDATE config SET value=? WHERE key='settings'", (json.dumps(settings),))
            self.rebuild_alerts(db)

    def _snapshot_devices(self, db, source, local):
        """Return device totals and observed addresses for the selected source."""
        scope = '' if source == 'all' else ' AND e.source=?'
        values = [] if source == 'all' else [source]
        local_id = local.get('id', '') if source in ('live', 'all') else ''
        devices = [dict(row) for row in db.execute(
            'SELECT d.*,MAX(e.last_ts) last_seen,COALESCE(SUM(e.packets),0) observations '
            'FROM devices d LEFT JOIN events e ON d.ip=e.device_ip' + scope +
            ' GROUP BY d.ip HAVING COUNT(e.id)>0 OR d.ip=? ORDER BY d.name', values + [local_id])]
        for item in devices:
            item['addresses'] = [row[0] for row in db.execute(
                'SELECT DISTINCT source_ip FROM event_addresses WHERE event_id IN '
                '(SELECT e.id FROM events e WHERE device_ip=?' + scope + ') ORDER BY source_ip',
                [item['ip']] + values)]
            item['is_local'] = item['ip'] == local.get('id')
        return devices

    def _snapshot_sessions(self, rows, settings, start, end):
        """Clip device sessions to the requested day and distribute them by hour."""
        hourly = [0.0] * 24
        sessions = []
        device_seconds = Counter()
        grouped = defaultdict(list)
        for row in rows:
            if active(row, settings):
                grouped[row['device_ip']].extend([row['first_ts'], row['last_ts']])
        for ip, timestamps in grouped.items():
            for first, last in estimate_sessions(timestamps, settings['idle_seconds']):
                first, last = max(first, start), min(last, end)
                if last < first:
                    continue
                sessions.append({'device_ip': ip, 'start': first, 'end': last, 'seconds': last - first})
                device_seconds[ip] += last - first
                for hour in range(24):
                    hourly[hour] += max(0, min(last, start + (hour + 1) * 3600) - max(first, start + hour * 3600))
        return hourly, sorted(sessions, key=lambda row: row['start'], reverse=True), dict(device_seconds)

    def _snapshot_activity(self, rows):
        """Sum packet and byte counters by device, domain and evidence."""
        domains = {}
        categories = Counter()
        for row in rows:
            domain = row['domain'] or row['remote_ip']
            categories[row['category']] += row['packets']
            key = (row['device_ip'], domain, row['evidence'])
            if key not in domains:
                domains[key] = {'device_ip': row['device_ip'], 'domain': domain, 'category': row['category'],
                                'evidence': row['evidence'], 'first': row['first_ts'], 'last': row['last_ts'],
                                'count': 0, 'bytes': 0}
            item = domains[key]
            item['last'] = max(item['last'], row['last_ts'])
            item['first'] = min(item['first'], row['first_ts'])
            item['count'] += row['packets']
            item['bytes'] += row['bytes']
        return sorted(domains.values(), key=lambda row: row['last'], reverse=True), dict(categories)

    def _snapshot_alerts(self, db, day, device, source):
        """Read reviewed and outstanding alerts in the existing dashboard order."""
        query = 'SELECT * FROM alerts WHERE day=?'
        values = [day]
        if source != 'all':
            query += ' AND source=?'
            values.append(source)
        if device:
            query += ' AND device_ip=?'
            values.append(device)
        return [dict(row) for row in db.execute(query + ' ORDER BY acknowledged,timestamp DESC', values)]

    def snapshot(self, day=None, device='', source='all'):
        """Build one consistent dashboard view with the existing public response shape."""
        if source not in ('all', 'live', 'import'):
            raise ValueError('Invalid activity source.')
        with self.connect() as db:
            db.execute('BEGIN')
            settings = self.settings(db)
            tz = dt.timezone(dt.timedelta(minutes=settings['utc_offset']))
            scope = '' if source == 'all' else ' AND source=?'
            scope_values = [] if source == 'all' else [source]
            dates = [row[0] for row in db.execute(
                "SELECT DISTINCT date(timestamp + ?, 'unixepoch') FROM events WHERE 1=1" + scope + ' ORDER BY 1 DESC',
                [settings['utc_offset'] * 60] + scope_values)]
            today = dt.datetime.now(tz).date().isoformat()
            day = day or (today if source == 'live' else dates[0] if dates else today)
            start, end = day_bounds(day, settings['utc_offset'])
            local_row = db.execute("SELECT value FROM config WHERE key='local_device'").fetchone()
            local = json.loads(local_row[0]) if local_row else {}
            devices = self._snapshot_devices(db, source, local)
            query = 'SELECT * FROM events WHERE timestamp>=? AND timestamp<?' + scope
            values = [start - settings['idle_seconds'], end + settings['idle_seconds']] + scope_values
            if device:
                query += ' AND device_ip=?'
                values.append(device)
            rows = [dict(row) for row in db.execute(query + ' ORDER BY timestamp', values)]
            day_rows = [row for row in rows if start <= row['timestamp'] < end]
            hourly, sessions, device_seconds = self._snapshot_sessions(rows, settings, start, end)
            activity, categories = self._snapshot_activity(day_rows)
            alerts = self._snapshot_alerts(db, day, device, source)
            captures = [dict(row) for row in db.execute(
                'SELECT * FROM captures WHERE 1=1' + scope + ' ORDER BY imported DESC LIMIT 30', scope_values)]
            for capture in captures:
                capture.pop('hash')
                capture['stats'] = json.loads(capture['stats'])
            return {'source': source, 'day': day, 'today': today, 'dates': dates, 'devices': devices, 'settings': settings,
                    'rules': [dict(row) for row in db.execute('SELECT * FROM rules ORDER BY id')],
                    'alerts': alerts, 'captures': captures, 'hourly': hourly, 'sessions': sessions,
                    'activity': activity, 'categories': categories, 'device_seconds': device_seconds,
                    'summary': {'seconds': sum(device_seconds.values()), 'observations': sum(row['packets'] for row in day_rows),
                                'domains': len({row['domain'] for row in day_rows if row['domain']}),
                                'unacknowledged': sum(not alert['acknowledged'] for alert in alerts),
                                'unknown': sum(row['packets'] for row in day_rows if not row['domain'])}}
