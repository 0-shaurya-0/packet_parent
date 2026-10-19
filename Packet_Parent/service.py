import datetime as dt
import hashlib
import json
import sqlite3
import threading
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path

from packets import CaptureError, clean_domain, parse_capture

CATEGORIES = {
    'Education': ['khanacademy.org', 'wikipedia.org', 'duolingo.com', 'coursera.org', 'edx.org', 'byjus.com', 'classroom.google.com'],
    'Entertainment': ['youtube.com', 'googlevideo.com', 'netflix.com', 'nflxvideo.net', 'spotify.com', 'twitch.tv', 'hotstar.com'],
    'Gaming': ['roblox.com', 'rbxcdn.com', 'steampowered.com', 'steamcontent.com', 'epicgames.com', 'minecraft.net', 'xboxlive.com'],
    'Social': ['instagram.com', 'facebook.com', 'discord.com', 'discord.gg', 'reddit.com', 'snapchat.com', 'tiktok.com', 'whatsapp.com'],
}
DEFAULT_SETTINGS = {'idle_seconds': 120, 'utc_offset': 330, 'ignored_domains': ['windowsupdate.com', 'update.microsoft.com', 'time.windows.com']}


def matches(domain, root):
    return bool(domain and root and (domain == root or domain.endswith('.' + root)))


def category(domain):
    for name, roots in CATEGORIES.items():
        if any(matches(domain, root) for root in roots):
            return name
    return 'Unknown'


def estimate_sessions(timestamps, idle=120):
    times = sorted(set(timestamps))
    if not times:
        return []
    sessions, start, last = [], times[0], times[0]
    for value in times[1:]:
        if value - last > idle:
            sessions.append((start, last))
            start = value
        last = value
    sessions.append((start, last))
    return sessions


def window_contains(minute, start, end):
    a = int(start[:2]) * 60 + int(start[3:])
    b = int(end[:2]) * 60 + int(end[3:])
    if a == b:
        return True
    return a <= minute < b if a < b else minute >= a or minute < b


def day_bounds(day, offset):
    tz = dt.timezone(dt.timedelta(minutes=offset))
    start = dt.datetime.combine(dt.date.fromisoformat(day), dt.time(), tz).timestamp()
    return start, start + 86400


def active(row, settings):
    return row['active'] and not any(matches(row['domain'], root) for root in settings['ignored_domains'])


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
            return json.loads(db.execute("SELECT value FROM config WHERE key='settings'").fetchone()[0])
        with self.connect() as conn:
            return self.settings(conn)

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

    def import_capture(self, data, name, demo=False, monitored=None, source=None):
        source = source or ('demo' if demo else 'live' if monitored else 'import')
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
                                  max((r['timestamp'] for r in rows), default=None), '{}', int(demo), source))
                capture_id, inserted = cur.lastrowid, 0
                for row in rows:
                    ip = row['device_ip']
                    db.execute('INSERT OR IGNORE INTO devices(ip,name) VALUES(?,?)', (ip, monitored['name'] if monitored else 'Device ' + ip))
                    row['fingerprint'] = hashlib.sha256((source + ':' + row['fingerprint']).encode()).hexdigest()
                    values = [row[k] for k in ('fingerprint', 'device_ip', 'timestamp', 'remote_ip', 'domain', 'protocol', 'evidence', 'active', 'bytes')]
                    inserted += db.execute('''INSERT OR IGNORE INTO events(fingerprint,device_ip,timestamp,remote_ip,domain,
                        protocol,evidence,active,bytes,capture_id,category,source_ip) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                        values + [capture_id, category(row['domain']), row['source_ip']]).rowcount
                stats['inserted'] = inserted
                stats['duplicates'] = len(rows) - inserted
                db.execute('UPDATE captures SET stats=? WHERE id=?', (json.dumps(stats), capture_id))
                if demo:
                    db.execute("UPDATE devices SET name='Aarav’s laptop',child='Aarav' WHERE ip='192.168.1.20' AND name LIKE 'Device %'")
                    db.execute("UPDATE devices SET name='Maya’s tablet',child='Maya' WHERE ip='192.168.1.21' AND name LIKE 'Device %'")
                    if not db.execute('SELECT 1 FROM rules').fetchone():
                        db.executemany('INSERT INTO rules(name,kind,target,start,end,minutes) VALUES(?,?,?,?,?,?)', [
                            ('Gaming during study hours', 'category', 'Gaming', '19:00', '21:00', 60),
                            ('Internet outside permitted hours', 'hours', '', '07:00', '22:00', 60),
                            ('Daily internet budget', 'budget', '', '', '', 60)])
                self.rebuild_alerts(db)
            return {'duplicate': False, 'id': capture_id, 'stats': stats, 'message': f'Imported {inserted:,} observations.'}

    def rebuild_alerts(self, db):
        if not db.execute('SELECT 1 FROM rules WHERE enabled=1').fetchone():
            db.execute('DELETE FROM alerts')
            return
        settings = self.settings(db)
        tz = dt.timezone(dt.timedelta(minutes=settings['utc_offset']))
        rows = [dict(r) for r in db.execute('SELECT e.*,c.source FROM events e JOIN captures c ON c.id=e.capture_id ORDER BY timestamp')]
        rules = [dict(r) for r in db.execute('SELECT * FROM rules WHERE enabled=1')]
        old_ack = {r['id']: r['acknowledged'] for r in db.execute('SELECT id,acknowledged FROM alerts')}
        output, times = {}, defaultdict(list)
        for row in rows:
            local = dt.datetime.fromtimestamp(row['timestamp'], tz)
            day, minute = local.date().isoformat(), local.hour * 60 + local.minute
            if active(row, settings):
                times[(row['source'], row['device_ip'])].append(row['timestamp'])
            for rule in rules:
                if rule['kind'] == 'budget' or (rule['device_ip'] and rule['device_ip'] != row['device_ip']):
                    continue
                if rule['kind'] == 'hours':
                    hit = active(row, settings) and not window_contains(minute, rule['start'], rule['end'])
                    reason = f"Observed internet traffic outside {rule['start']}–{rule['end']}."
                else:
                    hit = matches(row['domain'], rule['target']) if rule['kind'] == 'domain' else row['category'] == rule['target']
                    if rule['start']:
                        hit = hit and window_contains(minute, rule['start'], rule['end'])
                    reason = f"Observed {row['domain']} matched the {rule['kind']} rule: {rule['target']}."
                if not hit:
                    continue
                key = hashlib.sha256(f"{row['source']}|{rule['id']}|{row['device_ip']}|{day}|{row['domain'] or row['remote_ip']}".encode()).hexdigest()[:24]
                if key in output:
                    output[key]['count'] += 1
                    output[key]['last_seen'] = row['timestamp']
                else:
                    output[key] = dict(id=key, rule_id=rule['id'], device_ip=row['device_ip'], day=day,
                        timestamp=row['timestamp'], last_seen=row['timestamp'], domain=row['domain'] or row['remote_ip'],
                        title=rule['name'], reason=reason, evidence=row['evidence'], count=1, source=row['source'])
        for (source, ip), timestamps in times.items():
            totals, lasts = Counter(), {}
            for start, end in estimate_sessions(timestamps, settings['idle_seconds']):
                cursor = start
                while cursor < end:
                    day = dt.datetime.fromtimestamp(cursor, tz).date().isoformat()
                    _, boundary = day_bounds(day, settings['utc_offset'])
                    stop = min(end, boundary)
                    totals[day] += stop - cursor
                    lasts[day] = stop
                    cursor = stop
            for rule in rules:
                if rule['kind'] != 'budget' or (rule['device_ip'] and rule['device_ip'] != ip):
                    continue
                for day, seconds in totals.items():
                    if seconds <= rule['minutes'] * 60:
                        continue
                    key = hashlib.sha256(f"{source}|{rule['id']}|{ip}|{day}|budget".encode()).hexdigest()[:24]
                    output[key] = dict(id=key, rule_id=rule['id'], device_ip=ip, day=day, timestamp=lasts[day], last_seen=lasts[day], domain='',
                        title=rule['name'], reason=f"Estimated internet-active time is {seconds / 60:.1f} minutes; daily limit is {rule['minutes']} minutes.",
                        evidence='Payload activity sessions; background exclusions applied', count=1, source=source)
        db.execute('DELETE FROM alerts')
        for row in output.values():
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

    def snapshot(self, day=None, device='', source='all'):
        if source not in ('all', 'live', 'import', 'demo'):
            raise ValueError('Invalid activity source.')
        with self.connect() as db:
            settings = self.settings(db)
            tz = dt.timezone(dt.timedelta(minutes=settings['utc_offset']))
            scope = '' if source == 'all' else ' AND capture_id IN (SELECT id FROM captures WHERE source=?)'
            scope_values = [] if source == 'all' else [source]
            dates = [r[0] for r in db.execute("SELECT DISTINCT date(timestamp + ?, 'unixepoch') FROM events WHERE 1=1" + scope + ' ORDER BY 1 DESC', [settings['utc_offset'] * 60] + scope_values)]
            today = dt.datetime.now(tz).date().isoformat()
            day = day or (today if source == 'live' else dates[0] if dates else today)
            start, end = day_bounds(day, settings['utc_offset'])
            local_row = db.execute("SELECT value FROM config WHERE key='local_device'").fetchone()
            local = json.loads(local_row[0]) if local_row else {}
            devices = [dict(r) for r in db.execute('SELECT d.*,MAX(e.timestamp) last_seen,COUNT(e.id) observations FROM devices d LEFT JOIN events e ON d.ip=e.device_ip' + scope + ' GROUP BY d.ip HAVING COUNT(e.id)>0 OR d.ip=? ORDER BY d.name', scope_values + [local.get('id', '') if source in ('live', 'all') else ''])]
            for item in devices:
                item['addresses'] = [r[0] for r in db.execute('SELECT DISTINCT source_ip FROM events WHERE device_ip=?' + scope + ' ORDER BY source_ip', [item['ip']] + scope_values)]
                item['is_local'] = item['ip'] == local.get('id')
            rows = [dict(r) for r in db.execute('SELECT * FROM events WHERE timestamp>=? AND timestamp<?' + (' AND device_ip=?' if device else '') + ' ORDER BY timestamp',
                [start - settings['idle_seconds'], end + settings['idle_seconds']] + ([device] if device else []))] if source == 'all' else [dict(r) for r in db.execute('SELECT * FROM events WHERE timestamp>=? AND timestamp<?' + scope + (' AND device_ip=?' if device else '') + ' ORDER BY timestamp', [start - settings['idle_seconds'], end + settings['idle_seconds']] + scope_values + ([device] if device else []))]
            day_rows = [r for r in rows if start <= r['timestamp'] < end]
            hourly, sessions, device_seconds = [0.0] * 24, [], Counter()
            grouped = defaultdict(list)
            for row in rows:
                if active(row, settings):
                    grouped[row['device_ip']].append(row['timestamp'])
            for ip, timestamps in grouped.items():
                for a, b in estimate_sessions(timestamps, settings['idle_seconds']):
                    a, b = max(a, start), min(b, end)
                    if b < a:
                        continue
                    sessions.append({'device_ip': ip, 'start': a, 'end': b, 'seconds': b - a})
                    device_seconds[ip] += b - a
                    for hour in range(24):
                        hourly[hour] += max(0, min(b, start + (hour + 1) * 3600) - max(a, start + hour * 3600))
            domains, categories = {}, Counter()
            for row in day_rows:
                domain = row['domain'] or row['remote_ip']
                categories[row['category']] += 1
                key = (row['device_ip'], domain, row['evidence'])
                if key not in domains:
                    domains[key] = {'device_ip': row['device_ip'], 'domain': domain, 'category': row['category'],
                                    'evidence': row['evidence'], 'first': row['timestamp'], 'last': row['timestamp'], 'count': 0, 'bytes': 0}
                domains[key]['last'] = row['timestamp']
                domains[key]['count'] += 1
                domains[key]['bytes'] += row['bytes']
            source_condition = '' if source == 'all' else ' AND source=?'
            alerts = [dict(r) for r in db.execute('SELECT * FROM alerts WHERE day=?' + source_condition + (' AND device_ip=?' if device else '') + ' ORDER BY acknowledged,timestamp DESC', [day] + scope_values + ([device] if device else []))]
            captures = [dict(r) for r in db.execute('SELECT * FROM captures WHERE 1=1' + source_condition + ' ORDER BY imported DESC LIMIT 30', scope_values)]
            for capture in captures:
                capture.pop('hash')
                capture['stats'] = json.loads(capture['stats'])
            return {'source': source, 'day': day, 'today': today, 'dates': dates, 'devices': devices, 'settings': settings,
                    'rules': [dict(r) for r in db.execute('SELECT * FROM rules ORDER BY id')],
                    'alerts': alerts, 'captures': captures, 'hourly': hourly, 'sessions': sorted(sessions, key=lambda s: s['start'], reverse=True),
                    'activity': sorted(domains.values(), key=lambda r: r['last'], reverse=True),
                    'categories': dict(categories), 'device_seconds': dict(device_seconds),
                    'summary': {'seconds': sum(device_seconds.values()), 'observations': len(day_rows),
                                'domains': len({r['domain'] for r in day_rows if r['domain']}),
                                'unacknowledged': sum(not a['acknowledged'] for a in alerts),
                                'unknown': sum(not r['domain'] for r in day_rows)}}
