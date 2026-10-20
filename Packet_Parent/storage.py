"""Schema migration and per-second observation aggregation."""
import datetime as dt
import hashlib
import math
import sqlite3
from contextlib import closing
from pathlib import Path

EVENT_SCHEMA = """
CREATE TABLE events_v2(
    id INTEGER PRIMARY KEY,
    capture_id INTEGER REFERENCES captures(id),
    source TEXT NOT NULL,
    device_ip TEXT REFERENCES devices(ip), timestamp INTEGER NOT NULL,
    remote_ip TEXT NOT NULL, domain TEXT NOT NULL, protocol TEXT NOT NULL,
    evidence TEXT NOT NULL, active INTEGER NOT NULL, bytes INTEGER NOT NULL,
    category TEXT NOT NULL, source_ip TEXT NOT NULL,
    packets INTEGER NOT NULL, first_ts REAL NOT NULL, last_ts REAL NOT NULL,
    UNIQUE(source,device_ip,timestamp,remote_ip,domain,protocol,evidence,active)
);
"""


def migrate(store):
    """Back up populated legacy databases, then atomically fold packet rows."""
    with store.lock, store.connect() as db:
        if 'packets' in {row[1] for row in db.execute('PRAGMA table_info(events)')}:
            return
        if db.execute('SELECT 1 FROM events LIMIT 1').fetchone():
            folder = Path(store.path).parent / 'backups'
            folder.mkdir(exist_ok=True)
            backup = folder / ('before-aggregation-' + dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.sqlite3')
            with closing(sqlite3.connect(backup)) as destination:
                db.backup(destination)
        db.execute('BEGIN IMMEDIATE')
        db.execute(EVENT_SCHEMA)
        db.execute('''INSERT INTO events_v2(capture_id,source,device_ip,timestamp,remote_ip,
            domain,protocol,evidence,active,bytes,category,source_ip,packets,first_ts,last_ts)
            SELECT MIN(e.capture_id),c.source,e.device_ip,CAST(e.timestamp AS INTEGER),e.remote_ip,
            e.domain,e.protocol,e.evidence,e.active,SUM(e.bytes),e.category,e.source_ip,
            COUNT(*),MIN(e.timestamp),MAX(e.timestamp)
            FROM events e JOIN captures c ON c.id=e.capture_id
            GROUP BY c.source,e.device_ip,CAST(e.timestamp AS INTEGER),e.remote_ip,
                     e.domain,e.protocol,e.evidence,e.active''')
        db.execute('''CREATE TABLE fingerprints(
            fingerprint BLOB PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            capture_id INTEGER NOT NULL REFERENCES captures(id), timestamp REAL NOT NULL,
            bytes INTEGER NOT NULL, source_ip TEXT NOT NULL) WITHOUT ROWID''')
        # Point the FK at the final table only after removing the legacy table.
        db.execute('ALTER TABLE events RENAME TO legacy_events')
        db.execute('ALTER TABLE events_v2 RENAME TO events')
        # SQLite rewrites FKs on rename; recreate the empty ledger against the final name.
        db.execute('DROP TABLE fingerprints')
        db.execute('''CREATE TABLE fingerprints(
            fingerprint BLOB PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            capture_id INTEGER NOT NULL REFERENCES captures(id), timestamp REAL NOT NULL,
            bytes INTEGER NOT NULL, source_ip TEXT NOT NULL) WITHOUT ROWID''')
        query = '''SELECT old.fingerprint,new.id,old.capture_id,old.timestamp,old.bytes,old.source_ip
            FROM legacy_events old JOIN captures c ON c.id=old.capture_id JOIN events new
            ON new.source=c.source AND new.device_ip=old.device_ip
            AND new.timestamp=CAST(old.timestamp AS INTEGER) AND new.remote_ip=old.remote_ip
            AND new.domain=old.domain AND new.protocol=old.protocol
            AND new.evidence=old.evidence AND new.active=old.active'''
        db.executemany('INSERT INTO fingerprints VALUES(?,?,?,?,?,?)',
                       ((bytes.fromhex(row[0]), *row[1:]) for row in db.execute(query)))
        db.execute('DROP TABLE legacy_events')
        db.execute('CREATE INDEX event_time ON events(timestamp)')
        db.execute('CREATE INDEX event_device_time ON events(device_ip,timestamp)')
        db.execute('CREATE INDEX event_source_time ON events(source,timestamp)')
        db.execute('CREATE INDEX fingerprint_event ON fingerprints(event_id)')
        db.execute('CREATE INDEX fingerprint_capture ON fingerprints(capture_id)')


def ingest(db, rows, capture_id, source, categorize, name=None):
    """Count unseen fingerprints and upsert their exact second-level aggregates."""
    inserted = 0
    devices = set()
    for row in rows:
        fingerprint = hashlib.sha256((source + ':' + row['fingerprint']).encode()).digest()
        if db.execute('SELECT 1 FROM fingerprints WHERE fingerprint=?', (fingerprint,)).fetchone():
            continue
        ip = row['device_ip']
        if ip not in devices:
            db.execute('INSERT OR IGNORE INTO devices(ip,name) VALUES(?,?)', (ip, name or 'Device ' + ip))
            devices.add(ip)
        key = (source, ip, math.floor(row['timestamp']), row['remote_ip'], row['domain'],
               row['protocol'], row['evidence'], row['active'])
        event_id = db.execute('''INSERT INTO events(source,device_ip,timestamp,remote_ip,domain,
            protocol,evidence,active,bytes,capture_id,category,source_ip,packets,first_ts,last_ts)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)
            ON CONFLICT(source,device_ip,timestamp,remote_ip,domain,protocol,evidence,active)
            DO UPDATE SET packets=packets+1,bytes=bytes+excluded.bytes,
                first_ts=MIN(first_ts,excluded.first_ts),last_ts=MAX(last_ts,excluded.last_ts)
            RETURNING id''', key + (row['bytes'], capture_id, categorize(row['domain']),
                                    row['source_ip'], row['timestamp'], row['timestamp'])).fetchone()[0]
        db.execute('INSERT INTO fingerprints VALUES(?,?,?,?,?,?)',
                   (fingerprint, event_id, capture_id, row['timestamp'], row['bytes'], row['source_ip']))
        inserted += 1
    return inserted


def remove_capture_events(db, capture_id):
    """Remove one capture's contribution, retaining aggregates shared with other files."""
    ids = [row[0] for row in db.execute('SELECT DISTINCT event_id FROM fingerprints WHERE capture_id=?', (capture_id,))]
    db.execute('DELETE FROM fingerprints WHERE capture_id=?', (capture_id,))
    for event_id in ids:
        row = db.execute('''SELECT COUNT(*),SUM(bytes),MIN(timestamp),MAX(timestamp),MIN(capture_id)
                            FROM fingerprints WHERE event_id=?''', (event_id,)).fetchone()
        if not row[0]:
            db.execute('DELETE FROM events WHERE id=?', (event_id,))
        else:
            db.execute('UPDATE events SET packets=?,bytes=?,first_ts=?,last_ts=?,capture_id=? WHERE id=?', (*row, event_id))
