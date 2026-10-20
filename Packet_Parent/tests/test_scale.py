"""Regression tests for compact storage and legacy migration."""
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path

from service import Store
from test_packetparent import BASE, DAY, pcap
from traffic_fixtures import packet


class AggregationTests(unittest.TestCase):
    def test_seconds_merge_across_files_and_dedupe(self):
        """Counters, exact session endpoints and duplicates survive merging."""
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'db.sqlite3')
            frame = packet('192.168.1.3', '8.8.4.4', 50000, 443, b'hello')
            records = [(BASE + index / 100, frame) for index in range(200)]
            store.import_capture(pcap(records[:100]), 'first.pcap')
            store.import_capture(pcap(records[50:]), 'overlap.pcap')
            with store.connect() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 2)
                self.assertEqual(db.execute('SELECT SUM(packets) FROM events').fetchone()[0], 200)
                self.assertEqual(db.execute('SELECT SUM(bytes) FROM events').fetchone()[0], 1000)
            view = store.snapshot(DAY.isoformat())
            self.assertEqual(view['summary']['observations'], 200)
            self.assertAlmostEqual(view['summary']['seconds'], 1.99, places=5)
            self.assertEqual(store.import_capture(pcap(records, endian='>'), 'again.pcap')['stats']['inserted'], 0)

    def test_legacy_migration_backup_and_idempotence(self):
        """Migration folds old rows without losing hashes or creating repeat backups."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'db.sqlite3'
            store = Store(path)
            frame = packet('192.168.1.3', '8.8.4.4', 50000, 443, b'hello')
            raw = pcap([(BASE+.1, frame), (BASE+.2, frame)])
            store.import_capture(raw, 'old.pcap')
            with store.connect() as db:
                ledger = list(db.execute('SELECT * FROM fingerprints'))
                event = dict(db.execute('SELECT * FROM events').fetchone())
                db.execute('DROP TABLE fingerprints')
                db.execute('DROP TABLE events')
                db.execute('''CREATE TABLE events(id INTEGER PRIMARY KEY,fingerprint TEXT UNIQUE,
                    capture_id INTEGER,device_ip TEXT,timestamp REAL,remote_ip TEXT,domain TEXT,
                    protocol TEXT,evidence TEXT,active INTEGER,bytes INTEGER,category TEXT,source_ip TEXT)''')
                for row in ledger:
                    db.execute('INSERT INTO events VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?)',
                               (row['fingerprint'].hex(), row['capture_id'], event['device_ip'],
                                row['timestamp'], event['remote_ip'], event['domain'], event['protocol'],
                                event['evidence'], event['active'], row['bytes'], event['category'], row['source_ip']))
            migrated = Store(path)
            with migrated.connect() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)
                self.assertEqual(db.execute('SELECT packets FROM events').fetchone()[0], 2)
                self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
            backups = list((path.parent / 'backups').glob('before-aggregation-*'))
            self.assertEqual(len(backups), 1)
            with closing(sqlite3.connect(backups[0])) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 2)
            Store(path)
            self.assertEqual(len(list((path.parent / 'backups').glob('*'))), 1)
            self.assertEqual(migrated.import_capture(pcap([(BASE+.1, frame), (BASE+.2, frame)], endian='>'), 'again.pcap')['stats']['inserted'], 0)

