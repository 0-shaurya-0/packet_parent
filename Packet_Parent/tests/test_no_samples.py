import sqlite3
import tempfile
import unittest
from pathlib import Path

from service import Store
from test_packetparent import BASE, DAY, pcap
from traffic_fixtures import make_traffic, packet


class LegacyCleanupTests(unittest.TestCase):
    def test_cleanup_preserves_real_rows_password_settings_and_custom_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'test.sqlite3'
            store = Store(path)
            store.setup('unchanged-password-hash',330)
            sample = store.import_capture(make_traffic(day=DAY),'legacy.pcap')
            with store.connect() as db:
                db.execute("UPDATE captures SET demo=1,source='demo' WHERE id=?",(sample['id'],))
                db.execute("UPDATE devices SET name='Aarav’s laptop',child='Aarav' WHERE ip='192.168.1.20'")
            real = pcap([(BASE+1,packet('192.168.1.20','8.8.4.4',50000,443,b'real-test-traffic'))])
            store.import_capture(real,'own-capture.pcap')
            store.save_rule(dict(name='My rule',kind='domain',target='youtube.com',start='',end='',minutes=60,device_ip='',enabled=1))
            settings = store.settings()
            restored = Store(path)
            snapshot = restored.snapshot(DAY.isoformat())
            self.assertEqual(snapshot['summary']['observations'],1)
            self.assertEqual(len(snapshot['captures']),1)
            self.assertEqual(len(snapshot['devices']),1)
            self.assertEqual(snapshot['devices'][0]['name'],'Device 192.168.1.20')
            self.assertEqual([r['name'] for r in snapshot['rules']],['My rule'])
            self.assertEqual(snapshot['alerts'],[])
            self.assertEqual(restored.auth_hash(),'unchanged-password-hash')
            self.assertEqual(restored.settings(),settings)
            backups=list((path.parent/'backups').glob('*.sqlite3'))
            self.assertEqual(len(backups),1)
            connection=sqlite3.connect(backups[0])
            try:
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM events').fetchone()[0],506)
            finally:
                connection.close()
            Store(path)
            self.assertEqual(len(list((path.parent/'backups').glob('*.sqlite3'))),1)
            with restored.connect() as db:
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_original_sample_rules_removed_but_user_rule_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'test.sqlite3'
            store = Store(path)
            capture=store.import_capture(make_traffic(day=DAY),'legacy.pcap')
            with store.connect() as db:
                db.execute('UPDATE captures SET demo=1 WHERE id=?',(capture['id'],))
                db.executemany('INSERT INTO rules(name,kind,target,start,end,minutes) VALUES(?,?,?,?,?,?)',[
                    ('Gaming during study hours','category','Gaming','19:00','21:00',60),
                    ('Internet outside permitted hours','hours','','07:00','22:00',60),
                    ('Daily internet budget','budget','','','',60),
                    ('My budget','budget','','','',30)])
            snapshot=Store(path).snapshot(DAY.isoformat())
            self.assertEqual([r['name'] for r in snapshot['rules']],['My budget'])
            self.assertEqual(snapshot['devices'],[])
            self.assertEqual(snapshot['captures'],[])
            self.assertEqual(snapshot['summary']['observations'],0)

    def test_new_database_has_no_preloaded_activity_or_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory)/'test.sqlite3')
            snapshot=store.snapshot()
            for key in ('devices','captures','rules','alerts','activity'):
                self.assertEqual(snapshot[key],[])
            with self.assertRaises(ValueError):
                store.import_capture(make_traffic(day=DAY),'example.pcap',source='demo')
            with self.assertRaises(ValueError):
                store.snapshot(source='demo')
