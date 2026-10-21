"""Raw-file lifecycle and metadata retention regression tests."""
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from service import Store, day_bounds
from test_packetparent import pcap
from traffic_fixtures import packet


class PrivacyTests(unittest.TestCase):
    def test_success_disposition_default_and_keep(self):
        """Both raw capture and sidecar leave the inbox; keep never overwrites."""
        import app
        with tempfile.TemporaryDirectory() as directory:
            inbox = Path(directory) / 'inbox'
            inbox.mkdir()
            path = inbox / 'segment.pcap'
            sidecar = path.with_suffix('.json')
            for keep in (False, True, True):
                path.write_bytes(b'raw')
                sidecar.write_text('{}')
                app.finish_capture(path, keep)
                self.assertFalse(path.exists())
                self.assertFalse(sidecar.exists())
            self.assertEqual(len(list((inbox.parent / 'processed').glob('*.pcap'))), 2)
            self.assertEqual(len(list((inbox.parent / 'processed').glob('*.json'))), 2)

    def test_purge_boundary_alerts_and_forever(self):
        """Retention removes old metadata and ledger entries but keeps file receipts."""
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'db.sqlite3')
            now = day_bounds('2026-10-20', 330)[0] + 3600
            cutoff = day_bounds('2026-10-18', 330)[0]
            frame = packet('192.168.1.3', '8.8.4.4', 50000, 443, b'hello')
            store.save_rule(dict(name='hours', kind='hours', target='', start='07:00',
                                 end='22:00', minutes=1, device_ip='', enabled=1))
            raw = pcap([(cutoff-30, frame), (cutoff+30, frame)])
            store.import_capture(raw, 'boundary.pcap')
            settings = store.settings()
            settings['retention_days'] = 0
            store.save_settings(settings)
            self.assertEqual(store.purge(now), 0)
            settings['retention_days'] = 2
            store.save_settings(settings)
            self.assertEqual(store.purge(now), 1)
            self.assertEqual(store.purge(now), 0)
            self.assertEqual(store.snapshot('2026-10-18')['summary']['seconds'], 0)
            self.assertEqual(store.snapshot('2026-10-17')['alerts'], [])
            with store.connect() as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM fingerprints').fetchone()[0], 1)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM event_addresses').fetchone()[0], 1)
                self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
            self.assertTrue(store.import_capture(raw, 'same.pcap')['duplicate'])

class WatcherTests(unittest.TestCase):
    def test_corrupt_file_quarantined_once_and_other_files_continue(self):
        """A corrupt segment cannot block later imports or loop on every poll."""
        import app
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / 'inbox'
            inbox.mkdir()
            store = Store(root / 'db.sqlite3')
            context = dict(id='pc-test', name='Test PC', ips=['192.168.1.3'], macs=[])
            status = dict(running=True, last_import=None, error=None)
            bad = inbox / 'a-bad.pcap'
            bad.write_bytes(b'broken')
            bad.with_suffix('.json').write_text('{}')
            seen = {}
            with patch.object(app.app.state.runtime, 'store', store), patch.object(app.app.state.runtime, 'inbox', inbox), patch.object(app.app.state.runtime, 'watch_status', status), patch.object(app, 'capture_context', return_value=context), patch.object(store, 'import_capture', wraps=store.import_capture) as importer:
                app.poll_inbox(seen)
                app.poll_inbox(seen)
                self.assertEqual(importer.call_count, 1)
                self.assertIn('a-bad.pcap', status['error'])
                self.assertFalse(bad.exists())
                self.assertEqual(len(list((root / 'failed').glob('*.pcap'))), 1)
                self.assertEqual(len(list((root / 'failed').glob('*.json'))), 1)
                self.assertTrue(next((root / 'failed').glob('*.error.txt')).read_text())
                app.poll_inbox(seen)
                self.assertEqual(importer.call_count, 1)
                frame = packet('192.168.1.3', '8.8.4.4', 50000, 443, b'hello')
                (inbox / 'b-good.pcap').write_bytes(pcap([(dt.datetime.now().timestamp(), frame)]))
                app.poll_inbox(seen)
                app.poll_inbox(seen)
                self.assertEqual(importer.call_count, 2)
                self.assertIsNone(status['error'])
                self.assertIsNotNone(status['last_import'])
                self.assertEqual(store.snapshot()['summary']['observations'], 1)
                self.assertEqual(list(inbox.iterdir()), [])
                self.assertEqual(seen, {})
