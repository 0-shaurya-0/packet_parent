"""Configuration and server lifecycle regression tests."""
import datetime as dt
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import capture_agent
from local_monitor import server_port
from service import Store


class RuntimeTests(unittest.TestCase):
    def test_port_is_shared_with_capture_discovery(self):
        """The helper discovers the configured server port, and invalid ports fail."""
        with patch.dict(os.environ, {'PACKETPARENT_PORT': '9876'}):
            self.assertEqual(server_port(), 9876)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                reply = io.BytesIO(json.dumps({'application': 'PacketParent', 'data_dir': str(root)}).encode())
                with patch.dict(os.environ, {'PACKETPARENT_DATA': str(root)}), patch('capture_agent.urllib.request.urlopen', return_value=reply) as request:
                    self.assertEqual(capture_agent.resolve_root(), root.resolve())
                    self.assertEqual(request.call_args.args[0], 'http://127.0.0.1:9876/api/health')
        for value in ('no', '0', '65536'):
            with patch.dict(os.environ, {'PACKETPARENT_PORT': value}):
                with self.assertRaises(ValueError):
                    server_port()

    def test_startup_and_daily_purge(self):
        """Server startup purges once, and the running watcher revisits each day."""
        import app
        from fastapi.testclient import TestClient
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'db.sqlite3')
            with patch.object(app.app.state.runtime, 'store', store), patch.object(store, 'purge', wraps=store.purge) as purge:
                with TestClient(app.app):
                    self.assertEqual(purge.call_count, 1)
            stop = Mock()
            stop.wait.side_effect = [False, False, False, True]
            times = [dt.datetime(2026, 10, 20), dt.datetime(2026, 10, 20), dt.datetime(2026, 10, 21)]
            with patch.object(app.app.state.runtime, 'store', store), patch.object(store, 'purge') as purge, patch.object(app.dt, 'datetime') as clock:
                clock.now.side_effect = times
                app.watcher(stop)
                self.assertEqual(purge.call_count, 2)

    def test_snaplen_default_and_environment(self):
        """Argument parsing accepts the default and environment snapshot lengths."""
        # --list exercises parsing without starting capture or requiring TShark.
        for value in ('2048', '1024'):
            with patch.dict(os.environ, {'PACKETPARENT_SNAPLEN': value}), patch('sys.argv', ['capture.py', '--list']), patch('capture_agent.tshark_path', return_value='tshark'), patch('capture_agent.interfaces', return_value=[]):
                capture_agent.main()
        with patch.dict(os.environ, {'PACKETPARENT_SNAPLEN': '12'}), patch('sys.argv', ['capture.py', '--list']), patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(SystemExit):
                capture_agent.main()
