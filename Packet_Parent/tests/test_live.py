import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_packetparent import BASE, DAY, pcap
from traffic_fixtures import dns_pair, make_traffic, packet
from packets import parse_capture
from repair_history import repair
from service import Store

PC = {'id': 'pc-test', 'name': 'This PC', 'ips': ['192.168.1.3'], 'macs': ['66:77:88:99:aa:bb']}


class LiveTests(unittest.TestCase):
    def test_multicast_and_broadcast_not_internet(self):
        records = [(BASE+i, packet('192.168.1.3', ip, 50000, 1900, b'discovery'))
                   for i, ip in enumerate(['239.255.255.250', '224.0.0.251', '255.255.255.255'])]
        self.assertEqual(parse_capture(pcap(records))[0], [])
        self.assertEqual(parse_capture(pcap(records), PC)[0], [])

    def test_one_identity_when_address_changes_and_other_pc_ignored(self):
        own = packet('10.67.22.19', '8.8.4.4', 50000, 443, b'hello')
        changed = packet('10.12.245.195', '8.8.4.4', 50000, 443, b'hello')
        other = own[:6] + bytes.fromhex('102030405060') + own[12:]
        rows, stats = parse_capture(pcap([(BASE, own), (BASE+1, changed), (BASE+2, other)]), PC)
        self.assertEqual(len(rows), 2)
        self.assertEqual({r['device_ip'] for r in rows}, {'pc-test'})
        self.assertEqual({r['source_ip'] for r in rows}, {'10.67.22.19','10.12.245.195'})
        self.assertEqual(stats['other_device_packets'], 1)

    def test_dns_mapping_survives_segments_and_expires(self):
        query, answer = dns_pair('192.168.1.3', 'example.org', '8.8.4.4')
        state = {}
        parse_capture(pcap([(BASE,query),(BASE+.1,answer)]), PC, state)
        payload = packet('192.168.1.3','8.8.4.4',50000,443,b'hello')
        rows, _ = parse_capture(pcap([(BASE+10,payload)]), PC, state)
        self.assertEqual(rows[0]['domain'], 'example.org')
        rows, _ = parse_capture(pcap([(BASE+8000,payload)]), PC, state)
        self.assertEqual(rows[0]['domain'], '')
        rows, _ = parse_capture(pcap([(BASE+10,payload)]), PC, {})
        self.assertEqual(rows[0]['domain'], '')

    def test_source_isolation_and_empty_segment(self):
        with tempfile.TemporaryDirectory() as root:
            store = Store(Path(root)/'test.sqlite3')
            store.register_local(PC)
            store.import_capture(make_traffic(day=DAY), 'test.pcap')
            empty = store.import_capture(pcap([]), 'empty', monitored=PC)
            self.assertEqual(empty['stats']['inserted'], 0)
            live = store.snapshot(DAY.isoformat(), source='live')
            self.assertEqual([d['ip'] for d in live['devices']], ['pc-test'])
            self.assertEqual(live['summary']['observations'], 0)
            self.assertEqual(live['alerts'], [])
            self.assertEqual(store.snapshot(DAY.isoformat(), source='import')['summary']['observations'], 505)
            raw = pcap([(BASE,packet('192.168.1.3','8.8.4.4',50000,443,b'hello'))])
            store.import_capture(raw,'live',monitored=PC)
            store.import_capture(raw,'manual',source='import')
            self.assertEqual(store.snapshot(DAY.isoformat(), source='live')['summary']['observations'], 1)
            self.assertEqual(store.snapshot(DAY.isoformat(), source='import')['summary']['observations'], 506)

    def test_repair_preserves_metadata_and_backs_up(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); inbox = root/'inbox'; inbox.mkdir()
            raw = pcap([(BASE,packet('192.168.1.3','8.8.4.4',50000,443,b'hello'))])
            (inbox/'1234.pcap').write_bytes(raw)
            store = Store(root/'db.sqlite3')
            store.setup('preserved-hash',330)
            store.import_capture(raw,'1234.pcap')
            with store.connect() as db:
                db.execute("UPDATE devices SET name='My laptop',child='Owner'")
            with patch('repair_history.capture_context',return_value=PC):
                result = repair(store,root)
                self.assertEqual(repair(store,root)['repaired_captures'],0)
            self.assertTrue(Path(result['backup']).exists())
            self.assertEqual(store.auth_hash(),'preserved-hash')
            device = store.snapshot(DAY.isoformat(),source='live')['devices'][0]
            self.assertEqual((device['name'],device['child']),('My laptop','Owner'))
            self.assertEqual(device['addresses'],['192.168.1.3'])


if __name__ == '__main__':
    unittest.main()
