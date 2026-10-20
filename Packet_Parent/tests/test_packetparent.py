import datetime as dt
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traffic_fixtures import dns_pair, make_traffic, packet
from packets import CaptureError, dns_name, frames, parse_capture, tls_sni
from service import Store, category, day_bounds, estimate_sessions, matches, window_contains

DAY = dt.date(2026, 10, 14)
BASE = day_bounds(DAY.isoformat(), 330)[0]


def pcap(records, endian='<', nano=False, link=1):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    output = bytearray(struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, 65535, link))
    for timestamp, frame in records:
        sec = int(timestamp)
        output.extend(struct.pack(endian + 'IIII', sec, round((timestamp-sec)*(1e9 if nano else 1e6)), len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def block(kind, body, endian='<'):
    body += b'\0' * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack(endian + 'II', kind, length) + body + struct.pack(endian + 'I', length)


class ParserTests(unittest.TestCase):
    def test_capture_domain_evidence(self):
        rows, stats = parse_capture(make_traffic(day=DAY))
        self.assertEqual(stats['packets'], 512)
        self.assertEqual(len(rows), 505)
        self.assertEqual({r['device_ip'] for r in rows}, {'192.168.1.20', '192.168.1.21'})
        self.assertIn('roblox.com', {r['domain'] for r in rows})
        self.assertTrue(all(not r['active'] for r in rows if r['evidence'] == 'DNS query'))
        self.assertTrue(any(r['evidence'] == 'DNS-to-IP inference' for r in rows))

    def test_endian_and_nanosecond_formats(self):
        frame = packet('192.168.1.3','8.8.4.4',50000,443,b'hello')
        for endian in ('<','>'):
            for nano in (False,True):
                result = list(frames(pcap([(BASE+.125,frame)],endian,nano)))
                self.assertAlmostEqual(result[0][0],BASE+.125,places=5)
                self.assertEqual(result[0][2],frame)

    def test_pcapng_timestamp_and_endian(self):
        frame=packet('192.168.1.3','8.8.4.4',50000,443,b'hello')
        for endian in ('<','>'):
            section=block(0x0a0d0d0a,struct.pack(endian+'IHHq',0x1a2b3c4d,1,0,-1),endian)
            options=struct.pack(endian+'HH',9,1)+b'\x09\0\0\0'+struct.pack(endian+'HH',0,0)
            interface=block(1,struct.pack(endian+'HHI',1,0,65535)+options,endian)
            stamp=int(BASE*1e9)+125_000_000
            record=block(6,struct.pack(endian+'IIIII',0,stamp>>32,stamp&0xffffffff,len(frame),len(frame))+frame,endian)
            result=list(frames(section+interface+record))
            self.assertAlmostEqual(result[0][0],BASE+.125,places=5)
            self.assertEqual(parse_capture(section+interface+record)[0][0]['device_ip'],'192.168.1.3')

    def test_truncated_capture_rejected(self):
        for value in (b'not a capture',make_traffic(day=DAY)[:-2],b'\xd4\xc3\xb2\xa1'):
            with self.assertRaises(CaptureError):
                parse_capture(value)

    def test_unsupported_link_rejected(self):
        with self.assertRaises(CaptureError):
            parse_capture(pcap([(BASE,b'abcdef')],link=999))

    def test_dns_pointer_cycle_bounded(self):
        with self.assertRaises(ValueError):
            dns_name(b'\xc0\x00',0)

    def test_tls_visible_server_name(self):
        name=b'example.org'
        entry=b'\x00'+struct.pack('!H',len(name))+name
        sni=struct.pack('!H',len(entry))+entry
        extensions=struct.pack('!HH',0,len(sni))+sni
        hello=b'\x03\x03'+bytes(32)+b'\0'+b'\0\x02\x13\x01'+b'\x01\x00'+struct.pack('!H',len(extensions))+extensions
        handshake=b'\x01'+len(hello).to_bytes(3,'big')+hello
        record=b'\x16\x03\x01'+struct.pack('!H',len(handshake))+handshake
        self.assertEqual(tls_sni(record),'example.org')
        self.assertEqual(tls_sni(record[:15]),'')

    def test_dns_ttl_expires(self):
        query,answer=dns_pair('192.168.1.3','example.org','8.8.4.4')
        payload=packet('192.168.1.3','8.8.4.4',50000,443,b'hello')
        rows,_=parse_capture(pcap([(BASE,query),(BASE+.1,answer),(BASE+10,payload),(BASE+8000,payload)]))
        self.assertEqual(rows[-2]['domain'],'example.org')
        self.assertEqual(rows[-1]['domain'],'')

    def test_private_lan_and_ntp_do_not_count(self):
        records=[(BASE,packet('192.168.1.3','192.168.1.5',50000,443,b'local')),
                 (BASE+1,packet('192.168.1.3','8.8.4.4',50000,123,b'ntp'))]
        self.assertEqual(parse_capture(pcap(records))[0],[])

    def test_http_hostname_from_tcp_packet(self):
        payload=b'GET / HTTP/1.1\r\nHost: www.example.org\r\n\r\n'
        tcp=struct.pack('!HHIIBBHHH',50000,80,1,0,0x50,0x18,4096,0,0)+payload
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,0,64,6,0,bytes([192,168,1,3]),bytes([8,8,4,4]))
        raw=bytes.fromhex('00112233445566778899aabb0800')+ip+tcp
        rows,_=parse_capture(pcap([(BASE,raw)]))
        self.assertEqual(rows[0]['domain'],'www.example.org')
        self.assertEqual(rows[0]['evidence'],'HTTP Host')

    def test_raw_ipv6_ula_device(self):
        import ipaddress
        udp=struct.pack('!HHHH',50000,443,13,0)+b'hello'
        ipv6=struct.pack('!IHBB',6<<28,len(udp),17,64)+ipaddress.ip_address('fd00::3').packed+ipaddress.ip_address('2001:4860:4860::8888').packed+udp
        rows,_=parse_capture(pcap([(BASE,ipv6)],link=101))
        self.assertEqual(rows[0]['device_ip'],'fd00::3')
        self.assertEqual(rows[0]['active'],1)


class EstimationTests(unittest.TestCase):
    def test_overlapping_apps_are_merged_and_no_idle_tail(self):
        sessions=estimate_sessions([0,30,30,60,90,120,600,630],120)
        self.assertEqual(sessions,[(0,120),(600,630)])
        self.assertEqual(sum(b-a for a,b in sessions),150)

    def test_single_observation_has_zero_duration(self):
        self.assertEqual(estimate_sessions([42]),[(42,42)])
        self.assertEqual(estimate_sessions([]),[])

    def test_domain_boundaries(self):
        self.assertTrue(matches('www.youtube.com','youtube.com'))
        self.assertFalse(matches('notyoutube.com','youtube.com'))
        self.assertFalse(matches('youtube.com.evil.example','youtube.com'))
        self.assertEqual(category('classroom.google.com'),'Education')
        self.assertEqual(category('new-unknown.example'),'Unknown')

    def test_overnight_hours(self):
        self.assertTrue(window_contains(23*60,'22:00','06:00'))
        self.assertTrue(window_contains(5*60,'22:00','06:00'))
        self.assertFalse(window_contains(12*60,'22:00','06:00'))
        self.assertFalse(window_contains(6*60,'22:00','06:00'))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=Store(Path(self.temp.name)/'test.sqlite3')

    def tearDown(self):
        self.temp.cleanup()

    def load(self):
        result = self.store.import_capture(make_traffic(day=DAY),'test.pcap')
        if not self.store.snapshot()['rules']:
            for name,kind,target,start,end,minutes in [
                ('Gaming during study hours','category','Gaming','19:00','21:00',60),
                ('Internet outside permitted hours','hours','','07:00','22:00',60),
                ('Daily internet budget','budget','','','',60)]:
                self.store.save_rule(dict(name=name,kind=kind,target=target,start=start,end=end,minutes=minutes,device_ip='',enabled=1))
        return result

    def test_full_pipeline_expected_time_and_alerts(self):
        self.load(); snapshot=self.store.snapshot(DAY.isoformat())
        self.assertAlmostEqual(snapshot['device_seconds']['192.168.1.20']/60,76,delta=.02)
        self.assertAlmostEqual(snapshot['device_seconds']['192.168.1.21']/60,35,delta=.02)
        self.assertEqual(snapshot['summary']['unacknowledged'],3)
        self.assertAlmostEqual(sum(snapshot['hourly']),snapshot['summary']['seconds'])

    def test_file_and_packet_deduplication(self):
        self.load()
        self.assertTrue(self.load()['duplicate'])
        records=[(ts,frame) for ts,link,frame in frames(make_traffic(day=DAY))]
        result=self.store.import_capture(pcap(records,endian='>'),'reencoded.pcap')
        self.assertEqual(result['stats']['inserted'],0)
        self.assertEqual(self.store.snapshot()['summary']['observations'],505)

    def test_bad_import_does_not_partially_commit(self):
        with self.assertRaises(CaptureError):
            self.store.import_capture(make_traffic(day=DAY)[:-5],'broken.pcap')
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM captures').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)

    def test_ignored_domain_changes_time_not_activity(self):
        self.load(); settings=self.store.settings(); settings['ignored_domains']+=['youtube.com']
        self.store.save_settings(settings)
        snapshot=self.store.snapshot(DAY.isoformat(),'192.168.1.20')
        self.assertAlmostEqual(snapshot['summary']['seconds']/60,52,delta=.02)
        self.assertTrue(any(r['domain']=='youtube.com' for r in snapshot['activity']))
        self.assertFalse(any(a['title']=='Daily internet budget' for a in snapshot['alerts']))

    def test_acknowledgement_persists_when_rules_rebuilt(self):
        self.load(); alert=self.store.snapshot()['alerts'][0]
        with self.store.connect() as db:
            db.execute('UPDATE alerts SET acknowledged=1 WHERE id=?',(alert['id'],))
        self.store.save_settings(self.store.settings())
        self.assertTrue(next(a for a in self.store.snapshot()['alerts'] if a['id']==alert['id'])['acknowledged'])

    def test_midnight_sessions_split_between_days(self):
        end=BASE+86400
        frame=packet('192.168.1.3','8.8.4.4',50000,443,b'hello')
        self.store.import_capture(pcap([(end-30,frame),(end+30,frame)]),'midnight.pcap')
        self.assertEqual(self.store.snapshot('2026-10-14')['summary']['seconds'],30)
        self.assertEqual(self.store.snapshot('2026-10-15')['summary']['seconds'],30)

    def test_pause_and_delete_rules(self):
        self.load(); rule=self.store.snapshot()['rules'][0]; rid=rule.pop('id'); rule['enabled']=0
        self.store.save_rule(rule,rid)
        self.assertFalse(any(a['rule_id']==rid for a in self.store.snapshot()['alerts']))
        self.store.delete_rule(rid)
        self.assertEqual(len(self.store.snapshot()['rules']),2)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime=tempfile.TemporaryDirectory()
        os.environ['PACKETPARENT_DATA']=cls.runtime.name
        import app
        cls.module=app
        from fastapi.testclient import TestClient
        cls.TestClient=TestClient

    @classmethod
    def tearDownClass(cls):
        cls.runtime.cleanup()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.module.store=Store(Path(self.temp.name)/'api.sqlite3')
        self.module.sessions.clear();self.module.attempts.clear()
        self.client=self.TestClient(self.module.app)
        self.headers={'X-PacketParent':'1'}

    def tearDown(self):
        self.client.close();self.temp.cleanup()

    def setup_parent(self):
        result=self.client.post('/api/auth/setup',json={'password':'test-parent-123','utc_offset':330},headers=self.headers)
        self.assertEqual(result.status_code,200)

    def test_auth_and_request_protection(self):
        self.assertEqual(self.client.get('/api/dashboard').status_code,401)
        self.assertEqual(self.client.post('/api/auth/setup',json={'password':'test-parent-123'}).status_code,403)
        self.setup_parent()
        self.assertEqual(self.client.get('/api/dashboard').status_code,200)
        self.assertIn('HttpOnly',self.client.cookies.get('pp_session') and self.client.post('/api/auth/login',json={'password':'test-parent-123'},headers=self.headers).headers['set-cookie'])
        self.assertEqual(self.client.post('/api/auth/setup',json={'password':'test-parent-123'},headers=self.headers).status_code,409)
        self.client.post('/api/auth/logout',headers=self.headers)
        self.assertEqual(self.client.get('/api/dashboard').status_code,401)

    def test_api_import_and_duplicate(self):
        self.setup_parent();raw=make_traffic(day=DAY)
        first=self.client.post('/api/captures?name=test.pcap',content=raw,headers=self.headers)
        self.assertEqual(first.status_code,200)
        self.assertEqual(first.json()['stats']['inserted'],505)
        second=self.client.post('/api/captures?name=test.pcap',content=raw,headers=self.headers)
        self.assertTrue(second.json()['duplicate'])
        dashboard=self.client.get('/api/dashboard?day=2026-10-14&source=import').json()
        self.assertEqual(dashboard['summary']['domains'],7)

    def test_no_sample_endpoints_or_controls(self):
        self.setup_parent()
        self.assertEqual(self.client.post('/api/demo',headers=self.headers).status_code,404)
        self.assertEqual(self.client.get('/api/demo/download').status_code,404)
        self.assertEqual(self.client.get('/api/dashboard?source=demo').status_code,400)
        snapshot=self.client.get('/api/dashboard').json()
        self.assertEqual(snapshot['summary']['observations'],0)
        self.assertEqual(snapshot['rules'],[])
        self.assertNotIn('Sample demo',self.client.get('/').text)
        self.assertNotIn('Explore sample family',self.client.get('/static/app.js').text)

    def test_invalid_inputs_and_rule_validation(self):
        self.setup_parent()
        self.assertEqual(self.client.post('/api/captures?name=x.pcap',content=b'bad',headers=self.headers).status_code,400)
        self.assertEqual(self.client.get('/api/dashboard?day=not-a-date').status_code,400)
        self.assertEqual(self.client.post('/api/rules',json={'name':'Bad','kind':'domain','target':'https://example.com'},headers=self.headers).status_code,400)
        self.assertEqual(self.client.put('/api/settings',json={'idle_seconds':-10},headers=self.headers).status_code,400)
        self.assertEqual(self.client.post('/api/rules',json={'name':'Bad','kind':'hours','start':'25:00','end':'05:00'},headers=self.headers).status_code,400)

    def test_device_rule_and_alert_workflow(self):
        self.setup_parent();self.client.post('/api/captures?name=test.pcap',content=make_traffic(day=DAY),headers=self.headers)
        self.assertEqual(self.client.put('/api/devices/192.168.1.20',json={'name':'Study laptop','child':'Owner'},headers=self.headers).status_code,200)
        response=self.client.post('/api/rules',json={'name':'YouTube review','kind':'domain','target':'youtube.com'},headers=self.headers)
        self.assertEqual(response.status_code,200)
        snapshot=self.client.get('/api/dashboard?source=import&day=2026-10-14').json()
        alert=next(a for a in snapshot['alerts'] if a['title']=='YouTube review')
        self.client.post('/api/alerts/'+alert['id']+'/acknowledge',headers=self.headers)
        self.assertTrue(next(a for a in self.client.get('/api/dashboard?source=import&day=2026-10-14').json()['alerts'] if a['id']==alert['id'])['acknowledged'])

    def test_privacy_settings_validation(self):
        """Privacy settings accept only bounded integers and real booleans."""
        self.setup_parent()
        for value in (-1, 36501, True, '90'):
            self.assertEqual(self.client.put('/api/settings', json={'retention_days': value}, headers=self.headers).status_code, 400)
        self.assertEqual(self.client.put('/api/settings', json={'keep_raw_captures': 'false'}, headers=self.headers).status_code, 400)
        response = self.client.put('/api/settings', json={'keep_raw_captures': True, 'retention_days': 0}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        values = self.client.get('/api/dashboard').json()['settings']
        self.assertTrue(values['keep_raw_captures'])
        self.assertEqual(values['retention_days'], 0)

    def test_completed_inbox_file_is_imported(self):
        self.setup_parent()
        original=self.module.INBOX
        inbox=Path(self.temp.name)/'inbox';inbox.mkdir()
        self.module.INBOX=inbox
        (inbox/'finished.pcap').write_bytes(make_traffic())
        (inbox/'finished.json').write_text('{}')
        stop=threading.Event()
        worker=threading.Thread(target=self.module.watcher,args=(stop,))
        mock_context = patch.object(self.module, 'capture_context', return_value={'id':'pc-test','name':'Test PC','ips':['192.168.1.20','192.168.1.21'],'macs':[]})
        mock_context.start()
        worker.start()
        try:
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                if self.module.store.snapshot()['summary']['observations']==505 and not (inbox/'finished.pcap').exists():
                    break
                time.sleep(.1)
            self.assertEqual(self.module.store.snapshot()['summary']['observations'],505)
            self.assertIsNone(self.module.watch_status['error'])
            self.assertFalse((inbox/'finished.pcap').exists())
            self.assertFalse((inbox/'finished.json').exists())
        finally:
            stop.set();worker.join(timeout=3);self.module.INBOX=original;mock_context.stop()


if __name__=='__main__':
    unittest.main(verbosity=2)
