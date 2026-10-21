"""IPv6 extension and encrypted UDP evidence regression tests."""
import unittest

from packets import parse_capture
from test_packetparent import BASE, pcap
from traffic_fixtures import ipv6_udp, packet


class ExtensionTests(unittest.TestCase):
    def test_fragment_first_and_nonfirst(self):
        """First fragments may expose transport metadata; later fragments cannot."""
        rows, _ = parse_capture(pcap([(BASE, ipv6_udp(44))], link=101))
        self.assertEqual(rows[0]['device_ip'], 'fd00::3')
        self.assertEqual(rows[0]['evidence'], 'QUIC (encrypted)')
        self.assertEqual(parse_capture(pcap([(BASE, ipv6_udp(44, True))], link=101))[0], [])

    def test_authentication_header_length(self):
        """AH uses four-byte units plus two, unlike other extension headers."""
        rows, _ = parse_capture(pcap([(BASE, ipv6_udp(51))], link=101))
        self.assertEqual(rows[0]['bytes'], 5)
        self.assertEqual(rows[0]['protocol'], 'UDP')
        self.assertEqual(parse_capture(pcap([(BASE, ipv6_udp(51)[:46])], link=101))[0], [])

    def test_udp_443_evidence_and_other_udp(self):
        """Unidentified UDP/443 remains visible without claiming decryption."""
        for port, evidence in [(443, 'QUIC (encrypted)'), (444, 'IP connection')]:
            frame = packet('192.168.1.3', '8.8.4.4', 50000, port, b'hello')
            rows, _ = parse_capture(pcap([(BASE, frame)]))
            self.assertEqual(rows[0]['evidence'], evidence)
            self.assertEqual(rows[0]['domain'], '')
