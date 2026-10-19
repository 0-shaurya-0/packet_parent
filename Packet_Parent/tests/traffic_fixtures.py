"""Isolated packet fixtures for automated tests; never loaded by the application."""
import datetime as dt
import ipaddress
import struct


def checksum(data):
    data += b'\0' * (len(data) % 2)
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def packet(src, dst, sport, dport, payload):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex('00112233445566778899aabb0800') + ip + udp


def dns_pair(device, domain, remote):
    encoded = b''.join(bytes([len(label)]) + label.encode() for label in domain.split('.')) + b'\0'
    question = encoded + struct.pack('!HH', 1, 1)
    query = struct.pack('!6H', 123, 0x0100, 1, 0, 0, 0) + question
    answer = struct.pack('!6H', 123, 0x8180, 1, 1, 0, 0) + question
    answer += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 7200, 4) + ipaddress.ip_address(remote).packed
    return packet(device, '8.8.8.8', 52000, 53, query), packet('8.8.8.8', device, 53, 52000, answer)


def make_traffic(offset=330, day=None):
    tz = dt.timezone(dt.timedelta(minutes=offset))
    day = day or dt.datetime.now(tz).date()
    base = dt.datetime.combine(day, dt.time(), tz).timestamp()
    records = []
    # Two devices; overlapping apps deliberately exercise union-of-time estimation.
    sessions = [
        ('192.168.1.20', 'khanacademy.org', '142.250.1.1', 9 * 60, 28),
        ('192.168.1.20', 'wikipedia.org', '142.250.1.2', 9 * 60 + 10, 10),
        ('192.168.1.20', 'youtube.com', '142.250.1.3', 16 * 60, 24),
        ('192.168.1.20', 'roblox.com', '142.250.1.4', 19 * 60 + 10, 18),
        ('192.168.1.20', 'discord.com', '142.250.1.5', 22 * 60 + 15, 6),
        ('192.168.1.21', 'duolingo.com', '142.250.1.6', 10 * 60, 15),
        ('192.168.1.21', 'netflix.com', '142.250.1.7', 17 * 60, 20),
    ]
    for device, domain, remote, minute, duration in sessions:
        start = base + minute * 60
        query, answer = dns_pair(device, domain, remote)
        records.extend([(start, query), (start + .01, answer)])
        for second in range(0, duration * 60 + 1, 30):
            records.append((start + .1 + second, packet(device, remote, 53000, 443, b'TEST_TRAFFIC___' + b'x' * 90)))
            records.append((start + .2 + second, packet(remote, device, 443, 53000, b'TEST_TRAFFIC___' + b'y' * 350)))
    records.sort(key=lambda item: item[0])
    output = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for timestamp, frame in records:
        seconds = int(timestamp)
        output.extend(struct.pack('<IIII', seconds, int((timestamp - seconds) * 1e6), len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)
