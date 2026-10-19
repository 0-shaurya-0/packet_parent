"""Bounded metadata parser. No TLS decryption or packet payload persistence."""
import hashlib
import ipaddress
import re
import struct
from collections import Counter


class CaptureError(ValueError):
    pass


def frames(data):
    """Yield timestamp, link type, frame for classic PCAP and PCAPNG EPBs."""
    magic = data[:4]
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1e6), b'\xa1\xb2\xc3\xd4': ('>', 1e6),
               b'\x4d\x3c\xb2\xa1': ('<', 1e9), b'\xa1\xb2\x3c\x4d': ('>', 1e9)}
    if magic in formats:
        endian, divisor = formats[magic]
        if len(data) < 24:
            raise CaptureError('Truncated PCAP header.')
        major, minor = struct.unpack_from(endian + 'HH', data, 4)
        if (major, minor) != (2, 4):
            raise CaptureError('Unsupported PCAP version; export as PCAP 2.4.')
        link = struct.unpack_from(endian + 'I', data, 20)[0] & 0xffff
        pos = 24
        while pos < len(data):
            if pos + 16 > len(data):
                raise CaptureError('Incomplete packet header. Upload a finished capture.')
            sec, frac, length, original = struct.unpack_from(endian + 'IIII', data, pos)
            pos += 16
            if pos + length > len(data) or length > original or frac >= divisor:
                raise CaptureError('Invalid or incomplete packet record.')
            yield sec + frac / divisor, link, data[pos:pos + length]
            pos += length
    elif magic == b'\x0a\x0d\x0d\x0a':
        pos, endian, interfaces = 0, '<', []
        while pos < len(data):
            if pos + 12 > len(data):
                raise CaptureError('Incomplete PCAPNG block.')
            if data[pos:pos + 4] == magic:
                bom = data[pos + 8:pos + 12]
                if bom not in (b'\x4d\x3c\x2b\x1a', b'\x1a\x2b\x3c\x4d'):
                    raise CaptureError('Invalid PCAPNG byte order.')
                endian = '<' if bom[0] == 0x4d else '>'
                interfaces = []
            kind, length = struct.unpack_from(endian + 'II', data, pos)
            if length < 12 or length % 4 or pos + length > len(data):
                raise CaptureError('Invalid or incomplete PCAPNG block.')
            if struct.unpack_from(endian + 'I', data, pos + length - 4)[0] != length:
                raise CaptureError('PCAPNG block length mismatch.')
            body = data[pos + 8:pos + length - 4]
            if kind == 0x0a0d0d0a and len(body) < 16:
                raise CaptureError('Invalid section header.')
            if kind == 1:
                if len(body) < 8:
                    raise CaptureError('Invalid interface description.')
                link = struct.unpack_from(endian + 'H', body)[0]
                resolution, offset, op = 1e-6, 0, 8
                while op + 4 <= len(body):
                    code, size = struct.unpack_from(endian + 'HH', body, op)
                    op += 4
                    if op + size > len(body):
                        raise CaptureError('Invalid interface option.')
                    if code == 0:
                        break
                    if code == 9 and size == 1:
                        value = body[op]
                        resolution = (2 if value & 128 else 10) ** -(value & 127)
                    if code == 14 and size == 8:
                        offset = struct.unpack_from(endian + 'q', body, op)[0]
                    op += (size + 3) & ~3
                interfaces.append((link, resolution, offset))
            elif kind == 6:
                if len(body) < 20:
                    raise CaptureError('Invalid enhanced packet block.')
                interface, high, low, caplen, original = struct.unpack_from(endian + 'IIIII', body)
                if interface >= len(interfaces) or caplen > len(body) - 20 or caplen > original:
                    raise CaptureError('Invalid packet block interface or length.')
                link, resolution, offset = interfaces[interface]
                yield ((high << 32) | low) * resolution + offset, link, body[20:20 + caplen]
            elif kind in (2, 3):
                raise CaptureError('This PCAPNG uses legacy or untimestamped packet blocks. Export as classic PCAP.')
            pos += length
    else:
        raise CaptureError('Choose a PCAP or PCAPNG capture, not a text or CSV file.')


def clean_domain(value):
    value = value.strip().lower().rstrip('.')
    if not value or len(value) > 253 or not re.fullmatch(r'[a-z0-9_.-]+', value):
        return ''
    return value


def dns_name(buf, start):
    labels, pos, end, seen = [], start, None, set()
    while True:
        if pos >= len(buf) or pos in seen or len(seen) > 128:
            raise ValueError('Invalid DNS name')
        seen.add(pos)
        size = buf[pos]
        if size & 0xc0 == 0xc0:
            if pos + 1 >= len(buf):
                raise ValueError('Truncated DNS pointer')
            if end is None:
                end = pos + 2
            pos = ((size & 63) << 8) | buf[pos + 1]
            continue
        pos += 1
        if size == 0:
            return clean_domain('.'.join(labels)), end or pos
        if size > 63 or pos + size > len(buf):
            raise ValueError('Invalid DNS label')
        labels.append(buf[pos:pos + size].decode('ascii', errors='replace'))
        pos += size


def dns_metadata(buf):
    if len(buf) < 12:
        raise ValueError('Short DNS')
    ident, flags, questions, answers, _, _ = struct.unpack_from('!6H', buf)
    pos, names, records = 12, [], []
    if questions > 32 or answers > 256:
        raise ValueError('Oversized DNS')
    for _ in range(questions):
        name, pos = dns_name(buf, pos)
        if pos + 4 > len(buf):
            raise ValueError('Short question')
        names.append(name)
        pos += 4
    for _ in range(answers):
        name, pos = dns_name(buf, pos)
        typ, cls, ttl, size = struct.unpack_from('!HHIH', buf, pos)
        pos += 10
        if pos + size > len(buf):
            raise ValueError('Short answer')
        if cls == 1 and ((typ == 1 and size == 4) or (typ == 28 and size == 16)):
            records.append((str(ipaddress.ip_address(buf[pos:pos + size])), names[0] if names else name, ttl))
        pos += size
    return bool(flags & 0x8000), names, records


def tls_sni(payload):
    """Read visible SNI only when ClientHello is complete within this TCP payload."""
    try:
        if len(payload) < 9 or payload[0] != 22 or payload[5] != 1:
            return ''
        record_size = int.from_bytes(payload[3:5], 'big')
        if len(payload) < 5 + record_size:
            return ''
        p = payload[9:5 + record_size]
        pos = 34
        pos += 1 + p[pos]
        pos += 2 + int.from_bytes(p[pos:pos + 2], 'big')
        pos += 1 + p[pos]
        total = int.from_bytes(p[pos:pos + 2], 'big')
        pos += 2
        end = pos + total
        while pos + 4 <= min(end, len(p)):
            kind, size = struct.unpack_from('!HH', p, pos)
            pos += 4
            ext = p[pos:pos + size]
            if kind == 0 and len(ext) >= 5 and ext[2] == 0:
                n = int.from_bytes(ext[3:5], 'big')
                return clean_domain(ext[5:5 + n].decode('ascii')) if len(ext) >= 5 + n else ''
            pos += size
    except (IndexError, ValueError, UnicodeError, struct.error):
        pass
    return ''


def transport(frame, link):
    if link == 1:
        if len(frame) < 14:
            return None
        typ = int.from_bytes(frame[12:14], 'big')
        pos = 14
        while typ in (0x8100, 0x88a8):
            if pos + 4 > len(frame):
                return None
            typ = int.from_bytes(frame[pos + 2:pos + 4], 'big')
            pos += 4
        p = frame[pos:]
    elif link in (101, 228, 229):
        p = frame
    elif link == 113:
        p = frame[16:]
    elif link == 276:
        p = frame[20:]
    elif link == 0:
        p = frame[4:]
    else:
        return None
    if not p:
        return None
    version = p[0] >> 4
    if version == 4:
        if len(p) < 20:
            return None
        header = (p[0] & 15) * 4
        total = int.from_bytes(p[2:4], 'big')
        if header < 20 or len(p) < header or total < header or int.from_bytes(p[6:8], 'big') & 0x3fff:
            return None
        src, dst = str(ipaddress.ip_address(p[12:16])), str(ipaddress.ip_address(p[16:20]))
        proto, body = p[9], p[header:min(total, len(p))]
    elif version == 6:
        if len(p) < 40:
            return None
        src, dst = str(ipaddress.ip_address(p[8:24])), str(ipaddress.ip_address(p[24:40]))
        proto, pos = p[6], 40
        end = min(len(p), 40 + int.from_bytes(p[4:6], 'big'))
        for _ in range(8):
            if proto not in (0, 43, 60):
                break
            if pos + 2 > end:
                return None
            proto, length = p[pos], (p[pos + 1] + 1) * 8
            pos += length
        body = p[pos:end]
    else:
        return None
    if proto not in (6, 17) or len(body) < (20 if proto == 6 else 8):
        return None
    sport, dport = struct.unpack_from('!HH', body)
    header = (body[12] >> 4) * 4 if proto == 6 else 8
    if header < (20 if proto == 6 else 8) or header > len(body):
        return None
    return src, dst, sport, dport, 'TCP' if proto == 6 else 'UDP', body[header:]


LOCAL = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7')]


def is_local(value):
    addr = ipaddress.ip_address(value)
    return any(addr in net for net in LOCAL if addr.version == net.version)


def parse_capture(data):
    rows, stats, cache, flows = [], Counter(), {}, {}
    packets = []
    for record in frames(data):
        if len(packets) >= 150_000:
            raise CaptureError('Capture has more than 150,000 packets. Split it into smaller files.')
        packets.append(record)
    packets.sort(key=lambda x: x[0])
    supported = {0, 1, 101, 113, 228, 229, 276}
    for ts, link, frame in packets:
        stats['packets'] += 1
        if not 946684800 <= ts <= 4102444800:
            stats['invalid_timestamp'] += 1
            continue
        if link not in supported:
            stats['unsupported_link'] += 1
            continue
        try:
            decoded = transport(frame, link)
            if not decoded:
                stats['unsupported_or_non_ip'] += 1
                continue
            src, dst, sport, dport, proto, payload = decoded
            outbound = is_local(src) and not is_local(dst)
            inbound = is_local(dst) and not is_local(src)
            is_dns = proto == 'UDP' and (sport == 53 or dport == 53)
            if is_dns:
                response, names, answers = dns_metadata(payload)
                device = dst if response else src
                if not is_local(device):
                    continue
                if response:
                    for ip, name, ttl in answers:
                        cache[(device, ip)] = (name, ts + min(ttl, 86400))
                    continue
                domain = names[0] if names else ''
                if not domain:
                    continue
                remote, evidence, active = dst, 'DNS query', False
            else:
                if not (outbound or inbound) or not payload:
                    continue
                device, remote = (src, dst) if outbound else (dst, src)
                if not ipaddress.ip_address(remote).is_global:
                    continue
                local_port, remote_port = (sport, dport) if outbound else (dport, sport)
                if remote_port in (53, 67, 68, 123, 137, 138, 5353, 5355):
                    stats['background_packets'] += 1
                    continue
                key = (device, remote, local_port, remote_port, proto)
                domain, evidence = '', 'IP connection'
                if outbound and proto == 'TCP':
                    domain = tls_sni(payload)
                    if domain:
                        evidence = 'TLS server name'
                    elif re.match(rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ', payload):
                        host = re.search(rb'\r\nHost:\s*([^\r\n:]+)', payload[:16384], re.I)
                        if host:
                            domain = clean_domain(host.group(1).decode('ascii', errors='replace'))
                            evidence = 'HTTP Host'
                    if domain:
                        flows[key] = (domain, evidence, ts)
                if not domain and key in flows and ts - flows[key][2] <= 300:
                    domain, evidence, _ = flows[key]
                if not domain and (device, remote) in cache:
                    name, expiry = cache[(device, remote)]
                    if ts <= expiry:
                        domain, evidence = name, 'DNS-to-IP inference'
                active = True
            fingerprint = hashlib.sha256(struct.pack('!d', ts) + frame).hexdigest()
            rows.append({'fingerprint': fingerprint, 'timestamp': ts, 'device_ip': device,
                         'remote_ip': remote, 'domain': domain, 'protocol': proto,
                         'evidence': evidence, 'active': int(active), 'bytes': len(payload)})
        except (ValueError, IndexError, struct.error):
            stats['malformed_packets'] += 1
    if stats['unsupported_link'] == stats['packets'] and stats['packets']:
        raise CaptureError('Unsupported link type. Export an Ethernet, raw IP, loopback, or Linux cooked capture.')
    stats['observations'] = len(rows)
    return rows, dict(stats)
