"""Reproducible storage/alert benchmark; creates only temporary synthetic data."""
import argparse
import hashlib
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import Store, day_bounds


def observations(count, start, offset=0):
    """Generate twenty distinct payload observations per second."""
    for index in range(offset, offset + count):
        yield dict(fingerprint=hashlib.sha256(str(index).encode()).hexdigest(),
                   device_ip='192.168.1.3', source_ip='192.168.1.3',
                   timestamp=start + index // 20 + (index % 20) / 100,
                   remote_ip='8.8.4.4', domain='youtube.com', protocol='TCP',
                   evidence='TLS server name', active=1, bytes=1000)


def benchmark(count, spread=False):
    """Measure identical imports and dashboard work before and after aggregation."""
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / 'bench.sqlite3')
        start = day_bounds('2026-10-14', 330)[0]
        # Seed in bounded batches, without including parser cost in this storage benchmark.
        for offset in range(0, count, 100000):
            seed_start = start
            if spread:
                older_days = (count - offset - 1) // 100000
                seed_start -= older_days * 86400 + offset // 20
            rows = list(observations(min(100000, count-offset), seed_start, offset))
            with patch('service.parse_capture', return_value=(rows, {'observations': len(rows)})):
                store.import_capture(str(offset).encode(), 'synthetic.pcap')
        with store.connect() as db:
            db.execute("INSERT INTO rules(name,kind,target) VALUES('Video','domain','youtube.com')")
        then = time.perf_counter()
        with store.connect() as db:
            store.rebuild_alerts(db)
        rebuild = time.perf_counter() - then
        then = time.perf_counter()
        snapshot = store.snapshot('2026-10-14')
        snapshot_time = time.perf_counter() - then
        tail_start = start - (count - 100000) // 20 if spread else start
        rows = list(observations(200, tail_start, count))
        then = time.perf_counter()
        with patch('service.parse_capture', return_value=(rows, {'observations': len(rows)})):
            store.import_capture(b'tail', 'tail.pcap')
        tail = time.perf_counter() - then
        with store.connect() as db:
            stored = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        assert snapshot['summary']['observations'] == (min(count, 100000) if spread else count)
        print(f'spread={spread} raw={count:,} rows_after_tail={stored:,} rebuild={rebuild:.3f}s snapshot={snapshot_time:.3f}s tail_import={tail:.3f}s', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--counts', nargs='+', type=int, default=[100000, 500000, 1000000])
    parser.add_argument('--spread', action='store_true', help='Keep current-day traffic fixed; add older days')
    args = parser.parse_args()
    for size in args.counts:
        benchmark(size, args.spread)
