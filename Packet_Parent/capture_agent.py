"""Capture this PC only. CLI and dashboard use the same identity and inbox."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

from local_monitor import capture_context, data_directory, interfaces, tshark_path, write_status


def resolve_root():
    root = data_directory()
    try:
        with urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=2) as response:
            health = json.load(response)
        if health.get('application') == 'PacketParent' and health.get('data_dir'):
            active = Path(health['data_dir']).resolve()
            if 'PACKETPARENT_DATA' in os.environ and active != root:
                raise RuntimeError(f'The dashboard uses {active}, but this terminal uses {root}. Use the same PACKETPARENT_DATA setting.')
            return active
    except (OSError, ValueError):
        pass
    return root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true', help='List capture interfaces')
    parser.add_argument('--managed', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--interface', help='Interface number or name from --list')
    parser.add_argument('--snaplen', type=int, default=os.environ.get('PACKETPARENT_SNAPLEN', '2048'),
                        help='Bytes captured per packet (64-262144; default 2048)')
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--segments', type=int, default=0, help='Stop after this many segments (0: continuous)')
    args = parser.parse_args()
    if not 64 <= args.snaplen <= 262144:
        parser.error('--snaplen must be between 64 and 262144 bytes.')
    exe = tshark_path()
    if not exe:
        parser.error('Install Wireshark with TShark and Npcap first.')
    available = interfaces()
    if args.list:
        for item in available:
            print(f"{item['id']}. {item['name']} ({item['label']})")
        return
    chosen = next((item for item in available if args.interface in (item['id'], item['name'])), None)
    if not chosen or not 5 <= args.seconds <= 60 or args.segments < 0:
        parser.error('Choose an interface from --list; --seconds must be 5–60.')
    root = resolve_root()
    root.mkdir(parents=True, exist_ok=True)
    inbox = root / 'inbox'
    inbox.mkdir(exist_ok=True)
    lock = (root / 'capture.lock').open('a+b')
    lock.seek(0)
    if os.name == 'nt':
        import msvcrt
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            parser.error('Monitoring is already running for this data folder. Stop it before starting another sensor.')
    else:
        import fcntl
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            parser.error('Monitoring is already running.')
    stop_file = root / 'capture.stop'
    if not args.managed:
        stop_file.unlink(missing_ok=True)
    process = None
    partial = None
    status = {'state': 'starting', 'pid': os.getpid(), 'interface': chosen['label'], 'last_file': None, 'error': None}
    write_status(root, status)
    print(f"Monitoring this PC on {chosen['label']}. Inbox: {inbox}", flush=True)
    print('Keep PacketParent running. Ctrl+C stops monitoring.', flush=True)
    completed = 0
    try:
        while not stop_file.exists():
            context = capture_context(root)
            if not context['macs'] and not context['ips']:
                raise RuntimeError('This PC has no usable network addresses. Connect to Wi-Fi or Ethernet.')
            name = str(time.time_ns())
            partial = root / (name + '.partial')
            terms = ['ether host ' + mac for mac in context['macs']] or ['host ' + ip for ip in context['ips']]
            command = [exe, '-i', chosen['name'], '-p', '-f', '(' + ' or '.join(terms) + ')',
                       '-a', f'duration:{args.seconds}', '-a', 'filesize:20000', '-a', 'packets:100000',
                       '-s', str(args.snaplen), '-F', 'pcap', '-w', str(partial), '-q']
            status.update(state='recording', addresses=context['ips'], error=None)
            with (root / 'tshark.log').open('w', encoding='utf-8') as log:
                process = subprocess.Popen(command, stdout=log, stderr=log,
                                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                status['capture_pid'] = process.pid
                while process.poll() is None:
                    write_status(root, status)
                    if stop_file.exists():
                        process.terminate()
                        break
                    time.sleep(.5)
                process.wait(timeout=5)
            if stop_file.exists():
                break
            if process.returncode:
                detail = (root / 'tshark.log').read_text(encoding='utf-8', errors='replace')[-1500:]
                raise RuntimeError('TShark could not capture: ' + detail.strip())
            (inbox / (name + '.json')).write_text(json.dumps(context), encoding='utf-8')
            partial.rename(inbox / (name + '.pcap'))
            status['last_file'] = name + '.pcap'
            completed += 1
            write_status(root, status)
            print(f'Saved segment {completed}; dashboard will import it automatically.', flush=True)
            if args.segments and completed >= args.segments:
                break
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        status.update(state='error', error=str(exc))
        print(str(exc), flush=True)
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if partial is not None:
            partial.unlink(missing_ok=True)
        if status['state'] != 'error':
            status['state'] = 'stopped'
        status.pop('capture_pid', None)
        write_status(root, status)
        lock.close()
        print('Monitoring stopped.', flush=True)


if __name__ == '__main__':
    main()
