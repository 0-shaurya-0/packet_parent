"""Optional capture helper. Requires Wireshark/TShark and capture permissions.
python capture.py --list
python capture.py --interface 1
Only completed captures are moved into data/inbox for automatic import.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true', help='List capture interfaces')
    parser.add_argument('--interface', help='Interface number or name from --list')
    parser.add_argument('--seconds', type=int, default=10)
    args = parser.parse_args()
    tshark = shutil.which('tshark')
    fallback = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Wireshark/tshark.exe'
    if not tshark and fallback.exists():
        tshark = str(fallback)
    if not tshark:
        parser.error('Install Wireshark with TShark and the capture driver first. PCAP upload works without it.')
    if args.list:
        subprocess.run([tshark, '-D'], check=True)
        return
    if not args.interface or not 5 <= args.seconds <= 60:
        parser.error('Select --interface and a --seconds value between 5 and 60.')
    root = Path(os.environ.get('PACKETPARENT_DATA', str(Path(__file__).parent / 'data')))
    inbox = root / 'inbox'
    inbox.mkdir(parents=True, exist_ok=True)
    print('Capturing selected interface. Keep PacketParent running. Ctrl+C stops capture.')
    print('Files remain in data/inbox. Short gaps occur between capture segments.')
    try:
        while True:
            name = str(time.time_ns())
            partial = root / (name + '.partial')
            command = [tshark, '-i', args.interface, '-a', f'duration:{args.seconds}', '-a', 'filesize:20000',
                       '-s', '512', '-F', 'pcap', '-w', str(partial), '-q']
            result = subprocess.run(command)
            if result.returncode:
                raise SystemExit('Capture stopped. Check capture permissions and interface selection.')
            partial.rename(inbox / (name + '.pcap'))
    except KeyboardInterrupt:
        print('\nCapture stopped.')


if __name__ == '__main__':
    main()
