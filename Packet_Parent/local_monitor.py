"""Shared local capture identity, paths, network discovery, and sensor status."""
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
import uuid

import psutil

ROOT = Path(__file__).resolve().parent


def data_directory():
    return Path(os.environ.get('PACKETPARENT_DATA', str(ROOT / 'data'))).resolve()


def tshark_path():
    found = shutil.which('tshark')
    fallback = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Wireshark/tshark.exe'
    return found or (str(fallback) if fallback.exists() else None)


def local_addresses():
    ips, macs = set(), set()
    for values in psutil.net_if_addrs().values():
        for address in values:
            if address.family in (socket.AF_INET, socket.AF_INET6):
                value = address.address.split('%')[0]
                parsed = ipaddress.ip_address(value)
                if not parsed.is_loopback and not parsed.is_unspecified and not parsed.is_link_local:
                    ips.add(value)
            elif address.family == psutil.AF_LINK:
                value = address.address.replace('-', ':').lower()
                if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value) and value != '00:00:00:00:00:00':
                    macs.add(value)
    return {'ips': sorted(ips), 'macs': sorted(macs)}


def identity(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    path = root / 'local-device.json'
    try:
        info = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        info = {'id': 'pc-' + str(uuid.uuid4()), 'name': socket.gethostname() + ' (this PC)'}
        try:
            with path.open('x', encoding='utf-8') as stream:
                json.dump(info, stream)
        except FileExistsError:
            # Another local process may be creating the shared identity.
            for _ in range(20):
                try:
                    return json.loads(path.read_text(encoding='utf-8'))
                except json.JSONDecodeError:
                    time.sleep(.05)
            raise RuntimeError('Could not read the shared device identity.')
    if not isinstance(info, dict) or not str(info.get('id', '')).startswith('pc-'):
        raise RuntimeError('Invalid local-device.json. Restore the file from your backup.')
    return info


def capture_context(root):
    return {**identity(root), **local_addresses()}


def interfaces():
    exe = tshark_path()
    if not exe:
        return []
    result = subprocess.run([exe, '-D'], capture_output=True, text=True, errors='replace', timeout=15,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Could not list capture interfaces.')
    output = []
    for line in result.stdout.splitlines():
        match = re.match(r'^(\d+)\. (.+?)(?: \((.+)\))?$', line.strip())
        if match:
            number, name, label = match.groups()
            output.append({'id': number, 'name': name, 'label': label or name})
    return output


def write_status(root, values):
    path = Path(root) / 'capture-status.json'
    temporary = path.with_name(f'capture-status-{os.getpid()}.tmp')
    temporary.write_text(json.dumps({**values, 'updated': time.time()}), encoding='utf-8')
    # Windows briefly denies replacement while another process reads this file.
    for attempt in range(40):
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt == 39:
                raise
            time.sleep(.025)


def read_status(root):
    try:
        value = json.loads((Path(root) / 'capture-status.json').read_text(encoding='utf-8'))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {'state': 'stopped', 'updated': None}
    if value.get('state') in ('starting', 'recording') and (time.time() - value.get('updated', 0) > 90 or not psutil.pid_exists(value.get('pid', -1))):
        value['state'] = 'stopped'
        value['error'] = 'Capture process is no longer running. Start monitoring again.'
    return value
