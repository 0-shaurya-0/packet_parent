"""Repair legacy local captures using this PC's verified network MAC addresses."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import sqlite3
from contextlib import closing

from local_monitor import capture_context, data_directory
from packets import parse_capture
from service import Store, category


def repair(store, root, inbox=None):
    root = Path(root)
    inbox = Path(inbox) if inbox else root / 'inbox'
    context = capture_context(root)
    # Historical IP addresses may have been assigned to other computers since then.
    historical = {**context, 'ips': []}
    prepared, owned_ips, parser_state = [], set(), {}
    with store.connect() as db:
        legacy = list(db.execute("SELECT * FROM captures WHERE source='import' AND demo=0 ORDER BY first,id"))
    for capture in legacy:
        name = capture['name']
        if Path(name).name != name or not Path(name).stem.isdigit():
            continue
        path = inbox / name
        if not path.is_file():
            continue
        raw = path.read_bytes()
        rows, stats = parse_capture(raw, historical, parser_state)
        # Preserve captures that cannot be positively attributed to this PC.
        if not rows:
            continue
        owned_ips.update(row['source_ip'] for row in rows)
        prepared.append((capture['id'], raw, rows, stats))
    if not prepared:
        return {'repaired_captures': 0, 'message': 'No matching legacy captures need repair.'}
    backup_dir = root / 'backups'
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / ('before-local-repair-' + dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.sqlite3')
    with store.lock, store.connect() as db:
        with closing(sqlite3.connect(backup)) as destination:
            db.backup(destination)
        db.execute('INSERT OR IGNORE INTO devices(ip,name) VALUES(?,?)', (context['id'], context['name']))
        db.execute('INSERT OR REPLACE INTO config VALUES(?,?)', ('local_device', json.dumps(context)))
        before = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        for capture_id, raw, rows, stats in prepared:
            db.execute('DELETE FROM events WHERE capture_id=?', (capture_id,))
            inserted = 0
            for row in rows:
                values = [hashlib.sha256(('live:' + row['fingerprint']).encode()).hexdigest(), capture_id,
                          context['id'], row['timestamp'], row['remote_ip'], row['domain'], row['protocol'],
                          row['evidence'], row['active'], row['bytes'], category(row['domain']), row['source_ip']]
                inserted += db.execute('''INSERT OR IGNORE INTO events(fingerprint,capture_id,device_ip,timestamp,
                    remote_ip,domain,protocol,evidence,active,bytes,category,source_ip) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''', values).rowcount
            stats.update(inserted=inserted, duplicates=len(rows)-inserted)
            db.execute("UPDATE captures SET source='live',hash=?,stats=?,first=?,last=? WHERE id=?",
                       (hashlib.sha256(b'live\0'+raw).hexdigest(), json.dumps(stats), min(r['timestamp'] for r in rows),
                        max(r['timestamp'] for r in rows), capture_id))
        for ip in owned_ips:
            old = db.execute('SELECT name,child FROM devices WHERE ip=?', (ip,)).fetchone()
            if old and (old['child'] or not old['name'].startswith('Device ')):
                db.execute('UPDATE devices SET name=?,child=? WHERE ip=?', (old['name'], old['child'], context['id']))
            db.execute('UPDATE rules SET device_ip=? WHERE device_ip=?', (context['id'], ip))
        store.rebuild_alerts(db)
        db.execute('''DELETE FROM devices WHERE ip!=? AND ip NOT IN (SELECT device_ip FROM events)
            AND ip NOT IN (SELECT device_ip FROM rules)''', (context['id'],))
        after = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    return {'repaired_captures': len(prepared), 'removed_non_internet_observations': before-after,
            'retained_observations': after, 'backup': str(backup), 'device': context['name']}


if __name__ == '__main__':
    root = data_directory()
    print(json.dumps(repair(Store(root / 'packetparent.sqlite3'), root), indent=2))
