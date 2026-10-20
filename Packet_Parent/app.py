"""Local-only PacketParent prototype. Run: python app.py"""
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from packets import CaptureError, clean_domain
from service import CATEGORIES, Store
from local_monitor import capture_context, data_directory, interfaces, read_status, write_status, server_port

ROOT = Path(__file__).resolve().parent


class Runtime:
    """Own mutable server state under app.state instead of module-level dictionaries."""

    def __init__(self):
        """Initialize one local store, capture process and authentication state."""
        self.data = data_directory()
        self.data.mkdir(parents=True, exist_ok=True)
        self.inbox = self.data / 'inbox'
        self.inbox.mkdir(exist_ok=True)
        self.store = Store(self.data / 'packetparent.sqlite3')
        self.store.register_local(capture_context(self.data))
        self.monitor_process = None
        self.monitor_lock = threading.Lock()
        self.sessions = {}
        self.attempts = {}
        self.watch_status = {'running': False, 'last_import': None, 'error': None}


MAX_UPLOAD = 25 * 1024 * 1024


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 300_000).hex()
    return salt + ':' + digest


def finish_capture(path, keep):
    """Dispose of a successfully imported segment and its identity sidecar."""
    destination = path.parent.parent / 'processed'
    items = (path, path.with_suffix('.json'))
    prefix = ''
    if any((destination / item.name).exists() for item in items):
        prefix = str(time.time_ns()) + '-'
    for item in items:
        if not item.exists():
            continue
        if keep:
            destination.mkdir(exist_ok=True)
            item.rename(destination / (prefix + item.name))
        else:
            item.unlink()


def quarantine_capture(path, error):
    """Move failed input and its sidecar out of the inbox without overwriting files."""
    folder = path.parent.parent / 'failed'
    folder.mkdir(exist_ok=True)
    prefix = str(time.time_ns()) + '-'
    destination = folder / (prefix + path.name)
    path.rename(destination)
    sidecar = path.with_suffix('.json')
    if sidecar.exists():
        sidecar.rename(folder / (prefix + sidecar.name))
    destination.with_suffix(destination.suffix + '.error.txt').write_text(error[:1000], encoding='utf-8')


def poll_inbox(seen):
    """Import stable files once, disposing successes and quarantining failures."""
    runtime = app.state.runtime
    paths = sorted(path for path in runtime.inbox.glob('*.pcap*') if path.suffix.lower() in ('.pcap', '.pcapng'))
    present = {str(path) for path in paths}
    for missing in set(seen) - present:
        seen.pop(missing, None)
    for path in paths:
        try:
            stat = path.stat()
            signature = (stat.st_size, stat.st_mtime_ns)
            previous = seen.get(str(path))
            if previous and previous[0] == signature and previous[1]:
                continue
            if not previous or previous[0] != signature:
                seen[str(path)] = (signature, False)
                continue
            if stat.st_size > MAX_UPLOAD:
                raise ValueError('Capture exceeds 25 MB.')
            context = capture_context(runtime.data)
            sidecar = path.with_suffix('.json')
            if sidecar.exists():
                saved = json.loads(sidecar.read_text(encoding='utf-8'))
                if saved.get('id') == context['id']:
                    context = saved
            result = runtime.store.import_capture(path.read_bytes(), path.name, monitored=context)
            finish_capture(path, runtime.store.settings()['keep_raw_captures'])
            seen.pop(str(path), None)
            if not result['duplicate']:
                runtime.watch_status['last_import'] = time.time()
            runtime.watch_status['error'] = None
        except FileNotFoundError:
            # A producer/user may remove a file between listing and opening it.
            seen.pop(str(path), None)
        except Exception as exc:
            error = f'{path.name}: {str(exc)[:240]}'
            runtime.watch_status['error'] = error
            if str(path) in seen:
                seen[str(path)] = (seen[str(path)][0], True)
            try:
                quarantine_capture(path, error)
                seen.pop(str(path), None)
            except OSError as move_error:
                runtime.watch_status['error'] = error + '; could not quarantine: ' + str(move_error)[:160]


def watcher(stop):
    """Poll until shutdown, with one retention pass per UTC day."""
    runtime = app.state.runtime
    seen = {}
    last_purge = None
    runtime.watch_status['running'] = True
    try:
        while not stop.wait(2):
            today = dt.datetime.now(dt.timezone.utc).date()
            if today != last_purge:
                last_purge = today
                try:
                    runtime.store.purge()
                except Exception as exc:
                    runtime.watch_status['error'] = 'Retention failed: ' + str(exc)[:240]
            if runtime.store.auth_hash():
                poll_inbox(seen)
    finally:
        runtime.watch_status['running'] = False


@asynccontextmanager
async def lifespan(app):
    runtime = app.state.runtime
    await run_in_threadpool(runtime.store.purge)
    stop = threading.Event()
    worker = threading.Thread(target=watcher, args=(stop,), daemon=True)
    worker.start()
    yield
    stop.set()
    worker.join(timeout=3)
    if runtime.monitor_process and runtime.monitor_process.poll() is None:
        (runtime.data / 'capture.stop').touch()
        try:
            await run_in_threadpool(runtime.monitor_process.wait, 5)
        except subprocess.TimeoutExpired:
            pass


app = FastAPI(title='PacketParent', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.state.runtime = Runtime()
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', 'testserver'])


@app.middleware('http')
async def security(request, call_next):
    runtime = app.state.runtime
    if request.url.path.startswith('/api/'):
        if request.method not in ('GET', 'HEAD') and request.headers.get('x-packetparent') != '1':
            return JSONResponse({'detail': 'Missing request protection header.'}, status_code=403)
        public = ('/api/auth/status', '/api/auth/setup', '/api/auth/login', '/api/health')
        if request.url.path not in public:
            token = request.cookies.get('pp_session', '')
            expiry = runtime.sessions.get(token, 0)
            if expiry < time.time():
                runtime.sessions.pop(token, None)
                return JSONResponse({'detail': 'Please sign in.'}, status_code=401)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    return response


async def read_bytes(request, limit):
    output = bytearray()
    async for chunk in request.stream():
        output.extend(chunk)
        if len(output) > limit:
            raise HTTPException(413, f'File/request is too large (limit {limit // 1024} KB).')
    return bytes(output)


async def read_json(request):
    try:
        value = json.loads(await read_bytes(request, 16384))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError):
        raise HTTPException(400, 'Expected a JSON object.')


def text_field(data, key, limit=100, default=''):
    value = data.get(key, default)
    if not isinstance(value, str) or len(value) > limit:
        raise HTTPException(400, f'Invalid {key}.')
    return value.strip()


def integer(data, key, low, high, default):
    value = data.get(key, default)
    if type(value) is not int or not low <= value <= high:
        raise HTTPException(400, f'{key} must be between {low} and {high}.')
    return value


def signed_in():
    runtime = app.state.runtime
    token = secrets.token_urlsafe(32)
    runtime.sessions[token] = time.time() + 12 * 3600
    for expired in [key for key, expiry in runtime.sessions.items() if expiry < time.time()]:
        runtime.sessions.pop(expired, None)
    response = JSONResponse({'ok': True})
    response.set_cookie('pp_session', token, httponly=True, samesite='strict', max_age=12 * 3600)
    return response


@app.get('/api/auth/status')
def auth_status(request: Request):
    runtime = app.state.runtime
    return {'setup': runtime.store.auth_hash() is not None, 'authenticated': runtime.sessions.get(request.cookies.get('pp_session', ''), 0) > time.time()}


@app.post('/api/auth/setup')
async def setup(request: Request):
    runtime = app.state.runtime
    data = await read_json(request)
    password = text_field(data, 'password', 128)
    if len(password) < 8:
        raise HTTPException(400, 'Use a parent password of at least 8 characters.')
    offset = integer(data, 'utc_offset', -720, 840, 330)
    try:
        await run_in_threadpool(runtime.store.setup, password_hash(password), offset)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return signed_in()


@app.post('/api/auth/login')
async def login(request: Request):
    runtime = app.state.runtime
    peer = request.client.host if request.client else 'local'
    recent = [t for t in runtime.attempts.get(peer, []) if t > time.time() - 60]
    if len(recent) >= 8:
        raise HTTPException(429, 'Too many attempts. Try again in one minute.')
    runtime.attempts[peer] = recent + [time.time()]
    data = await read_json(request)
    password = text_field(data, 'password', 128)
    stored = runtime.store.auth_hash()
    if not stored or not hmac.compare_digest(await run_in_threadpool(password_hash, password, stored.split(':')[0]), stored):
        raise HTTPException(401, 'Incorrect parent password.')
    runtime.attempts.pop(peer, None)
    return signed_in()


@app.post('/api/auth/logout')
def logout(request: Request):
    runtime = app.state.runtime
    runtime.sessions.pop(request.cookies.get('pp_session', ''), None)
    response = JSONResponse({'ok': True})
    response.delete_cookie('pp_session')
    return response


@app.get('/api/dashboard')
def dashboard(day: str = '', device: str = '', source: str = 'live'):
    runtime = app.state.runtime
    try:
        result = runtime.store.snapshot(day or None, device, source)
    except (ValueError, OverflowError):
        raise HTTPException(400, 'Use a valid date in YYYY-MM-DD format.')
    result['watcher'] = runtime.watch_status
    result['monitor'] = read_status(runtime.data)
    return result


@app.get('/api/health')
def health():
    runtime = app.state.runtime
    return {'application': 'PacketParent', 'version': 2, 'data_dir': str(runtime.data)}


@app.get('/api/monitor')
def monitor():
    runtime = app.state.runtime
    try:
        available, error = interfaces(), None
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        available, error = [], str(exc)
    return {'status': read_status(runtime.data), 'interfaces': available, 'error': error, 'data_dir': str(runtime.data)}


@app.post('/api/monitor/start')
async def start_monitor(request: Request):
    runtime = app.state.runtime
    data = await read_json(request)
    selected = text_field(data, 'interface', 250)
    def launch():
        with runtime.monitor_lock:
            if (runtime.monitor_process and runtime.monitor_process.poll() is None) or read_status(runtime.data)['state'] in ('starting', 'recording'):
                raise HTTPException(409, 'Monitoring is already running.')
            try:
                match = next((i for i in interfaces() if selected in (i['id'], i['name'])), None)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                raise HTTPException(400, str(exc))
            if not match:
                raise HTTPException(400, 'Choose an available network adapter.')
            (runtime.data / 'capture.stop').unlink(missing_ok=True)
            with (runtime.data / 'capture-agent.log').open('w') as log:
                runtime.monitor_process = subprocess.Popen([sys.executable, str(ROOT / 'capture.py'), '--managed', '--interface', match['name']],
                    cwd=ROOT, env={**os.environ, 'PACKETPARENT_DATA': str(runtime.data)}, stdout=log, stderr=log,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            write_status(runtime.data, {'state':'starting', 'pid':runtime.monitor_process.pid, 'interface':match['label'], 'error':None})
            return {'ok': True}
    return await run_in_threadpool(launch)


@app.post('/api/monitor/stop')
def stop_monitor():
    runtime = app.state.runtime
    (runtime.data / 'capture.stop').touch()
    return {'ok': True}


@app.post('/api/captures')
async def upload(request: Request, name: str = 'capture.pcap', source: str = 'import'):
    runtime = app.state.runtime
    if source not in ('live', 'import'):
        raise HTTPException(400, 'Choose live or imported captures.')
    if not name.lower().endswith(('.pcap', '.pcapng')):
        raise HTTPException(400, 'Choose a .pcap or .pcapng file.')
    data = await read_bytes(request, MAX_UPLOAD)
    try:
        return await run_in_threadpool(runtime.store.import_capture, data, Path(name).name, monitored=capture_context(runtime.data) if source == 'live' else None)
    except CaptureError as exc:
        raise HTTPException(400, str(exc))


def validated_rule(data):
    kind = text_field(data, 'kind')
    if kind not in ('domain', 'category', 'hours', 'budget'):
        raise HTTPException(400, 'Choose a supported rule type.')
    name = text_field(data, 'name')
    if not name:
        raise HTTPException(400, 'Give the rule a name.')
    target = text_field(data, 'target', 253)
    if kind == 'domain':
        target = clean_domain(target)
        if not target or '.' not in target:
            raise HTTPException(400, 'Enter a domain such as youtube.com, without https://.')
    elif kind == 'category':
        if target not in list(CATEGORIES) + ['Unknown']:
            raise HTTPException(400, 'Choose a category.')
    else:
        target = ''
    start, end = text_field(data, 'start', 5), text_field(data, 'end', 5)
    pattern = r'(?:[01]\d|2[0-3]):[0-5]\d'
    if kind == 'budget':
        start = end = ''
    elif kind == 'hours' or start or end:
        if not re.fullmatch(pattern, start) or not re.fullmatch(pattern, end) or start == end:
            raise HTTPException(400, 'Set different start and end times in HH:MM format.')
    return {'name': name, 'kind': kind, 'target': target, 'start': start, 'end': end,
            'minutes': integer(data, 'minutes', 1, 1440, 60), 'device_ip': text_field(data, 'device_ip', 60),
            'enabled': integer(data, 'enabled', 0, 1, 1)}


@app.post('/api/rules')
async def add_rule(request: Request):
    runtime = app.state.runtime
    rule = validated_rule(await read_json(request))
    try:
        await run_in_threadpool(runtime.store.save_rule, rule)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {'ok': True}


@app.put('/api/rules/{rule_id}')
async def edit_rule(rule_id: int, request: Request):
    runtime = app.state.runtime
    rule = validated_rule(await read_json(request))
    try:
        await run_in_threadpool(runtime.store.save_rule, rule, rule_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {'ok': True}


@app.delete('/api/rules/{rule_id}')
def remove_rule(rule_id: int):
    runtime = app.state.runtime
    runtime.store.delete_rule(rule_id)
    return {'ok': True}


@app.post('/api/alerts/{alert_id}/acknowledge')
def acknowledge(alert_id: str):
    runtime = app.state.runtime
    with runtime.store.lock, runtime.store.connect() as db:
        db.execute('UPDATE alerts SET acknowledged=1 WHERE id=?', (alert_id,))
    return {'ok': True}


@app.put('/api/devices/{ip}')
async def rename_device(ip: str, request: Request):
    runtime = app.state.runtime
    data = await read_json(request)
    name, child = text_field(data, 'name', 80), text_field(data, 'child', 60)
    if not name:
        raise HTTPException(400, 'Enter a device name.')
    with runtime.store.lock, runtime.store.connect() as db:
        if not db.execute('UPDATE devices SET name=?,child=? WHERE ip=?', (name, child, ip)).rowcount:
            raise HTTPException(404, 'Device not found.')
    return {'ok': True}


@app.put('/api/settings')
async def settings(request: Request):
    runtime = app.state.runtime
    data = await read_json(request)
    ignored = data.get('ignored_domains', [])
    if not isinstance(ignored, list) or len(ignored) > 100 or any(not isinstance(x, str) or not clean_domain(x) for x in ignored):
        raise HTTPException(400, 'Enter up to 100 valid background domains.')
    keep = data.get('keep_raw_captures', runtime.store.settings()['keep_raw_captures'])
    if type(keep) is not bool:
        raise HTTPException(400, 'keep_raw_captures must be true or false.')
    values = {'keep_raw_captures': keep,
              'retention_days': integer(data, 'retention_days', 0, 36500, runtime.store.settings()['retention_days']),
              'idle_seconds': integer(data, 'idle_seconds', 30, 600, 120),
              'utc_offset': integer(data, 'utc_offset', -720, 840, 330),
              'ignored_domains': [clean_domain(x) for x in ignored]}
    await run_in_threadpool(runtime.store.save_settings, values)
    await run_in_threadpool(runtime.store.purge)
    return {'ok': True}


@app.get('/')
def home():
    return FileResponse(ROOT / 'static' / 'index.html')


app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')

if __name__ == '__main__':
    import uvicorn
    port = server_port()
    print(f'\nPacketParent: http://127.0.0.1:{port}\nPress Ctrl+C to stop.\n')
    uvicorn.run(app, host='127.0.0.1', port=port, log_level='warning')
