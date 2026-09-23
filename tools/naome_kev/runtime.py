"""Pinned, offline local inference with a private, automatically started worker.

Only explicit setup downloads software or weights. Inference has no network
fallback and never installs anything while a ballot attempt is reserved.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import stat
import subprocess
import time

from . import config
from .schema import encode, loads

SOURCE_REVISION = '3e04f90f21004afcff77c3472ea5402562d29c6b'
REQUEST_SECONDS = 50
MAX_FRAME = 131072
IDLE_SECONDS = 300
STOP_SECONDS = 10
STARTUP_SECONDS = 180


class RuntimeFailure(ValueError):
    """Operator-safe diagnostics; never include model input or arbitrary exceptions."""
    def __init__(self, code, message, hint):
        super().__init__(message)
        self.code = code
        self.hint = hint


def _directory(value):
    path = Path(value)
    if not path.is_absolute():
        raise ValueError('runtime directory must be absolute')
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_mode & 0o077 or meta.st_uid != os.geteuid():
        raise ValueError('runtime directory must be private, owned, and not a symlink')
    if len(os.fsencode(path / 'worker.sock')) >= 104:
        raise ValueError('runtime directory is too long for a Unix socket')
    return path


def _environment(root):
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LANG', 'TMPDIR') if k in os.environ}
    env.update(HF_HOME=str(root / 'hf-cache'), HF_HUB_OFFLINE='1',
               TRANSFORMERS_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1',
               TOKENIZERS_PARALLELISM='false', PYTHONUNBUFFERED='1',
               PYTHONNOUSERSITE='1', OMP_NUM_THREADS='4')
    return env


def _fingerprint(root):
    manifest = config.read_private(root / 'manifest.json', 131072)
    parsed = loads(manifest)
    if parsed['source_revision'] != SOURCE_REVISION or parsed['model'] != config.MODEL:
        raise ValueError('runtime manifest differs from pinned implementation')
    digest = hashlib.sha256(manifest)
    digest.update(Path(__file__).read_bytes())
    digest.update(Path(__file__).with_name('worker.py').read_bytes())
    return digest.hexdigest()


def _rpc(root, message, timeout):
    # Option order is part of model input; canonical digest encoding sorts keys.
    raw = json.dumps(message, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode() + b'\n'
    if len(raw) > MAX_FRAME:
        raise ValueError('local request exceeds size limit')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        deadline = time.monotonic() + timeout
        stream.settimeout(max(0.01, timeout))
        stream.connect(str(root / 'worker.sock'))
        stream.settimeout(max(0.01, deadline - time.monotonic()))
        stream.sendall(raw)
        data = bytearray()
        while not data.endswith(b'\n'):
            if time.monotonic() >= deadline:
                raise TimeoutError('local worker response deadline exceeded')
            stream.settimeout(deadline - time.monotonic())
            block = stream.recv(min(8192, MAX_FRAME + 1 - len(data)))
            if not block:
                raise ValueError('local worker closed an incomplete response')
            data.extend(block)
            if len(data) > MAX_FRAME:
                raise ValueError('local response exceeds size limit')
        reply = loads(data)
    if not isinstance(reply, dict):
        raise ValueError('invalid local worker response')
    if reply.get('error'):
        raise RuntimeFailure('worker_request_failed', 'The local model could not complete the request.',
                             'Run status to inspect the worker; no vote was produced.')
    return reply


def _running(root, fingerprint, timeout=1):
    try:
        info = _rpc(root, {'command': 'status'}, timeout)
    except (OSError, ValueError):
        return None
    if info.get('fingerprint') != fingerprint or info.get('model') != config.MODEL:
        raise RuntimeFailure('worker_changed', 'A worker from a different runtime version is running.',
                             'Run stop, then start again to load the installed version.')
    return info


def _poll_owned(process):
    """Reap an exclusively owned child without Popen's interruptible wait lock."""
    if process.returncode is not None:
        return process.returncode
    try:
        pid, status = os.waitpid(process.pid, os.WNOHANG)
    except ChildProcessError:
        # A signal can raise after waitpid reaps the child but before Python
        # stores its status. Never report an unknown exit as setup success.
        process.returncode = 125
    else:
        if pid == process.pid:
            process.returncode = os.waitstatus_to_exitcode(status)
    return process.returncode


def _wait_owned(process, timeout):
    deadline = time.monotonic() + timeout
    while True:
        result = _poll_owned(process)
        if result is not None:
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout)
        time.sleep(min(0.05, remaining))


def _terminate_owned(process):
    """Only a Popen session created here, including descendants of its leader."""
    if _poll_owned(process) is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            _wait_owned(process, 2)
        except subprocess.TimeoutExpired:
            pass
    # A leader may exit promptly while its loader/download descendant ignores
    # TERM. The owned process group remains our cleanup target after that exit.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    _wait_owned(process, 2)


def _ensure(settings, deadline, progress=None):
    config.validate(settings)
    root = _directory(settings['runtime_dir'])
    if not (root / 'manifest.json').is_file() or not (root / 'venv/bin/python').is_file():
        raise RuntimeFailure('not_installed', 'The local KEV installation is incomplete.',
                             'Run setup again to finish or resume installation before starting KEV.')
    fingerprint = _fingerprint(root)
    info = _running(root, fingerprint, min(1, max(.01, deadline - time.monotonic())))
    if info and info.get('state', 'ready') == 'ready':
        return root, info
    fd = os.open(root / 'start.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as lock:
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeFailure('startup_busy', 'Another command is starting KEV.',
                                         'Run status to see progress, or stop to cancel startup.')
                time.sleep(0.1)
        info = _running(root, fingerprint, min(1, max(.01, deadline - time.monotonic())))
        if info and info.get('state', 'ready') == 'ready':
            return root, info
        process = None
        ready = False
        try:
            if not _lock_held(root, 'daemon.lock'):
                remaining = min(STARTUP_SECONDS, deadline - time.monotonic())
                if remaining <= 0:
                    raise RuntimeFailure('startup_timeout', 'KEV startup ran out of time.',
                                         'Use start before voting to allow a longer model warmup.')
                log_fd = os.open(root / 'worker.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
                with os.fdopen(log_fd, 'ab') as log:
                    process = subprocess.Popen(
                        [str(root / 'venv/bin/python'), str(Path(__file__).with_name('worker.py')),
                         str(root), str(remaining)], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                        env=_environment(root), start_new_session=True, close_fds=True)
                if progress:
                    progress('Loading KEV locally. Use stop in another terminal to cancel.')
            last_update = time.monotonic()
            while time.monotonic() < deadline:
                info = _running(root, fingerprint, min(.5, max(.01, deadline - time.monotonic())))
                if info and info.get('state', 'ready') == 'ready':
                    ready = True
                    return root, info
                if info and info.get('state') in ('failed', 'stopping'):
                    raise RuntimeFailure('startup_failed', 'KEV startup failed or was cancelled.',
                                         'Inspect the private worker.log; free memory and run start again.')
                if process is not None and _poll_owned(process) is not None:
                    raise RuntimeFailure('worker_exited', 'The KEV worker exited before becoming ready.',
                                         'Inspect the private worker.log; free memory and run start again.')
                if progress and time.monotonic() - last_update >= 10:
                    progress('Still loading KEV; the model is not ready for voting yet.')
                    last_update = time.monotonic()
                time.sleep(.1)
            raise RuntimeFailure('startup_timeout', 'KEV did not become ready within the startup limit.',
                                 'The worker started by this command is being stopped. Run start before voting.')
        finally:
            # Includes Ctrl-C and the provider alarm. Never kill a shared worker
            # which was already running when this invocation arrived.
            if process is not None and not ready:
                _terminate_owned(process)


def start(settings, progress=None):
    """Explicit prewarming has a separate allowance from a ballot invocation."""
    _, info = _ensure(settings, time.monotonic() + STARTUP_SECONDS, progress)
    return info


def status(settings):
    """Compatibility API for evaluation harnesses: warm and return loaded status."""
    return start(settings)


def inspect(runtime_dir):
    """Read installation/worker state without creating locks or loading a model."""
    root = Path(runtime_dir).absolute()
    base = {'runtime_dir': str(root), 'config': str(root / 'kev.json')}
    if not root.exists():
        return {**base, 'state': 'not_installed', 'installed': False, 'running': False}
    _directory(root)
    # Observe ownership even for a damaged installation so recovery remains usable.
    active = _worker_active(root, create=False)
    try:
        settings = config.load(root / 'kev.json')
        if settings['runtime_dir'] != str(root):
            raise ValueError('runtime directory mismatch')
        complete = (root / 'manifest.json').is_file() and (root / 'venv/bin/python').is_file()
        if not complete:
            return {**base, 'state': 'incomplete', 'installed': False, 'running': active}
        info = _running(root, _fingerprint(root))
    except FileNotFoundError:
        return {**base, 'state': 'incomplete', 'installed': False, 'running': active}
    except RuntimeFailure as error:
        if error.code == 'worker_changed':
            return {**base, 'state': 'outdated', 'installed': True, 'running': True}
        raise
    except (ValueError, KeyError, OSError):
        return {**base, 'state': 'needs_repair', 'installed': False, 'running': active}
    if info:
        return {**base, **info, 'installed': True, 'running': active}
    return {**base, 'state': 'starting' if active else 'stopped',
            'installed': True, 'running': active}


def request(settings, payload):
    deadline = time.monotonic() + REQUEST_SECONDS
    root, _ = _ensure(settings, deadline)
    if payload.get('model') != settings['model']:
        raise ValueError('request model does not match the pinned configuration')
    # macOS Python 3.9 and 3.12 use different monotonic clock origins. Never
    # transmit absolute monotonic timestamps between the provider and worker.
    remaining = deadline - time.monotonic()
    reply = _rpc(root, {'command': 'infer', 'payload': payload, 'budget_seconds': remaining}, remaining)
    if reply.get('model') != settings['model']:
        raise ValueError('local worker returned a different model')
    return reply


def _lock_held(root, name, create=True):
    flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else 0)
    try:
        fd = os.open(root / name, flags, 0o600)
    except FileNotFoundError:
        return False
    with os.fdopen(fd, 'wb') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True


def _worker_active(root, create=True):
    # Hold the start lock during daemon inspection to avoid a false stopped result.
    flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else 0)
    try:
        fd = os.open(root / 'start.lock', flags, 0o600)
    except FileNotFoundError:
        return _lock_held(root, 'daemon.lock', create=False)
    with os.fdopen(fd, 'wb') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return _lock_held(root, 'daemon.lock', create=create)


def stop(settings_or_root):
    # Cleanup must remain possible if model/configuration verification fails.
    root = Path(settings_or_root['runtime_dir'] if isinstance(settings_or_root, dict)
                else settings_or_root).absolute()
    if not root.exists():
        return {'stopped': True, 'already_stopped': True, 'state': 'stopped'}
    _directory(root)
    deadline = time.monotonic() + STOP_SECONDS
    requested = False
    while time.monotonic() < deadline:
        if not requested:
            try:
                _rpc(root, {'command': 'stop'}, min(.5, max(.01, deadline - time.monotonic())))
                requested = True
            except (OSError, ValueError):
                pass
        if not _worker_active(root, create=False):
            return {'stopped': True, 'already_stopped': not requested, 'state': 'stopped'}
        time.sleep(.1)
    return {'stopped': False, 'state': 'stopping',
            'message': 'Worker ownership is still active; shutdown could not be confirmed.',
            'hint': 'Inspect the private worker.log. No unrelated processes were signalled.'}


def setup(runtime_dir):
    """Install without loading the model; explicit start/check warms it afterwards."""
    from .setup import setup as install
    return install(runtime_dir)
