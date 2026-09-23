"""Explicit, resumable local installation. Setup never starts model inference."""
from contextlib import contextmanager
import fcntl
import io
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

from . import config, install

GIB = 1024 ** 3
FRESH_BYTES = 15 * GIB
MINIMUM_RESUME_BYTES = 2 * GIB
MINIMUM_MEMORY_BYTES = 16 * GIB
PROGRESS_SECONDS = 10
MAX_ARCHIVE_BYTES = 64 * 1024 ** 2
MAX_SOURCE_BYTES = 256 * 1024 ** 2
SOURCE_FILES = ('pyproject.toml', 'uv.lock', 'kev/__init__.py', 'kev/checkpoint.py', 'kev/model.py', 'kev/api.py')


class SetupError(ValueError):
    """Only these predefined messages may be presented directly by the CLI."""
    MESSAGES = {
        'unsupported_host': 'Kev setup requires macOS on Apple Silicon (arm64).',
        'memory_check_failed': 'Could not read physical memory with sysctl. Check this Mac before retrying setup.',
        'insufficient_memory': 'The pinned 4B Kev model requires a Mac with at least 16 GiB of physical memory. Use a Mac with more memory.',
        'invalid_directory': 'Use a private, owned runtime directory with a short absolute path.',
        'setup_busy': 'Another Kev setup is using this directory. Wait for it to finish, then rerun setup.',
        'missing_uv': 'Install uv from https://docs.astral.sh/uv/ and ensure it is on PATH, then rerun setup.',
        'insufficient_disk': 'Not enough free disk space for Kev setup. Free the reported space and rerun setup; existing downloads are retained.',
        'invalid_config': 'The private kev.json configuration is invalid or names another runtime directory. Restore it or choose a fresh runtime directory.',
        'invalid_installation': 'Installed files or metadata have changed. Preserve this directory for diagnosis and run setup in a fresh runtime directory.',
        'missing_python': 'The managed Python environment is missing. Restore it or run setup in a fresh runtime directory.',
        'source_failed': 'Pinned Kev source could not be installed. Check network access and free disk space, then rerun setup; model downloads are retained.',
        'unsafe_source': 'The source archive failed validation. Rerun setup to download the pinned source again.',
        'source_revision': 'The existing source belongs to another revision. Choose a fresh runtime directory.',
        'dependencies_failed': 'Locked Python dependencies could not be installed. Inspect the private setup.log, then rerun setup; downloads are retained.',
        'models_failed': 'Pinned model download or verification failed. Inspect the private setup.log, check network access and disk space, then rerun setup.',
        'packages_changed': 'The managed Python packages differ from the installation manifest. Restore the environment or choose a fresh runtime directory.',
    }

    def __init__(self, code):
        self.code = code
        super().__init__(self.MESSAGES[code])


@contextmanager
def setup_lock(root):
    try:
        descriptor = os.open(root / 'setup.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid():
                raise SetupError('invalid_directory')
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SetupError('setup_busy') from None
            yield
    except SetupError:
        raise
    except OSError:
        raise SetupError('invalid_directory') from None


@contextmanager
def termination_cleanup():
    # A CLI terminate request must unwind the same cleanup as Ctrl-C. Without
    # this handler the detached installation subprocess outlives setup.lock.
    def terminate(number, _frame):
        raise SystemExit(128 + number)

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def remaining_space(root):
    # This is an installation allowance, not a model-memory estimate. Count only
    # regular, unique files in known runtime trees; root-level unrelated files
    # and symlinks cannot reduce the requirement. Cap credit per component.
    seen = set()
    credit = 0
    for names, cap in ((('adapter', 'base'), 10 * GIB),
                       (('python', 'venv', 'uv-cache'), 3 * GIB),
                       (('vendor',), MAX_SOURCE_BYTES)):
        subtotal = 0
        for name in names:
            directory = root / name
            if directory.is_symlink():
                continue
            for current, directories, files in os.walk(directory, followlinks=False):
                directories[:] = [item for item in directories if not (Path(current) / item).is_symlink()]
                for filename in files:
                    metadata = (Path(current) / filename).lstat()
                    key = (metadata.st_dev, metadata.st_ino)
                    if stat.S_ISREG(metadata.st_mode) and key not in seen:
                        seen.add(key)
                        subtotal += min(metadata.st_size, metadata.st_blocks * 512)
        credit += min(cap, subtotal)
    return max(MINIMUM_RESUME_BYTES, FRESH_BYTES - credit)


def physical_memory():
    """Machine capacity preflight; this is not a promise of available memory."""
    try:
        result = subprocess.run(['/usr/sbin/sysctl', '-n', 'hw.memsize'], capture_output=True,
                                check=True, timeout=5, text=True)
        capacity = int(result.stdout.strip())
        if capacity <= 0:
            raise ValueError('invalid capacity')
        return capacity
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SetupError('memory_check_failed') from None


def progress(message):
    print(message, file=sys.stderr, flush=True)


def _marker(path):
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise SetupError('source_revision')
    with path.open('rb') as stream:
        return stream.read(128).decode('ascii').strip()


def _extract(data, stage):
    size = count = 0
    top = None
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            count += 1
            path = PurePosixPath(member.name)
            if (count > 10000 or path.is_absolute() or '..' in path.parts
                    or not (member.isdir() or member.isfile())):
                raise SetupError('unsafe_source')
            if not path.parts:
                continue
            if top is None:
                top = path.parts[0]
            if path.parts[0] != top:
                raise SetupError('unsafe_source')
            parts = path.parts[1:]
            if not parts:
                continue
            size += member.size
            if size > MAX_SOURCE_BYTES:
                raise SetupError('unsafe_source')
            target = stage.joinpath(*parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with target.open('xb') as out, archive.extractfile(member) as source:
                    shutil.copyfileobj(source, out, length=1024 * 1024)
    if not all((stage / name).is_file() for name in SOURCE_FILES):
        raise SetupError('unsafe_source')


def source(root):
    from .runtime import SOURCE_REVISION
    vendor = root / 'vendor'
    # A process killed during extraction leaves only disposable source stages.
    for path in root.glob('.vendor-stage-*'):
        if path.is_symlink() or not path.is_dir():
            raise SetupError('invalid_directory')
        shutil.rmtree(path)
    if vendor.is_symlink():
        raise SetupError('invalid_directory')
    if vendor.exists():
        revision = _marker(vendor / '.source-revision') or _marker(root / 'source-revision')
        if revision is not None and revision != SOURCE_REVISION:
            raise SetupError('source_revision')
        if revision == SOURCE_REVISION and all((vendor / name).is_file() for name in SOURCE_FILES):
            return
        # Legacy interrupted extraction is cache, not model or authority state.
        shutil.rmtree(vendor)
    stage = Path(tempfile.mkdtemp(prefix='.vendor-stage-', dir=root))
    try:
        progress('Downloading pinned Kev source...')
        with urllib.request.urlopen('https://api.github.com/repos/jaredpalmer/kev/tarball/' + SOURCE_REVISION,
                                    timeout=60) as response:
            data = response.read(MAX_ARCHIVE_BYTES + 1)
        if len(data) > MAX_ARCHIVE_BYTES:
            raise SetupError('unsafe_source')
        _extract(data, stage)
        (stage / '.source-revision').write_text(SOURCE_REVISION + '\n')
        os.replace(stage, vendor)
        install.sync_directory(root)
    except SetupError:
        raise
    except Exception:
        raise SetupError('source_failed') from None
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def _run(root, argv, env, code):
    from .runtime import _terminate_owned, _wait_owned
    descriptor = os.open(root / 'setup.log', os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'ab') as log:
        metadata = os.fstat(log.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
                or metadata.st_uid != os.geteuid()):
            raise SetupError('invalid_directory')
        process = None
        started = time.monotonic()
        try:
            process = subprocess.Popen(argv, env=env, stdout=log, stderr=log, start_new_session=True)
            while True:
                try:
                    returncode = _wait_owned(process, PROGRESS_SECONDS)
                    break
                except subprocess.TimeoutExpired:
                    progress('Kev setup is still working (%.0f seconds in this phase). Details: %s' %
                             (time.monotonic() - started, root / 'setup.log'))
            if returncode:
                raise SetupError(code)
        except OSError:
            raise SetupError(code) from None
        finally:
            if process is not None:
                # Ctrl-C, an outer deadline or another Python exception must not
                # leave uv or its download process running after setup unlocks.
                _terminate_owned(process)


def setup(runtime_dir):
    from .runtime import _directory, _environment
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise SetupError('unsupported_host')
    memory = physical_memory()
    if memory < MINIMUM_MEMORY_BYTES:
        progress('Physical memory: %.1f GiB; the pinned model requires at least 16 GiB.' % (memory / GIB))
        raise SetupError('insufficient_memory')
    root = Path(runtime_dir).absolute()
    try:
        config.validate(config.default(root))
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _directory(root)
    except (OSError, ValueError):
        raise SetupError('invalid_directory') from None
    with termination_cleanup(), setup_lock(root):
        progress('Setup details are saved privately to: ' + str(root / 'setup.log'))
        settings_path = root / 'kev.json'
        if settings_path.exists():
            try:
                settings = config.load(settings_path)
                if settings['runtime_dir'] != str(root):
                    raise ValueError('runtime mismatch')
            except (OSError, ValueError):
                raise SetupError('invalid_config') from None
        python = root / 'venv/bin/python'
        env = _environment(root)
        if (root / 'manifest.json').exists():
            progress('Verifying existing installation; the model stays unloaded...')
            try:
                install.check_install(root, check_packages=False)
            except install.InstallError:
                raise SetupError('invalid_installation') from None
            if not python.is_file() or not settings_path.is_file():
                raise SetupError('missing_python')
            _run(root, [str(python), str(Path(install.__file__)), str(root), '--check'], env, 'packages_changed')
            return {'config': str(settings_path), 'installed': True, 'reused': True, 'model': config.MODEL}
        uv = shutil.which('uv')
        if not uv:
            raise SetupError('missing_uv')
        required = remaining_space(root)
        free = shutil.disk_usage(root).free
        if free < required:
            progress('Kev setup requires %.1f GiB of free disk space; %.1f GiB is available.' %
                     (required / GIB, free / GIB))
            raise SetupError('insufficient_disk')
        source(root)
        env.pop('HF_HUB_OFFLINE')
        env.pop('TRANSFORMERS_OFFLINE')
        env.update(UV_CACHE_DIR=str(root / 'uv-cache'), UV_PYTHON_INSTALL_DIR=str(root / 'python'),
                   UV_PROJECT_ENVIRONMENT=str(root / 'venv'))
        progress('Installing locked Python dependencies; existing downloads are reused...')
        _run(root, [uv, 'sync', '--project', str(root / 'vendor'), '--frozen', '--no-dev', '--python', '3.12'],
             env, 'dependencies_failed')
        if not settings_path.exists():
            install.atomic_json(settings_path, config.default(root), replace=False)
        progress('Downloading and verifying pinned model weights; existing downloads are reused...')
        _run(root, [str(python), str(Path(install.__file__)), str(root)], env, 'models_failed')
        try:
            install.check_install(root, check_packages=False)
        except install.InstallError:
            raise SetupError('models_failed') from None
        return {'config': str(settings_path), 'installed': True, 'reused': False, 'model': config.MODEL}
