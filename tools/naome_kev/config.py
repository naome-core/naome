"""Private local settings and immutable model and execution identities."""
import copy
import os
from pathlib import Path
import stat
from . import policy
from .context import VERSION as CONTEXT_VERSION, BUILDERS
from .schema import exact, integer, loads, encode

MODEL_ID = 'jaredpalmer/kev-4b'
MODEL_REVISION = '485ace8703592fcf405488b262449990824cfed1'
BASE_MODEL_ID = 'Qwen/Qwen3.5-4B-Base'
BASE_MODEL_REVISION = '1001bb4d826a52d1f399e183466143f4da7b741b'
EXECUTION = 'mps-bf16-unmerged-sdpa-prefix-v1'
MODEL = f'kev-4b@{MODEL_REVISION}+base@{BASE_MODEL_REVISION}+{EXECUTION}'
IDENTITY = {'model': MODEL, 'model_id': MODEL_ID, 'model_revision': MODEL_REVISION,
            'base_model_id': BASE_MODEL_ID, 'base_model_revision': BASE_MODEL_REVISION,
            'execution': EXECUTION}


def read_private(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
                or metadata.st_uid != os.geteuid()):
            raise ValueError('file must be private, owned, and regular')
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('private file exceeds size limit')
        return data


def validate(settings):
    exact(settings, ('version', *IDENTITY, 'runtime_dir', 'context_version', 'policy'), 'Kev config')
    integer(settings['version'], 1, 1, 'config version')
    if any(settings[name] != expected for name, expected in IDENTITY.items()):
        raise ValueError('use the pinned Kev checkpoint and execution identity')
    if settings['context_version'] not in BUILDERS:
        raise ValueError('unsupported context version')
    directory = settings['runtime_dir']
    if (not isinstance(directory, str) or not Path(directory).is_absolute()
            or len(directory.encode()) > 4096 or '\x00' in directory or '..' in Path(directory).parts):
        raise ValueError('runtime_dir must be an absolute local path')
    policy.validate(settings['policy'])
    return settings


def load(path):
    return validate(loads(read_private(path, 8192)))


def default(runtime_dir):
    return {'version': 1, **IDENTITY, 'runtime_dir': str(Path(runtime_dir).absolute()),
            'context_version': CONTEXT_VERSION, 'policy': copy.deepcopy(policy.DEFAULT)}


def _create(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def configure(directory):
    directory = Path(directory).absolute()
    settings = validate(default(directory))
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid():
        raise ValueError('configuration directory must be private and owned')
    config_path = directory / 'kev.json'
    _create(config_path, encode(settings) + b'\n')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return config_path
