"""Model download and installation checks; never imports or loads the model."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from naome_kev import config
from naome_kev.schema import loads

PACKAGES = ('torch', 'transformers', 'peft', 'huggingface-hub', 'numpy')
IDENTITY_FIELDS = ('dev', 'ino', 'size', 'mtime_ns', 'ctime_ns')
REQUIRED_FILES = {
    'adapter/adapter_config.json', 'adapter/adapter_model.safetensors', 'adapter/head.pt',
    'base/config.json', 'base/tokenizer.json', 'base/tokenizer_config.json',
    'base/model.safetensors.index.json',
    'base/model.safetensors-00001-of-00002.safetensors',
    'base/model.safetensors-00002-of-00002.safetensors',
}
REQUIRED_SOURCES = {'vendor/uv.lock', 'vendor/kev/__init__.py', 'vendor/kev/api.py',
                    'vendor/kev/checkpoint.py', 'vendor/kev/model.py'}


class InstallError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def sha256(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def identity(metadata):
    return {key: getattr(metadata, 'st_' + key) for key in IDENTITY_FIELDS}


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json(path, value, replace=True):
    """Publish complete private JSON; interruption never exposes partial bytes."""
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(json.dumps(value, allow_nan=False, sort_keys=True, indent=2).encode() + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
            os.unlink(temporary)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _relative_file(root, name, prefixes):
    if (not isinstance(name, str) or Path(name).is_absolute() or '..' in Path(name).parts
            or len(Path(name).parts) < 2 or Path(name).parts[0] not in prefixes):
        raise InstallError('manifest_invalid')
    path = root / name
    try:
        current = root
        for part in Path(name).parts:
            current = current / part
            if current.is_symlink():
                raise InstallError('installation_changed')
        metadata = path.lstat()
    except OSError:
        raise InstallError('installation_incomplete') from None
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallError('installation_changed')
    return path, metadata


def check_install(root, check_packages=True):
    """Shared setup/startup verification without Torch imports or GPU work."""
    from naome_kev.runtime import SOURCE_REVISION
    try:
        manifest = loads(config.read_private(root / 'manifest.json', 131072))
        if (not isinstance(manifest, dict) or manifest.get('version') != 1
                or manifest.get('source_revision') != SOURCE_REVISION
                or manifest.get('model') != config.MODEL):
            raise InstallError('manifest_invalid')
        if (not isinstance(manifest.get('files'), dict)
                or not REQUIRED_FILES.issubset(manifest['files'])
                or not isinstance(manifest.get('sources'), dict)
                or not REQUIRED_SOURCES.issubset(manifest['sources'])
                or not isinstance(manifest.get('packages'), dict)
                or set(manifest['packages']) != set(PACKAGES)):
            raise InstallError('manifest_invalid')
        for name, entry in manifest['files'].items():
            path, metadata = _relative_file(root, name, ('adapter', 'base'))
            if (not isinstance(entry, dict) or set(entry) != {'sha256', 'bytes', 'identity'}
                    or not isinstance(entry['sha256'], str)
                    or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])
                    or not isinstance(entry['identity'], dict)
                    or set(entry['identity']) != set(IDENTITY_FIELDS)):
                raise InstallError('manifest_invalid')
            if entry['bytes'] != metadata.st_size or identity(metadata) != entry['identity']:
                raise InstallError('installation_changed')
        for name, expected in manifest['sources'].items():
            path, _ = _relative_file(root, name, ('vendor',))
            if sha256(path) != expected:
                raise InstallError('source_changed')
        if check_packages:
            for name, expected in manifest['packages'].items():
                if importlib.metadata.version(name) != expected:
                    raise InstallError('packages_changed')
        return manifest
    except InstallError:
        raise
    except (OSError, ValueError, TypeError, KeyError, importlib.metadata.PackageNotFoundError):
        raise InstallError('manifest_invalid') from None


def install(root):
    from huggingface_hub import snapshot_download
    from naome_kev.runtime import SOURCE_REVISION
    settings = config.load(root / 'kev.json')
    files = {}
    for name, revision, directory in ((settings['model_id'], settings['model_revision'], 'adapter'),
                                       (settings['base_model_id'], settings['base_model_revision'], 'base')):
        print('Downloading immutable snapshot: ' + name + '@' + revision, flush=True)
        snapshot_download(name, revision=revision, local_dir=root / directory,
                          allow_patterns=['*.json', '*.safetensors', '*.pt', '*.txt', '*.jinja', '*.md'],
                          max_workers=2)
        for path in sorted((root / directory).rglob('*')):
            if path.is_file() and '.cache' not in path.parts:
                path, before = _relative_file(root, str(path.relative_to(root)), ('adapter', 'base'))
                digest = sha256(path)
                after = path.stat()
                if identity(before) != identity(after):
                    raise InstallError('installation_changed')
                files[str(path.relative_to(root))] = {'sha256': digest, 'bytes': after.st_size,
                                                     'identity': identity(after)}
    if not REQUIRED_FILES.issubset(files):
        raise InstallError('installation_incomplete')
    sources = {str(path.relative_to(root)): sha256(path) for path in sorted((root / 'vendor/kev').glob('*.py'))}
    sources['vendor/uv.lock'] = sha256(root / 'vendor/uv.lock')
    if not REQUIRED_SOURCES.issubset(sources):
        raise InstallError('installation_incomplete')
    manifest = {'version': 1, 'source_revision': SOURCE_REVISION, 'model': settings['model'],
                'files': files, 'sources': sources,
                'packages': {name: importlib.metadata.version(name) for name in PACKAGES},
                'python': sys.version}
    atomic_json(root / 'manifest.json', manifest)
    print('Pinned weights and source manifest recorded', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runtime_dir', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        check_install(args.runtime_dir)
    else:
        install(args.runtime_dir)


if __name__ == '__main__':
    try:
        main()
    except InstallError as error:
        print('Kev installation check failed: ' + error.code + '.', file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Kev installation failed. Check network access and free disk space, then rerun setup.', file=sys.stderr)
        sys.exit(1)
