#!/usr/bin/env python3
"""Prepare private, relocatable trusted-pilot bundles and replay collected evidence.

No SSH, key regeneration, archive extraction, service installation, or remote
execution. Transfer each fresh bundle exactly once before any validator starts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
PATHS = {
    'genesis': 'genesis.bin', 'history': 'data/history',
    'history_anchor': 'anchors/history', 'signer': 'data/signer',
    'signer_anchor': 'anchors/signer', 'consensus_key': 'consensus.key',
    'transport_key': 'transport.key', 'account_key': 'account.key',
    'agenda_profile': 'agenda-profile.txt', 'control_socket': 'control.sock',
}
STORES = ('history', 'history_anchor', 'signer', 'signer_anchor')
AGREEMENT = ('genesis', 'profile', 'height', 'head', 'state', 'library_root',
             'accounts', 'reserve_atoms', 'claims', 'paid_completions',
             'consensus_commitment')


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def mkdir(path):
    Path(path).mkdir(mode=0o700)
    sync_directory(Path(path).parent)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def move(source, destination):
    source.rename(destination)
    for parent in {source.parent, destination.parent}:
        sync_directory(parent)


def write(path, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    create(path, data)


def create(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(Path(path).parent)


def read(path):
    metadata = Path(path).lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 1024 * 1024,
            'expected bounded regular JSON file')
    return json.loads(Path(path).read_text())


def run(binary, *args, timeout=120):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True,
                            text=True, timeout=timeout)
    # Native diagnostics contain no keys; never echo signed actions or archives.
    require(result.returncode == 0, f'{Path(binary).name} {args[0]} failed: {result.stderr[-2000:]}')
    value = json.loads(result.stdout)
    require(isinstance(value, dict) and 'error' not in value, 'native command rejected')
    return value


def binaries(directory):
    directory = Path(directory).resolve(strict=True)
    result = {name: directory / name for name in ('naome', 'naome-validator', 'naome-verifier')}
    require(all(p.is_file() and os.access(p, os.X_OK) for p in result.values()),
            'build all three native binaries for this host first')
    return result


def source():
    paths = [REPO / n for n in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml')]
    paths += [p for p in (REPO / 'crates').rglob('*') if p.suffix in ('.rs', '.toml')]
    paths += [Path(__file__).resolve(), Path(__file__).with_name('rehearse_pilot.py').resolve()]
    manifest = {str(p.relative_to(REPO)): digest(p) for p in sorted(paths) if p.is_file()}
    encoded = json.dumps(manifest, sort_keys=True).encode()
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    return {'git_head': revision, 'source_sha256': hashlib.sha256(encoded).hexdigest(),
            'scope': 'Cargo manifests, lockfile, pinned toolchain, Rust sources and pilot tooling; includes working changes'}


def prepare(args):
    native = binaries(args.bin_dir)
    endpoints = read(args.endpoints)
    require(isinstance(endpoints, list) and len(endpoints) == 4,
            'endpoints JSON must contain four literal IP:port strings')
    root = args.directory.absolute()
    mkdir(root)  # Never reuse a previous run, even after a failed preparation.
    plan = root / 'endpoints.json'
    write(plan, endpoints)
    staging = root / 'provisioning'
    configured = run(native['naome'], 'setup', staging, args.timing, args.records,
                     44100, args.limits, plan)
    profile = run(native['naome'], 'profile-info', staging / 'genesis.bin')
    manifest = {'version': 1, 'genesis': configured['genesis'], 'profile': profile,
                'genesis_sha256': digest(staging / 'genesis.bin'), 'endpoints': endpoints,
                'timing': args.timing, 'limits': args.limits, 'source': source(),
                'provisioner_binary_sha256': {n: digest(p) for n, p in native.items()},
                'custody': 'Fresh initialized stores; move each bundle to one operator before first start. Never run a copied signer.'}
    for index in range(4):
        bundle = root / f'node-{index}'
        move(staging / f'node-{index}', bundle)
        config_path = bundle / 'node.json'
        config = read(config_path)
        mkdir(bundle / 'data')
        mkdir(bundle / 'anchors')
        for field in ('history', 'signer'):
            move(bundle / field, bundle / PATHS[field])
        for field in ('history_anchor', 'signer_anchor', 'account_key'):
            move(Path(config[field]), bundle / PATHS[field])
        create(bundle / 'genesis.bin', (staging / 'genesis.bin').read_bytes())
        config.update(PATHS)
        config['simulation'] = False
        config_path.unlink()
        write(config_path, config)
        write(bundle / 'pilot.json', dict(manifest, node_index=index))
    authors = root / 'authors'
    move(staging / 'accounts', authors)
    create(authors / 'genesis.bin', (staging / 'genesis.bin').read_bytes())
    move(staging / 'genesis.bin', root / 'genesis.bin')
    staging.rmdir()
    write(root / 'pilot.json', manifest)
    return {'status': 'prepared', 'directory': str(root), 'genesis': manifest['genesis'],
            'timing': args.timing, 'limits': args.limits, 'validators_started': False,
            'required_storage_bytes_per_node': profile['required_storage_bytes_per_node']}


def private(path, directory=False):
    m = path.lstat()
    require((stat.S_ISDIR(m.st_mode) if directory else stat.S_ISREG(m.st_mode))
            and m.st_uid == os.getuid() and m.st_mode & 0o077 == 0,
            f'private owned {"directory" if directory else "file"} required: {path.name}')


def check(bundle, native):
    private(bundle, True)
    bundle = bundle.resolve(strict=True)
    private(bundle, True)
    private(bundle / 'node.json')
    private(bundle / 'pilot.json')
    config, manifest = read(bundle / 'node.json'), read(bundle / 'pilot.json')
    require(manifest['version'] == 1 and type(manifest['node_index']) is int
            and 0 <= manifest['node_index'] < 4, 'unsupported pilot bundle')
    require(config['version'] == 2 and config['simulation'] is False,
            'pilot requires configuration v2 with simulation disabled')
    require(all(config[k] == v for k, v in PATHS.items()), 'bundle paths were changed')
    for parent in ('data', 'anchors'):
        private(bundle / parent, True)
    for field in STORES:
        path = bundle / config[field]
        private(path, True)
        require(any(path.iterdir()), f'initialized {field} is missing; never regenerate it')
    for name in ('genesis.bin', 'consensus.key', 'transport.key', 'account.key', 'agenda-profile.txt'):
        private(bundle / name)
    require(digest(bundle / 'genesis.bin') == manifest['genesis_sha256'], 'genesis file changed')
    profile = run(native['naome'], 'profile-info', bundle / 'genesis.bin')
    require(profile == manifest['profile'] and profile['genesis'] == manifest['genesis'],
            'genesis/profile differ from pilot plan')
    require(config['maximum_round'] == profile['limits']['consensus_rounds'], 'round limit changed')
    require(len(os.fsencode(bundle / 'control.sock')) < 100,
            'bundle path too long for portable Unix control socket; move to a shorter path')
    require(all(shutil.disk_usage(bundle / config[field]).free >= profile['required_storage_bytes_per_node']
                for field in ('history', 'signer')),
            'insufficient free storage for the immutable run profile')
    return {'status': 'preflight_passed', 'node_index': manifest['node_index'],
            'genesis': profile['genesis'], 'profile': profile['profile'],
            'endpoint': manifest['endpoints'][manifest['node_index']],
            'required_storage_bytes': profile['required_storage_bytes_per_node'],
            'binary_sha256': {n: digest(p) for n, p in native.items()},
            'boundary': 'File/layout/capacity checks only. Native startup validates keys, anchored history and signing custody.'}


def snapshot(args):
    native = binaries(args.bin_dir)
    checked = check(args.bundle, native)
    output = args.directory.absolute()
    mkdir(output)
    archive = output / 'archive'
    run(native['naome'], 'export', args.bundle / 'node.json', archive, timeout=600)
    replay = run(native['naome-verifier'], 'verify', args.bundle / 'genesis.bin', archive, timeout=600)
    manifest = read(args.bundle / 'pilot.json')
    report = {'version': 1, 'node_index': checked['node_index'], 'genesis': checked['genesis'],
              'host_label': args.host_label, 'host_identity': 'operator supplied; not attested',
              'host': {'system': platform.system(), 'machine': platform.machine()},
              'collected_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'source': manifest['source'], 'binary_sha256': checked['binary_sha256'],
              'replay': replay}
    write(output / 'snapshot.json', report)
    return {'status': 'snapshot_verified', 'node_index': checked['node_index'],
            'height': replay['height'], 'directory': str(output),
            'private': 'Archive contains finalized reveal material; keep the whole snapshot private.'}


def compare(replays, minimum_completions):
    require(len(replays) == 4, 'exactly four replays required')
    require(all(all(field in r for field in AGREEMENT) for r in replays), 'incomplete replay result')
    reference = {k: replays[0][k] for k in AGREEMENT}
    require(reference['height'] > 0, 'genesis-only agreement is not pilot execution')
    require(reference['paid_completions'] >= minimum_completions, 'research completion target not met')
    require(all({k: r[k] for k in AGREEMENT} == reference for r in replays),
            'archives do not agree at the same finalized tip; collect again after convergence')
    return reference


def collect(args):
    native = binaries(args.bin_dir)
    reports, replays = [], []
    for directory in args.snapshots:
        report = read(directory / 'snapshot.json')
        require(report['version'] == 1 and type(report['node_index']) is int, 'invalid snapshot identity')
        archive = directory / 'archive'
        require(digest(archive / 'genesis.bin') == digest(args.genesis), 'snapshot genesis differs from trusted genesis')
        replay = run(native['naome-verifier'], 'verify', args.genesis, archive, timeout=600)
        require(replay == report['replay'] and replay['genesis'] == report['genesis'], 'snapshot report does not match replay')
        reports.append(report)
        replays.append(replay)
    require(sorted(r['node_index'] for r in reports) == [0, 1, 2, 3], 'one snapshot from each node required')
    require(all(r['source'] == reports[0]['source'] for r in reports), 'provisioning source differs')
    agreed = compare(replays, args.minimum_completions)
    result = {'version': 1, 'outcome': 'four_archives_verified_and_agree', 'agreed': agreed,
              'sources': [{k: r[k] for k in ('node_index', 'host_label', 'host_identity', 'host', 'binary_sha256', 'source')} for r in reports],
              'verifier_sha256': digest(native['naome-verifier']),
              'qualification': 'Replay agreement only. Physical machine independence, actual deployment source, agent use, timing and fault scenarios require separate operator evidence.'}
    write(args.report, result)
    return {'outcome': result['outcome'], 'height': agreed['height'], 'paid_completions': agreed['paid_completions'], 'report': str(args.report)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--endpoints', type=Path, required=True)
    p.add_argument('--directory', type=Path, required=True)
    p.add_argument('--timing', choices=('lab', 'research', 'short-test'), default='lab')
    p.add_argument('--limits', choices=('standard', 'compact'), default='standard')
    p.add_argument('--records', type=int, default=128)
    for name in ('check', 'start', 'snapshot'):
        p = sub.add_parser(name)
        p.add_argument('--bundle', type=Path, required=True)
        if name == 'snapshot':
            p.add_argument('--directory', type=Path, required=True)
            p.add_argument('--host-label', required=True)
    p = sub.add_parser('collect')
    p.add_argument('--genesis', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--minimum-completions', type=int, default=2)
    p.add_argument('snapshots', nargs=4, type=Path)
    args = parser.parse_args()
    if args.command == 'prepare':
        result = prepare(args)
    elif args.command == 'snapshot':
        result = snapshot(args)
    elif args.command == 'collect':
        require(args.minimum_completions >= 0, 'minimum completions must be nonnegative')
        result = collect(args)
    else:
        native = binaries(args.bin_dir)
        result = check(args.bundle, native)
        if args.command == 'start':
            os.execv(native['naome-validator'], [str(native['naome-validator']), 'start', str(args.bundle.resolve() / 'node.json')])
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'pilot: {error}', file=sys.stderr)
        sys.exit(1)
