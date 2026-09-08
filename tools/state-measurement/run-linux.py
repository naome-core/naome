#!/usr/bin/env python3
"""Run primitive calibration inside a verified, externally imposed cgroup scope."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    root = Path(__file__).resolve().parents[2]
    os.chdir(root)
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('Requires Linux x86_64')
    groups = Path('/proc/self/cgroup').read_text().splitlines()
    unified = [line.removeprefix('0::') for line in groups if line.startswith('0::')]
    if len(unified) != 1:
        raise RuntimeError('Requires unified cgroup v2')
    group = Path('/sys/fs/cgroup') / unified[0].lstrip('/')
    limits = {name: (group / name).read_text().strip() for name in
              ['memory.max', 'memory.swap.max', 'cpu.max', 'cpuset.cpus.effective']}
    affinity = sorted(os.sched_getaffinity(0))
    quota, period = limits['cpu.max'].split()
    if (limits['memory.max'] != str(8 * 1024**3)
            or limits['memory.swap.max'] != '0'
            or quota == 'max' or int(quota) != 4 * int(period)
            or len(affinity) != 4):
        raise RuntimeError(f'Unexpected measurement constraints: {limits}, {affinity}')
    tracked = command('git', 'ls-files', 'tools/state-measurement',
                      'rust-toolchain.toml', '.github/workflows/ci.yml').splitlines()
    if not tracked or command('git', 'status', '--porcelain'):
        raise RuntimeError('Requires a clean, committed checkout')
    binary = root / 'tools/state-measurement/target/release/naome-state-measurement'
    metadata = {
        'kind': 'linux_primitive_calibration_metadata',
        'scope': 'authorization core and integer decoders; no full block or SSD I/O',
        'head': command('git', 'rev-parse', 'HEAD'),
        'tree': command('git', 'rev-parse', 'HEAD^{tree}'),
        'uname': platform.uname()._asdict(),
        'cpuinfo': Path('/proc/cpuinfo').read_text(),
        'meminfo': Path('/proc/meminfo').read_text(),
        'storage': command('lsblk', '-J', '-o', 'NAME,TYPE,SIZE,ROTA'),
        'cgroup': str(group), 'limits': limits, 'affinity': affinity,
        'rustc': command('rustc', '--version', '--verbose'),
        'cargo': command('cargo', '--version', '--verbose'),
        'cargo_incremental': os.environ.get('CARGO_INCREMENTAL'),
        'rustflags': os.environ.get('RUSTFLAGS', ''),
        'profile': 'release; opt-level 3; overflow-checks true',
        'source_sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                          for name in tracked},
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    print(json.dumps(metadata), flush=True)
    start = time.monotonic()
    subprocess.run([str(binary)], check=True)
    print(json.dumps({'kind': 'runtime_summary', 'elapsed_seconds': time.monotonic() - start,
                      'cgroup_memory_peak_bytes': int((group / 'memory.peak').read_text()),
                      'memory_events': (group / 'memory.events').read_text()}), flush=True)


if __name__ == '__main__':
    main()
