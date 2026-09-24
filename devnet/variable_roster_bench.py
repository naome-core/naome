#!/usr/bin/env python3
"""Measure local consensus and handoff with a sealed roster of N processes."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import time

from state_backend import Backend, BINARIES, command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--validators', type=int, required=True)
    parser.add_argument('--heights', type=int, default=2)
    parser.add_argument('--run-records', type=int, default=65)
    parser.add_argument('--deadline-seconds', type=int, default=180)
    args = parser.parse_args()
    if not 4 <= args.validators <= 32 or not 1 <= args.heights <= 16 or not 65 <= args.run_records <= 8192:
        parser.error('benchmark supports 4..32 processes, 1..16 heights, and 65..8192 records')
    args.directory = args.directory.resolve()
    args.bin_dir = args.bin_dir.resolve(strict=True)
    args.backend = 'process'
    args.delay_ms = 0
    args.directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.umask(0o077)
    backend = Backend(args, args.directory)
    repo = Path(__file__).resolve().parent.parent
    binary_repo = args.bin_dir.parent.parent
    start = time.monotonic()
    result = {
        'schema_version': 1,
        'roster_size': args.validators,
        'quorum': args.validators * 2 // 3 + 1,
        'target_height': args.heights,
        'run_records': args.run_records,
        'backend': 'local processes with zero-delay TCP proxies',
        'binary_sha256': {name: hashlib.sha256((args.bin_dir / name).read_bytes()).hexdigest()
                          for name in BINARIES},
        'source_commit': command(['git', '-C', binary_repo, 'rev-parse', 'HEAD']).stdout.strip(),
        'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'outcome': 'running',
    }

    def save():
        (args.directory / 'report.json').write_text(json.dumps(result, indent=2) + '\n')

    def interrupted(*_):
        raise KeyboardInterrupt('benchmark interrupted')

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        (args.directory / 'retirement-order.json').write_text(json.dumps(list(range(args.validators))))
        (args.directory / 'endpoints.json').write_text(json.dumps(backend.fronts))
        (args.directory / 'handoff-endpoints.json').write_text(json.dumps(backend.handoff_fronts))
        command([args.bin_dir / 'naome', 'setup', args.directory / 'run', 'ci-test', args.run_records,
                 44100, args.directory / 'retirement-order.json', 'compact',
                 args.directory / 'endpoints.json', args.directory / 'handoff-endpoints.json'],
                timeout=120)
        result['setup_seconds'] = round(time.monotonic() - start, 3)
        question = args.directory / 'question.nao'
        shutil.copy2(repo / 'examples/state-workflow/question-a.nao', question)
        for index in range(args.validators):
            config = backend.config(index)
            value = json.loads(config.read_text())
            value['listen_address'] = backend.backs[index]
            value['handoff_listen_address'] = backend.handoff_backs[index]
            config.write_text(json.dumps(value))
            backend.start(index)
        launched = time.monotonic()
        deadline = launched + args.deadline_seconds
        first_quorum = None
        submitted = False
        with ThreadPoolExecutor(max_workers=min(args.validators, 32)) as executor:
            while time.monotonic() < deadline:
                if any(not backend.alive(index) for index in range(args.validators)):
                    raise RuntimeError('validator exited before the target height')
                statuses = list(executor.map(
                    lambda index: backend.cli(index, 'status', backend.config(index),
                                              tolerate=True, timeout=8),
                    range(args.validators)))
                if all(status is not None for status in statuses):
                    if not submitted:
                        config = backend.config(0)
                        account_key = json.loads(config.read_text())['account_key']
                        submission = backend.cli(0, 'submit', config, account_key, question,
                                                 'Variable roster benchmark',
                                                 args.directory / 'submission.bin')
                        result['submission'] = submission['operation']
                        submitted = True
                    at_target = [status for status in statuses
                                 if status['height'] >= args.heights]
                    if first_quorum is None and len(at_target) >= result['quorum']:
                        first_quorum = round(time.monotonic() - launched, 3)
                    if len(at_target) == args.validators:
                        heads = {(status['height'], status['head'], status['state'])
                                 for status in statuses}
                        if len(heads) == 1:
                            result['outcome'] = 'passed'
                            result['finalized_height'] = statuses[0]['height']
                            result['head'] = statuses[0]['head']
                            result['state'] = statuses[0]['state']
                            result['first_quorum_seconds'] = first_quorum
                            result['all_nodes_seconds'] = round(time.monotonic() - launched, 3)
                            result['resources'] = {str(index): backend.resources(index)
                                                   for index in range(args.validators)}
                            result['total_sampled_memory_bytes'] = sum(
                                value['memory_bytes'] or 0 for value in result['resources'].values())
                            result['total_disk_bytes'] = sum(
                                value['disk_bytes'] for value in result['resources'].values())
                            break
                time.sleep(0.25)
            else:
                raise RuntimeError('target height did not converge before deadline')
    except (Exception, KeyboardInterrupt) as error:
        result['outcome'] = 'failed'
        result['failure'] = str(error)[:300]
    finally:
        try:
            backend.cleanup()
        except Exception as error:
            result['cleanup_failure'] = str(error)[:300]
            result['outcome'] = 'failed'
        result['elapsed_seconds'] = round(time.monotonic() - start, 3)
        save()
    print(json.dumps({key: result.get(key) for key in (
        'roster_size', 'quorum', 'outcome', 'failure', 'finalized_height',
        'first_quorum_seconds', 'all_nodes_seconds', 'total_sampled_memory_bytes',
        'total_disk_bytes', 'elapsed_seconds')}, indent=2))
    return 0 if result['outcome'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
