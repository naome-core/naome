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
import socket
import struct
import sys
import time

from state_backend import Backend, BINARIES, command


def direct_status(config):
    """Read compact progress over the local control socket without a CLI process."""
    try:
        path = json.loads(config.read_text())['control_socket']
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(35)
            connection.connect(path)
            request = b'{"command":"progress"}'
            connection.sendall(struct.pack('>I', len(request)) + request)

            def exact(length):
                result = bytearray()
                while len(result) < length:
                    part = connection.recv(length - len(result))
                    if not part:
                        raise OSError('short control response')
                    result.extend(part)
                return result

            length = struct.unpack('>I', exact(4))[0]
            if not 0 < length <= 3 * 1024 * 1024:
                raise ValueError('status response size')
            value = json.loads(exact(length))
            return value if isinstance(value, dict) and 'error' not in value else None
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None


def status_poll_interval(validators):
    if validators <= 32:
        return max(0.25, min(5.0, validators / 16))
    return min(20.0, validators / 4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--validators', type=int, required=True)
    parser.add_argument('--heights', type=int, default=2)
    parser.add_argument('--run-records', type=int, default=65)
    parser.add_argument('--deadline-seconds', type=int, default=180)
    parser.add_argument('--settle-seconds', type=int, default=0,
                        help='wait after all validators start before submitting work')
    parser.add_argument('--direct', action='store_true',
                        help='start native validators without zero-delay proxy wrappers')
    parser.add_argument('--mixed-loopback', action='store_true',
                        help='split direct local TCP listeners across IPv4 and IPv6 loopback')
    args = parser.parse_args()
    minimum_records = max(64, args.validators + 2 * 16 + 7) + 1
    if (not 4 <= args.validators <= 256 or not 1 <= args.heights <= 16
            or not minimum_records <= args.run_records <= 8192
            or not 0 <= args.settle_seconds <= 120):
        parser.error(f'benchmark supports 4..256 processes, 1..16 heights, and '
                     f'{minimum_records}..8192 records for this roster')
    if args.mixed_loopback and not args.direct:
        parser.error('--mixed-loopback requires --direct')
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
        'backend': ('direct local validator processes' if args.direct else
                    'local processes with zero-delay TCP proxies'),
        'loopback_address_families': (['127.0.0.1', '::1'] if args.mixed_loopback else
                                      ['127.0.0.1']),
        'settle_seconds': args.settle_seconds,
        'poll_interval_seconds': status_poll_interval(args.validators),
        'binary_sha256': {name: hashlib.sha256((args.bin_dir / name).read_bytes()).hexdigest()
                          for name in BINARIES},
        'source_commit': command(['git', '-C', binary_repo, 'rev-parse', 'HEAD']).stdout.strip(),
        'source_tree_clean': not command(['git', '-C', binary_repo, 'status', '--porcelain']).stdout.strip(),
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
        settle_until = time.monotonic() + args.settle_seconds
        while time.monotonic() < settle_until:
            if any(not backend.alive(index) for index in range(args.validators)):
                raise RuntimeError('validator exited during network startup')
            time.sleep(min(1, max(0, settle_until - time.monotonic())))
        launched = time.monotonic()
        deadline = launched + args.deadline_seconds
        poll_interval = status_poll_interval(args.validators)
        first_quorum = None
        submitted = False
        with ThreadPoolExecutor(max_workers=min(args.validators, 32)) as executor:
            while time.monotonic() < deadline:
                if any(not backend.alive(index) for index in range(args.validators)):
                    raise RuntimeError('validator exited before the target height')
                if not submitted:
                    config = backend.config(0)
                    first_status = (direct_status(config) if args.direct else
                                    backend.cli(0, 'status', config, tolerate=True, timeout=8))
                    if first_status is not None:
                        account_key = json.loads(config.read_text())['account_key']
                        submission = backend.cli(0, 'submit', config, account_key, question,
                                                 'Variable roster benchmark',
                                                 args.directory / 'submission.bin')
                        result['submission'] = submission['operation']
                        submitted = True
                    else:
                        time.sleep(poll_interval)
                        continue
                if args.direct:
                    statuses = list(executor.map(
                        lambda index: direct_status(backend.config(index)),
                        range(args.validators)))
                else:
                    statuses = list(executor.map(
                        lambda index: backend.cli(index, 'status', backend.config(index),
                                                  tolerate=True, timeout=8),
                        range(args.validators)))
                responding = [status for status in statuses if status is not None]
                if responding:
                    diagnostics = [status.get('transport_diagnostics') for status in responding]
                    if all(isinstance(item, dict) for item in diagnostics):
                        result['latest_progress'] = {
                            'responded': len(responding),
                            'height_range': [min(status['height'] for status in responding),
                                             max(status['height'] for status in responding)],
                            'pending_operation_range': [
                                min(status['pending_operations'] for status in responding),
                                max(status['pending_operations'] for status in responding)],
                            'local_proposer_count': sum(status.get('local_proposer', False)
                                                        for status in responding),
                            'proposal_authored_count': sum(status.get('proposal_authored', False)
                                                           for status in responding),
                            'observed_proposal_range': [
                                min(status.get('observed_proposals', 0) for status in responding),
                                max(status.get('observed_proposals', 0) for status in responding)],
                            'observed_prevote_range': [
                                min(status.get('observed_prevotes', 0) for status in responding),
                                max(status.get('observed_prevotes', 0) for status in responding)],
                            'observed_precommit_range': [
                                min(status.get('observed_precommits', 0) for status in responding),
                                max(status.get('observed_precommits', 0) for status in responding)],
                            'connected_peer_range': [
                                min(item['connected_peers'] for item in diagnostics),
                                max(item['connected_peers'] for item in diagnostics)],
                            'offer_range': [min(item['offers'] for item in diagnostics),
                                            max(item['offers'] for item in diagnostics)],
                            'time_report_range': [
                                min(item['time_reports'] for item in diagnostics),
                                max(item['time_reports'] for item in diagnostics)],
                            'queued_delivery_range': [
                                min(item['queued_deliveries'] for item in diagnostics),
                                max(item['queued_deliveries'] for item in diagnostics)],
                            'work_ready_count': sum(item['work_ready'] for item in diagnostics),
                            'agreement_ready_count': sum(item['agreement_ready'] for item in diagnostics),
                        }
                        if all('ready_signatures' in item for item in diagnostics):
                            result['latest_progress']['ready_signature_range'] = [
                                min(item['ready_signatures'] for item in diagnostics),
                                max(item['ready_signatures'] for item in diagnostics)]
                            result['latest_progress']['terminal_signature_range'] = [
                                min(item['terminal_signatures'] for item in diagnostics),
                                max(item['terminal_signatures'] for item in diagnostics)]
                    at_target = [status for status in responding
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
                            memory = [value['memory_bytes'] for value in result['resources'].values()]
                            result['total_sampled_memory_bytes'] = (
                                sum(memory) if all(value is not None for value in memory) else None)
                            result['total_disk_bytes'] = sum(
                                value['disk_bytes'] for value in result['resources'].values())
                            break
                time.sleep(poll_interval)
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
