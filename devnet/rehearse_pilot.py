#!/usr/bin/env python3
"""Exercise moved pilot bundles with four native processes on ONE machine."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from types import SimpleNamespace

import pilot


def rehearse(args):
    native = pilot.binaries(args.bin_dir)
    root = args.directory.absolute()
    pilot.mkdir(root)
    sockets = [socket.socket() for _ in range(4)]
    try:
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        endpoints = [f'127.0.0.1:{s.getsockname()[1]}' for s in sockets]
    finally:
        for sock in sockets:
            sock.close()
    plan = root / 'endpoints.json'
    pilot.write(plan, endpoints)
    prepared = root / 'prepared'
    pilot.prepare(SimpleNamespace(bin_dir=args.bin_dir, endpoints=plan, directory=prepared,
                                  timing='short-test', records=128, limits='compact'))
    bundles, children, logs = [], {}, []
    checks = {}
    started = time.monotonic()
    script = Path(__file__).with_name('pilot.py').resolve()
    fixtures = pilot.REPO / 'examples/state-workflow'

    def cli(index, *arguments):
        return pilot.run(native['naome'], arguments[0], bundles[index] / 'node.json', *arguments[1:])

    def start(index):
        log = (root / f'node-{index}-{len(logs)}.log').open('wb')
        logs.append(log)
        children[index] = subprocess.Popen([sys.executable, '-B', str(script), '--bin-dir', str(args.bin_dir.resolve()),
            'start', '--bundle', str(bundles[index])], cwd='/', stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def wait(index, predicate):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            pilot.require(all(c.poll() is None for c in children.values()), 'validator exited; private logs retained')
            try:
                value = cli(index, 'status')
            except RuntimeError:
                time.sleep(.2)
                continue
            if predicate(value):
                return value
            time.sleep(.2)
        raise RuntimeError('pilot rehearsal timed out waiting for finalized state')

    def stop(index):
        cli(index, 'shutdown')
        # Keep ownership until exit is confirmed so finally can terminate a
        # process whose graceful shutdown exceeded the deadline.
        pilot.require(children[index].wait(timeout=15) == 0, 'unclean validator shutdown')
        del children[index]

    try:
        for index in range(4):
            destination = root / f'host-{index}'
            (prepared / f'node-{index}').rename(destination)
            bundles.append(destination)
            pilot.require(sorted(str(p.relative_to(destination)) for p in destination.rglob('*.key')) ==
                          ['account.key', 'consensus.key', 'transport.key'], 'bundle contains another role key')
            pilot.check(destination, native)
            start(index)
        for index in range(4):
            wait(index, lambda s: s['height'] == 0)
        checks['relocated_bundles_with_separate_keys'] = True
        denied = subprocess.run([str(native['naome']), 'peer', str(bundles[0] / 'node.json'), '0', 'off'], capture_output=True, timeout=15)
        pilot.require(denied.returncode != 0 and b'simulation controls are disabled' in denied.stderr,
                      'pilot did not explicitly reject simulation controls')
        checks['simulation_controls_disabled'] = True
        stop(3)
        author = prepared / 'authors/account-4.key'
        cli(0, 'submit', author, fixtures / 'question-a.nao', 'Pilot: reusable reflexivity', root / 'submit.bin')
        for index in range(3):
            wait(index, lambda s: (s.get('active') or {}).get('phase') == 'Voting')
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(lambda i: cli(i, 'vote', bundles[i] / 'account.key', 'YES', root / f'vote-{i}.bin'), range(3)))
        wait(0, lambda s: (s.get('active') or {}).get('phase') == 'Commit')
        package = root / 'solution.package'
        pilot.run(native['naome'], 'package', prepared / 'genesis.bin', author, package,
                  fixtures / 'solution-a.nao', '--helper', fixtures / 'helper-h.nao')
        cli(0, 'commit', author, package, root / 'secret.bin', root / 'commit.bin')
        wait(0, lambda s: (s.get('active') or {}).get('phase') == 'Reveal')
        cli(0, 'reveal', author, root / 'secret.bin', root / 'reveal.bin')
        settled = wait(0, lambda s: s['paid_completions'] == 1 and s['active'] is None)
        checks['real_proof_and_helper_settled_with_one_node_offline'] = True
        start(3)
        for index in range(4):
            wait(index, lambda s: s['state'] == settled['state'])
        checks['returning_node_caught_up'] = True
        for index in range(4):
            stop(index)
        for index in range(4):
            start(index)
        for index in range(4):
            wait(index, lambda s: s['state'] == settled['state'])
        checks['all_nodes_cold_reopened_same_state'] = True
        snapshots = []
        for index in range(4):
            output = root / f'snapshot-{index}'
            pilot.snapshot(SimpleNamespace(bin_dir=args.bin_dir, bundle=bundles[index], directory=output, host_label='local-rehearsal'))
            snapshots.append(output)
        pilot.collect(SimpleNamespace(bin_dir=args.bin_dir, genesis=prepared / 'genesis.bin', snapshots=snapshots,
                                      minimum_completions=1, report=root / 'agreement.json'))
        checks['four_independent_archive_replays_agree'] = True
        duplicate = SimpleNamespace(bin_dir=args.bin_dir, genesis=prepared / 'genesis.bin',
                                    snapshots=[snapshots[0]] * 4, minimum_completions=1,
                                    report=root / 'must-not-exist.json')
        try:
            pilot.collect(duplicate)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('duplicate node exports accepted')
        pilot.require(not duplicate.report.exists(), 'failed collection published a success report')
        checks['duplicate_node_exports_rejected'] = True
        corrupted = root / 'corrupt-archive'
        shutil.copytree(snapshots[0] / 'archive', corrupted)
        finality = corrupted / '00000001.finality'
        data = bytearray(finality.read_bytes())
        data[-1] ^= 1
        finality.write_bytes(data)
        rejected = subprocess.run([str(native['naome-verifier']), 'verify', str(prepared / 'genesis.bin'), str(corrupted)], capture_output=True, timeout=15)
        pilot.require(rejected.returncode != 0, 'corrupt archive accepted')
        checks['corrupt_archive_rejected'] = True
        # No missing anchor can cause fresh signing-state initialization.
        stop(3)
        anchor = bundles[3] / 'anchors/signer'
        saved = bundles[3] / 'anchors/signer-held'
        anchor.rename(saved)
        rejected = subprocess.run([sys.executable, '-B', str(script), '--bin-dir', str(args.bin_dir.resolve()),
                                   'start', '--bundle', str(bundles[3])], capture_output=True, timeout=15)
        pilot.require(rejected.returncode != 0 and not anchor.exists(), 'missing authority was recreated')
        saved.rename(anchor)
        checks['missing_anchor_rejected_without_reinitialization'] = True
        result = {'version': 1, 'outcome': 'passed', 'scope': 'one-host, four-process relocated-bundle rehearsal; compact short-test profile; manual agenda votes',
                  'multi_machine': False, 'real_agent': False, 'lab_or_research_windows': False,
                  'checks': checks, 'height': settled['height'], 'paid_completions': settled['paid_completions'],
                  'source': pilot.source(), 'binary_sha256': {n: pilot.digest(p) for n, p in native.items()},
                  'elapsed_seconds': round(time.monotonic() - started, 3)}
    finally:
        for child in children.values():
            if child.poll() is None:
                child.terminate()
        for child in children.values():
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        for log in logs:
            log.close()
    result['cleanup_complete'] = True
    pilot.write(root / 'rehearsal-report.json', result)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin-dir', type=Path, required=True)
    p.add_argument('--directory', type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(rehearse(args), indent=2))
