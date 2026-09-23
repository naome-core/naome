#!/usr/bin/env python3
"""Qualify canonical full-state records through four actual validator processes."""
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

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
OBSERVATION_POLL_SECONDS = 0.2


def atomic(path, value):
    temporary = path.with_suffix('.pending')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


class Qualification:
    def __init__(self, args):
        self.args = args
        self.root = args.directory.resolve()
        self.root.mkdir(mode=0o700)
        self.backend = Backend(args, self.root)
        self.started = time.monotonic()
        self.deadline = self.started + args.deadline_seconds
        self.latest, self.resources = {}, {}
        self.isolated = None
        self.report = {'schema_version': 1, 'outcome': 'running', 'backend': args.backend,
            'scope': 'four stable authority slots with sealed key rotation; canonical records, authenticated operations and certified phase transitions; accelerated qualification',
            'requested_minimum_heights': args.heights, 'genesis_run_records': 256, 'timing_profile': args.timing,
            'delay_ms_each_direction_per_chunk': args.delay_ms,
            'delay_proxy_prefetched_chunks_per_direction': 1,
            'observation_poll_seconds': OBSERVATION_POLL_SECONDS,
            'deadline_seconds': args.deadline_seconds, 'consensus_commands_sent': 0,
            'workload': 'alternating independent owner submissions and full-window NotApproved settlement; proof publication/citation separately qualified by the four-process Rust suite',
            'limits': {'sampled_role_disk_bytes': 512 * 1024 * 1024, 'container_memory_bytes': 512 * 1024 * 1024},
            'attempts': [], 'faults': [], 'verified': [],
            'binary_sha256': {name: hashlib.sha256((args.bin_dir / name).read_bytes()).hexdigest() for name in BINARIES},
            'source_commit': command(['git', '-C', REPO, 'rev-parse', 'HEAD']).stdout.strip(),
            'source_worktree_clean': not command(['git', '-C', REPO, 'status', '--porcelain']).stdout.strip(),
            'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'harness_sha256': {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in ('state_qualify.py', 'state_backend.py', 'state_agent.py', 'proxy.py')}}

    def save(self):
        self.report['elapsed_seconds'] = round(time.monotonic() - self.started, 3)
        self.report['resources'] = self.resources
        atomic(self.root / 'report.json', self.report)

    def prepare(self):
        endpoints = self.root / 'endpoints.json'
        endpoints.write_text(json.dumps(self.backend.fronts))
        handoff_endpoints = self.root / 'handoff-endpoints.json'
        handoff_endpoints.write_text(json.dumps(self.backend.handoff_fronts))
        retirement = self.root / 'retirement-order.json'
        retirement.write_text(json.dumps([2, 0, 3, 1]))
        command([self.args.bin_dir / 'naome', 'setup', self.root / 'run', self.args.timing, 256, 44100, retirement, 'compact', endpoints, handoff_endpoints])
        anchors = self.root / 'anchors'
        anchors.mkdir(mode=0o700)
        for i in range(4):
            (anchors / str(i)).mkdir(mode=0o700)
            config = json.loads(self.backend.config(i).read_text())
            config['listen_address'] = self.backend.backs[i]
            config['handoff_listen_address'] = self.backend.handoff_backs[i]
            for field, name in (('history_anchor', 'history'), ('signer_anchor', 'signer'), ('custody_anchor', 'custody'), ('handoff_anchor', 'handoff')):
                source = Path(config[field])
                destination = anchors / str(i) / name
                source.rename(destination)
                for parent in (source.parent, destination.parent):
                    descriptor = os.open(parent, os.O_RDONLY)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                config[field] = str(destination)
            private = self.backend.node(i) / 'account.key'
            shutil.copy2(config['account_key'], private)
            config['account_key'] = str(private)
            atomic(self.backend.config(i), config)
            shutil.copy2(REPO / 'examples/state-workflow/question-a.nao', self.backend.node(i) / 'question.nao')
            require(all(Path(config[field]).is_dir() and any(Path(config[field]).iterdir())
                        for field in ('history', 'signer', 'custody', 'handoff', 'history_anchor', 'signer_anchor', 'custody_anchor', 'handoff_anchor')),
                    'setup must initialize all four authority stores')
        self.report['authority_stores_initialized_by_setup'] = True
        if self.args.backend == 'docker':
            self.backend.prepare_containers()
            self.report['image_id'] = self.backend.image_id
            self.report['runtime_binary_sha256'] = self.backend.runtime_hashes
        for i in range(4):
            self.backend.start(i)
        initial = self.wait('genesis startup', range(4), lambda values: all(v['height'] == 0 for v in values.values()), starting=True)
        # Malformed operations are delivered to the running node's own bounded
        # intake, bypassing the operator client's early checks. Every rejection
        # must leave canonical authority and pending intake unchanged.
        for value in range(32):
            response = self.backend.control(0, {'command': 'submit', 'bytes': bytes([value]).hex()})
            require('error' in response, 'malformed operation accepted by canonical ingress')
        after = self.backend.cli(0, 'status', self.backend.config(0))
        require((after['height'], after['head'], after['state'], after['pending_operations']) ==
                (initial[0]['height'], initial[0]['head'], initial[0]['state'], 0), 'malformed ingress changed authority or intake')
        self.report['malformed_ingress_rejected_without_authority_change'] = 32
        self.save()

    def observe(self, indices, starting=False):
        started = time.monotonic()
        result = {}
        def sample(i):
            if self.args.backend == 'docker':
                observed = self.backend.status_memory(i, tolerate=starting)
                if observed is None:
                    require(self.backend.alive(i), f'validator {i} unexpectedly exited')
                    return None
                value, memory_bytes = observed
                return value, self.backend.resources(i, memory_bytes=memory_bytes)
            require(self.backend.alive(i), f'validator {i} unexpectedly exited')
            value = self.backend.cli(i, 'status', self.backend.config(i), tolerate=starting)
            if value is None:
                return None
            return value, self.backend.resources(i)

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {i: pool.submit(sample, i) for i in indices}
        for i, future in futures.items():
            observed = future.result()
            if observed is None:
                continue
            value, resources = observed
            require(value['status'] == 'finalized', 'status must represent finalized authority')
            prior = self.latest.get(i)
            require(prior is None or value['height'] >= prior['height'], 'finalized height regressed')
            if prior and value['height'] == prior['height']:
                require(value['head'] == prior['head'] and value['state'] == prior['state'], 'same-height authority changed')
            self.latest[i] = result[i] = value
            require(resources['disk_bytes'] <= self.report['limits']['sampled_role_disk_bytes'], 'sampled role disk cap exceeded')
            if self.args.backend == 'docker':
                require(resources['memory_bytes'] is not None, 'container memory sample absent')
                require(resources['memory_bytes'] <= self.report['limits']['container_memory_bytes'], 'container memory cap exceeded')
            peak = self.resources.setdefault(str(i), {'samples': 0, 'peak_disk_bytes': 0, 'peak_memory_bytes': 0})
            peak['samples'] += 1
            peak['peak_disk_bytes'] = max(peak['peak_disk_bytes'], resources['disk_bytes'])
            peak['peak_memory_bytes'] = max(peak['peak_memory_bytes'], resources['memory_bytes'] or 0)
        # Different heights can legitimately coexist; equal heights must agree.
        seen = {}
        for value in result.values():
            identity = (value['head'], value['state'], value['library_root'])
            require(value['height'] not in seen or seen[value['height']] == identity, 'validators disagree at equal finalized height')
            seen[value['height']] = identity
        timings = self.report.setdefault('timing_seconds', {})
        timings['observation'] = timings.get('observation', 0) + time.monotonic() - started
        return result

    def service_fault(self):
        if self.isolated is not None and time.monotonic() >= self.isolated[2]:
            index, before, _ = self.isolated
            stale = self.backend.cli(index, 'status', self.backend.config(index))
            require(stale['height'] == before['height'] and stale['head'] == before['head'], 'isolated validator advanced')
            # Healing has a time bound independent of progress. Capture the
            # fresh-quorum oracle before reconnecting, then fail if it was absent.
            survivor_heights = {i: self.backend.cli(i, 'status', self.backend.config(i))['height'] for i in range(4) if i != index}
            self.backend.heal(index)
            self.isolated = None
            self.report['faults'].append({'operation': 'partition_healed_on_deadline', 'validator': index,
                                         'height_at_cut': before['height'], 'survivor_heights_before_heal': survivor_heights})
            require(any(height > before['height'] for height in survivor_heights.values()), 'surviving quorum made no progress while isolated')

    def wait(self, label, indices, predicate, starting=False):
        indices = list(indices)
        until = min(self.deadline, time.monotonic() + self.args.height_timeout)
        while time.monotonic() < until:
            self.service_fault()
            values = self.observe(indices, starting=starting)
            if len(values) == len(indices) and predicate(values):
                return values
            time.sleep(OBSERVATION_POLL_SECONDS)
        raise RuntimeError(f'deadline: {label}')

    def converge(self, indices, height):
        return self.wait('same finalized tip', indices, lambda values: all(v['height'] >= height for v in values.values()) and
                         len({(v['height'], v['head'], v['state']) for v in values.values()}) == 1)

    def attempt(self, number, indices):
        started = time.monotonic()
        checkpoint = started
        phases = {}
        def record(name):
            nonlocal checkpoint
            now = time.monotonic()
            phases[name] = round(now - checkpoint, 3)
            checkpoint = now
        owner = number % 2
        config, node = self.backend.config(owner), self.backend.node(owner)
        before = self.backend.cli(owner, 'status', config)
        require(before['active'] is None and before['queued'] == 0, 'previous attempt not settled')
        submitted = self.backend.cli(owner, 'submit', config, node / 'account.key', node / 'question.nao',
                                     f'Canonical qualification attempt {number}', node / f'action-{number}.bin')
        if before['consensus_position'] is None:
            # The alternating account still signs its own action. A vacant
            # slot has only recovery access, so deliver those exact signed
            # bytes through a currently active validator's ordinary ingress.
            live = self.wait('active submission ingress', indices,
                             lambda values: any(v['consensus_position'] is not None for v in values.values()))
            ingress = next(i for i, value in live.items() if value['consensus_position'] is not None)
            response = self.backend.control(ingress, {
                'command': 'submit', 'bytes': (node / f'action-{number}.bin').read_bytes().hex()})
            require('error' not in response, 'active ingress rejected authenticated owner submission')
        record('submit')
        operation = submitted['operation']
        self.wait('authenticated submission receipt', [owner], lambda _: self.backend.cli(owner, 'receipt', config, operation)['status'] == 'finalized')
        record('receipt')
        active = self.wait('full voting window opens', indices,
                           lambda values: all(v['active'] is not None and v['active']['phase'] == 'Voting' for v in values.values()))
        record('voting_open')
        submission = active[owner]['active']['submission']
        deadline = active[owner]['active']['deadline']
        require(all(v['active']['submission'] == submission and v['active']['deadline'] == deadline for v in active.values()), 'active attempt or deadline disagreement')
        finished = self.wait('full-window NotApproved settlement', indices,
            lambda values: all(v['height'] > before['height'] and v['active'] is None and v['queued'] == 0 for v in values.values()))
        record('settlement')
        height = max(v['height'] for v in finished.values())
        finished = self.converge(indices, height)
        record('converge')
        require(all(v['time'] >= deadline for v in finished.values()), 'voting closed before its certified deadline')
        question = self.backend.cli(owner, 'question', config, submission)
        record('question')
        require(question['status'] == 'NotApproved', 'unexpected agenda outcome')
        self.report['attempts'].append({'number': number, 'owner': owner, 'operation': operation,
            'submission': submission, 'height': height, 'head': finished[owner]['head'], 'state': finished[owner]['state'],
            'voting_deadline': deadline, 'certified_start': active[owner]['time'], 'certified_end': finished[owner]['time'],
            'elapsed_seconds': round(time.monotonic() - started, 3), 'phase_seconds': phases,
            'active_slots_at_settlement': {str(i): value['authority']['active_slots'] for i, value in finished.items()}})
        self.save()
        print(json.dumps({'event': 'canonical_devnet_progress', 'attempt': number, 'height': height}), flush=True)
        return height

    def restart(self, index, force):
        started = time.monotonic()
        before = self.backend.cli(index, 'status', self.backend.config(index))
        require(before['consensus_position'] is not None, 'restart target is not an active signer')
        prefix = self.backend.node(index) / f'before-restart-{self.backend.generations[index]}'
        self.backend.cli(index, 'export', self.backend.config(index), prefix, timeout=180)
        self.backend.stop(index, force=force)
        self.backend.start(index)
        after = self.wait('strict restart', [index], lambda values: values[index]['height'] == before['height'], starting=True)[index]
        require((after['head'], after['state']) == (before['head'], before['state']), 'restart changed finalized state')
        reopened = self.backend.node(index) / f'after-restart-{self.backend.generations[index]}'
        self.backend.cli(index, 'export', self.backend.config(index), reopened, timeout=180)
        for height in range(1, before['height'] + 1):
            name = f'{height:08}.finality'
            require((prefix / name).read_bytes() == (reopened / name).read_bytes(), 'restart replaced selected finality evidence')
        self.report['faults'].append({'operation': 'sigkill_restart' if force else 'graceful_restart', 'validator': index, 'height': before['height'],
                                     'active_signer_before_restart': True,
                                     'elapsed_seconds': round(time.monotonic() - started, 3)})

    def verify(self):
        tip = self.converge(range(4), self.args.heights)[0]
        consensus = None
        for i in range(4):
            archive = self.backend.node(i) / 'export'
            started = time.monotonic()
            self.backend.cli(i, 'export', self.backend.config(i), archive, timeout=180)
            export_seconds = time.monotonic() - started
            started = time.monotonic()
            result = json.loads(command([self.args.bin_dir / 'naome-verifier', 'verify', self.root / 'run/genesis.bin', archive], timeout=180).stdout)
            replay_seconds = time.monotonic() - started
            require((result['height'], result['head'], result['state']) == (tip['height'], tip['head'], tip['state']), 'independent replay differs from live state')
            frames = [hashlib.sha256((archive / f'{height:08}.finality').read_bytes()).hexdigest() for height in range(1, tip['height'] + 1)]
            # Each verified head binds the full record ancestry. Different sufficient
            # certificate signer subsets are legal; they do not change that history.
            require(consensus is None or consensus == result['consensus_commitment'], 'independent consensus history differs')
            consensus = result['consensus_commitment']
            self.report['verified'].append({'validator': i, 'height': result['height'], 'head': result['head'], 'state': result['state'],
                'consensus_commitment': result['consensus_commitment'], 'retained_finality_frame_sha256': frames,
                'export_seconds': round(export_seconds, 3), 'replay_seconds': round(replay_seconds, 3)})
        # A corrupt export must be rejected by the actual independent executable.
        path = self.backend.node(0) / 'export/00000001.finality'
        original = path.read_bytes()
        corrupt = bytearray(original)
        corrupt[-1] ^= 1
        path.write_bytes(corrupt)
        result = command([self.args.bin_dir / 'naome-verifier', 'verify', self.root / 'run/genesis.bin', path.parent], tolerate=True, timeout=180)
        require(result.returncode != 0, 'corrupt export accepted')
        require(path.read_bytes() == corrupt, 'verifier rewrote corrupt input')
        path.write_bytes(original)
        self.report['corrupt_export_rejected_without_repair'] = True

    @staticmethod
    def partition_ready(values):
        return (set(values) == set(range(4))
                and len({(v['height'], v['head'], v['state']) for v in values.values()}) == 1
                and all(v['authority']['active_slots'] == 4
                        and v['consensus_position'] is not None for v in values.values()))

    def run(self):
        started = time.monotonic()
        self.prepare()
        self.report.setdefault('timing_seconds', {})['startup'] = round(time.monotonic() - started, 3)
        height, attempt, fault_stage = 0, 0, 0
        partitioned = False
        partition_prepare_until = None
        last_restart_height = None
        while (height < self.args.heights or (self.args.faults and fault_stage < 3)
               or (last_restart_height is not None and height <= last_restart_height)):
            if self.args.faults and attempt >= 1 and fault_stage == 0:
                if partition_prepare_until is None:
                    partition_prepare_until = min(self.deadline, time.monotonic() + self.args.height_timeout)
                require(time.monotonic() < partition_prepare_until,
                        'four available slots were not restored before partition deadline')
                # A legal vacant slot already consumes the one-fault allowance.
                # Continue genuine measured workload until all four selected
                # slots are available, then remove one actual signer. Never
                # weaken this into cutting an already vacant slot.
                ready = self.observe(range(4))
                if self.partition_ready(ready):
                    old = ready[3]
                    kind = self.backend.cut(3)
                    partitioned = True
                    cut_at = time.monotonic()
                    self.isolated = (3, old, cut_at + self.args.partition_seconds)
                    self.report['faults'].append({'operation': kind, 'validator': 3, 'height': old['height'],
                                                 'active_slots_before_cut': 4})
            height = self.attempt(attempt, range(3) if partitioned else range(4))
            if partitioned:
                repair_started = time.monotonic()
                while self.isolated is not None:
                    self.service_fault()
                    require(time.monotonic() < self.deadline, 'overall deadline during outage')
                    time.sleep(.5)
                partitioned = False
                self.converge(range(4), height)
                self.report['faults'].append({'operation': 'healed_and_caught_up', 'validator': 3, 'height': height,
                                             'wait_and_catchup_seconds': round(time.monotonic() - repair_started, 3)})
                fault_stage = 1
            elif self.args.faults and fault_stage in (1, 2):
                live = self.observe(range(4))
                preferred = fault_stage - 1
                candidates = [preferred] + [i for i in range(4) if i != preferred]
                index = next((i for i in candidates if live[i]['consensus_position'] is not None), None)
                require(index is not None, 'no active signer available for restart fault')
                self.restart(index, force=fault_stage == 1)
                last_restart_height = height
                fault_stage += 1
            attempt += 1
        self.verify()
        if self.args.faults:
            require(last_restart_height is not None and height > last_restart_height,
                    'no finalized progress after final restart')
            self.report['post_restart_progress'] = {'restart_height': last_restart_height,
                                                    'verified_height': height}
        self.report['timing_seconds']['attempts'] = round(sum(a['elapsed_seconds'] for a in self.report['attempts']), 3)
        self.report['timing_seconds']['certified_voting_windows'] = sum(
            a['voting_deadline'] - a['certified_start'] for a in self.report['attempts'])
        # Observation and certified windows overlap the attempt phases. They
        # are attribution counters, not additive portions of elapsed time.
        self.report['timing_seconds']['attempt_phases'] = {
            phase: round(sum(a['phase_seconds'][phase] for a in self.report['attempts']), 3)
            for phase in ('submit', 'receipt', 'voting_open', 'settlement', 'converge', 'question')}
        phases = self.report['timing_seconds']['attempt_phases']
        self.report['timing_seconds']['consensus_and_delivery_before_voting_observed'] = round(
            phases['receipt'] + phases['voting_open'], 3)
        self.report['timing_seconds']['settlement_including_voting_wait'] = phases['settlement']
        self.report['timing_seconds']['fault_restarts'] = round(sum(
            fault.get('elapsed_seconds', 0) for fault in self.report['faults']), 3)
        for i in range(4):
            self.backend.stop(i)
        self.report['outcome'] = 'passed'
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--backend', choices=('docker', 'process'), default='docker')
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--image', default='naome-devnet:local')
    parser.add_argument('--subnet', default='172.30.88.0/24')
    parser.add_argument('--heights', type=int, default=100)
    parser.add_argument('--timing', choices=('short-test', 'ci-test'), default='short-test')
    parser.add_argument('--height-timeout', type=int, default=180)
    parser.add_argument('--deadline-seconds', type=int, default=2400)
    parser.add_argument('--delay-ms', type=int, default=50)
    parser.add_argument('--partition-seconds', type=int, default=30)
    parser.add_argument('--no-faults', dest='faults', action='store_false')
    args = parser.parse_args()
    args.bin_dir = args.bin_dir.resolve(strict=True)
    if not 4 <= args.heights <= 128 or (args.faults and args.heights < 12):
        parser.error('heights must be 4..128; faults require at least 12')
    if not 10 <= args.height_timeout <= 3600 or not 60 <= args.deadline_seconds <= 86400 or not 0 <= args.delay_ms <= 1000:
        parser.error('invalid duration or delay bounds')
    if not 1 <= args.partition_seconds < args.height_timeout:
        parser.error('invalid partition duration')
    os.umask(0o077)
    qualification = Qualification(args)
    def interrupted(*_):
        raise KeyboardInterrupt('qualification interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    code = 0
    try:
        qualification.run()
    except (Exception, KeyboardInterrupt) as error:
        code = 1
        qualification.report['outcome'] = 'failed'
        qualification.report['failure'] = str(error)[:300]
    finally:
        try:
            qualification.backend.cleanup()
        except Exception as error:
            code = 1
            qualification.report['outcome'] = 'failed'
            qualification.report['cleanup_failure'] = str(error)[:300]
        qualification.save()
    return code


if __name__ == '__main__':
    sys.exit(main())
