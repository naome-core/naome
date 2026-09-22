#!/usr/bin/env python3
"""Exercise the actual local Kev provider through a fresh four-validator MVP.

Uses real LAB timing, private temporary keys and immutable copies of supplied
binaries. It tests review/reuse/signing and archive replay, not a complete proof
lifecycle or separate-machine operation. Model judgments are recorded unchanged;
YES, NO and unsigned REVIEW can all be valid integration outcomes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from naome_kev import config, runtime

REPO = Path(__file__).resolve().parents[1]
PROVIDER = REPO / 'tools/agenda_agent_kev.py'
QUESTION = REPO / 'examples/state-workflow/question-a.nao'
PROFILES = ('Reusable equality lemmas are a priority.',
            'Research only graph connectivity; explicitly exclude pure equality reflexivity.')
MATCHING_PROFILE = (
    'Build a verified library of elementary equality laws. Highest priority: universally '
    'quantified reflexivity, stating that every object equals itself, including versions '
    'with an unused universal variable. Such basic lemmas are useful as starting points '
    'for later derivations. Novelty and difficulty are not required. No areas are excluded.')
PURPOSE = ('Resolve universally quantified equality reflexivity: for every y and every x, '
           'x equals itself. The extra universal y does not change the self-equality claim.')
AGREEMENT = ('genesis', 'profile', 'height', 'head', 'state', 'accounts', 'reserve_atoms',
             'claims', 'library_root', 'paid_completions', 'active')


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def free_ports():
    for _ in range(1000):
        base = 20000 + int.from_bytes(os.urandom(2), 'big') % 40000
        held = []
        try:
            for index in range(4):
                listener = socket.socket()
                held.append(listener)
                listener.bind(('127.0.0.1', base + index))
            return base
        except OSError:
            pass
        finally:
            for listener in held:
                listener.close()
    raise RuntimeError('cannot find four available local TCP ports')


class Smoke:
    def __init__(self, args):
        self.args = args
        self.profiles = ((MATCHING_PROFILE, PROFILES[1])
                         if args.scenario == 'require-yes' else PROFILES)
        self.root = Path(tempfile.mkdtemp(prefix='nkev-', dir='/tmp'))
        os.chmod(self.root, 0o700)
        self.nodes = {}
        self.binaries = {}
        self.started = time.monotonic()
        self.report = {
            'version': 1, 'result': 'running',
            'scenario': args.scenario,
            'qualification': 'four local validator processes and actual local Kev; not separate-machine evidence',
            'scope': 'agenda review, retained vote reuse, and finalized history replay; full LAB lifecycle not run',
            'timing': {'profile': 'lab', 'voting_seconds': 300,
                       'commitment_seconds': 120, 'reveal_seconds': 120},
            'run_records': 128, 'compact': True,
            'host': {'system': platform.system(), 'release': platform.release(),
                     'machine': platform.machine()},
            'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'runner_sha256': digest(__file__), 'provider_sha256': digest(PROVIDER),
            'provider_sources': {str(path.relative_to(REPO)): digest(path)
                                 for path in sorted((REPO / 'tools/naome_kev').glob('*.py'))},
            'commands': [], 'reviews': [], 'checks': {}, 'shutdown': [],
        }
        self.save()
        print(json.dumps({'event': 'private_run_created', 'directory': str(self.root)}), flush=True)

    def save(self):
        path = self.root / 'smoke-report.next'
        path.write_text(json.dumps(self.report, indent=2, allow_nan=False) + '\n')
        path.replace(self.root / 'smoke-report.json')

    def public(self, value):
        return str(value).replace(str(self.root), '$RUN').replace(str(REPO), '$REPO')

    def node_config(self, index):
        return self.root / 'network' / f'node-{index}' / 'node.json'

    def key(self, index):
        return self.root / 'network' / 'accounts' / f'account-{index}.key'

    def command(self, name, *args, timeout=30, tolerate=False, record=True):
        argv = [str(self.binaries[name]), *map(str, args)]
        started = time.monotonic()
        result = None
        timed_out = False
        try:
            result = subprocess.run(argv, capture_output=True, timeout=timeout, cwd=REPO)
        except subprocess.TimeoutExpired as error:
            timed_out = True
            (self.root / 'last-command.stderr').write_bytes(error.stderr or b'')
            (self.root / 'last-command.stdout').write_bytes(error.stdout or b'')
        finally:
            if record:
                self.report['commands'].append({
                    'argv': [self.public(arg) for arg in argv],
                    'elapsed_seconds': round(time.monotonic() - started, 3),
                    'exit_code': None if result is None else result.returncode,
                    'timed_out': timed_out,
                })
                self.save()
        if timed_out or result.returncode:
            if result is not None:
                (self.root / 'last-command.stderr').write_bytes(result.stderr)
                (self.root / 'last-command.stdout').write_bytes(result.stdout)
            if tolerate:
                return None
            raise RuntimeError('CLI command failed: ' + str(args[0]) + '; private diagnostics retained')
        return json.loads(result.stdout)

    def status(self, index):
        return self.command('naome', 'status', self.node_config(index), timeout=5,
                            tolerate=True, record=False)

    def wait(self, predicate, label, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for index, process in self.nodes.items():
                require(process.poll() is None, f'validator {index} exited before {label}')
            value = predicate()
            if value:
                return value
            time.sleep(0.25)
        raise RuntimeError('timeout waiting for ' + label)

    def receipt(self, index, operation):
        def query():
            receipt = self.command('naome', 'receipt', self.node_config(index), operation,
                                   record=False)
            require(receipt['status'] != 'rejected', 'operation was rejected')
            return receipt if receipt['status'] == 'finalized' else None
        return self.wait(query, 'finalized operation receipt')

    def runtime_state(self):
        value = runtime.status(self.settings)
        return {key: value[key] for key in ('model', 'fingerprint', 'pid', 'calls')}

    def retained_request_hashes(self, index):
        signer = Path(json.loads(self.node_config(index).read_text())['signer'])
        return {path.name: digest(path) for path in sorted(signer.glob('agent-*.request.json'))}

    def review(self, index):
        report_path = self.root / f'kev-review-{index}.json'
        action_path = self.root / f'kev-vote-{index}.bin'
        before = self.runtime_state()
        value = self.command('naome', 'agent-review', self.node_config(index), self.key(index),
                             report_path, PROVIDER, '--provider-config', self.args.config,
                             timeout=135)
        after_review = self.runtime_state()
        require(value['vote_signed'] is False and value['submission'] is None,
                'agent-review unexpectedly signed or submitted a vote')
        require(not action_path.exists(), 'review created an action file')
        review = value['agent_review']
        require(review == json.loads(report_path.read_text()), 'saved review differs from CLI output')
        decision = review['decision']['decision']
        require(decision in ('YES', 'NO', 'REVIEW'), 'invalid actual Kev decision')
        report_hash = digest(report_path)
        requests = self.retained_request_hashes(index)
        require(review['request_sha256'] in requests.values(), 'retained request digest mismatch')
        signer = Path(json.loads(self.node_config(index).read_text())['signer'])
        request_path = next(signer / name for name, sha in requests.items()
                            if sha == review['request_sha256'])
        request = json.loads(request_path.read_text())
        author = request['author']
        require(review['decision']['assessment']['input_sha256'] == review['request_sha256'],
                'assessment does not bind retained request')
        require(after_review['pid'] == before['pid'] and after_review['calls'] > before['calls'],
                'actual model invocation was not observed on the loaded worker')
        row = {'node': index, 'profile': self.profiles[index], 'author': author,
               'attempt': request['attempt'], 'review': review,
               'review_report_sha256': report_hash, 'request_files': requests,
               'runtime_before_review': before, 'runtime_after_review': after_review,
               'review_was_unsigned': True, 'vote_reuse': 'pending'}
        self.report['reviews'].append(row)
        self.save()
        voted = self.command('naome', 'agent-vote', self.node_config(index), self.key(index),
                             action_path, report_path, PROVIDER, '--provider-config', self.args.config,
                             timeout=135)
        after_vote = self.runtime_state()
        reused = dict(voted['agent_review'])
        reused.pop('operation', None)
        require(reused == review, 'vote did not reuse the exact retained assessment')
        require(after_vote == after_review, 'retained vote unexpectedly invoked or replaced the model')
        require(digest(report_path) == report_hash, 'retained vote changed saved review')
        require(self.retained_request_hashes(index) == requests, 'retained vote reserved another inference')
        row.update(runtime_after_vote=after_vote, vote_reuse='passed', additional_inference=False,
                   retained_report_unchanged=True, retained_requests_unchanged=True)
        if decision == 'REVIEW':
            require(voted['vote_signed'] is False and voted['submission'] is None,
                    'REVIEW unexpectedly authorized a ballot')
            require(not action_path.exists(), 'REVIEW created an action file')
            row.update(vote_signed=False, action_created=False, finalized_receipt=None)
        else:
            require(action_path.is_file(), 'definitive retained decision did not create its ballot')
            operation = voted['agent_review']['operation']
            row.update(vote_signed=True, action_created=True, action_sha256=digest(action_path),
                       operation=operation, finalized_receipt=self.receipt(index, operation))
        self.save()
        print(json.dumps({'event': 'kev_review_reused', 'node': index, 'decision': decision,
                          'vote_signed': row['vote_signed'], 'additional_inference': False}), flush=True)

    def execute(self):
        self.settings = config.load(self.args.config)
        self.report['configuration_sha256'] = digest(self.args.config)
        # Load before reserving an on-chain voting window or inference attempt.
        self.report['runtime_before'] = runtime.status(self.settings)
        self.report['model'] = self.settings['model']
        bindir = self.root / 'bin'
        bindir.mkdir(mode=0o700)
        self.report['executables'] = {}
        for name, source in (('naome', self.args.binary), ('naome-validator', self.args.validator),
                             ('naome-verifier', self.args.verifier)):
            source = source.resolve(strict=True)
            original_hash = digest(source)
            target = bindir / name
            shutil.copyfile(source, target)
            os.chmod(target, 0o500)
            require(digest(target) == original_hash == digest(source), 'binary changed while being copied')
            self.binaries[name] = target
            self.report['executables'][name] = {'source': self.public(source), 'sha256': original_hash}
        configured = self.command('naome', 'setup', self.root / 'network', 'lab', '128', free_ports(), 'compact')
        self.report.update(genesis=configured['genesis'], profile=configured['profile'],
                           required_storage_bytes=configured['required_storage_bytes'])
        genesis = self.root / 'network/genesis.bin'
        immutable = self.command('naome', 'profile-info', genesis)
        self.report['immutable_profile'] = immutable
        node_settings = [json.loads(self.node_config(index).read_text()) for index in range(4)]
        for field in ('history', 'history_anchor', 'signer', 'signer_anchor', 'consensus_key',
                      'transport_key', 'control_socket'):
            require(len({value[field] for value in node_settings}) == 4, 'nodes share custody path: ' + field)
        self.report['checks']['separate_node_custody'] = True
        for index, text in enumerate(self.profiles):
            path = self.root / f'agenda-{index}.txt'
            path.write_text(text + '\n')
            self.command('naome', 'profile', self.node_config(index), path)
        require(self.command('naome', 'profile-info', genesis) == immutable,
                'agenda edit changed immutable genesis profile')
        self.report['checks']['immutable_profile_unchanged'] = True
        self.report['question'] = {'source': QUESTION.read_text(), 'source_sha256': digest(QUESTION),
                                   'purpose': PURPOSE,
                                   'compiled': self.command('naome', 'compile-question', genesis, QUESTION)}
        for index in range(4):
            argv = [str(self.binaries['naome-validator']), 'start', str(self.node_config(index))]
            with (self.root / f'node-{index}.stdout').open('wb') as out, \
                    (self.root / f'node-{index}.stderr').open('wb') as err:
                self.nodes[index] = subprocess.Popen(argv, stdout=out, stderr=err)
            self.report['commands'].append({'argv': [self.public(v) for v in argv],
                                            'pid': self.nodes[index].pid, 'exit_code': None})
        self.save()
        for index in range(4):
            self.wait(lambda index=index: self.status(index), f'validator {index} startup')
        submitted = self.command('naome', 'submit', self.node_config(0), self.key(4), QUESTION,
                                 PURPOSE, self.root / 'question-a-submit.bin')
        self.report['submission'] = {'operation': submitted['operation'],
                                     'receipt': self.receipt(0, submitted['operation'])}
        for index in (0, 1):
            def voting(index=index):
                value = self.status(index)
                return value if value and (value.get('active') or {}).get('phase') == 'Voting' else None
            self.wait(voting, f'validator {index} Voting phase')
            self.review(index)
        def agreed():
            statuses = [self.status(index) for index in range(4)]
            if any(value is None for value in statuses):
                return None
            return statuses if all(all(value[field] == statuses[0][field] for field in AGREEMENT)
                                   for value in statuses) else None
        statuses = self.wait(agreed, 'four identical finalized histories')
        expected = {field: statuses[0][field] for field in AGREEMENT}
        self.report['finalized_agreement'] = expected
        for row in self.report['reviews']:
            decision = row['review']['decision']['decision']
            for status in statuses:
                active = status.get('active') or {}
                require(active.get('question') == row['review']['question_id'],
                        'finalized ballot belongs to a different question')
                require(active.get('attempt') == row['attempt'],
                        'finalized ballot belongs to a different attempt')
                ballots = [vote for vote in active.get('votes', [])
                           if vote['owner'] == row['author']]
                wanted = [] if decision == 'REVIEW' else [
                    {'owner': row['author'], 'yes': decision == 'YES'}]
                require(ballots == wanted, 'finalized ballot differs from actual Kev decision')
            row['ballot_verified_on_all_four_nodes'] = True
            if row['vote_signed']:
                receipts = [self.receipt(index, row['operation']) for index in range(4)]
                require(all(receipt == row['finalized_receipt'] for receipt in receipts),
                        'validators disagree on ballot receipt')
                row['four_finalized_receipts'] = receipts
        self.report['archives'] = []
        for index in range(4):
            archive = self.root / f'export-node-{index}'
            exported = self.command('naome', 'export', self.node_config(index), archive, timeout=90)
            verified = self.command('naome-verifier', 'verify', genesis, archive, timeout=90)
            require(all(verified[field] == expected[field] for field in AGREEMENT),
                    'independent archive replay differs from agreed finalized history')
            self.report['archives'].append({'node': index, 'export_status': exported['status'],
                                            'manifest_sha256': digest(archive / 'manifest.json'),
                                            'verified': {field: verified[field] for field in AGREEMENT}})
            self.save()
        self.report['checks']['four_archives_replayed_to_identical_head'] = True
        self.report['checks']['actual_model_ballots_verified_in_all_four_replays'] = True
        yes_count = sum(row['review']['decision']['decision'] == 'YES'
                        and row['vote_signed'] for row in self.report['reviews'])
        self.report['checks']['finalized_yes_ballots'] = yes_count
        if self.args.scenario == 'require-yes':
            require(yes_count > 0, 'actual Kev did not produce a finalized YES in this scenario')
        self.report['runtime_after'] = runtime.status(self.settings)
        self.report['result'] = 'passed'

    def cleanup(self):
        for index, process in self.nodes.items():
            graceful = False
            if process.poll() is None:
                try:
                    graceful = self.command('naome', 'shutdown', self.node_config(index),
                                            timeout=10, tolerate=True) is not None
                except Exception:
                    pass
            forced = False
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                forced = True
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            self.report['shutdown'].append({'node': index, 'graceful_request': graceful,
                                            'forced': forced, 'exit_code': process.returncode})
        self.nodes.clear()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--validator', type=Path, required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--scenario', choices=('baseline', 'require-yes'), default='baseline',
                        help='require-yes uses an explicit equality-library priority and requires a real YES')
    args = parser.parse_args()
    args.config = args.config.resolve(strict=True)
    os.umask(0o077)
    smoke = Smoke(args)
    try:
        smoke.execute()
    except KeyboardInterrupt:
        smoke.report['result'] = 'interrupted'
    except Exception as error:
        smoke.report['result'] = 'failed'
        # Harness errors contain labels, never captured model or key diagnostics.
        smoke.report['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        smoke.cleanup()
        if any(row['forced'] or row['exit_code'] != 0 for row in smoke.report['shutdown']):
            smoke.report['result'] = 'failed'
        smoke.report['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        smoke.report['elapsed_seconds'] = round(time.monotonic() - smoke.started, 3)
        smoke.save()
    print(json.dumps({'result': smoke.report['result'], 'report': str(smoke.root / 'smoke-report.json'),
                      'private_run': str(smoke.root)}), flush=True)
    return 0 if smoke.report['result'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
