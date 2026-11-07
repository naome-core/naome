#!/usr/bin/env python3
"""Capture a bounded fresh-node finder arm without requiring a positive result.

Run the old and new ordinary binaries sequentially with identical arguments.
Wall time and resource profile are matched; adaptive budgets and discoveries
are recorded, so differences do not by themselves establish a learning effect.
"""
import argparse
import json
from pathlib import Path
import time
import traceback
from autonomous_lifecycle import Node, Trial, write_receipt
from native_learning import snapshot
from finder_cold_start import finder_state, source_identity
from proof_network import stored_objects


def run(trial, seconds, goal):
    node = Node(trial, 0)
    node.config['runtime']['jobs'] = {'native_proof_learning': True}
    node.config['discovery'] = {'mdns': False, 'dht': False, 'internet': False}
    node.write_config()
    node.start()
    initial = trial.wait(lambda: snapshot(node), maximum=10)
    assert not node.ids() and initial['learning']['accepted'] == 0
    assert initial['learning']['model']['updates'] == 0
    assert finder_state(node)['model']['updates'] == 0
    write_receipt(trial.output / 'initial.json', initial)
    node.stop()
    if goal:
        node.config['formal_goal'] = goal
    node.config['runtime']['question_interval_ms'] = 500
    node.write_config()
    node.start()
    records = {}
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        current = snapshot(node)
        if current:
            records.update(current['records'])
        assert len(records) <= 4096, 'bounded observer record capacity reached'
        assert not any(e.get('event') == 'fatal_error' for e in node.logs())
        time.sleep(0.25)
    trial.summary['measurement_seconds'] = time.monotonic() - started
    trial.summary['live_status'] = trial.call(node, 'status')
    node.stop()
    final = trial.wait(lambda: snapshot(node), maximum=5)
    records.update(final['records'])
    events = node.logs()
    objects = stored_objects(node)
    accepted = {o['artifact_id'] for o in objects}
    generated = {e['job']: e for e in events if e.get('event') == 'proof_generated' and e['id'] in accepted}
    solves = [r for r in records.values() if r['input']['role'] == 'solve']
    trial.summary.update({'accepted_resolutions': len(generated), 'catalog_artifacts': len(accepted),
        'solve_attempts': len(solves), 'distinct_attempted_questions': len({r['input']['question'] for r in solves}),
        'completed_attempts': sum(r['state'] == 'complete' for r in solves),
        'generated_questions': sum(r['input']['role'] == 'find' for r in records.values()),
        'support_events': [e for e in events if e.get('event') == 'finder_goal_supported'],
        'final_finder': finder_state(node), 'learning': final['learning'], 'formal_goal': goal})
    write_receipt(trial.output / 'records.json', {str(k): v for k,v in records.items()})
    write_receipt(trial.output / 'events.json', events)
    write_receipt(trial.output / 'accepted-artifacts.json', objects)
    answers = []
    proofs = trial.output / 'proofs'
    proofs.mkdir()
    for job, event in generated.items():
        record = records.get(job)
        progress = (record or {}).get('native', {}).get('progress') or {}
        result = progress.get('result')
        entry = {'job': job, 'artifact_id': event['id'], 'question': record['input']['question'] if record else None,
                 'observed_result_available': result is not None}
        if result:
            entry.update({'refuted': result['refuted'], 'proof_id': result['proof_id']})
            (proofs / f'job-{job}.nao').write_text(result['source'] + '\n')
            for i, helper in enumerate(result['helpers']):
                (proofs / f'job-{job}-helper-{i}.nao').write_text(helper + '\n')
        answers.append(entry)
    write_receipt(trial.output / 'answers.json', answers)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--goal', type=Path)
    parser.add_argument('--program-commit', help='Source commit associated with the supplied binary')
    args = parser.parse_args()
    assert 1 <= args.seconds <= 180
    trial = Trial(args.binary, args.output, args.seconds + 120, 'release', 'finder_quality')
    trial.summary.update({'fixture': 'fresh_node_finder_quality', 'node_count': 1, 'observer_source': source_identity(), 'program_commit': args.program_commit,
        'claim': 'Bounded ordinary-node observation; no novelty, calibrated utility or causal learning-gain claim.'})
    try:
        run(trial, args.seconds, args.goal.read_text() if args.goal else None)
        trial.summary['result'] = 'pass'
    except Exception:
        trial.summary.update({'result': 'fail', 'error': traceback.format_exc()})
    finally:
        trial.close()
        write_receipt(trial.output / 'summary.json', trial.summary)
    print(json.dumps({k:trial.summary.get(k) for k in ['result','measurement_seconds','accepted_resolutions','generated_questions','completed_attempts','error']}))
    return 0 if trial.summary['result'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
