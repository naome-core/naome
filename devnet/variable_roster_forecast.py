#!/usr/bin/env python3
"""Summarize a profiled local roster run and explicit network-only scenarios.

The scenario is a sensitivity calculation, not a predicted 32-machine wall time.
It adds assumed serial one-way message waves and link serialization to measured
local resource demand; scheduling, independent host speed, and real network
behavior have not been measured here.
"""

import argparse
import json
from pathlib import Path
import statistics


STAGES = ('work_ready', 'prevote', 'precommit', 'agreement',
          'ready_quorum', 'terminal_quorum', 'finalized')
INTERVALS = tuple(zip(STAGES, STAGES[1:]))
INTERVALS += (('agreement', 'finalized'), ('work_ready', 'finalized'))


def spread(values):
    ordered = sorted(values)
    if not ordered:
        return None
    return {'count': len(ordered), 'min': round(ordered[0], 3),
            'median': round(statistics.median(ordered), 3),
            'p90': round(ordered[(9 * len(ordered) - 1) // 10], 3),
            'max': round(ordered[-1], 3)}


def summarize(report):
    profile = report.get('profile')
    if not isinstance(profile, dict) or not profile.get('nodes'):
        raise ValueError('report has no per-validator profile')
    nodes = profile['nodes']
    count = report['roster_size']
    if len(nodes) != count:
        raise ValueError('last profile does not cover every validator')
    cpu = []
    sent_bytes = []
    received_bytes = []
    request_starts = []
    requests_received = []
    response_starts = []
    responses_received = []
    queued_peaks = []
    flight_peaks = []
    finalization_tails = []
    intervals = {height: {f'{a}_to_{b}': [] for a, b in INTERVALS}
                 for height in range(1, report['target_height'] + 1)}
    rounds = []
    for node_id, node in nodes.items():
        if node['timing_events_dropped']:
            raise ValueError('validator timing ring overflowed')
        cpu.append(sum(node['cpu_millis_since_submission'].values()) / 1000)
        queued_peaks.append(node['peak_queued_deliveries'])
        flight_peaks.append(node['peak_in_flight_deliveries'])
        traffic = node['traffic_since_submission']
        request_starts.append(traffic['request_starts'])
        requests_received.append(traffic['requests_received'])
        response_starts.append(traffic['response_starts'])
        responses_received.append(traffic['responses_received'])
        sent_bytes.append(traffic['request_start_bytes'] + traffic['response_start_bytes'])
        received_bytes.append(traffic['request_bytes_received']
                              + traffic['response_bytes_received'])
        for height in intervals:
            events = [event for event in node['timing_events']
                      if event['height'] == height]
            positions = [event for event in events
                         if event['stage'] in ('proposal', 'prevote', 'precommit')]
            rounds.extend(event['round'] for event in positions
                          if event['round'] is not None)
            first = {}
            for event in events:
                first.setdefault(event['stage'], event['elapsed_millis'])
            if (height == report['target_height'] and 'agreement' in first
                    and 'finalized' in first):
                finalization_tails.append({
                    'validator': int(node_id),
                    'agreement_to_finalized_seconds': round(
                        (first['finalized'] - first['agreement']) / 1000, 3)})
            for a, b in INTERVALS:
                if a in first and b in first and first[b] >= first[a]:
                    intervals[height][f'{a}_to_{b}'].append(
                        (first[b] - first[a]) / 1000)
    return {
        'roster_size': count,
        'outcome': report['outcome'],
        'source_commit': report['source_commit'],
        'source_tree_clean': report['source_tree_clean'],
        'all_nodes_seconds': report.get('all_nodes_seconds'),
        'first_quorum_seconds': report.get('first_quorum_seconds'),
        'convergence_tail_seconds': (round(report['all_nodes_seconds']
                                           - report['first_quorum_seconds'], 3)
                                     if report.get('all_nodes_seconds') is not None
                                     and report.get('first_quorum_seconds') is not None else None),
        'host_logical_cpus': report.get('host_logical_cpus'),
        'one_way_proxy_delay_millis': report.get('one_way_proxy_delay_millis', 0),
        'validator_cpu_seconds': spread(cpu),
        'validator_canonical_egress_bytes': spread(sent_bytes),
        'validator_canonical_ingress_bytes': spread(received_bytes),
        'validator_request_starts': spread(request_starts),
        'validator_requests_received': spread(requests_received),
        'validator_response_starts': spread(response_starts),
        'validator_responses_received': spread(responses_received),
        'validator_peak_queued_deliveries': spread(queued_peaks),
        'validator_peak_in_flight_deliveries': spread(flight_peaks),
        'peak_total_queued_deliveries': profile['peak_total_queued_deliveries'],
        'peak_total_in_flight_deliveries': profile['peak_total_in_flight_deliveries'],
        'highest_observed_round': max(rounds, default=None),
        'slowest_finalizers': sorted(
            finalization_tails,
            key=lambda item: item['agreement_to_finalized_seconds'], reverse=True)[:5],
        'stage_intervals_seconds': {
            height: {name: spread(values) for name, values in stages.items()}
            for height, stages in intervals.items()},
    }


def scenarios(summary, heights, rtt_values, link_mbps):
    # Six transition classes are visible per height after work becomes ready.
    # An extra wave per class represents quorum and response/fanout uncertainty.
    # Neither count is an observed critical-path hop count.
    maximum_egress = summary['validator_canonical_egress_bytes']['max']
    return [
        {'assumed_rtt_millis': rtt,
         'assumed_link_mbps': bandwidth,
         'assumed_serial_one_way_waves': [6 * heights, 12 * heights],
         'propagation_seconds': [round(waves * rtt / 2000, 3)
                                 for waves in (6 * heights, 12 * heights)],
         'egress_serialization_seconds_for_started_envelopes':
             round(maximum_egress * 8 / (bandwidth * 1_000_000), 3)}
        for rtt in rtt_values for bandwidth in link_mbps
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--rtt-ms', type=int, nargs='+', default=[50, 100])
    parser.add_argument('--link-mbps', type=int, nargs='+', default=[100, 1000])
    args = parser.parse_args()
    if any(value <= 0 for value in (*args.rtt_ms, *args.link_mbps)):
        parser.error('RTT and link speed must be positive')
    report = json.loads(args.report.read_text())
    summary = summarize(report)
    summary['network_only_scenarios'] = scenarios(
        summary, report['target_height'], args.rtt_ms, args.link_mbps)
    summary['scenario_scope'] = (
        'Assumed propagation plus canonical-envelope egress serialization only; '
        'no 32-machine total wall-time prediction or real network measurement.')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
