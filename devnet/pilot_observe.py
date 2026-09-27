#!/usr/bin/env python3
"""Record operator-side TCP, finalized status and receipt evidence for a pilot.

Reports are assertions from the machine running this tool, not host attestation.
Only the local Unix control socket is used for node queries. No key is read or
transmitted by this tool, and a TCP connection does not authenticate a peer.
"""
import argparse
import json
from pathlib import Path
import platform
import socket
import sys
import time

import pilot


LIVE_AGREEMENT = tuple(field for field in pilot.AGREEMENT if field != 'consensus_commitment')


def identity(bundle, native):
    checked = pilot.check(bundle, native)
    manifest = pilot.read(bundle / 'pilot.json')
    return checked, manifest


def evidence(kind, checked, manifest, label):
    pilot.require(label.strip() == label and bool(label), 'nonempty host label required')
    return {'version': 1, 'kind': kind, 'node_index': checked['node_index'],
            'genesis': checked['genesis'], 'profile': checked['profile'],
            'host_label': label, 'host_identity': 'operator supplied; not attested',
            'host': {'system': platform.system(), 'machine': platform.machine()},
            'collected_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'provisioning_source': manifest['source'],
            'observer_sha256': pilot.digest(Path(__file__)),
            'binary_sha256': checked['binary_sha256']}


def address(value):
    # The plan contains canonical literal IP:port endpoints validated by setup.
    # getaddrinfo parses IPv6 brackets without accepting DNS or wildcard binds.
    if value.startswith('['):
        host, separator, port = value[1:].partition(']:')
    else:
        host, separator, port = value.rpartition(':')
    pilot.require(separator and host and port.isdecimal(), 'invalid endpoint in pilot plan')
    try:
        socket.inet_pton(socket.AF_INET, host)
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
        except OSError as error:
            raise RuntimeError('pilot endpoint must be a literal IP address') from error
    number = int(port)
    pilot.require(0 < number <= 65535, 'invalid endpoint port')
    return host, number


def probe(args):
    native = pilot.binaries(args.bin_dir)
    checked, manifest = identity(args.bundle, native)
    config = pilot.read(args.bundle / 'node.json')
    recovery = config['recovery_endpoints']
    pilot.require(isinstance(recovery, list) and len(recovery) == 8
                  and recovery[:4] == manifest['endpoints']
                  and config['primary_endpoint'] == recovery[checked['node_index']]
                  and config['handoff_endpoint'] == recovery[4 + checked['node_index']],
                  'primary and handoff endpoint plan differs from node configuration')
    endpoints = recovery[:4] if args.channel == 'primary' else recovery[4:]
    pilot.require(isinstance(endpoints, list) and len(endpoints) == 4,
                  'four pilot endpoints required')
    result = evidence('directed_tcp_probe', checked, manifest, args.host_label)
    result['channel'] = args.channel
    result['targets'] = []
    for index, endpoint in enumerate(endpoints):
        if index == checked['node_index']:
            continue
        host, port = address(endpoint)
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=args.timeout):
                reachable = True
                error = None
        except OSError as failure:
            reachable = False
            error = type(failure).__name__
        result['targets'].append({'node_index': index, 'endpoint': endpoint,
                                  'tcp_connected': reachable, 'error_type': error,
                                  'elapsed_seconds': round(time.monotonic() - started, 3)})
    result['all_connected'] = all(target['tcp_connected'] for target in result['targets'])
    result['boundary'] = 'TCP reachability only; no remote authentication, validator identity or consensus proof.'
    pilot.write(args.report, result)
    return result


def observe(args):
    native = pilot.binaries(args.bin_dir)
    checked, manifest = identity(args.bundle, native)
    pilot.require(args.stage.strip() == args.stage and bool(args.stage),
                  'nonempty observation stage required')
    status = pilot.run(native['naome'], 'status', args.bundle / 'node.json')
    pilot.require(status.get('status') == 'finalized'
                  and status.get('genesis') == checked['genesis']
                  and status.get('profile') == checked['profile']
                  and all(field in status for field in LIVE_AGREEMENT),
                  'live status is incomplete or from another pilot')
    result = evidence('live_observation', checked, manifest, args.host_label)
    result['stage'] = args.stage
    result['status'] = status
    result['receipts'] = {}
    for operation in args.operation:
        pilot.require(len(operation) == 64 and all(c in '0123456789abcdef' for c in operation),
                      'operation ID must be 64 lowercase hex digits')
        pilot.require(operation not in result['receipts'], 'duplicate operation ID')
        receipt = pilot.run(native['naome'], 'receipt', args.bundle / 'node.json', operation)
        result['receipts'][operation] = receipt
    result['boundary'] = 'Local control-socket observation; a finalized receipt is distinct from transport acceptance.'
    pilot.write(args.report, result)
    return {'kind': result['kind'], 'node_index': checked['node_index'],
            'height': status['height'], 'head': status['head'], 'state': status['state'],
            'receipt_statuses': {key: value.get('status') for key, value in result['receipts'].items()},
            'report': str(args.report)}


def compare(args):
    reports = [pilot.read(path) for path in args.observations]
    pilot.require(sorted(r.get('node_index') for r in reports) == [0, 1, 2, 3]
                  and all(r.get('version') == 1 and r.get('kind') == 'live_observation' for r in reports),
                  'one live observation from each of four nodes required')
    pilot.require(len({r['stage'] for r in reports}) == 1, 'observation stages differ')
    pilot.require(len({r['observer_sha256'] for r in reports}) == 1,
                  'observation tool versions differ')
    pilot.require(all(r['provisioning_source'] == reports[0]['provisioning_source'] for r in reports),
                  'observation provisioning sources differ')
    reference = {key: reports[0]['status'].get(key) for key in LIVE_AGREEMENT}
    pilot.require(type(reference['height']) is int and reference['height'] > 0,
                  'common finalized height above genesis required')
    pilot.require(all({key: r['status'].get(key) for key in LIVE_AGREEMENT} == reference
                      for r in reports), 'live finalized heads or state differ')
    pilot.require(all(r['status'].get('genesis') == r['genesis']
                      and r['status'].get('profile') == r['profile'] for r in reports),
                  'observation manifest differs from live status')
    pilot.require(all(r['receipts'] == reports[0]['receipts'] for r in reports),
                  'receipt responses differ across nodes')
    pilot.require(all(value.get('status') == 'finalized'
                      for value in reports[0]['receipts'].values()),
                  'one or more requested receipts are not finalized')
    result = {'version': 1, 'outcome': 'four_live_statuses_agree',
              'stage': reports[0]['stage'], 'agreed': reference,
              'receipts': reports[0]['receipts'],
              'observer_sha256': reports[0]['observer_sha256'],
              'provisioning_source': reports[0]['provisioning_source'],
              'host_labels': [r['host_label'] for r in reports],
              'boundary': 'Host labels are operator assertions. This report alone does not prove separate-machine placement or archive replay.'}
    pilot.write(args.report, result)
    return {'outcome': result['outcome'], 'height': reference['height'], 'report': str(args.report)}


def compare_probes(args):
    reports = [pilot.read(path) for path in args.probes]
    pilot.require(sorted(r.get('node_index') for r in reports) == [0, 1, 2, 3]
                  and all(r.get('version') == 1 and r.get('kind') == 'directed_tcp_probe' for r in reports),
                  'one TCP probe report from each of four nodes required')
    pilot.require(len({(r['genesis'], r['profile']) for r in reports}) == 1,
                  'TCP probe reports are from different runs')
    pilot.require(len({r['observer_sha256'] for r in reports}) == 1,
                  'TCP probe tool versions differ')
    pilot.require(all(r['provisioning_source'] == reports[0]['provisioning_source'] for r in reports),
                  'TCP probe provisioning sources differ')
    pilot.require(len({r.get('channel') for r in reports}) == 1,
                  'TCP probe reports use different endpoint periods')
    endpoint_by_index = {}
    for report in reports:
        source = report['node_index']
        targets = report['targets']
        pilot.require(sorted(t.get('node_index') for t in targets) ==
                      [index for index in range(4) if index != source],
                      'directed probe graph is incomplete')
        for target in targets:
            index = target['node_index']
            pilot.require(target.get('tcp_connected') is True, 'one or more directed TCP probes failed')
            endpoint_by_index.setdefault(index, target['endpoint'])
            pilot.require(endpoint_by_index[index] == target['endpoint'],
                          'target endpoint differs across probe reports')
    result = {'version': 1, 'outcome': 'twelve_directed_tcp_connections_recorded',
              'genesis': reports[0]['genesis'], 'profile': reports[0]['profile'],
              'channel': reports[0]['channel'],
              'observer_sha256': reports[0]['observer_sha256'],
              'provisioning_source': reports[0]['provisioning_source'],
              'host_labels': [r['host_label'] for r in reports],
              'boundary': 'TCP only; host labels are untrusted assertions and do not establish physical placement or peer authentication.'}
    pilot.write(args.report, result)
    return {'outcome': result['outcome'], 'report': str(args.report)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('probe')
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--host-label', required=True)
    p.add_argument('--timeout', type=float, default=3)
    p.add_argument('--channel', choices=('primary', 'handoff'), default='primary')
    p.add_argument('--report', type=Path, required=True)
    p = sub.add_parser('observe')
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--host-label', required=True)
    p.add_argument('--stage', required=True)
    p.add_argument('--operation', action='append', default=[])
    p.add_argument('--report', type=Path, required=True)
    p = sub.add_parser('compare')
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('observations', nargs=4, type=Path)
    p = sub.add_parser('compare-probes')
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('probes', nargs=4, type=Path)
    args = parser.parse_args()
    if args.command == 'probe':
        pilot.require(0 < args.timeout <= 30, 'timeout must be 0 to 30 seconds')
        result = probe(args)
    elif args.command == 'observe':
        result = observe(args)
    elif args.command == 'compare-probes':
        result = compare_probes(args)
    else:
        result = compare(args)
    print(json.dumps(result, indent=2))
    if args.command == 'probe' and not result['all_connected']:
        sys.exit(2)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print(f'pilot observation: {error}', file=sys.stderr)
        sys.exit(1)
