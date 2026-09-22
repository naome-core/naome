"""Orchestration boundary; pure context/policy can be tested without loading a model."""
import hashlib
from . import client, config, context, policy
from .schema import loads, digest


def evaluate(raw, transport=client.request):
    if len(raw) > 65536:
        raise ValueError('agent request exceeds input limit')
    request = loads(raw)
    settings = config.validate(request['provider_config'])
    payload = context.build(request, settings)
    response = transport(settings, payload)
    probabilities = client.decode(response, settings['model'])
    result = policy.decide(probabilities, settings['policy'])
    return {
        'version': 2, 'decision': result['decision'], 'provider': 'local-kev', 'tool_calls': 0,
        'assessment': {
            'version': 1, 'model': response['model'],
            'context_version': settings['context_version'], 'policy_version': settings['policy']['version'],
            'input_sha256': hashlib.sha256(raw).hexdigest(),
            'context_sha256': digest(payload['state']), 'evaluation_sha256': digest(payload),
            'policy_sha256': digest(settings['policy']),
            'response_sha256': digest(response),
            # Decimal JSON strings survive Rust JSON persistence without float rounding.
            'probability_encoding': 'decimal-json-v1',
            'probabilities': {k: str(v) for k, v in probabilities.items()},
            'usage': response['usage'], **{k: v for k, v in result.items() if k != 'decision'},
        },
    }


def replay(report, settings):
    """Compare a saved assessment to a new local policy; never signs or runs inference.

    Does not claim to authenticate user-supplied reports. Changing model or
    context requires a new evaluation dataset, not a relabelled old response.
    """
    config.validate(settings)
    original = report['decision']
    assessment = original['assessment']
    if (original['version'] != 2 or assessment['version'] != 1
            or assessment['model'] != settings['model']
            or assessment['context_version'] != settings['context_version']
            or assessment['probability_encoding'] != 'decimal-json-v1'):
        raise ValueError('replay requires the original model and context versions')
    response = {'model': assessment['model'], 'usage': assessment['usage'],
                'answers': {k: {'type': 'noul', 'noul': loads(v)} for k, v in assessment['probabilities'].items() if isinstance(v, str)}}
    probabilities = client.decode(response, settings['model'])
    if digest(response) != assessment['response_sha256']:
        raise ValueError('saved response digest mismatch')
    return {'kind': 'offline_policy_comparison', 'original_decision': original['decision'],
            'original_policy_sha256': assessment['policy_sha256'],
            'policy_sha256': digest(settings['policy']), 'vote_signed': False,
            'result': policy.decide(probabilities, settings['policy'])}
