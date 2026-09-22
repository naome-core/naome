"""Pure local policy. Basis points are policy scores, not consensus weights.

There is no statistical independence assumption or probability-of-correctness
claim. Keep response decoding, future calibration, and decision policy separate.
"""
from decimal import Decimal, ROUND_HALF_UP
from .schema import exact, integer

VERSION = 'weighted-agenda-v1'
SIGNALS = ('relevance', 'value', 'fidelity', 'sufficient', 'excluded')
DEFAULT = {
    'version': VERSION,
    'weights': {'relevance': 7000, 'value': 3000},
    'yes_bps': 7500, 'no_bps': 2500,
    'minimum_context_bps': 8000, 'minimum_fidelity_bps': 8000,
    'exclusion_no_bps': 8000, 'exclusion_clear_bps': 2000,
}


def _validate_v1(policy):
    exact(policy, DEFAULT, 'policy')
    if policy['version'] != VERSION:
        raise ValueError('unsupported policy version')
    exact(policy['weights'], ('relevance', 'value'), 'weights')
    for name, value in policy['weights'].items():
        integer(value, 1, 9999, name + ' weight')
    if sum(policy['weights'].values()) != 10000:
        raise ValueError('policy weights must sum to 10000')
    for name in DEFAULT.keys() - {'version', 'weights'}:
        integer(policy[name], 0, 10000, name)
    if not 0 < policy['no_bps'] < 5000 < policy['yes_bps'] < 10000:
        raise ValueError('policy requires an uncertainty band around 5000')
    if not 0 <= policy['exclusion_clear_bps'] < 5000 < policy['exclusion_no_bps'] <= 10000:
        raise ValueError('policy requires an exclusion uncertainty band')
    if min(policy['minimum_context_bps'], policy['minimum_fidelity_bps']) <= 5000:
        raise ValueError('context gates must exceed 5000')
    return policy


def identity_calibration_v1(probabilities):
    """Single conversion boundary; replace/version after held-out calibration.

    Nearest basis point, decimal half-up, so replay never depends on binary
    floating-point arithmetic in the weighted policy.
    """
    exact(probabilities, SIGNALS, 'probabilities')
    result = {}
    for name, value in probabilities.items():
        if type(value) not in (int, float, Decimal):
            raise ValueError('invalid probability type')
        number = Decimal(str(value))
        if not number.is_finite() or not 0 <= number <= 1:
            raise ValueError('probability outside [0,1]')
        result[name] = int((number * 10000).quantize(Decimal('1'), rounding=ROUND_HALF_UP))
    return result


def _decide_v1(probabilities, policy):
    _validate_v1(policy)
    points = identity_calibration_v1(probabilities)
    score = (sum(points[k] * w for k, w in policy['weights'].items()) + 5000) // 10000
    # Missing interpretability takes precedence over every automatic ballot.
    if points['sufficient'] < policy['minimum_context_bps']:
        decision, route = 'REVIEW', 'insufficient_context'
    elif points['fidelity'] < policy['minimum_fidelity_bps']:
        decision, route = 'REVIEW', 'uncertain_purpose_alignment'
    elif points['excluded'] >= policy['exclusion_no_bps']:
        decision, route = 'NO', 'explicit_exclusion'
    elif points['excluded'] > policy['exclusion_clear_bps']:
        decision, route = 'REVIEW', 'uncertain_exclusion'
    elif score >= policy['yes_bps']:
        decision, route = 'YES', 'weighted_support'
    elif score <= policy['no_bps']:
        decision, route = 'NO', 'weighted_opposition'
    else:
        decision, route = 'REVIEW', 'score_uncertainty_band'
    return {'decision': decision, 'route': route, 'score_bps': score,
            'signals_bps': points, 'calibration_version': 'identity-bps-v1'}


# Explicit dispatch keeps historical policies reproducible after new algorithms
# are added. No dynamic imports, executable expressions, or plugin discovery.
POLICIES = {VERSION: (_validate_v1, _decide_v1)}


def validate(policy):
    if not isinstance(policy, dict) or policy.get('version') not in POLICIES:
        raise ValueError('unsupported policy version')
    return POLICIES[policy['version']][0](policy)


def decide(probabilities, policy):
    validate(policy)
    return POLICIES[policy['version']][1](probabilities, policy)
