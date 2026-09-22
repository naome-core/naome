"""Strict local inference boundary; no endpoint, credentials, or cloud fallback."""
from .schema import exact, integer
from .policy import SIGNALS, identity_calibration_v1


def request(settings, payload):
    # Keep context construction and offline replay independent of model packages.
    from . import runtime
    return runtime.request(settings, payload)


def decode(response, model):
    exact(response, ('model', 'answers', 'usage'), 'Kev response')
    if response['model'] != model:
        raise ValueError('Kev returned a different model or execution identity')
    exact(response['answers'], SIGNALS, 'Kev answers')
    probabilities = {}
    for name, answer in response['answers'].items():
        exact(answer, ('type', 'noul'), 'Kev Noul answer')
        if answer['type'] != 'noul':
            raise ValueError('unexpected Kev answer type')
        probabilities[name] = answer['noul']
    identity_calibration_v1(probabilities)
    exact(response['usage'], ('input_tokens', 'output_tokens'), 'Kev usage')
    for value in response['usage'].values():
        integer(value, 0, 2**63 - 1, 'token usage')
    return probabilities
