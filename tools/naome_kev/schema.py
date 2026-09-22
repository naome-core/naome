"""Strict JSON and deterministic digests shared by the replaceable algorithms."""
import hashlib
import json


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def loads(data):
    def invalid(_):
        raise ValueError('non-finite JSON number')
    return json.loads(data, object_pairs_hook=_pairs, parse_constant=invalid)


def encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError('invalid ' + label + ' fields')


def integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('invalid ' + label)
    return value


def text(value, maximum, label):
    if not isinstance(value, str) or not value.strip() or len(value.encode()) > maximum:
        raise ValueError('invalid ' + label)
    return value
