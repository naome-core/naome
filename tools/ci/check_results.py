"""Fail a CI fan-in unless every expected dependency explicitly succeeded."""

import json
import os
import sys


def require_success(needs, expected):
    if not expected or not isinstance(needs, dict):
        raise ValueError("Expected a nonempty dependency set")
    unexpected = set(needs) - set(expected)
    if unexpected:
        raise ValueError("Unexpected CI dependencies: " + ", ".join(sorted(unexpected)))
    failures = []
    for name in expected:
        result = needs.get(name, {}).get("result")
        if result != "success":
            failures.append(f"{name}: {result or 'missing'}")
    if failures:
        raise ValueError("Required CI dependencies did not succeed: " + ", ".join(failures))


if __name__ == "__main__":
    try:
        require_success(json.loads(os.environ["NEEDS"]), sys.argv[1:])
    except (KeyError, ValueError, TypeError) as error:
        raise SystemExit(str(error)) from error
    print("All required CI dependencies succeeded.")
