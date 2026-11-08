"""Run one selected Cargo test target and reject empty test selections."""

import re
import subprocess
import sys


def run(command):
    result = subprocess.run(command, stdout=subprocess.PIPE)
    sys.stdout.buffer.write(result.stdout)
    if result.returncode:
        return result.returncode
    counts = re.findall(rb"^test result: ok\. ([0-9]+) passed;", result.stdout, re.MULTILINE)
    if len(counts) != 1 or int(counts[0]) == 0:
        print("Required selection must execute at least one test in exactly one target", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
