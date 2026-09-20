#!/usr/bin/env python3
"""Own one validator and a bounded TCP delay proxy, without consensus authority."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from proxy import Proxy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--validator', required=True)
    parser.add_argument('--front', required=True)
    parser.add_argument('--back', required=True)
    parser.add_argument('--delay-ms', type=int, required=True)
    args = parser.parse_args()
    proxy = Proxy(args.front, args.back, args.delay_ms)
    child = None
    def stop(*_):
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGINT)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        child = subprocess.Popen([args.validator, 'start', str(args.config)], stdin=subprocess.DEVNULL)
        (args.config.parent / 'runtime-pid.json').write_text(json.dumps({'wrapper': os.getpid(), 'validator': child.pid}))
        return child.wait()
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        proxy.close()


if __name__ == '__main__':
    sys.exit(main())
