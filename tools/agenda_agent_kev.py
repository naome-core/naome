#!/usr/bin/env python3
"""Install and manage the local KEV agenda provider.

setup [DIRECTORY]: install or resume; does not load the model.
start [DIRECTORY|CONFIG]: load the model before voting (up to three minutes).
status [DIRECTORY|CONFIG]: inspect without loading anything.
stop [DIRECTORY|CONFIG]: cancel loading or stop the model and release memory.
check: alias for start, retained for existing commands.
replay REPORT CONFIG: compare a saved assessment with another local policy.
With no arguments, process one bounded provider request on stdin.
"""
import argparse
from pathlib import Path
import shlex
import signal
import sys
from naome_kev import config, engine
from naome_kev.schema import loads, encode

DEFAULT_ROOT = Path(__file__).resolve().parents[1] / '.local/kev'


def locations(value, control=False):
    target = Path(value).absolute()
    explicit_config = not target.is_dir() and (target.suffix == '.json' or target.is_file())
    settings_path = target if explicit_config else target / 'kev.json'
    root = settings_path.parent
    if control and not explicit_config:
        return root, settings_path
    if settings_path.exists():
        # Stop/status must work even if the model identity in a configuration is
        # stale. Directory ownership is checked by the runtime before any IPC.
        data = (config.load(settings_path) if control else
                loads(config.read_private(settings_path, 8192)))
        if isinstance(data, dict) and isinstance(data.get('runtime_dir'), str):
            root = Path(data['runtime_dir'])
    return root, settings_path


def next_command(command, root):
    return 'python3 ' + shlex.quote(str(Path(__file__).resolve())) + ' ' + command + ' ' + shlex.quote(str(root))


def show(value, command, root, json_output):
    if json_output:
        print(encode(value).decode())
        return
    if command == 'setup':
        print('KEV installation is ready' + (' (existing files verified).' if value.get('reused') else '.'))
        print('Configuration: ' + str(value['config']))
        print('Load the model before voting:\n  ' + next_command('start', root))
        return
    state = value.get('state', 'ready' if value.get('model') else 'unknown')
    messages = {
        'ready': 'KEV is ready for local inference.',
        'starting': 'KEV is still loading; it is not ready for voting.',
        'stopping': 'KEV shutdown has not completed.',
        'stopped': 'KEV is stopped; no model is loaded.',
        'not_installed': 'KEV is not installed.',
        'incomplete': 'KEV installation is incomplete. Setup can resume it.',
        'needs_repair': 'KEV installation needs attention.',
        'outdated': 'A worker from an older runtime version is running.',
        'failed': 'KEV failed to load or stopped after a runtime error.',
    }
    print(messages.get(state, 'KEV state: ' + str(state)))
    if state == 'ready':
        print('Model: ' + str(value['model']))
        if 'mps_allocated_bytes' in value:
            print('Model GPU allocation: %.2f GB' % (value['mps_allocated_bytes'] / 1e9))
        if 'load_seconds' in value:
            print('Startup: %.1f seconds' % value['load_seconds'])
    elif state in ('not_installed', 'incomplete', 'needs_repair'):
        print('Run:\n  ' + next_command('setup', root))
    elif state == 'stopped' and command != 'stop':
        print('To load it:\n  ' + next_command('start', root))
    elif state in ('starting', 'outdated', 'failed'):
        print('To cancel or reset the worker:\n  ' + next_command('stop', root))
    if value.get('hint'):
        print(value['hint'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command')
    for name in ('setup', 'start', 'check', 'status', 'stop'):
        command = sub.add_parser(name)
        command.add_argument('location', nargs='?', default=str(DEFAULT_ROOT),
                             help='runtime directory or config file; defaults to this checkout\'s .local/kev')
        command.add_argument('--json', action='store_true', help='emit machine-readable JSON')
    replay = sub.add_parser('replay')
    replay.add_argument('report')
    replay.add_argument('config')
    args = parser.parse_args(argv)
    if args.command in ('setup', 'start', 'check', 'status', 'stop'):
        previous_term = signal.signal(signal.SIGTERM, terminate)
        # Separate human lifecycle work from the 55-second provider deadline.
        seconds = 190 if args.command in ('start', 'check') else 15
        if args.command != 'setup':
            signal.signal(signal.SIGALRM, timeout)
            signal.alarm(seconds)
        try:
            from naome_kev import runtime
            if args.command == 'setup':
                root = Path(args.location).absolute()
                value = runtime.setup(root)
            else:
                try:
                    root, settings_path = locations(args.location, control=args.command in ('status', 'stop'))
                except (ValueError, OSError):
                    # A malformed config must not prevent an explicit stop of
                    # the owned runtime directory containing that file.
                    if args.command not in ('status', 'stop'):
                        raise
                    target = Path(args.location).absolute()
                    explicit_config = not target.is_dir() and (target.suffix == '.json' or target.is_file())
                    root = target.parent if explicit_config else target
                if args.command in ('start', 'check'):
                    settings = config.load(settings_path)
                    progress = None if args.json else lambda message: print(message, file=sys.stderr, flush=True)
                    value = runtime.start(settings, progress=progress)
                elif args.command == 'status':
                    value = runtime.inspect(root)
                else:
                    value = runtime.stop(root)
            show(value, args.command, root, args.json)
            return 1 if args.command == 'stop' and not value['stopped'] else 0
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGTERM, previous_term)
    if args.command == 'replay':
        report = loads(config.read_private(args.report, 16384))
        print(encode(engine.replay(report, config.load(args.config))).decode())
        return 0
    signal.signal(signal.SIGALRM, timeout)
    previous_term = signal.signal(signal.SIGTERM, terminate)
    signal.alarm(55)
    try:
        result = engine.evaluate(sys.stdin.buffer.read(65537))
        output = encode(result)
        if len(output) > 8192:
            raise ValueError('KEV result exceeds adapter output limit')
        print(output.decode())
        return 0
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGTERM, previous_term)


def timeout(_signal, _frame):
    raise TimeoutError('KEV command deadline exceeded')


def terminate(signum, _frame):
    # Unwind owned startup/install cleanup before responding to termination.
    raise SystemExit(128 + signum)


def cli():
    try:
        return main()
    except KeyboardInterrupt:
        print('Cancelled. Any worker started by this command was stopped; rerun setup to resume an installation.', file=sys.stderr)
        return 130
    except Exception as error:
        # Provider failures never echo input, paths from a model response, or
        # arbitrary exception messages. Lifecycle errors use controlled messages.
        lifecycle = len(sys.argv) > 1 and sys.argv[1] in ('setup', 'start', 'check', 'status', 'stop')
        if lifecycle:
            safe_errors = tuple(getattr(sys.modules[name], kind) for name, kind in
                                (('naome_kev.runtime', 'RuntimeFailure'), ('naome_kev.setup', 'SetupError'))
                                if name in sys.modules and hasattr(sys.modules[name], kind))
            if isinstance(error, safe_errors):
                message = str(error)
                hint = getattr(error, 'hint', '')
                code = error.code
            elif isinstance(error, FileNotFoundError):
                code, message, hint = ('not_installed', 'KEV configuration or runtime files were not found.',
                                      'Run setup with the same runtime directory, then start.')
            elif isinstance(error, PermissionError):
                code, message, hint = ('permissions', 'KEV cannot access its private runtime files.',
                                      'Use a directory owned by your account, with private permissions.')
            elif isinstance(error, TimeoutError):
                code, message, hint = ('timeout', 'The KEV command exceeded its time limit.',
                                      'Run status, or stop to cancel the worker before retrying start.')
            elif isinstance(error, ImportError):
                code, message, hint = ('unsupported_platform', 'This KEV runtime requires macOS on Apple Silicon.',
                                      'Other node platforms can use a different provider executable.')
            else:
                code, message, hint = ('invalid_runtime', 'KEV configuration or runtime verification failed.',
                                      'Run status and inspect the private setup.log or worker.log for recovery details.')
            if '--json' in sys.argv:
                print(encode({'error': {'code': code, 'message': message, 'hint': hint}}).decode(), file=sys.stderr)
            else:
                print(message + ('\n' + hint if hint else ''), file=sys.stderr)
        else:
            print('KEV provider unavailable or invalid input; no vote produced. Run status or start to inspect the local runtime.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(cli())
