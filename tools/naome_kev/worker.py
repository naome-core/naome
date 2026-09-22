"""Single resident MPS model, private Unix socket, no external network access."""
import fcntl
import json
import math
import os
from pathlib import Path
import resource
import select
import signal
import subprocess
import socket
import socketserver
import sys
import threading
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from naome_kev import config
from naome_kev.runtime import MAX_FRAME, IDLE_SECONDS, _directory, _fingerprint
from naome_kev.schema import encode, loads


class Model:
    def __init__(self, root):
        started = time.monotonic()
        import torch
        from naome_kev.install import check_install

        self.root = root
        self.settings = config.load(root / 'kev.json')
        self.fingerprint = _fingerprint(root)
        self.stage_seconds = {}
        check_install(root)
        from kev.checkpoint import Checkpoint, LoadOptions
        self.stage_seconds['imports_and_verification'] = time.monotonic() - started
        if not torch.backends.mps.is_available():
            raise ValueError('this execution profile requires Apple Silicon MPS')
        checkpoint = Checkpoint(str(root / 'adapter'))
        if (checkpoint.meta.base != self.settings['base_model_id']
                or checkpoint.meta.base_revision != self.settings['base_model_revision']):
            raise ValueError('checkpoint was trained against a different base revision')
        checkpoint.meta.base = str(root / 'base')
        checkpoint.meta.base_revision = None
        self.tokenizer, self.model = checkpoint.load('mps', LoadOptions(dtype=torch.bfloat16, merge=False, attn='sdpa'))
        torch.mps.synchronize()
        self.load_seconds = time.monotonic() - started
        self.stage_seconds['load'] = self.load_seconds - self.stage_seconds['imports_and_verification']
        self.temperature = self.model.head.temperature
        self.calls = 0
        self.last_seconds = None
        self.inference_lock = threading.Lock()

    def status(self):
        import torch
        return {'model': self.settings['model'], 'fingerprint': self.fingerprint,
                'pid': os.getpid(), 'device': 'mps', 'dtype': 'bfloat16', 'merge': False, 'attention': 'sdpa',
                'temperature': self.temperature, 'load_seconds': self.load_seconds,
                'startup_stages_seconds': self.stage_seconds,
                'shared_state_prefix': True,
                'calls': self.calls, 'last_inference_seconds': self.last_seconds,
                'mps_allocated_bytes': torch.mps.current_allocated_memory(),
                'mps_driver_bytes': torch.mps.driver_allocated_memory(),
                'peak_resident_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                'idle_shutdown_seconds': IDLE_SECONDS,
                'max_branch_tokens': 2048, 'max_questions': 8}

    def infer(self, payload):
        import torch
        from kev.api import SystemOneRequest, to_record, choice_confidence, score_confidence
        if payload.get('model') != self.settings['model']:
            raise ValueError('unrecognized model identity')
        req = SystemOneRequest.model_validate(payload)
        if len(req.questions) > 8:
            raise ValueError('at most eight atomic questions per local call')
        rec, meta = to_record(req)
        # Reject whole oversized requests; never clip preferences or formulas.
        encodings = [self.model.encode(self.tokenizer, {'state': rec['state'], 'questions': [question]},
                                      max_state=2048, max_branch=2048, strict=True)
                     for question in rec['questions']]
        started = time.monotonic()
        with torch.inference_mode():
            # One question at a time bounds activations independently of batch size.
            # All encodings come from the exact same state. Kev's own prefix API
            # copies recurrent state for each independent branch, avoiding five
            # repeated passes over the operator profile and formal targets.
            if len(encodings) > 1:
                prefix = self.model.prefix(encodings[0])
                probabilities = [self.model.probs_with_prefix(enc, prefix)[0].tolist() for enc in encodings]
            else:
                probabilities = [self.model.probs(encodings[0])[0].tolist()]
        torch.mps.synchronize()
        self.last_seconds = time.monotonic() - started
        self.calls += 1
        answers = {}
        for p, m in zip(probabilities, meta):
            if any(not math.isfinite(v) or not 0 <= v <= 1 for v in p) or abs(sum(p) - 1) > 0.001:
                raise ValueError('model returned an invalid probability distribution')
            if m['type'] == 'noul':
                answer = {'type': 'noul', 'noul': p[1]}
            elif m['type'] == 'choice':
                answer = {'type': 'choice', 'choice': m['keys'][max(range(len(p)), key=lambda i: p[i])],
                          'confidence': choice_confidence(p), 'probabilities': dict(zip(m['keys'], p))}
            else:
                answer = {'type': 'score', 'score': sum(i * v for i, v in enumerate(p)),
                          'legend': m['legend'], 'probabilities': dict(zip(m['keys'], p)),
                          'confidence': score_confidence(p)}
            answers[m['id']] = answer
        # Full precision is intentional: upstream HTTP responses round to 0.01.
        return {'model': self.settings['model'], 'answers': answers,
                'usage': {'input_tokens': sum(len(enc['ids']) for enc in encodings), 'output_tokens': 0}}


class Supervisor:
    """Own the model process; never import Torch in the control process."""
    def __init__(self, root, startup_seconds, child_command=None):
        self.settings = config.load(root / 'kev.json')
        self.fingerprint = _fingerprint(root)
        self.condition = threading.Condition()
        self.inference_lock = threading.Lock()
        self.state = 'starting'
        self.error = None
        self.failed_at = None
        self.cached = {}
        self.serial = 0
        self.pending = None
        self.answer = None
        self.started = time.monotonic()
        self.startup_deadline = self.started + startup_seconds
        self.inference_deadline = None
        command = child_command or [sys.executable, str(Path(__file__).resolve()), '--model', str(root)]
        # Inherit this supervisor's process group so its launcher has one bounded
        # cleanup target. Only this exact Popen child is signalled by the supervisor.
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=None, close_fds=True, bufsize=0)
        self.reader = threading.Thread(target=self._read, daemon=True)
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
            self.reader.start()
        except BaseException:
            # If control initialization fails after spawn, construction still
            # owns the child and must reap it before daemon.lock can be released.
            while not self.reap():
                time.sleep(.1)
            self.process.stdin.close()
            self.process.stdout.close()
            raise

    def _fail(self, code):
        with self.condition:
            if self.state not in ('failed', 'stopping'):
                self.state = 'failed'
                self.error = code
                self.failed_at = time.monotonic()
            self.condition.notify_all()

    def _read(self):
        try:
            while True:
                raw = self.process.stdout.readline(MAX_FRAME + 1)
                if not raw:
                    self._fail('model_process_exited')
                    return
                if len(raw) > MAX_FRAME or not raw.endswith(b'\n'):
                    raise ValueError('invalid child frame')
                message = loads(raw)
                with self.condition:
                    event = message.get('event')
                    if event == 'ready' and self.state == 'starting':
                        if time.monotonic() >= self.startup_deadline:
                            self._fail('model_startup_timeout')
                            return
                        status = message['status']
                        if (status.get('model') != self.settings['model']
                                or status.get('fingerprint') != self.fingerprint):
                            raise ValueError('child identity mismatch')
                        self.cached = status
                        self.state = 'ready'
                    elif event in ('result', 'request_error') and self.state == 'ready':
                        if self.pending is None or message.get('request') != self.pending:
                            raise ValueError('unexpected child response')
                        if time.monotonic() >= self.inference_deadline:
                            self._fail('model_inference_timeout')
                            return
                        if event == 'result':
                            status = message['status']
                            if (status.get('model') != self.settings['model']
                                    or status.get('fingerprint') != self.fingerprint):
                                raise ValueError('child identity mismatch')
                            self.cached = status
                        self.answer = message
                    elif event == 'failed':
                        self._fail('model_load_failed')
                        return
                    elif self.state in ('stopping', 'failed'):
                        return
                    else:
                        raise ValueError('unexpected child message')
                    self.condition.notify_all()
        except Exception:
            self._fail('model_protocol_failed')

    def status(self):
        with self.condition:
            return {**self.cached, 'state': self.state, 'model': self.settings['model'],
                    'fingerprint': self.fingerprint, 'pid': self.process.pid,
                    'supervisor_pid': os.getpid(), 'error_code': self.error,
                    'startup_elapsed_seconds': time.monotonic() - self.started}

    def stop(self):
        with self.condition:
            self.state = 'stopping'
            self.condition.notify_all()

    def reap(self):
        """Bounded termination attempts; caller retains daemon ownership on failure."""
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    return False
        self.process.wait(timeout=0)
        return True

    def tick(self):
        now = time.monotonic()
        with self.condition:
            if self.state == 'starting' and now >= self.startup_deadline:
                self._fail('model_startup_timeout')
            if (self.state == 'ready' and self.inference_deadline is not None
                    and now >= self.inference_deadline):
                self._fail('model_inference_timeout')
            if self.process.poll() is not None:
                self._fail('model_process_exited')
            ending = self.state in ('failed', 'stopping')
        return not ending or self.reap()

    def infer(self, payload, budget_seconds):
        deadline = time.monotonic() + budget_seconds
        with self.condition:
            if self.state != 'ready':
                raise ValueError('model_not_ready')
            self.serial += 1
            request = self.serial
            self.pending = request
            self.answer = None
            self.inference_deadline = deadline
        try:
            # Preserve option order, as on the external IPC boundary.
            raw = json.dumps({'request': request, 'payload': payload}, ensure_ascii=False,
                             allow_nan=False, separators=(',', ':')).encode() + b'\n'
            if len(raw) > MAX_FRAME:
                raise ValueError('request_too_large')
            offset = 0
            fd = self.process.stdin.fileno()
            while offset < len(raw):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                    self._fail('model_inference_timeout')
                    raise TimeoutError('model_inference_timeout')
                offset += os.write(fd, raw[offset:])
            with self.condition:
                while self.answer is None and self.state == 'ready':
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._fail('model_inference_timeout')
                        break
                    self.condition.wait(remaining)
                if self.state != 'ready':
                    raise ValueError('model_unavailable')
                answer = self.answer
                if answer['event'] == 'request_error':
                    raise ValueError('model_request_failed')
                return answer['response']
        except (BrokenPipeError, OSError):
            self._fail('model_transport_failed')
            raise
        finally:
            with self.condition:
                self.pending = None
                self.answer = None
                self.inference_deadline = None


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.server.last_activity = time.monotonic()
        self.connection.settimeout(2)
        try:
            raw = self.rfile.readline(MAX_FRAME + 1)
            if len(raw) > MAX_FRAME or not raw.endswith(b'\n'):
                return
            message = loads(raw)
            command = message.get('command')
            if command == 'status':
                reply = self.server.model.status()
            elif command == 'infer':
                if not self.server.model.inference_lock.acquire(blocking=False):
                    raise ValueError('worker_busy')
                try:
                    remaining = float(message['budget_seconds'])
                    if not math.isfinite(remaining) or remaining <= 0:
                        raise ValueError('request_expired')
                    reply = self.server.model.infer(message['payload'], min(45.0, remaining))
                finally:
                    self.server.model.inference_lock.release()
            elif command == 'stop':
                self.server.model.stop()
                self.server.stopping = True
                reply = {'stopped': False, 'state': 'stopping'}
            else:
                raise ValueError('unknown_command')
        except Exception as exc:
            reply = {'error': 'request failed (' + type(exc).__name__ + ')'}
        try:
            self.wfile.write(encode(reply) + b'\n')
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass
        self.server.last_activity = time.monotonic()


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    request_queue_size = 8


def serve(root, startup_seconds=180, child_command=None):
    """Internal test injection changes only the subprocess, never the public CLI."""
    startup_seconds = float(startup_seconds)
    if not math.isfinite(startup_seconds) or not 0 < startup_seconds <= 180:
        raise ValueError('invalid startup budget')
    root = _directory(root)
    fd = os.open(root / 'daemon.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        path = root / 'worker.sock'
        path.unlink(missing_ok=True)
        supervisor = None
        previous = {}
        try:
            with Server(str(path), Handler) as server:
                # Bind before the child starts its potentially blocking imports.
                server.stopping = False
                server.timeout = .1
                server.last_activity = time.monotonic()
                if threading.current_thread() is threading.main_thread():
                    def stopping(_signum, _frame):
                        server.stopping = True
                        if supervisor is not None:
                            supervisor.stop()
                    for signum in (signal.SIGTERM, signal.SIGINT):
                        previous[signum] = signal.signal(signum, stopping)
                supervisor = Supervisor(root, startup_seconds, child_command)
                server.model = supervisor
                # A signal may have arrived during Popen, before its return made
                # the child available to the handler. Honor it before serving.
                if server.stopping:
                    supervisor.stop()
                while True:
                    server.handle_request()
                    exited = supervisor.tick()
                    state = supervisor.status()['state']
                    if state == 'stopping' and exited:
                        break
                    if (state == 'failed' and exited
                            and time.monotonic() - supervisor.failed_at >= 5):
                        break
                    if time.monotonic() - server.last_activity >= IDLE_SECONDS:
                        supervisor.stop()
        finally:
            if supervisor is not None:
                supervisor.stop()
                # Never release ownership while an owned model process is alive.
                while not supervisor.reap():
                    time.sleep(.1)
                supervisor.process.stdin.close()
                supervisor.reader.join(timeout=1)
                supervisor.process.stdout.close()
            for signum, handler in previous.items():
                signal.signal(signum, handler)
            path.unlink(missing_ok=True)


def model_main(root):
    # Duplicate the protocol descriptor before routing Python AND native stdout
    # diagnostics to stderr. No model import can corrupt the JSON channel.
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), 'wb', buffering=0)
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    def send(message):
        protocol.write(encode(message) + b'\n')
    try:
        model = Model(root)
        send({'event': 'ready', 'status': model.status()})
    except Exception:
        # The launcher directs stderr to the private worker.log. Keep detailed
        # installation/load diagnostics there, never in status or ballot data.
        traceback.print_exc(file=sys.stderr)
        send({'event': 'failed'})
        return 1
    for raw in iter(lambda: sys.stdin.buffer.readline(MAX_FRAME + 1), b''):
        if len(raw) > MAX_FRAME or not raw.endswith(b'\n'):
            return 1
        message = loads(raw)
        try:
            response = model.infer(message['payload'])
            send({'event': 'result', 'request': message['request'],
                  'response': response, 'status': model.status()})
        except Exception:
            send({'event': 'request_error', 'request': message['request']})
    return 0


def main():
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] == '--model':
        return model_main(_directory(sys.argv[2]))
    if len(sys.argv) not in (2, 3):
        raise ValueError('invalid worker arguments')
    serve(Path(sys.argv[1]), float(sys.argv[2]) if len(sys.argv) == 3 else 180)
    return 0


if __name__ == '__main__':
    sys.exit(main())
