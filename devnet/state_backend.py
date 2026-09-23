"""Isolated process/container ownership for canonical-state qualification."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
BINARIES = ('naome', 'naome-validator', 'naome-verifier')

# One long-lived, read-only probe per running container. Each input byte asks
# the actual configured local control socket for a fresh status and cgroup use.
# No operator binary or network listener is started by this script.
STATUS_MEMORY = """import json,pathlib,socket,struct,sys
MAX=3*1024*1024
memory=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else pathlib.Path('/sys/fs/cgroup/memory.current')
if len(sys.argv)==2 and not memory.exists(): memory=pathlib.Path('/sys/fs/cgroup/memory/memory.usage_in_bytes')
def exact(sock,n):
 out=bytearray()
 while len(out)<n:
  part=sock.recv(n-len(out))
  if not part: raise RuntimeError('short control response')
  out.extend(part)
 return bytes(out)
while True:
 token=sys.stdin.buffer.readline(8)
 if not token: break
 if token!=b'S\\n': break
 try:
  config=json.loads(pathlib.Path(sys.argv[1]).read_text())
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
   sock.settimeout(10)
   sock.connect(config['control_socket'])
   request=b'{"command":"status"}'
   sock.sendall(struct.pack('>I',len(request))+request)
   size=struct.unpack('>I',exact(sock,4))[0]
   if size>MAX: raise RuntimeError('oversized control response')
   status=json.loads(exact(sock,size))
  if not isinstance(status,dict) or 'error' in status: raise RuntimeError('control status rejected')
  used=int(memory.read_text())
  if used<0: raise RuntimeError('negative cgroup memory')
  response={'status':status,'memory_bytes':used}
  frame=json.dumps(response,separators=(',',':')).encode()
  if len(frame)>MAX+4096: raise RuntimeError('oversized probe response')
 except Exception as error:
  frame=json.dumps({'error':type(error).__name__}).encode()
 sys.stdout.buffer.write(struct.pack('>I',len(frame))+frame)
 sys.stdout.buffer.flush()
"""

PROBE_TIMEOUT = 20
MAX_PROBE_RESPONSE = 3 * 1024 * 1024 + 4096


class StatusProbe:
    """One bounded request at a time over a persistent Docker exec pipe."""
    def __init__(self, argv):
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, bufsize=0)
        self.lock = threading.Lock()
        self.closed = False

    def close(self):
        if self.closed:
            return
        self.closed = True
        process = self.process
        if process.stdin:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
        if process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
        if process.stdout:
            process.stdout.close()

    def _ready(self, stream, write, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Docker status probe timed out')
        readable, writable, _ = select.select([] if write else [stream],
                                               [stream] if write else [], [], remaining)
        if not (writable if write else readable):
            raise TimeoutError('Docker status probe timed out')

    def _exact(self, size, deadline):
        result = bytearray()
        while len(result) < size:
            self._ready(self.process.stdout, False, deadline)
            chunk = os.read(self.process.stdout.fileno(), size - len(result))
            if not chunk:
                raise RuntimeError('Docker status probe closed its pipe')
            result.extend(chunk)
        return bytes(result)

    def request(self, timeout=PROBE_TIMEOUT):
        with self.lock:
            if self.closed:
                raise RuntimeError('Docker status probe is closed')
            deadline = time.monotonic() + timeout
            try:
                self._ready(self.process.stdin, True, deadline)
                if os.write(self.process.stdin.fileno(), b'S\n') != 2:
                    raise RuntimeError('short Docker status probe request')
                size = struct.unpack('>I', self._exact(4, deadline))[0]
                if not 0 < size <= MAX_PROBE_RESPONSE:
                    raise RuntimeError('oversized Docker status probe response')
                value = json.loads(self._exact(size, deadline))
                if not isinstance(value, dict) or 'error' in value:
                    raise RuntimeError('Docker status probe rejected status')
                status, memory_bytes = value['status'], value['memory_bytes']
                if not isinstance(status, dict) or not isinstance(memory_bytes, int) or memory_bytes < 0:
                    raise RuntimeError('invalid Docker status probe response')
                return status, memory_bytes
            except TimeoutError:
                self.close()
                raise
            except OSError as error:
                self.close()
                raise RuntimeError('Docker status probe pipe failed') from error
            except Exception:
                self.close()
                raise


def command(args, timeout=60, tolerate=False):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)
    if result.returncode and not tolerate:
        # Native stderr may contain private state. Retain it only in the caller's
        # private process logs, never in the public qualification report.
        raise RuntimeError(f'{Path(str(args[0])).name}: exit {result.returncode}')
    return result


def free_ports(count):
    sockets = []
    try:
        for _ in range(count):
            s = socket.socket()
            s.bind(('127.0.0.1', 0))
            sockets.append(s)
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:
            s.close()


class Backend:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.children, self.logs = {}, {}
        self.project = 'naome-state-' + uuid.uuid4().hex[:12]
        self.network = self.project + '-network'
        self.compose_file = root / 'compose.json'
        self.containers, self.disconnected = {}, set()
        self.probes = {}
        self.image_id = None
        self.generations = [0] * 4
        if args.backend == 'docker':
            subnet = ipaddress.ip_network(args.subnet)
            if subnet.version != 4 or subnet.prefixlen != 24 or not subnet.is_private:
                raise ValueError('explicit private IPv4 /24 required')
            self.ips = [str(subnet[i]) for i in range(10, 14)]
            self.fronts = [f'{ip}:4200' for ip in self.ips]
            self.backs = [f'{ip}:4100' for ip in self.ips]
            self.handoff_fronts = [f'{ip}:4204' for ip in self.ips]
            self.handoff_backs = [f'{ip}:4104' for ip in self.ips]
        else:
            ports = free_ports(16)
            self.fronts = [f'127.0.0.1:{p}' for p in ports[:4]]
            self.backs = [f'127.0.0.1:{p}' for p in ports[4:8]]
            self.handoff_fronts = [f'127.0.0.1:{p}' for p in ports[8:12]]
            self.handoff_backs = [f'127.0.0.1:{p}' for p in ports[12:]]

    def node(self, index):
        return self.root / 'run' / f'node-{index}'

    def config(self, index):
        return self.node(index) / 'node.json'

    def cli(self, index, *args, tolerate=False, timeout=60):
        binary = '/usr/local/bin/naome' if self.args.backend == 'docker' else self.args.bin_dir / 'naome'
        argv = [binary, *args]
        if self.args.backend == 'docker':
            argv = ['docker', 'exec', self.containers[index], *argv]
        result = command(argv, timeout=timeout, tolerate=tolerate)
        if result.returncode:
            return None
        value = json.loads(result.stdout)
        if isinstance(value, dict) and 'error' in value:
            if tolerate:
                return None
            raise RuntimeError('operator command rejected')
        return value

    def status_memory(self, index, tolerate=False):
        """Read fresh control status and actual cgroup use over one owned pipe."""
        probe = self.probes.get(index)
        if probe is None:
            probe = StatusProbe(['docker', 'exec', '-i', self.containers[index],
                                 'python3', '-u', '-c', STATUS_MEMORY, str(self.config(index))])
            self.probes[index] = probe
        try:
            return probe.request()
        except Exception as error:
            self._close_probe(index)
            if tolerate and isinstance(error, RuntimeError):
                return None
            raise

    def _close_probe(self, index):
        probe = getattr(self, 'probes', {}).pop(index, None)
        if probe is not None:
            probe.close()

    def control(self, index, request):
        # Exercise the actual bounded local ingress; the canonical runtime still
        # authenticates and validates every operation. No signing is done here.
        script = """import json,socket,struct,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(10);s.connect(sys.argv[1])
b=sys.argv[2].encode();s.sendall(struct.pack('>I',len(b))+b)
def exact(n):
 out=b''
 while len(out)<n:
  part=s.recv(n-len(out))
  if not part: raise RuntimeError('short control response')
  out+=part
 return out
n=struct.unpack('>I',exact(4))[0]
if n>3*1024*1024: raise RuntimeError('oversized control response')
print(exact(n).decode());s.close()
"""
        python = 'python3' if self.args.backend == 'docker' else sys.executable
        argv = [python, '-c', script, str(self.node(index) / 'control.sock'), json.dumps(request)]
        if self.args.backend == 'docker':
            argv = ['docker', 'exec', self.containers[index], *argv]
        return json.loads(command(argv, timeout=15).stdout)

    def compose(self, *args):
        return command(['docker', 'compose', '--project-name', self.project, '--file', self.compose_file, *args], timeout=120).stdout

    def prepare_containers(self):
        self.image_id = json.loads(command(['docker', 'image', 'inspect', self.args.image]).stdout)[0]['Id']
        probe_name = self.project + '-probe'
        try:
            probe = command(['docker', 'run', '--name', probe_name, '--network', 'none', '--read-only',
                             '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '512m',
                             '--memory-swap', '512m', '--pids-limit', '128', self.image_id,
                             'python3', '-c', "import hashlib,json,pathlib;print(json.dumps({n:hashlib.sha256(pathlib.Path('/usr/local/bin',n).read_bytes()).hexdigest() for n in ('naome','naome-validator','naome-verifier')}))"])
        finally:
            # A timed-out attached Docker command does not own the container lifetime.
            command(['docker', 'rm', '--force', probe_name])
        self.runtime_hashes = json.loads(probe.stdout)
        native = {n: hashlib.sha256((self.args.bin_dir / n).read_bytes()).hexdigest() for n in BINARIES}
        if sys.platform == 'linux' and native != self.runtime_hashes:
            raise RuntimeError('container binaries differ from qualified native binaries')
        services = {}
        for i in range(4):
            node, anchor, genesis = self.node(i), self.root / 'anchors' / str(i), self.root / 'run' / 'genesis.bin'
            volumes = [{'type': 'bind', 'source': str(p), 'target': str(p), 'read_only': p == genesis,
                        'bind': {'create_host_path': False}} for p in (node, anchor, genesis)]
            services[f'validator-{i}'] = {
                'image': self.image_id, 'user': f'{os.getuid()}:{os.getgid()}',
                'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
                'pids_limit': 128, 'mem_limit': '512m', 'memswap_limit': '512m', 'cpus': 2,
                'tmpfs': ['/tmp:rw,noexec,nosuid,size=64m'], 'restart': 'no', 'stop_grace_period': '20s',
                'volumes': volumes, 'networks': {'devnet': {'ipv4_address': self.ips[i]}},
                'command': ['python3', '-B', '/opt/naome/devnet/state_agent.py', '--config', str(self.config(i)),
                            '--validator', '/usr/local/bin/naome-validator', '--front', self.multi(self.fronts[i]),
                            '--back', self.multi(self.backs[i]),
                            '--handoff-front', self.multi(self.handoff_fronts[i]),
                            '--handoff-back', self.multi(self.handoff_backs[i]), '--delay-ms', str(self.args.delay_ms)],
                'logging': {'driver': 'json-file', 'options': {'max-size': '8m', 'max-file': '2'}},
            }
        self.compose_file.write_text(json.dumps({'services': services, 'networks': {'devnet': {
            'name': self.network, 'internal': True, 'ipam': {'config': [{'subnet': self.args.subnet}]}}}}, indent=2))
        self.compose('create', '--pull', 'never')
        for i in range(4):
            self.containers[i] = self.compose('ps', '--all', '--quiet', f'validator-{i}').strip()
            if not self.containers[i]:
                raise RuntimeError('missing validator container')

    @staticmethod
    def multi(address):
        ip, port = address.rsplit(':', 1)
        return f'/ip4/{ip}/tcp/{port}'

    def start(self, i):
        self._close_probe(i)
        self.generations[i] += 1
        if self.args.backend == 'docker':
            self.compose('start', f'validator-{i}')
        else:
            log = open(self.node(i) / f'process-{self.generations[i]}.log', 'ab')
            self.logs[i] = log
            self.children[i] = subprocess.Popen([sys.executable, '-B', str(HERE / 'state_agent.py'),
                '--config', str(self.config(i)), '--validator', str(self.args.bin_dir / 'naome-validator'),
                '--front', self.multi(self.fronts[i]), '--back', self.multi(self.backs[i]),
                '--handoff-front', self.multi(self.handoff_fronts[i]),
                '--handoff-back', self.multi(self.handoff_backs[i]), '--delay-ms', str(self.args.delay_ms)], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)

    def alive(self, i):
        if self.args.backend == 'docker':
            state = json.loads(command(['docker', 'inspect', self.containers[i]]).stdout)[0]['State']
            if state['OOMKilled']:
                raise RuntimeError('validator container exceeded memory cap')
            return state['Running']
        return i in self.children and self.children[i].poll() is None

    def stop(self, i, force=False):
        self._close_probe(i)
        if self.args.backend == 'docker':
            self.compose('kill' if force else 'stop', f'validator-{i}')
            state = json.loads(command(['docker', 'inspect', self.containers[i]]).stdout)[0]['State']
            if not force and (state['Running'] or state['ExitCode'] != 0 or state['OOMKilled']):
                raise RuntimeError('validator did not stop cleanly')
        else:
            child = self.children.pop(i)
            if force:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif child.poll() is None:
                child.terminate()
            try:
                code = child.wait(timeout=20)
                if not force and code != 0:
                    raise RuntimeError('validator did not stop cleanly')
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
                raise RuntimeError('validator shutdown timeout')
            finally:
                # Kill surviving descendants even if their wrapper already died.
                if child.returncode != 0:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.logs.pop(i).close()

    def cut(self, i):
        if self.args.backend == 'docker':
            command(['docker', 'network', 'disconnect', self.network, self.containers[i]])
            self.disconnected.add(i)
            return 'container_network_disconnected'
        # Block authenticated links through the explicit simulation interface;
        # the process remains live and can expose its finalized state.
        status = self.cli(i, 'status', self.config(i))
        for peer, validator in enumerate(status['validators']):
            if validator['endpoint'] not in (self.fronts[i], self.handoff_fronts[i]):
                self.cli(i, 'peer', self.config(i), peer, 'off')
        return 'authenticated_links_disabled'

    def heal(self, i):
        if self.args.backend == 'docker':
            if i in self.disconnected:
                command(['docker', 'network', 'connect', '--ip', self.ips[i], self.network, self.containers[i]])
                self.disconnected.remove(i)
        else:
            status = self.cli(i, 'status', self.config(i))
            for peer, validator in enumerate(status['validators']):
                if validator['endpoint'] not in (self.fronts[i], self.handoff_fronts[i]):
                    self.cli(i, 'peer', self.config(i), peer, 'on')

    def resources(self, i, memory_bytes=None):
        rss = memory_bytes
        if self.args.backend == 'docker':
            # cgroup usage includes the delay proxy, wrapper and validator.
            if rss is None:
                out = command(['docker', 'exec', self.containers[i], 'python3', '-c',
                               "from pathlib import Path;p=Path('/sys/fs/cgroup/memory.current');print(p.read_text() if p.exists() else Path('/sys/fs/cgroup/memory/memory.usage_in_bytes').read_text())"]).stdout
                rss = int(out.strip())
        else:
            pidfile = self.node(i) / 'runtime-pid.json'
            if pidfile.exists():
                pids = json.loads(pidfile.read_text())
                out = command(['ps', '-o', 'rss=', '-p', ','.join(map(str, pids.values()))], tolerate=True).stdout
                if out.strip():
                    rss = sum(int(line) for line in out.split()) * 1024
        paths = (self.node(i), self.root / 'anchors' / str(i))
        sizes = []
        for root in paths:
            for directory, _, files in os.walk(root, followlinks=False):
                for name in files:
                    if len(sizes) >= 100_000:
                        raise RuntimeError('validator file count exceeded')
                    try:
                        sizes.append(os.stat(Path(directory) / name, follow_symlinks=False).st_size)
                    except FileNotFoundError:
                        pass
        return {'memory_bytes': rss, 'disk_bytes': sum(sizes), 'file_count': len(sizes)}

    def cleanup(self):
        for i in list(getattr(self, 'probes', {})):
            self._close_probe(i)
        if self.args.backend == 'docker':
            if self.compose_file.exists():
                self.compose('down', '--timeout', '20')
        else:
            errors = []
            for i in list(self.children):
                try:
                    self.stop(i, force=True)
                except Exception as error:
                    errors.append(str(error))
            if errors:
                raise RuntimeError('; '.join(errors))
