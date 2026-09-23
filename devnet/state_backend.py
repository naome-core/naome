"""Isolated process/container ownership for canonical-state qualification."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
BINARIES = ('naome', 'naome-validator', 'naome-verifier')

# Collect finalized status and cgroup memory in one container probe. The local
# control request is still served by naome itself; this wrapper has no authority.
STATUS_MEMORY = """import json,pathlib,subprocess,sys
result=subprocess.run(['/usr/local/bin/naome','status',sys.argv[1]],capture_output=True,text=True,timeout=15)
if result.returncode: sys.exit(result.returncode)
status=json.loads(result.stdout)
if 'error' in status: sys.exit(1)
memory=pathlib.Path('/sys/fs/cgroup/memory.current')
if not memory.exists(): memory=pathlib.Path('/sys/fs/cgroup/memory/memory.usage_in_bytes')
print(json.dumps({'status':status,'memory_bytes':int(memory.read_text())}))
"""


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
        """Probe a Docker node's actual control status and cgroup use together."""
        result = command(['docker', 'exec', self.containers[index], 'python3', '-c', STATUS_MEMORY,
                          self.config(index)], timeout=20, tolerate=tolerate)
        if result.returncode:
            return None
        value = json.loads(result.stdout)
        return value['status'], value['memory_bytes']

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
