"""Explicit local-process and Docker backends for the same devnet qualification."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent


def command(args, timeout=60):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout


def ports(count, excluded=()):
    reserved = []
    try:
        while len(reserved) < count:
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            if listener.getsockname()[1] in excluded:
                listener.close()
            else:
                reserved.append(listener)
        return [s.getsockname()[1] for s in reserved]
    finally:
        for listener in reserved:
            listener.close()


class Backend:
    def __init__(self, args, root):
        self.args = args
        self.root = root
        self.roles = [f"validator-{i}" for i in range(4)] + [f"publisher-{i}" for i in range(2)]
        self.health_ports = dict(zip(self.roles, ports(6)))

    def status(self, name):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.health_ports[name]}/status", timeout=2) as response:
            value = json.load(response)
        if value.get("role") != name or value.get("schema_version") != 0:
            raise RuntimeError("status endpoint role/schema mismatch")
        return value

    def role_dir(self, name):
        if name not in self.roles:
            raise ValueError("unknown deployment role")
        return self.root / "roles" / name

    def tool(self, name, operation, height):
        raise NotImplementedError

    def diagnostics(self):
        return {}


class ProcessBackend(Backend):
    """Development smoke path. Suspension is explicitly not a network partition."""
    kind = "local_processes"

    def __init__(self, args, root):
        super().__init__(args, root)
        self.children = {}
        self.logs = {}
        self.paused = {}

    def plan(self):
        available = ports(12, self.health_ports.values())
        addresses = [f"/ip4/127.0.0.1/tcp/{p}" for p in available[:6]]
        listeners = [f"/ip4/127.0.0.1/tcp/{p}" for p in available[6:]]
        return {"version": 0, "heights": self.args.heights, "validator_addresses": addresses[:4], "publisher_addresses": addresses[4:], "validator_listen_addresses": listeners[:4], "publisher_listen_addresses": listeners[4:]}

    def start(self, names=None):
        for name in names or self.roles:
            output = open(self.role_dir(name) / "logs" / "agent.log", "ab")
            self.logs[name] = output
            self.children[name] = subprocess.Popen([sys.executable, "-B", str(HERE / "agent.py"), "run", "--role", str(self.role_dir(name)), "--validator", str(self.args.bin_dir / "naome-validator"), "--port", str(self.health_ports[name]), "--delay-ms", str(self.args.delay_ms), "--stall-seconds", str(self.args.height_timeout)], stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)

    def stop(self, names=None, force=False):
        for name in names or list(self.children):
            self.heal(name)
            child = self.children.get(name)
            if child is None:
                continue
            if child.poll() is None:
                if force:
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.terminate()
            try:
                code = child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
                raise RuntimeError(f"{name}: agent shutdown timeout")
            finally:
                if child.returncode != 0:
                    # The agent may have died before its own shutdown handler.
                    # Its children still belong to this run's process group.
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.logs.pop(name).close()
                self.children.pop(name)
            if not force and code != 0:
                raise RuntimeError(f"{name}: agent exited {code}")

    def cut(self, name):
        pid = self.status(name)["child_pid"]
        os.kill(pid, signal.SIGSTOP)
        self.paused[name] = pid
        return "child_process_suspended"

    def heal(self, name):
        pid = self.paused.pop(name, None)
        if pid is not None:
            os.kill(pid, signal.SIGCONT)

    def tool(self, name, operation, height):
        return json.loads(command([self.args.bin_dir / "naome-devnet", operation, self.role_dir(name), height], timeout=180))

    def cleanup(self):
        errors = []
        for name in list(self.children):
            try:
                self.stop([name])
            except Exception as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError("; ".join(errors))


class DockerBackend(Backend):
    kind = "isolated_containers"

    def __init__(self, args, root):
        super().__init__(args, root)
        self.project = "naome-devnet-" + uuid.uuid4().hex[:12]
        self.network = self.project + "-network"
        self.compose_path = root / "compose.json"
        self.containers = {}
        self.disconnected = set()
        self.image_id = None
        self.control_label = f"naome.devnet.owner={self.project}"

    def plan(self):
        import ipaddress
        subnet = ipaddress.ip_network(self.args.subnet)
        if subnet.version != 4 or subnet.prefixlen != 24 or not subnet.is_private:
            raise ValueError("devnet requires an explicit private IPv4 /24 subnet")
        self.ips = dict(zip(self.roles, [str(subnet[i]) for i in range(10, 16)]))
        addresses = [f"/ip4/{self.ips[name]}/tcp/4200" for name in self.roles]
        listeners = [f"/ip4/{self.ips[name]}/tcp/4100" for name in self.roles]
        return {"version": 0, "heights": self.args.heights, "validator_addresses": addresses[:4], "publisher_addresses": addresses[4:], "validator_listen_addresses": listeners[:4], "publisher_listen_addresses": listeners[4:]}

    def compose(self, *args):
        return command(["docker", "compose", "--project-name", self.project, "--file", self.compose_path, *args], timeout=120)

    def status(self, name):
        # Internal-only bridges do not reliably publish host ports. Keep the
        # network isolated and use the role's own read-only HTTP endpoint.
        try:
            raw = command(["docker", "exec", self.containers[name], "python3", "-B", "-c",
                           "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/status',timeout=2).read().decode())"], timeout=10)
        except RuntimeError as error:
            state = json.loads(command(["docker", "inspect", self.containers[name]]))[0]["State"]
            if not state["Running"]:
                raise RuntimeError(f"{name}: container exited {state['ExitCode']}") from error
            raise urllib.error.URLError(f"{name}: internal status not ready") from error
        value = json.loads(raw)
        if value.get("role") != name or value.get("schema_version") != 0:
            raise RuntimeError("status endpoint role/schema mismatch")
        return value

    def diagnostics(self):
        result = {}
        for name, identifier in self.containers.items():
            try:
                state = json.loads(command(["docker", "inspect", identifier], timeout=5))[0]["State"]
                logs = subprocess.run(["docker", "logs", "--tail", "20", identifier], capture_output=True, text=True, timeout=5)
                # Only the wrapper's bounded error reports, never native private
                # state, keys, full inspect output, or the role's process log.
                result[name] = {"running": state["Running"], "exit_code": state["ExitCode"],
                                "oom_killed": state["OOMKilled"], "health": state.get("Health", {}).get("Status"),
                                "wrapper_log": (logs.stdout + logs.stderr)[-4096:]}
            except Exception as error:
                result[name] = {"diagnostic_error": str(error)[:200]}
        return result

    def remove_controls(self):
        identifiers = command(["docker", "ps", "--all", "--quiet", "--filter", f"label={self.control_label}"]).split()
        if identifiers:
            command(["docker", "rm", "--force", *identifiers])

    def control(self, options, *args):
        # Auxiliary processes are owned even if their attached CLI is interrupted.
        try:
            return command(["docker", "run", "--label", self.control_label, "--name", self.project + "-control",
                            "--network", "none", "--read-only", "--cap-drop", "ALL",
                            "--security-opt", "no-new-privileges:true", "--memory", "512m",
                            "--memory-swap", "512m", "--pids-limit", "128", *options,
                            self.image_id, *args], timeout=180)
        finally:
            self.remove_controls()

    def start(self, names=None):
        if not self.compose_path.exists():
            command(["docker", "compose", "version"])
            self.image_id = json.loads(command(["docker", "image", "inspect", self.args.image]))[0]["Id"]
            self.runtime_binary_sha256 = json.loads(self.control([], "python3", "-B", "-c",
                "import hashlib,json,pathlib; print(json.dumps({n:hashlib.sha256(pathlib.Path('/usr/local/bin',n).read_bytes()).hexdigest() for n in ('naome-devnet','naome-validator')}))",
            ))
            if sys.platform == "linux":
                import hashlib
                native = {n: hashlib.sha256((self.args.bin_dir / n).read_bytes()).hexdigest() for n in self.runtime_binary_sha256}
                if self.runtime_binary_sha256 != native:
                    raise RuntimeError("container binaries differ from locally validated Linux binaries")
            services = {}
            for name in self.roles:
                services[name] = {
                    "image": self.image_id, "user": f"{os.getuid()}:{os.getgid()}",
                    "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
                    "pids_limit": 128, "mem_limit": "512m", "memswap_limit": "512m", "cpus": 2,
                    "tmpfs": ["/tmp:rw,noexec,nosuid,size=64m"], "stdin_open": False,
                    "restart": "no", "stop_grace_period": "20s",
                    "volumes": [{"type": "bind", "source": str(self.role_dir(name)), "target": "/data", "bind": {"create_host_path": False}}],
                    "networks": {"devnet": {"ipv4_address": self.ips[name]}},
                    "command": ["python3", "-B", "/opt/naome/devnet/agent.py", "run", "--role", "/data", "--bind", "0.0.0.0", "--delay-ms", str(self.args.delay_ms), "--stall-seconds", str(self.args.height_timeout)],
                    "healthcheck": {"test": ["CMD", "python3", "-B", "/opt/naome/devnet/agent.py", "health"], "interval": "5s", "timeout": "4s", "start_period": "20s", "retries": 3},
                    "logging": {"driver": "json-file", "options": {"max-size": "8m", "max-file": "2"}},
                }
            self.compose_path.write_text(json.dumps({"services": services, "networks": {"devnet": {"name": self.network, "internal": True, "ipam": {"config": [{"subnet": self.args.subnet}]}}}}, indent=2))
            self.compose("up", "--detach", "--pull", "never")
            for name in self.roles:
                self.containers[name] = self.compose("ps", "--all", "--quiet", name).strip()
                if not self.containers[name]:
                    raise RuntimeError(f"missing container for {name}")
        else:
            self.compose("start", *(names or self.roles))

    def stop(self, names=None, force=False):
        selected = names or self.roles
        for name in selected:
            self.heal(name)
        self.compose("kill" if force else "stop", *selected)
        if not force:
            for name in selected:
                state = json.loads(command(["docker", "inspect", self.containers[name]]))[0]["State"]
                if state["Running"] or state["ExitCode"] != 0 or state["OOMKilled"]:
                    raise RuntimeError(f"{name}: unsuccessful container shutdown {state['ExitCode']}")

    def cut(self, name):
        command(["docker", "network", "disconnect", self.network, self.containers[name]])
        self.disconnected.add(name)
        return "container_network_disconnected"

    def heal(self, name):
        if name in self.disconnected:
            command(["docker", "network", "connect", "--ip", self.ips[name], self.network, self.containers[name]])
            self.disconnected.remove(name)

    def tool(self, name, operation, height):
        if operation == "publish":
            args = ["docker", "exec", self.containers[name], "naome-devnet", operation, "/data", height]
            return json.loads(command(args, timeout=180))
        return json.loads(self.control(["--user", f"{os.getuid()}:{os.getgid()}", "--mount", f"type=bind,src={self.role_dir(name)},dst=/data"], "naome-devnet", operation, "/data", height))

    def cleanup(self):
        try:
            self.remove_controls()
        finally:
            if self.compose_path.exists():
                self.compose("down", "--timeout", "20")
