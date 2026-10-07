"""Record a finite real multicast loopback probe for hosted macOS CI."""

import argparse
import hashlib
import json
import os
import platform
import select
import signal
import socket
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path


def clean_group(process, record):
    """Reap the owned leader and stop any remaining members of its group."""
    record["owned_group_empty"] = False
    for stop in [signal.SIGTERM, signal.SIGKILL]:
        try:
            os.killpg(process.pid, stop)
        except ProcessLookupError:
            record["owned_group_empty"] = True
            break
        except PermissionError as error:
            record["transient_group_signal_errno"] = error.errno
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            process.poll()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                record["owned_group_empty"] = True
                break
            except PermissionError as error:
                # Orphan teardown can temporarily retain an unsignalable
                # group. Only ESRCH confirms it is empty; keep polling.
                record["transient_group_probe_errno"] = error.errno
            time.sleep(0.05)
        if record["owned_group_empty"]:
            break
    if not record["owned_group_empty"]:
        record["cleanup_errors"].append("owned mDNS process group did not exit")


def watch_driver(arguments, lifeline, receipt):
    """Own the driver independently of the invoking supervisor's lifetime."""
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    record = {"schema": 1, "effective_uid": os.geteuid(), "python": sys.executable,
              "command": [sys.executable, *arguments], "timeout_seconds": 220,
              "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "github_run_id": os.environ.get("GITHUB_RUN_ID"),
              "watchdog_pid": os.getpid(), "cleanup_errors": [], "exit_code": 1}
    process = None
    started = time.monotonic()
    try:
        process = subprocess.Popen(record["command"], start_new_session=True)
        record["owned_process_group"] = process.pid
        receipt.write_text(json.dumps(record, indent=2) + "\n")
        while True:
            if select.select([lifeline], [], [], 0.1)[0] and not os.read(lifeline, 1):
                record["stop_reason"] = "supervisor_lifeline_closed"
                break
            if process.poll() is not None:
                record["exit_code"] = process.returncode
                record["stop_reason"] = "driver_exited"
                break
            if time.monotonic() - started >= 220:
                record["stop_reason"] = "independent_wall_timeout"
                break
    except OSError as error:
        record["error"] = str(error)
    finally:
        if process is not None:
            clean_group(process, record)
        os.close(lifeline)
        record["driver_exited"] = process is not None and process.poll() is not None
        if record["cleanup_errors"]:
            record["exit_code"] = 1
        receipt.write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(record), flush=True)
    return record["exit_code"]


def run_driver(arguments):
    """Supervise only the mDNS proof fixture in an owned root process group."""
    if (sys.platform != "darwin" or os.geteuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("NAOME_MDNS_CI_ROOT") != "1"):
        raise ValueError("mDNS CI supervisor requires its explicit hosted root context")
    driver = Path(__file__).resolve().with_name("proof_network_discovery.py")
    if not arguments or Path(arguments[0]).resolve() != driver:
        raise ValueError("supervisor accepts only the repository's proof discovery driver")
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=["mdns"], required=True)
    parser.add_argument("--timeout", choices=["180"], required=True)
    parser.add_argument("--profile", choices=["test", "release"], required=True)
    args = parser.parse_args(arguments[1:])
    receipt = args.output.parent / f"mdns-ci-runner-{args.profile}-{os.getpid()}.json"
    receipt.parent.mkdir(parents=True, exist_ok=True)
    read_end, write_end = os.pipe()
    watchdog = os.fork()
    if watchdog == 0:
        os.close(write_end)
        try:
            result = watch_driver(arguments, read_end, receipt)
        except BaseException:
            traceback.print_exc()
            result = 1
        os._exit(0 if result == 0 else 1)
    os.close(read_end)

    def interrupted(_signal, _frame):
        raise InterruptedError("CI supervisor termination requested")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    completed = False
    try:
        deadline = time.monotonic() + 235
        while time.monotonic() < deadline:
            child, status = os.waitpid(watchdog, os.WNOHANG)
            if child:
                completed = True
                return os.waitstatus_to_exitcode(status)
            time.sleep(0.05)
        raise TimeoutError("independent mDNS watchdog exceeded its bounded lifetime")
    finally:
        os.close(write_end)
        if not completed:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                child, _status = os.waitpid(watchdog, os.WNOHANG)
                if child:
                    break
                time.sleep(0.05)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--run-driver":
        return run_driver(sys.argv[2:])
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-root", action="store_true")
    args = parser.parse_args()
    uid = os.geteuid() if hasattr(os, "geteuid") else None
    record = {
        "schema": 1, "result": "fail", "effective_uid": uid,
        "pid": os.getpid(), "python": sys.executable,
        "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "platform": platform.uname()._asdict(),
        "image_os": os.environ.get("ImageOS"),
        "image_version": os.environ.get("ImageVersion"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "group": "224.0.0.251", "port": 53530,
        "timeout_seconds": 3, "send_calls": 0, "send_returns": 0,
        "matching_receives": 0, "stage": "context",
    }
    if sys.platform == "darwin":
        try:
            interfaces = subprocess.run(["/sbin/ifconfig", "-a"], capture_output=True,
                                        text=True, timeout=5)
            record["interfaces"] = [line for line in interfaces.stdout.splitlines()
                                    if (line and not line[0].isspace())
                                    or line.lstrip().startswith(("inet ", "inet6 ", "status:"))]
            record["interface_command_exit"] = interfaces.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            record["interface_command_error"] = str(error)
    try:
        if args.require_root and (sys.platform != "darwin" or uid != 0
                                  or os.environ.get("GITHUB_ACTIONS") != "true"):
            raise ValueError("root probe requires the explicit hosted macOS CI context")
        token = b"naome-mdns-ci-probe:" + uuid.uuid4().hex.encode()
        record["stage"] = "socket"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            receiver.bind(("0.0.0.0", record["port"]))
            receiver.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                socket.inet_aton(record["group"]) + socket.inet_aton("0.0.0.0"))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
                sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                sender.bind(("0.0.0.0", 0))
                record["stage"] = "send"
                record["send_calls"] += 1
                record["bytes_sent"] = sender.sendto(token, (record["group"], record["port"]))
                record["send_returns"] += 1
                record["sender_socket"] = sender.getsockname()
                record["stage"] = "receive"
                deadline = time.monotonic() + record["timeout_seconds"]
                while time.monotonic() < deadline:
                    receiver.settimeout(max(0.001, deadline - time.monotonic()))
                    data, address = receiver.recvfrom(2048)
                    if data == token:
                        record["matching_receives"] += 1
                        record["received_from"] = address
                        record["result"] = "pass"
                        break
                if record["result"] != "pass":
                    raise TimeoutError("no matching multicast packet received")
    except (OSError, ValueError) as error:
        record["error"] = str(error)
        record["error_type"] = type(error).__name__
        record["native_errno"] = getattr(error, "errno", None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record))
    return 0 if record["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
