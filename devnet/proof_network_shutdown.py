#!/usr/bin/env python3
"""Finite POSIX one-shot shutdown controls during node and relay activity."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import sys
import threading
import time
import zipfile

from proof_network import Driver, Node, digest, source
from proof_network_discovery import Relay, port


def trial(driver, role, stop_signal, index):
    root_output = driver.output
    driver.output = root_output / f"case-{index}"
    driver.output.mkdir()
    directory = driver.output / role
    identity = driver.init_identity(directory)
    subject = (Node if role == "node" else Relay)(driver, index, directory, identity, port())
    companion = None
    writer = None
    active = threading.Event()
    finished = threading.Event()
    connected = []
    result = {"role": role, "signal": stop_signal.name, "signals_sent": 0}
    driver.summary["trials"].append(result)
    try:
        if role == "node":
            driver.nodes = [subject]
            subject.start(test_controls=False)
            produced = subject.command("produce", source=source(3))
            assert produced["result"]["status"] == "accepted"

            def commands():
                try:
                    for serial in range(512):
                        if finished.is_set():
                            break
                        subject.process.stdin.write(json.dumps({"command": "status", "request": f"busy-{serial}"}) + "\n")
                        subject.process.stdin.flush()
                        active.set()
                except (BrokenPipeError, OSError, ValueError):
                    pass

            writer = threading.Thread(target=commands, daemon=True)
            writer.start()
            assert active.wait(timeout=2)
            subject.wait_event(lambda event: event.get("request") == "busy-3")
            result["activity"] = "checked production followed by queued operator status requests"
        else:
            subject.start()
            other_directory = driver.output / f"companion-{index}"
            companion = Node(driver, 0, other_directory, driver.init_identity(other_directory), port())
            driver.nodes = [companion]
            companion.start(test_controls=False, network_config={"peers": [], "discovery": {
                "mdns": False, "dht": True, "hole_punch": False,
                "bootstrap": [{"id": identity, "address": f"/ip4/127.0.0.1/tcp/{subject.port}"}]}})
            subject.wait_event(lambda event: event.get("event") == "relay_connected")
            # At most sixteen additional pending TCP handshakes, all local and
            # closed in finally. The authenticated connection is recorded too.
            for _ in range(16):
                connected.append(socket.create_connection(("127.0.0.1", subject.port), timeout=2))
            result["activity"] = "authenticated libp2p peer plus sixteen pending TCP handshakes"
        driver.check_deadline()
        assert subject.process.poll() is None
        if role == "node":
            result["status_responses_before_signal"] = sum(
                str(event.get("request", "")).startswith("busy-") for event in subject.events)
        result["pid"] = subject.process.pid
        result["signal_sent_monotonic"] = time.monotonic()
        subject.process.send_signal(stop_signal)
        result["signals_sent"] = 1
        subject.process.wait(timeout=min(5, max(0.001, driver.deadline - time.monotonic())))
        result["exit_code"] = subject.process.returncode
        result["shutdown_seconds"] = time.monotonic() - result["signal_sent_monotonic"]
        assert subject.process.returncode == 0, result
        stopped = subject.wait_event(lambda event: event.get("event") == "stopped")
        assert stopped["observed_monotonic"] >= result["signal_sent_monotonic"]
        result["stopped_event_observed"] = True
        result["result"] = "pass"
    finally:
        finished.set()
        for connection in connected:
            connection.close()
        if writer is not None:
            writer.join(timeout=2)
        result["required_extra_subject_signal"] = subject.process is not None and subject.process.poll() is None
        cleanup_errors = []
        for process in [subject, companion]:
            if process is not None and process.process is not None:
                try:
                    process.stop()
                except Exception as error:
                    cleanup_errors.append(str(error))
        if writer is not None:
            writer.join(timeout=2)
            assert not writer.is_alive(), "command writer did not exit"
        result["process_exit_codes"] = [process.process.returncode for process in [subject, companion]
                                         if process is not None and process.process is not None]
        result["cleanup_errors"] = cleanup_errors
        driver.nodes = []
        driver.output = root_output
        assert not cleanup_errors, cleanup_errors
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("this control requires POSIX signals")
    driver = Driver(args.binary, args.output, args.timeout, args.profile)
    driver.summary.update({"fixture": "busy_shutdown", "node_count": 1,
        "shutdown_driver_sha256": digest(__file__), "trials": [],
        "execution_context": {"effective_uid": os.geteuid(), "hosted_ci": os.environ.get("GITHUB_ACTIONS") == "true"},
        "claim": "one-shot POSIX shutdown under these finite activities; no claim of exhaustive race coverage"})
    try:
        for index, (role, stop_signal) in enumerate([
                (role, stop_signal) for role in ["node", "relay"]
                for stop_signal in [signal.SIGTERM, signal.SIGINT]]):
            trial(driver, role, stop_signal, index)
        driver.summary["result"] = "pass"
    except Exception as error:
        driver.summary["result"] = "fail"
        driver.summary["error"] = str(error)
    driver.summary["cleanup"] = {
        "all_processes_exited": all(all(code is not None for code in trial.get("process_exit_codes", []))
                                    for trial in driver.summary["trials"]),
        "errors": [error for trial in driver.summary["trials"] for error in trial.get("cleanup_errors", [])]}
    driver.summary["artifacts"] = {str(path): digest(path) for path in sorted(driver.output.rglob("*"))
                                    if path.is_file() and path.name not in ["summary.json", "identity.key", "knowledge.lock"]}
    (driver.output / "summary.json").write_text(json.dumps(driver.summary, indent=2) + "\n")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        archive = driver.output.parent / f"shutdown-ci-{args.profile}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path in sorted(driver.output.rglob("*")):
                if path.is_file() and path.name not in ["identity.key", "knowledge.lock"]:
                    bundle.write(path, str(path.relative_to(driver.output)))
    print(json.dumps({"result": driver.summary["result"], "output": str(driver.output)}))
    return 0 if driver.summary["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
