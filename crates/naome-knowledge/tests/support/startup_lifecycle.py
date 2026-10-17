#!/usr/bin/env python3
"""Finite startup lifeline cases; internal custody is separate from ordinary CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from autonomous_lifecycle import (
    Node, Trial, digest, process_group, process_identity, process_startup_sample,
    retain_evidence, stop_owned_group, wait_until, write_receipt,
)


def stop_and_reap_direct_child(trial, node, child, record):
    """Run ordinary stop while this driver reaps its direct daemon Child."""
    started = time.monotonic()
    stop_end = min(trial.deadline, started + 5)
    child_end = min(stop_end, started + 3)
    cleanup_end = min(trial.deadline, stop_end + 2)

    def remaining(end):
        value = end - time.monotonic()
        assert value > 0, "original internal stop/reap cutoff expired"
        return value

    command = [str(trial.binary), "--json", "stop"]
    stop = None
    record["stop_cli"] = {"command": command,
        "stop_deadline": stop_end, "daemon_reap_deadline": child_end,
        "cleanup_deadline": cleanup_end, "reaped": False}
    try:
        remaining(child_end)
        stop = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "NAOME_NODE_DIR": str(node.directory)})
        record["stop_cli"]["pid"] = stop.pid
        # The stop CLI waits for the daemon group to disappear. Our direct
        # Child must be collected here so its zombie cannot hold that group.
        child.wait(timeout=remaining(child_end))
        record["actual_direct_child_reaped_during_stop"] = True
        record["direct_child_exit_code_during_stop"] = child.returncode
        remaining(child_end)
        stdout, stderr = stop.communicate(timeout=remaining(stop_end))
        record["stop_cli"].update(reaped=True, exit_code=stop.returncode)
        remaining(stop_end)
        trial.summary["commands"].append({"node": node.index, "command": command,
            "exit_code": stop.returncode, "stdout": stdout, "stderr": stderr})
        # Preserve Trial.call's exact successful status/type oracles. Stop
        # additionally must report the same stopped state as Node.stop.
        assert stop.returncode == 0, f"stop: {stderr}"
        assert stderr == "", f"stop: {stderr}"
        value = json.loads(stdout)
        assert set(value) == {"running", "accepted_proofs", "interest"}, value
        assert isinstance(value["running"], bool), value
        assert type(value["accepted_proofs"]) is int and value["accepted_proofs"] >= 0, value
        assert isinstance(value["interest"], str), value
        assert value["running"] is False, "internal stop CLI reported running"
        record["stop_cli"]["status"] = value
    finally:
        if stop is not None:
            try:
                remaining(cleanup_end)
                if stop.poll() is None:
                    remaining(cleanup_end)
                    stop.kill()  # Only this exact unreaped direct Popen handle.
                    stop.communicate(timeout=remaining(cleanup_end))
                    record["stop_cli"].update(reaped=True, exit_code=stop.returncode,
                        failure_cleanup_killed_direct_child=True)
                    remaining(cleanup_end)
                record["stop_cli"].update(reaped=True, exit_code=stop.returncode)
            except BaseException as error:
                record["stop_cli"].update(cleanup_error_kind=type(error).__name__,
                    cleanup_unqualified=True)
                raise
            finally:
                stop.stdout.close()
                stop.stderr.close()


def internal_case(trial, node, name, hold_seconds=0):
    token = hashlib.sha256(os.urandom(32)).hexdigest()
    offset = len(node.logs())
    node.event_offset = offset
    child = subprocess.Popen([str(trial.binary), "start"], stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        env={**os.environ, "NAOME_NODE_DIR": str(node.directory), "NAOME_DAEMON_NONCE": token})
    identity = None
    record = {"case": name, "path": "INTERNAL_DAEMON_ONLY",
        "ordinary_installed_start": "NOT_QUALIFIED", "instance_sha256": hashlib.sha256(token.encode()).hexdigest()}
    trial.summary.setdefault("internal_startup_cases", []).append(record)
    try:
        def detached():
            item = process_identity(child.pid)
            return item if item is not None and item["pid"] == item["group"] == item["session"] else None
        identity = wait_until(detached, time.monotonic() + trial.remaining(2))
        node.process = identity
        native = process_startup_sample(identity)
        assert native["parent"] == os.getpid(), "internal startup is not our direct Child"
        assert not (node.directory / "control.json").exists(), "internal begin barrier did not precede control"
        write_receipt(trial.output / f"node-{node.index}.process.json", identity)
        record.update(identity=identity, before_begin_native=native)
        if name == "parent_eof_before_begin":
            child.stdin.close()
        elif name == "wrong_begin_instance":
            child.stdin.write(("begin " + "cd" * 32 + "\n").encode())
            child.stdin.flush()
        elif name == "acknowledgement_before_begin":
            child.stdin.write(("ready " + token + "\n").encode())
            child.stdin.flush()
        else:
            held_until = time.monotonic() + hold_seconds
            while time.monotonic() < held_until:
                assert time.monotonic() < trial.deadline, "original startup fixture deadline"
                assert child.poll() is None and not (node.directory / "control.json").exists(), "begin barrier released early"
                process_startup_sample(identity)
                time.sleep(min(.1, max(0, held_until - time.monotonic())))
            child.stdin.write(("begin " + token + "\n").encode())
            child.stdin.flush()
            def ready():
                if not (node.directory / "control.json").exists():
                    return False
                endpoint = json.loads((node.directory / "control.json").read_text())
                assert endpoint["pid"] == child.pid and endpoint["token"] == token, "internal checked endpoint instance changed"
                return trial.call(node, "status")["running"]
            wait_until(ready, time.monotonic() + trial.remaining(5))
            phases = [event for event in node.logs()[offset:]
                if event.get("event") == "startup_replay" and event.get("pid") == child.pid]
            assert [event["phase"] for event in phases] == ["begin", "checked"], phases
            assert all(event["instance_sha256"] == record["instance_sha256"] for event in phases)
            child.stdin.write(("ready " + token + "\n").encode())
            child.stdin.flush()
            child.stdin.close()
            time.sleep(.1)
            assert child.poll() is None, "checked acknowledged daemon died on parent pipe close"
            record["held_begin_seconds"] = hold_seconds
            record["checked_acknowledgement_survived_pipe_close"] = True
            stop_and_reap_direct_child(trial, node, child, record)
        if name in ("parent_eof_before_begin", "wrong_begin_instance", "acknowledgement_before_begin"):
            child.wait(timeout=trial.remaining(3))
            assert child.returncode != 0 and not (node.directory / "control.json").exists(), "refused internal startup became ready"
        else:
            assert record["actual_direct_child_reaped_during_stop"] and record["stop_cli"]["reaped"], "internal stop did not actually reap both direct children"
            assert child.returncode == 0, "acknowledged internal daemon did not stop normally"
        assert not process_group(identity), "internal owned group remained"
        record.update(result="pass", actual_direct_child_reaped=True,
            exit_code=child.returncode, owned_group_empty=True)
    except BaseException as error:
        record.update(result="fail", error_kind=type(error).__name__)
        raise
    finally:
        if child.stdin is not None and not child.stdin.closed:
            child.stdin.close()
        if child.poll() is None:
            if identity is not None:
                record["safety_cleanup"] = stop_owned_group(identity, child)
            else:
                # We still own this exact unreaped direct Popen child. There
                # is no unbound discovered daemon/group signal fallback.
                child.kill()
                child.wait(timeout=2)
        if child.stderr is not None:
            child.stderr.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--timeout", type=float, default=50)
    parser.add_argument("--mode", choices=["startup"], default="startup")
    args = parser.parse_args()
    assert 0 < args.timeout <= 50, "startup fixture requires an explicit finite at-most50s allowance"
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "startup")
    trial.summary.update(fixture="startup_lifeline", node_count=1,
        internal_required_cases=["parent_eof_before_begin", "wrong_begin_instance",
            "acknowledgement_before_begin", "checked_acknowledgement", "held_begin_after_old15s"],
        ordinary_large_replay_cancellation="OPEN_REQUIRES_ROOT_ADMITTED_ACTUAL_CORPUS",
        startup_resource_qualification="UNQUALIFIED",
        claim="internal tiny custody/handshake tests and preserved ordinary functional setup; no ordinary large replay or capacity qualification")
    try:
        node = Node(trial, 0)
        # The ordinary path initializes the existing identity/catalog/config.
        # Its functional result never repairs a raced pre-ready resource trace.
        node.start()
        node.stop()
        node.release_port()
        for name in trial.summary["internal_required_cases"]:
            internal_case(trial, node, name, 16 if name == "held_begin_after_old15s" else 0)
        assert len(trial.summary["internal_startup_cases"]) == 5
        assert all(case["result"] == "pass" for case in trial.summary["internal_startup_cases"])
        trial.summary["result"] = "pass"
    except BaseException as error:
        trial.summary.update(result="fail", error_kind=type(error).__name__)
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "startup", args.profile)
    print(json.dumps({"result": trial.summary["result"], "output": str(trial.output)}))
    return 0 if trial.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
