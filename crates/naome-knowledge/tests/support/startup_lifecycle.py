#!/usr/bin/env python3
"""Finite startup lifeline cases; internal custody is separate from ordinary CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import select
import socket
import subprocess
import time

from autonomous_lifecycle import (
    Node, Trial, digest, kernel_birth, process_group, process_identity, process_startup_sample,
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
        assert set(value) == {"running", "accepted_proofs", "interest", "proof_verification", "computation", "computation_reason"}, value
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


def handoff_abort_case(trial, node, name, active_ns):
    """Real installed pipe/nonce/TERM controls; never a mock abort receipt."""
    node.release_port()
    record = {"case": name, "result": "fail", "closure_errors": [],
              "ownership_disposition": "NO_PYTHON_GROUP_AUTHORITY"}
    trial.summary.setdefault("handoff_abort_cases", []).append(record)
    assert time.clock_gettime_ns(time.CLOCK_MONOTONIC) < active_ns, "original handoff control endpoint expired before launch"
    process = subprocess.Popen([str(trial.binary), "--json", "--startup-handoff", "start"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "NAOME_NODE_DIR": str(node.directory),
             "NAOME_STARTUP_HANDOFF_ACTIVE_NS": str(active_ns),
             "NAOME_STARTUP_HANDOFF_CLEANUP_NS": str(active_ns + 10_000_000_000)})
    record["actual_custodian_pid"] = process.pid
    frame = bytearray()
    offer = original = failure = None
    control_request = None
    control_issued = False
    stdout = stderr = b""
    lifeline = process.stdin
    forced = False
    try:
        while b"\n" not in frame:
            left = (active_ns - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) / 1e9
            assert left > 0, "original handoff control endpoint expired"
            if not select.select([process.stdout], [], [], min(.2, left))[0]:
                continue
            block = os.read(process.stdout.fileno(), 1024)
            frame.extend(block)
            assert block and len(frame) <= 4096, "missing/oversized original custody offer"
        candidate = json.loads(bytes(frame).split(b"\n", 1)[0])
        assert candidate["kind"] == "STARTUP_CHILD_CUSTODY_V1"
        assert candidate["active_ns"] == active_ns
        assert candidate["cleanup_ns"] == active_ns + 10_000_000_000
        assert type(candidate["pid"]) is int and candidate["pid"] > 1
        assert isinstance(candidate["token"], str) and len(candidate["token"]) == 64
        assert len(bytes.fromhex(candidate["token"])) == 32
        offer = candidate
        control_path = node.directory / "control.json"
        assert control_path.is_file() and not control_path.is_symlink() and control_path.stat().st_size <= 65536
        control = json.loads(control_path.read_bytes())
        assert control["pid"] == offer["pid"] and control["token"] == offer["token"]
        original = process_identity(offer["pid"])
        assert original is not None and original["pid"] == original["group"] == original["session"]
        assert str(trial.binary) in original["command"]
        expected_socket = "/tmp/naome-" + hashlib.sha256(os.fsencode(node.directory)).hexdigest() + ".sock"
        assert control["version"] == 1 and control["socket"] == expected_socket
        # Existing Node.accept_startup_offer protocol: a live nonce reply and
        # closing birth/session sample precede any Python cleanup authority.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            left = (active_ns - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) / 1e9
            assert left > 0, "original control endpoint expired before nonce RPC"
            channel.settimeout(min(2, left))
            channel.connect(control["socket"])
            left = (active_ns - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) / 1e9
            assert left > 0, "original control endpoint expired before nonce request"
            channel.settimeout(min(2, left))
            channel.sendall((json.dumps({"version": 1, "token": offer["token"], "operation": "status"}) + "\n").encode())
            reply = bytearray()
            while not reply.endswith(b"\n"):
                left = (active_ns - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) / 1e9
                assert left > 0, "original control endpoint expired during nonce reply"
                channel.settimeout(min(2, left))
                part = channel.recv(min(4096, 65537 - len(reply)))
                assert part and len(reply) + len(part) <= 65536
                reply.extend(part)
            value = json.loads(reply)
            assert set(value) == {"token", "status"} and value["token"] == offer["token"]
            assert value["status"]["running"] is True
        assert kernel_birth(offer["pid"]) == original["kernel_birth"]
        assert os.getpgid(offer["pid"]) == os.getsid(offer["pid"]) == offer["pid"]
        assert time.clock_gettime_ns(time.CLOCK_MONOTONIC) < active_ns, "original control endpoint expired before ownership publication"
        record["nonce_bound_original_identity"] = original
        record["ownership_disposition"] = "LIVE_NONCE_BOUND_ORIGINAL"
        node.process = original
        write_receipt(trial.output / f"handoff-{name}.original.json", original)
        published = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        record["identity_receipt_published_ns"] = published
        assert published < active_ns, "original control endpoint expired during ownership publication"
        expected_primary = {
            "eof_after_offer": "startup owner lifeline closed before custody acknowledgement",
            "wrong_nonce_after_offer": "startup owner instance mismatch",
            "term_after_offer": "node startup cancelled",
        }[name]
        # Reserve the existing800ms custodian cap inside the same original A.
        # A late fsync/native sample never earns a new control interval.
        before_control = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        assert active_ns - before_control >= 800_000_000, "insufficient original control headroom"
        assert process.returncode is None, "original retained Ci already reaped before control"
        control_request = {"case": name, "attempted_ns": before_control,
                           "expected_primary_abort": expected_primary,
                           "active_ns": active_ns, "operation_returned": False}
        record["control_request"] = control_request
        if name == "wrong_nonce_after_offer":
            wrong = "ff" * 32 if offer["token"] == "00" * 32 else "00" * 32
            message = ("owned " + wrong + "\n").encode()
            control_request["write_bytes"] = process.stdin.write(message)
            process.stdin.flush()
            assert control_request["write_bytes"] == len(message)
            control_request["operation"] = "WRONG_NONCE_WRITE_AND_FLUSH"
        elif name == "term_after_offer":
            # This exact direct Ci is still unreaped. Unlike Popen.terminate,
            # os.kill cannot silently poll/reap and skip the syscall. Success
            # alone is not delivery proof; the real primary error must match.
            os.kill(process.pid, signal.SIGTERM)
            control_request.update(operation="DIRECT_UNREAPED_CI_SIGTERM",
                                   signal_syscall_returned=True)
        else:
            lifeline.close()
            assert lifeline.closed
            control_request["operation"] = "ORIGINAL_OWNER_LIFELINE_EOF"
        control_request.update(operation_returned=True,
            completed_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC))
        assert control_request["completed_ns"] < active_ns, "named control completed after original A"
        control_issued = True
    except BaseException as error:
        failure = error
        record["error_kind"] = type(error).__name__
    finally:
        # Failure cleanup requests owned EOF;the real TERM control retains
        # its pipe while awaiting cancellation so EOF cannot supply its cause.
        # These are the existing custodian/leaf ends,never a fresh allowance.
        started = (control_request["attempted_ns"] if control_issued
                   else time.clock_gettime_ns(time.CLOCK_MONOTONIC))
        custodian_end = min(active_ns + 800_000_000, started + 700_000_000)
        leaf_end = active_ns + 1_000_000_000
        record.update(abort_started_ns=started, custodian_end_ns=custodian_end,
                      leaf_end_ns=leaf_end, forced_custodian_loss=False)
        try:
            try:
                # For a real TERM control keep EOF from racing its primary
                # cancellation cause. Error paths still request owned EOF;
                # communicate must not implicitly close this retained pipe.
                if failure is not None or not control_issued or name != "term_after_offer":
                    lifeline.close()
            except BaseException as error:
                record["closure_errors"].append("lifeline EOF: " + repr(error))
            finally:
                process.stdin = None
            left = (custodian_end - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) / 1e9
            if left <= 0:
                raise subprocess.TimeoutExpired("original handoff custodian", 0)
            stdout, stderr = process.communicate(timeout=left)
        except BaseException as error:
            record["closure_errors"].append("Rust abort completion wait: " + repr(error))
            try:
                lifeline.close()
            except BaseException as eof_error:
                record["closure_errors"].append("failure lifeline EOF: " + repr(eof_error))
        finally:
            if process.returncode is None:
                try:
                    left = (custodian_end - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) / 1e9
                    if left <= 0:
                        raise subprocess.TimeoutExpired("original handoff custodian", 0)
                    # An earlier pipe exception does not authorize premature Ci loss.
                    process.wait(timeout=left)
                except BaseException as error:
                    record["closure_errors"].append("custodian retained wait: " + repr(error))
                if process.returncode is None:
                    now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                    if custodian_end <= now < leaf_end:
                        forced = True
                        record["forced_custodian_loss"] = True
                        try:
                            process.kill()  # Only this exact retained direct Ci.
                            left = (leaf_end - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) / 1e9
                            assert left > 0, "original handoff leaf endpoint expired"
                            stdout, stderr = process.communicate(timeout=min(.15, left))
                        except BaseException as error:
                            record["closure_errors"].append("forced direct Ci close: " + repr(error))
                    else:
                        record["closure_errors"].append("custodian closure unknown at original leaf endpoint")
            for pipe in (lifeline, process.stdout, process.stderr):
                try:
                    pipe.close()
                except BaseException as error:
                    record["closure_errors"].append("custodian pipe close: " + repr(error))
            record.update(actual_custodian_reaped=process.returncode is not None,
                          custodian_exit_code=process.returncode,
                          pipes_closed=all(pipe.closed for pipe in (lifeline, process.stdout, process.stderr)))
    try:
        assert len(stdout) <= 65536 and len(stderr) <= 65536
        completions = []
        for line in (bytes(frame) + stdout).splitlines():
            try:
                value = json.loads(line)
            except (ValueError, UnicodeError) as error:
                record["closure_errors"].append("malformed custodian output: " + repr(error))
                continue
            if isinstance(value, dict) and value.get("kind") == "STARTUP_ABORT_COMPLETION_V1":
                completions.append(value)
        assert len(completions) == 1, "missing/duplicate real Rust abort completion"
        done = completions[0]
        assert done["active_ns"] == active_ns and done["cleanup_ns"] == active_ns + 10_000_000_000
        assert type(done["pid"]) is int and done["pid"] > 1
        assert isinstance(done["token"], str) and len(done["token"]) == 64
        assert len(bytes.fromhex(done["token"])) == 32
        assert offer is not None, "no validated original offer to bind abort completion"
        assert done["token"] == offer["token"] and done["pid"] == offer["pid"]
        proof = done["report"]
        assert done["timely"] is True
        assert done["observed_ns"] <= min(time.clock_gettime_ns(time.CLOCK_MONOTONIC), active_ns + 700_000_000)
        assert proof["complete"] is True and proof["original_child_reaped"] is True
        assert proof["original_child_pid"] == done["pid"]
        assert proof["errors"] == [] and proof["authority_lost"] is False and "clock_error" not in proof
        assert proof["session_state"] == "CONFIRMED_STOPPED_DETACHED_SESSION"
        assert proof["owned_group_empty"] is True
        assert process.returncode == 1 and not forced
        assert time.clock_gettime_ns(time.CLOCK_MONOTONIC) <= custodian_end
        assert record["actual_custodian_reaped"] and record["pipes_closed"]
        assert not record["closure_errors"], record["closure_errors"]
        assert original is not None and record.get("nonce_bound_original_identity") == original
        assert not process_group(original), "verified abort left the original owned group"
        assert time.clock_gettime_ns(time.CLOCK_MONOTONIC) <= custodian_end, "original custodian endpoint expired during group proof"
        record["actual_abort_completion"] = done
        # Retain the actual abort/identity evidence,then release ordinary-stop
        # ownership. An intentional abort has no graceful stopped-event oracle.
        record["ownership_disposition"] = "ORIGINAL_ABORT_COMPLETED"
        node.process = None
    except BaseException as error:
        record["closure_errors"].append("abort completion validation: " + repr(error))
    if failure is not None:
        raise failure
    assert not record["closure_errors"], record["closure_errors"]
    assert record["ownership_disposition"] == "ORIGINAL_ABORT_COMPLETED"
    assert control_issued and control_request["operation_returned"] is True
    assert control_request["attempted_ns"] <= control_request["completed_ns"] < active_ns
    assert control_request["attempted_ns"] <= record["actual_abort_completion"]["observed_ns"]
    expected_error = "naome: " + control_request["expected_primary_abort"] + "; owned startup child reaped\n"
    assert stderr.decode() == expected_error, "abort primary error does not prove the named control"
    control_request["causal_primary_abort"] = stderr.decode().rstrip("\n")
    assert time.clock_gettime_ns(time.CLOCK_MONOTONIC) <= custodian_end, "original custodian endpoint expired before case completion"
    record.update(result="pass", abort_elapsed_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC) - started,
                  native_runtime_qualification="THIS_EXACT_CASE_ONLY")


def run_handoff_abort_controls(trial, profile):
    # One original native endpoint for all three controls,not a reset per case.
    active_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC) + int(trial.remaining(15) * 1e9)
    try:
        for index, name in enumerate(("eof_after_offer", "wrong_nonce_after_offer", "term_after_offer")):
            node = Node(trial, index)
            handoff_abort_case(trial, node, name, active_ns)
        trial.summary["result"] = "pass"
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "startup-handoff", profile)
    return 0 if trial.summary["result"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--timeout", type=float, default=50)
    parser.add_argument("--mode", choices=["startup", "handoff"], default="startup")
    args = parser.parse_args()
    assert 0 < args.timeout <= 50, "startup fixture requires an explicit finite at-most50s allowance"
    trial = Trial(args.binary, args.output, args.timeout, args.profile, "startup")
    if args.mode == "handoff":
        # The caller separately admits the exact new installed binary and this
        # bounded native fixture;source presence is no executed-case evidence.
        return run_handoff_abort_controls(trial, args.profile)
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
