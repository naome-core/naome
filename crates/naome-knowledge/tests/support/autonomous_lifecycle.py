#!/usr/bin/env python3
"""Ordinary lifecycle and autonomous real direct, discovery and relay qualification."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import select
import socket
import subprocess
import sys
import time
import traceback
import zipfile
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from proof_network import digest, stored_objects, replace_catalog_payload


def assert_node_status(value, *, running, accepted_artifacts=None):
    assert set(value) == {"running", "accepted_artifacts", "artifact_verification", "computation", "computation_reason"}, value
    assert value["running"] is running, value
    assert type(value["accepted_artifacts"]) is int and value["accepted_artifacts"] >= 0, value
    if accepted_artifacts is not None:
        assert value["accepted_artifacts"] == accepted_artifacts, value
    assert value["artifact_verification"] == ("checked" if running else "not_run"), value
    if not running:
        assert value["computation"] == "stopped" and value["computation_reason"] is None, value
    elif value["computation"] == "running":
        assert value["computation_reason"] is None, value
    else:
        assert value["computation"] in {"pausing", "paused"}, value
        assert isinstance(value["computation_reason"], str) and value["computation_reason"], value


class StartupWrapperExit(RuntimeError):
    """An incomplete sample after the exact direct CLI Child was reaped."""


class Trial:
    def __init__(self, binary, output, timeout, profile, mode):
        self.binary = binary.resolve()
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.deadline = time.monotonic() + timeout
        self.nodes = []
        self.relay = None
        self.mode = mode
        self.summary = {
            "fixture": "ordinary_autonomous_lifecycle", "profile": profile,
            "binary": str(self.binary), "binary_sha256": digest(self.binary),
            "driver_sha256": digest(__file__), "timeout_seconds": timeout,
            "mode": mode, "node_count": 3 if mode == "dht" else 2,
            "commands": [], "scenarios": {}, "processes": [],
            "claim": "local process, real checking and libp2p exchange with bounded question/proof providers and structural selection",
        }
        read_end, self.lifeline = os.pipe()
        self.guardian_log = (self.output / "guardian.log").open("w")
        self.guardian = subprocess.Popen([
            sys.executable, str(Path(__file__).resolve()), "--guardian",
            "--binary", str(self.binary), "--output", str(self.output),
            "--lifetime", str(timeout + 30), "--fd", str(read_end),
        ], pass_fds=(read_end,), stdin=subprocess.DEVNULL,
            stdout=self.guardian_log, stderr=subprocess.STDOUT, start_new_session=True)
        os.close(read_end)
        self.guardian_identity = process_identity(self.guardian.pid)
        assert self.guardian_identity is not None
        write_receipt(self.output / "guardian-process.json", self.guardian_identity)

    def remaining(self, maximum=10):
        remaining = self.deadline - time.monotonic()
        assert remaining > 0, "whole autonomous lifecycle deadline exceeded"
        return min(maximum, remaining)

    def call(self, node, verb, success=True, cleanup=False, text=None):
        command = [str(self.binary), "--json", verb]
        if text is not None:
            command.append(text)
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, env={**os.environ, "NAOME_NODE_DIR": str(node.directory)},
                                timeout=getattr(self,"cleanup_timeout",5) if cleanup else self.remaining(getattr(self,"command_timeout",10)))
        self.summary["commands"].append({"node": node.index, "command": command,
            "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        if not success:
            assert result.returncode != 0, f"ordinary CLI accepted {verb!r}"
            assert result.stdout == "", "rejected commands must not publish status"
            return None
        assert result.returncode == 0, f"{verb}: {result.stderr}"
        assert result.stderr == "", f"{verb}: {result.stderr}"
        value = json.loads(result.stdout)
        assert set(value) == {"running", "accepted_artifacts", "artifact_verification", "computation", "computation_reason"}, value
        assert isinstance(value["running"], bool), value
        assert type(value["accepted_artifacts"]) is int and value["accepted_artifacts"] >= 0, value

        return value

    def begin_functional_start(self, node, mode):
        record = {"node": node.index, "mode": mode, "wrapper": None,
            "pre_ready_capture": False, "capture_pending": True,
            "complete_pre_ready_resource_frames": 0,
            "sampled_peak_actor_rss_bytes": None,
            "coverage": "UNQUALIFIED_FUNCTIONAL_ENDPOINT_ONLY",
            "startup_resource_qualification": "UNQUALIFIED",
            "clock_domain": "driver_process_local_monotonic",
            "claim": "ordinary CLI readiness and post-ready daemon custody only; no pre-ready/resource qualification"}
        self.summary.setdefault("startup_attempts", []).append(record)
        node.startup_record = record
        return record

    def start(self, node, strict_startup=False, cancel_replay=False):
        """Own the ordinary CLI and witness its actual child before readiness."""
        command = [str(self.binary), "--json", "start"]
        if not (strict_startup or cancel_replay):
            # Functional readiness retains post-ready native daemon custody.
            # It never qualifies pre-ready custody or startup resource frames.
            end = self.deadline
            cleanup_end = end + 2
            record = self.begin_functional_start(node, "ordinary_start")
            process = None
            try:
                remaining = end - time.monotonic()
                assert remaining > 0, "ordinary functional startup original deadline expired"
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                    env={**os.environ, "NAOME_NODE_DIR": str(node.directory)})
                record["wrapper_pid"] = process.pid
                record["wrapper_reaped"] = False
                remaining = end - time.monotonic()
                assert remaining > 0, "ordinary functional startup original deadline expired"
                stdout, stderr = process.communicate(timeout=remaining)
                record.update(cli_exit_code=process.returncode, wrapper_reaped=True)
                assert time.monotonic() < end, "ordinary functional startup original deadline expired"
                self.summary["commands"].append({"node": node.index, "command": command,
                    "exit_code": process.returncode, "stdout": stdout.decode(), "stderr": stderr.decode()})
                assert process.returncode == 0 and not stderr, f"start: {stderr.decode()}"
                status = json.loads(stdout)
                assert set(status) == {"running", "accepted_artifacts", "artifact_verification", "computation", "computation_reason"}, status
                assert isinstance(status["running"], bool) and status["running"] is True, status
                assert type(status["accepted_artifacts"]) is int and status["accepted_artifacts"] >= 0, status

                node.capture_process()
                record.update(daemon=node.process, capture_pending=True,
                    post_ready_native_daemon_captured=True)
                assert time.monotonic() < end, "ordinary functional startup post-ready capture expired"
                return status
            except BaseException as error:
                record.update(error_kind=type(error).__name__, functional_startup_failed=True)
                if process is not None:
                    record["unresolved_wrapper_requires_guardian_cleanup"] = process.returncode is None
                    if process.returncode is None:
                        remaining = cleanup_end - time.monotonic()
                        assert remaining > 0, "ordinary functional wrapper signal original deadline expired"
                        process.kill()  # Only this exact own unreaped CLI Child.
                        if process.returncode is not None:
                            record.update(cli_exit_code=process.returncode, wrapper_reaped=True,
                                unresolved_wrapper_requires_guardian_cleanup=False)
                        remaining = cleanup_end - time.monotonic()
                        assert remaining > 0, "ordinary functional wrapper cleanup original deadline expired"
                        process.communicate(timeout=min(2, remaining))
                        record.update(cli_exit_code=process.returncode, wrapper_reaped=True,
                            unresolved_wrapper_requires_guardian_cleanup=False)
                        assert time.monotonic() < cleanup_end, "ordinary functional wrapper cleanup original deadline expired"
                endpoint_path = node.directory / "control.json"
                if endpoint_path.exists():
                    # Endpoint custody is safety cleanup only after failure.
                    node.capture_process()
                if node.process is not None:
                    record["cleanup"] = stop_owned_group(node.process)
                raise
        before_events = node.logs()
        event_boundary = len(before_events)
        prefix_sha256 = hashlib.sha256(json.dumps(before_events, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        prior_phase_hashes = {event.get("instance_sha256") for event in before_events
            if event.get("event") == "startup_replay"
            and isinstance(event.get("instance_sha256"), str)
            and len(event["instance_sha256"]) == 64
            and all(character in "0123456789abcdef" for character in event["instance_sha256"])}
        assert len(prior_phase_hashes) <= 4096, "startup prior phase-instance inventory capacity"
        del before_events
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            env={**os.environ, "NAOME_NODE_DIR": str(node.directory)})
        wrapper = None
        attempt = len(self.summary.setdefault("startup_attempts", []))
        record = {"node": node.index, "wrapper": wrapper, "pre_ready_capture": False,
            "capture_pending": True, "complete_pre_ready_resource_frames": 0,
            "known_sampled_actor_rss_lower_bound_peak_bytes": 0,
            "coverage": "UNQUALIFIED", "sampled_peak_actor_rss_bytes": None,
            "observer_reserve_bytes": 64 * 1024**2,
            "clock_domain": "driver_process_local_monotonic",
            "prelaunch_log_event_boundary": event_boundary,
            "prelaunch_log_prefix_sha256": prefix_sha256,
            "prelaunch_phase_instance_sha256": sorted(prior_phase_hashes),
            "claim": "sequential native actor samples; no simultaneous or instantaneous peak claim"}
        self.summary["startup_attempts"].append(record)
        node.startup_record = record
        trace_path = self.output / f"node-{node.index}.startup-{attempt}.ndjson"
        trace_bytes = 0
        record.update(trace=str(trace_path), trace_bytes=0)
        endpoint_path = node.directory / "control.json"
        daemon = None
        end = min(self.deadline, time.monotonic() + 1800)
        observation = None

        def capture_rss(role, sample):
            # Raw RSS may precede a failed closing-birth check. Preserve its
            # known negative without granting unfinished custody authority.
            captured = {**sample, "role": role,
                "custody": "CLOSING_NATIVE_CHECK_PENDING_NOT_SIGNAL_AUTHORITY"}
            observation["captured_native_rss"][role] = captured
            highest = observation["highest_captured_native_rss"].get(role)
            if highest is None or captured["rss_bytes"] > highest["rss_bytes"]:
                observation["highest_captured_native_rss"][role] = captured
            actors = observation["highest_captured_native_rss"].values()
            assert len({item["pid"] for item in actors}) == len(observation["highest_captured_native_rss"]), "startup RSS roles alias a PID"
            lower_bound = sum(max(0, item["rss_bytes"]) for item in observation["highest_captured_native_rss"].values())
            observation["known_sequential_rss_lower_bound_bytes"] = lower_bound
            record["known_sampled_actor_rss_lower_bound_peak_bytes"] = max(
                record["known_sampled_actor_rss_lower_bound_peak_bytes"], lower_bound)
            if lower_bound + record["observer_reserve_bytes"] > 512 * 1024**2:
                record["known_startup_rss_breach"] = {
                    "lower_bound_bytes": lower_bound,
                    "observer_reserve_bytes": record["observer_reserve_bytes"],
                    "ceiling_bytes": 512 * 1024**2,
                    "closing_native_custody": "PENDING_NOT_QUALIFIED"}
                raise AssertionError("known startup sampled RSS lower bound plus reserve exceeded")

        try:
            wrapper = process_identity(process.pid)
            record["wrapper"] = wrapper
            assert wrapper is not None or process.poll() is not None, "live ordinary startup wrapper identity unavailable"
            with trace_path.open("xb") as trace:
                while process.poll() is None:
                    try:
                        started = time.monotonic()
                        assert started < end, "ordinary startup original deadline expired"
                        before_frame_endpoint = endpoint_path.exists()
                        observation = {"started": started, "captured_native_rss": {},
                            "highest_captured_native_rss": {}, "complete_four_actor_frame": False}
                        record["latest_native_actor_observation"] = observation
                        if daemon is None:
                            before_endpoint = endpoint_path.exists()
                            children = direct_children(wrapper, process)
                            assert len(children) <= 1, "ordinary launcher has unexpected children"
                            if children:
                                candidate = process_identity(children[0])
                                if candidate is None:
                                    try:
                                        os.kill(children[0], 0)
                                    except ProcessLookupError:
                                        continue
                                    raise AssertionError("live actual startup child native identity unavailable")
                                if candidate is not None and candidate["group"] == candidate["session"] == candidate["pid"]:
                                    # The PPID and native wrapper birth establish
                                    # custody. Command text is supplementary only.
                                    sample = process_startup_sample(candidate, captured=lambda item: capture_rss("daemon", item))
                                    record["early_native_daemon"] = sample
                                    if sample["parent"] != wrapper["pid"] and process.poll() is not None:
                                        raise StartupWrapperExit("startup child reparented after exact launcher exit; incomplete capture")
                                    assert sample["parent"] == wrapper["pid"], "startup child parent changed"
                                    startup_birth(wrapper, process)
                                    assert str(self.binary) in candidate["command"], "owned child executable mismatch"
                                    daemon = candidate
                                    node.process = daemon
                                    write_receipt(self.output / f"node-{node.index}.process.json", daemon)
                                    record.update(daemon=daemon,
                                        early_native_daemon=sample,
                                        pre_ready_capture=not before_endpoint and not endpoint_path.exists(),
                                        coverage="NATIVE_PARENT_CHILD_CUSTODY_ONLY")
                        actors = [("driver", process_identity(os.getpid())),
                            ("guardian", self.guardian_identity), ("wrapper", wrapper)]
                        if daemon is not None:
                            actors.append(("daemon", daemon))
                        samples = []
                        for role, identity in actors:
                            assert identity is not None, f"startup {role} identity unavailable"
                            item = process_startup_sample(identity, process if role == "wrapper" else None,
                                captured=lambda value: capture_rss(role, value))
                            item["role"] = role
                            samples.append(item)
                        startup_birth(wrapper, process)
                        completed = time.monotonic()
                        assert completed - started < 2 and completed < end, "startup actor sample stale"
                        total = sum(item["rss_bytes"] for item in samples)
                        assert total + record["observer_reserve_bytes"] <= 512 * 1024**2, "startup sampled RSS reserve exceeded"
                        complete = (len(samples) == 4
                            and {item["role"] for item in samples} == {"driver", "guardian", "wrapper", "daemon"}
                            and len({item["pid"] for item in samples}) == 4)
                        pre_ready_frame = (complete and record["pre_ready_capture"]
                            and not before_frame_endpoint and not endpoint_path.exists())
                        observation.update(completed=completed, complete_four_actor_frame=complete,
                            pre_ready_frame=pre_ready_frame, closing_native_actors=samples)
                        record["sampled_peak_actor_rss_bytes"] = max(
                            record["sampled_peak_actor_rss_bytes"] or 0, total)
                        frame = {"started": started, "completed": completed, "actors": samples,
                            "sequential_sampled_rss_bytes": total,
                            "observer_reserve_bytes": record["observer_reserve_bytes"],
                            "complete_four_actor_frame": complete, "pre_ready_frame": pre_ready_frame}
                        body = (json.dumps(frame, separators=(",", ":")) + "\n").encode()
                        assert len(body) <= 8192 and trace_bytes + len(body) <= 32 * 1024**2, "startup trace limit"
                        trace.write(body)
                        trace.flush()
                        trace_bytes += len(body)
                        record["trace_bytes"] = trace_bytes
                        published = time.monotonic()
                        observation["trace_published"] = published
                        assert published - started < 2 and published < end, "startup frame publication stale"
                        if pre_ready_frame:
                            record["complete_pre_ready_resource_frames"] += 1
                            record["last_complete_pre_ready_resource_frame"] = {
                                "started": started, "completed": completed, "published": published,
                                "sequential_sampled_rss_bytes": total,
                                "observer_reserve_bytes": record["observer_reserve_bytes"]}
                        if cancel_replay and daemon is not None:
                            startup_birth(daemon)
                            events = node.logs()
                            assert len(events) >= event_boundary, "startup attempt log truncated"
                            prefix = hashlib.sha256(json.dumps(events[:event_boundary], sort_keys=True,
                                separators=(",", ":")).encode()).hexdigest()
                            assert prefix == prefix_sha256, "startup prelaunch log prefix changed"
                            phases = [(event_boundary + index, event) for index, event in enumerate(events[event_boundary:])
                                if event.get("event") == "startup_replay" and event.get("pid") == daemon["pid"]]
                            if phases:
                                hashes = {event.get("instance_sha256") for _, event in phases}
                                assert len(hashes) == 1, "startup attempt phase-instance changed"
                                instance = next(iter(hashes))
                                assert isinstance(instance, str) and len(instance) == 64 and all(
                                    character in "0123456789abcdef" for character in instance), "startup attempt phase-instance malformed"
                                assert instance not in prior_phase_hashes, "startup replay phase reused prelaunch instance"
                                assert [event.get("phase") for _, event in phases] in (["begin"], ["begin", "checked"]), "startup current attempt phase order malformed"
                                assert record.get("replay_instance_sha256", instance) == instance, "startup bound replay instance changed"
                                record["replay_instance_sha256"] = instance
                            startup_birth(daemon)
                            if phases and phases[-1][1]["phase"] == "begin" and not endpoint_path.exists():
                                assert record["pre_ready_capture"], "cancellation lacks native pre-ready custody"
                                startup_birth(wrapper, process)
                                assert time.monotonic() < end, "startup cancellation original deadline expired"
                                process.send_signal(signal.SIGTERM)
                                record["cancelled_during_observed_replay"] = True
                                record["cancelled_replay_phase"] = {"log_event_offset": phases[-1][0],
                                    "pid": daemon["pid"], "phase": "begin", "instance_sha256": instance}
                                break
                        time.sleep(min(.01, max(0, end - time.monotonic())))
                    except StartupWrapperExit:
                        record['incomplete_sample_after_observed_wrapper_exit'] = True
                        break
            stdout, stderr = process.communicate(timeout=max(.001, end - time.monotonic()))
            record.update(cli_exit_code=process.returncode, wrapper_reaped=True,
                trace=str(trace_path), trace_bytes=trace_bytes, trace_sha256=digest(trace_path))
            self.summary["commands"].append({"node": node.index, "command": command,
                "exit_code": process.returncode, "stdout": stdout.decode(), "stderr": stderr.decode()})
            if strict_startup:
                assert daemon is not None and record["pre_ready_capture"], "ordinary startup lacks native pre-ready custody/RSS"
                assert record["complete_pre_ready_resource_frames"] > 0, "ordinary startup lacks a complete fresh four-actor pre-ready resource frame"
            if cancel_replay:
                assert record.get("cancelled_during_observed_replay") is True, "replay ended before cancellation; case unqualified"
                assert process.returncode != 0 and stdout == b"", "cancelled startup published success"
                assert b"owned startup child reaped" in stderr, "launcher did not confirm actual child reap"
                end_cleanup = min(self.deadline, time.monotonic() + 10)
                wait_until(lambda: not process_group(daemon), end_cleanup)
                record.update(coverage="CANCELLED_REPLAY_NATIVE_CUSTODY_ONLY", owned_group_empty=True,
                    launcher_reports_daemon_reaped=True)
                return None
            assert process.returncode == 0 and not stderr, f"start: {stderr.decode()}"
            status = json.loads(stdout)
            assert set(status) == {"running", "accepted_artifacts", "artifact_verification", "computation", "computation_reason"} and status["running"] is True, status
            if record["pre_ready_capture"] and record["complete_pre_ready_resource_frames"]:
                record["coverage"] = "COMPLETE_SAMPLED_PRE_READY_NATIVE_CUSTODY_ONLY"
            elif record["pre_ready_capture"]:
                record["coverage"] = "UNQUALIFIED_PRE_READY_RESOURCE_FRAME_MISSING"
            else:
                record["coverage"] = "UNQUALIFIED_PRE_READY_CAPTURE_RACED"
            return status
        except BaseException as error:
            record.update(coverage="UNQUALIFIED", error_kind=type(error).__name__)
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=2)
            record.update(cli_exit_code=process.returncode, wrapper_reaped=True)
            if endpoint_path.exists():
                # Existing endpoint custody is available only for safety
                # cleanup; it cannot repair a missing pre-ready observation.
                node.capture_process()
            if node.process is not None:
                record["cleanup"] = stop_owned_group(node.process)
            raise

    def wait(self, predicate, maximum=15):
        end = time.monotonic() + self.remaining(maximum)
        return wait_until(predicate, end)

    def close(self):
        failures = []
        for node in reversed(self.nodes):
            try:
                node.stop(cleanup=True)
            except Exception as error:
                failures.append(f"{type(error).__name__}: {error}")
                traceback.print_exc()
                try:
                    node.emergency_cleanup()
                except Exception as cleanup_error:
                    failures.append(str(cleanup_error))
            finally:
                node.release_port()
        if self.relay is not None:
            try:
                self.relay.stop()
            except Exception as error:
                failures.append(str(error))
                try:
                    self.relay.emergency_cleanup()
                except Exception as cleanup_error:
                    failures.append(str(cleanup_error))
        self.summary["cleanup"] = {"errors": failures,
            "all_owned_groups_empty": all(not process_group(node.process) for node in self.nodes)
            and (self.relay is None or not process_group(self.relay.identity))}
        os.close(self.lifeline)
        try:
            self.guardian.wait(timeout=30)
            assert self.guardian.returncode == 0, "independent daemon cleanup guardian failed"
        except Exception as error:
            failures.append(str(error))
            if self.guardian.poll() is None:
                os.killpg(self.guardian.pid, signal.SIGTERM)
                try:
                    self.guardian.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(self.guardian.pid, signal.SIGKILL)
                    self.guardian.wait(timeout=3)
        finally:
            self.guardian_log.close()
        if failures or not self.summary["cleanup"]["all_owned_groups_empty"]:
            self.summary["result"] = "fail"


def write_receipt(path, value):
    temporary = path.with_suffix(path.suffix + ".incoming")
    with temporary.open("w") as file:
        file.write(json.dumps(value, indent=2) + "\n")
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)


def wait_until(predicate, deadline):
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError("bounded autonomous lifecycle observation timed out")


def retain_evidence(output, summary, mode, profile):
    private = {"identity.key", "control.json", ".control-incoming", "knowledge.lock", "lifecycle.lock"}
    paths = [path for path in sorted(output.rglob("*"))
        if path.is_file() and not path.is_symlink()
        and path.name != "summary.json" and not private.intersection(path.relative_to(output).parts)]
    summary["artifacts"] = {str(path.relative_to(output)): digest(path) for path in paths}
    archive = output.parent / f"autonomous-{mode}-ci-{profile}-{os.getpid()}.zip"
    if os.environ.get("GITHUB_ACTIONS") == "true":
        summary["ci_archive"] = str(archive)
    write_receipt(output / "summary.json", summary)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path in [output / "summary.json", *paths]:
                assert path.resolve().is_relative_to(output)
                assert not private.intersection(path.relative_to(output).parts)
                bundle.write(path, str(path.relative_to(output)))


def kernel_birth(pid):
    """Bind cleanup to kernel birth ticks/time, including subsecond Darwin time."""
    if sys.platform == "linux":
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
            return ["linux_proc_start_ticks", int(fields[19])]
        except FileNotFoundError:
            return None
    if sys.platform == "darwin":
        # Darwin's documented PROC_PIDTBSDINFO proc_bsdinfo layout. The last
        # two fields are kernel start timeval seconds and microseconds.
        class BsdInfo(ctypes.Structure):
            _fields_ = [("prefix", ctypes.c_uint32 * 12), ("comm", ctypes.c_char * 16),
                ("name", ctypes.c_char * 32), ("nfiles", ctypes.c_uint32),
                ("pgid", ctypes.c_uint32), ("jobc", ctypes.c_uint32),
                ("tdev", ctypes.c_uint32), ("tpgid", ctypes.c_uint32),
                ("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64),
                ("start_usec", ctypes.c_uint64)]
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        query = library.proc_pidinfo
        query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        query.restype = ctypes.c_int
        info = BsdInfo()
        if query(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
            return None
        assert info.prefix[3] == pid, "kernel process identity changed during read"
        return ["darwin_proc_start_time", int(info.start_sec), int(info.start_usec)]
    raise AssertionError("kernel process birth binding requires supported Linux or macOS")


def process_identity(pid):
    if pid is None:
        return None
    born = kernel_birth(pid)
    if born is None:
        return None
    result = subprocess.run(["ps", "-p", str(pid), "-o", "pid=,pgid=,lstart=,command="],
                            capture_output=True, text=True, timeout=2)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    parts = result.stdout.strip().split(None, 7)
    assert len(parts) == 8, result.stdout
    try:
        session = os.getsid(pid)
    except ProcessLookupError:
        return None
    if kernel_birth(pid) != born:
        return None
    return {"pid": int(parts[0]), "group": int(parts[1]), "session": session,
            "born": " ".join(parts[2:7]), "kernel_birth": born, "command": parts[7]}


def startup_birth(identity, exit_witness=None):
    born = kernel_birth(identity["pid"])
    if born is None and exit_witness is not None and exit_witness.poll() is not None:
        raise StartupWrapperExit("exact startup wrapper exited during an incomplete sample")
    assert born == identity["kernel_birth"], "startup actor birth changed or unavailable"


def direct_children(parent, exit_witness=None):
    """Use an actual live PPID relationship, never a command-name search."""
    startup_birth(parent, exit_witness)
    result = subprocess.run(["ps", "-A", "-o", "pid=,ppid="],
        capture_output=True, text=True, timeout=2, check=True)
    rows = result.stdout.splitlines()
    assert len(rows) <= 4096 and len(result.stdout) <= 256 * 1024, "startup public inventory capacity"
    children = []
    for row in rows:
        fields = row.split()
        assert len(fields) == 2 and all(part.isdigit() for part in fields), "startup public parent metadata malformed"
        pid, ppid = map(int, fields)
        if ppid == parent["pid"]:
            children.append(pid)
    startup_birth(parent, exit_witness)
    return children


def process_startup_sample(identity, exit_witness=None, captured=None):
    """Native positive RSS and parent/group/session for one retained actor."""
    # Optional raw capture preserves negatives; only the returned sample has
    # passed every original closing native identity and membership check.
    pid = identity["pid"]
    startup_birth(identity, exit_witness)
    try:
        if sys.platform == "linux":
            with Path(f"/proc/{pid}/stat").open("rb") as source:
                raw = source.read(16385)
            assert len(raw) <= 16384, "startup native stat width"
            head, tail = raw.rsplit(b") ", 1)
            fields = tail.split()
            assert int(head.split(b" (", 1)[0]) == pid and len(fields) >= 22, "startup native stat layout"
            assert fields[0] != b"Z", "startup actor is a zombie"
            parent, group, session = map(int, fields[1:4])
            assert ["linux_proc_start_ticks", int(fields[19])] == identity["kernel_birth"], "startup native stat birth mismatch"
            page = os.sysconf("SC_PAGESIZE")
            assert page > 0, "startup native page width unavailable"
            rss = int(fields[21]) * page
            measurement = "linux_proc_stat_native_rss"
        elif sys.platform == "darwin":
            class BsdInfo(ctypes.Structure):
                _fields_ = [("prefix", ctypes.c_uint32 * 12), ("comm", ctypes.c_char * 16),
                    ("name", ctypes.c_char * 32), ("nfiles", ctypes.c_uint32),
                    ("pgid", ctypes.c_uint32), ("jobc", ctypes.c_uint32),
                    ("tdev", ctypes.c_uint32), ("tpgid", ctypes.c_uint32),
                    ("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64),
                    ("start_usec", ctypes.c_uint64)]
            class TaskInfo(ctypes.Structure):
                _fields_ = [("times", ctypes.c_uint64 * 6), ("counters", ctypes.c_int32 * 12)]
            library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            query = library.proc_pidinfo
            query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
            query.restype = ctypes.c_int
            bsd, task = BsdInfo(), TaskInfo()
            width = query(pid, 3, 0, ctypes.byref(bsd), ctypes.sizeof(bsd))
            if width != ctypes.sizeof(bsd):
                startup_birth(identity, exit_witness)
            assert width == ctypes.sizeof(bsd), "startup native BSD unavailable"
            assert bsd.prefix[3] == pid and bsd.prefix[1] != 5, "startup native BSD actor mismatch or zombie"
            assert ["darwin_proc_start_time", int(bsd.start_sec), int(bsd.start_usec)] == identity["kernel_birth"], "startup native BSD birth mismatch"
            width = query(pid, 4, 0, ctypes.byref(task), ctypes.sizeof(task))
            if width != ctypes.sizeof(task):
                startup_birth(identity, exit_witness)
            assert width == ctypes.sizeof(task), "startup native task RSS unavailable"
            if captured is not None:
                captured({"pid": pid, "parent": int(bsd.prefix[4]), "group": int(bsd.pgid),
                    "session": None, "kernel_birth": identity["kernel_birth"],
                    "rss_bytes": int(task.times[1]), "measurement_source": "darwin_proc_pidtaskinfo_resident_size"})
            parent, group, session = int(bsd.prefix[4]), int(bsd.pgid), os.getsid(pid)
            rss = int(task.times[1])
            measurement = "darwin_proc_pidtaskinfo_resident_size"
        else:
            raise AssertionError("startup native samples require a supported platform")
        if captured is not None:
            captured({"pid": pid, "parent": parent, "group": group, "session": session,
                "kernel_birth": identity["kernel_birth"], "rss_bytes": rss, "measurement_source": measurement})
        assert rss > 0, "startup live actor RSS is unavailable or nonpositive"
        assert group == identity["group"] == os.getpgid(pid), "startup actor group changed"
        assert session == identity["session"] == os.getsid(pid), "startup actor session changed"
        startup_birth(identity, exit_witness)
        return {"pid": pid, "parent": parent, "group": group, "session": session,
            "kernel_birth": identity["kernel_birth"], "rss_bytes": rss, "measurement_source": measurement}
    except (FileNotFoundError, ProcessLookupError):
        startup_birth(identity, exit_witness)
        raise


def process_cpu_sample(identity):
    """Read CPU time at native resolution for the same retained process birth."""
    assert identity is not None, "CPU witness requires a live process identity"
    pid = identity["pid"]
    assert kernel_birth(pid) == identity["kernel_birth"], "CPU witness process birth changed"
    sample = {"pid": pid, "kernel_birth": identity["kernel_birth"]}
    if sys.platform == "linux":
        # procps TIME displays whole seconds; /proc retains user/system ticks.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        assert ["linux_proc_start_ticks", int(fields[19])] == identity["kernel_birth"]
        ticks_per_second = os.sysconf("SC_CLK_TCK")
        assert ticks_per_second > 0, "CPU clock resolution unavailable"
        user_ticks, system_ticks = int(fields[11]), int(fields[12])
        sample.update(measurement_source="linux_proc_stat_ticks", user_ticks=user_ticks,
            system_ticks=system_ticks, ticks_per_second=ticks_per_second,
            cpu_seconds=(user_ticks + system_ticks) / ticks_per_second)
    elif sys.platform == "darwin":
        value = subprocess.check_output(["ps", "-p", str(pid), "-o", "time="],
            text=True, timeout=2).strip()
        sample.update(measurement_source="darwin_ps_time_fractional", raw_time=value,
            cpu_seconds=sum(float(part)*60**index for index,part in enumerate(reversed(value.split(":")))))
    else:
        raise AssertionError("CPU witness requires supported Linux or macOS")
    assert kernel_birth(pid) == identity["kernel_birth"], "CPU witness process birth changed"
    return sample


def process_group(identity):
    if identity is None:
        return []
    result = subprocess.run(["ps", "-A", "-o", "pid=,pgid=,command="],
                            capture_output=True, text=True, timeout=2, check=True)
    members = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and int(parts[1]) == identity["group"]:
            members.append({"pid": int(parts[0]), "command": parts[2]})
    return members


def stop_owned_group(identity, child=None):
    """Signal only a retained, still-identical process in its exclusive session."""
    record = {"identity": identity, "signals": [], "identity_match": False}
    for stop in [signal.SIGTERM, signal.SIGKILL]:
        if child is not None:
            child.poll()
        if not process_group(identity):
            break
        if (identity is None or identity["pid"] != identity["group"]
                or identity["session"] != identity["pid"]
                or process_identity(identity["pid"]) != identity):
            record["refused"] = "retained process identity no longer matches"
            break
        record["identity_match"] = True
        try:
            os.killpg(identity["group"], stop)
            record["signals"].append(stop.name)
        except ProcessLookupError:
            break
        end = time.monotonic() + 2
        while time.monotonic() < end:
            if child is not None:
                child.poll()
            if not process_group(identity):
                break
            time.sleep(0.05)
    if child is not None:
        child.wait(timeout=2)
        record["child_reaped"] = True
        record["exit_code"] = child.returncode
    record["owned_group_empty"] = not process_group(identity)
    return record


def guardian_main():
    """The fixture owns detached daemons even after abrupt driver loss."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--guardian", action="store_true", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fd", required=True, type=int)
    parser.add_argument("--lifetime", required=True, type=float)
    args = parser.parse_args()
    record = {"pid": os.getpid(), "errors": [], "nodes": []}
    if select.select([args.fd], [], [], args.lifetime)[0]:
        assert os.read(args.fd, 1) == b"", "unexpected guardian lifeline bytes"
        record["reason"] = "driver_lifeline_closed"
    else:
        record["reason"] = "independent_wall_timeout"
        record["errors"].append("driver exceeded its independent lifetime")
    os.close(args.fd)
    for directory in sorted(args.output.glob("node-*")):
        if not directory.is_dir():
            continue
        node_record = {"directory": directory.name}
        try:
            result = subprocess.run([str(args.binary), "--json", "stop"], stdin=subprocess.DEVNULL,
                capture_output=True, text=True, env={**os.environ, "NAOME_NODE_DIR": str(directory)}, timeout=5)
            assert result.returncode == 0, result.stderr
            status = json.loads(result.stdout)
            assert not status["running"]
            node_record["status"] = status
        except Exception as error:
            node_record["stop_error"] = str(error)
        identity_receipt = args.output / f"{directory.name}.process.json"
        try:
            if identity_receipt.exists():
                identity = json.loads(identity_receipt.read_text())
                node_record["cleanup"] = stop_owned_group(identity)
                assert node_record["cleanup"]["owned_group_empty"], "node group remained after guardian cleanup"
            else:
                assert "stop_error" not in node_record, "stop failed without a retained kernel process receipt"
        except Exception as error:
            record["errors"].append(f"{directory.name}: {error}")
        record["nodes"].append(node_record)
    relay_receipt = args.output / "relay-process.json"
    if relay_receipt.exists():
        try:
            identity = json.loads(relay_receipt.read_text())
            record["relay_cleanup"] = stop_owned_group(identity)
            assert record["relay_cleanup"]["owned_group_empty"], "relay group remained after guardian cleanup"
        except Exception as error:
            record["errors"].append(str(error))
    # Process-backed research owns independent groups. Their node/lifeline
    # teardown must close them even after this fixture's driver disappears.
    research_receipt=args.output/"research-processes.json"
    if research_receipt.exists():
        try:
            identities=json.loads(research_receipt.read_text())
            assert isinstance(identities,list) and len(identities)<=256
            groups={identity["group"] for identity in identities}
            assert all(identity["pid"]>1 and identity["kernel_birth"]
                and str(args.binary.resolve()) in identity["command"]
                and "--research-" in identity["command"] for identity in identities)
            def remaining():
                result=subprocess.run(["ps","-A","-o","pid=,pgid=,command="],
                    capture_output=True,text=True,timeout=2,check=True)
                return [line.strip() for line in result.stdout.splitlines()
                    if len(line.split(None,2))==3 and int(line.split(None,2)[1]) in groups]
            deadline=time.monotonic()+5
            members=remaining()
            while members and time.monotonic()<deadline:
                time.sleep(.05);members=remaining()
            record["research_cleanup"]={"retained_processes":len(identities),"remaining_groups":members}
            assert not members,"research group remained after node/lifeline teardown"
        except Exception as error:
            record["errors"].append("research cleanup: "+str(error))
    write_receipt(args.output / "guardian-receipt.json", record)
    return 1 if record["errors"] else 0


class Relay:
    def __init__(self, trial, binary):
        self.trial, self.identity = trial, None
        self.process, self.log = None, None
        self.emergency_record = None
        trial.relay = self
        directory = trial.output / "relay"
        result = subprocess.run([str(binary), "init", str(directory)], stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=trial.remaining())
        assert result.returncode == 0, result.stderr
        self.peer = json.loads(result.stdout)["peer_id"]
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        self.port = reservation.getsockname()[1]
        config = trial.output / "relay.config.json"
        config.write_text(json.dumps({"directory": str(directory), "listen": f"/ip4/127.0.0.1/tcp/{self.port}", "allow_private_addresses": True}) + "\n")
        self.log = (trial.output / "relay.log").open("w")
        reservation.close()
        self.process = subprocess.Popen([str(binary), "relay", str(config)], stdin=subprocess.DEVNULL,
            stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        self.identity = process_identity(self.process.pid)
        assert self.identity is not None and self.identity["pid"] == self.identity["group"]
        (trial.output / "relay-process.json").write_text(json.dumps(self.identity) + "\n")
        trial.wait(lambda: any(event.get("event") == "ready" for event in self.logs()))
        trial.summary["relay"] = {"peer_id": self.peer, **self.identity}

    def logs(self):
        events = []
        for line in (self.trial.output / "relay.log").read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def stop(self):
        if self.process is None:
            return
        if self.emergency_record is not None:
            assert self.process.poll() is not None and not process_group(self.identity)
            return
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
        assert self.process.returncode == 0, "relay infrastructure did not shut down gracefully"
        assert not process_group(self.identity), "owned relay group remained after stop"
        if self.log is not None:
            self.log.close()

    def emergency_cleanup(self):
        record = stop_owned_group(self.identity, self.process)
        self.trial.summary["relay_emergency_cleanup"] = record
        assert record["child_reaped"] and record["owned_group_empty"], "relay fallback did not reap its child and empty its group"
        self.emergency_record = record
        if self.log is not None:
            self.log.close()


class Node:
    def __init__(self, trial, index):
        self.trial, self.index = trial, index
        self.directory = trial.output / f"node-{index}"
        self.directory.mkdir()
        self.process = None
        self.peer = None
        self.port = None
        self.reservation = None
        self.reserve_port()
        self.config = {
            "directory": str(self.directory),
            "listen": f"/ip4/127.0.0.1/tcp/{self.port}", "peers": [],
            "producer_sources": [], "discovery": {"mdns": False, "dht": False},
            "runtime": {"question_interval_ms": 3600000, "proof_interval_ms": 100},
        }
        self.write_config()
        trial.nodes.append(self)

    def reserve_port(self):
        if self.reservation is not None:
            return
        self.reservation = socket.socket()
        self.reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.reservation.bind(("127.0.0.1", self.port or 0))
        self.reservation.listen(1)
        self.port = self.reservation.getsockname()[1]

    def release_port(self):
        if self.reservation is not None:
            self.reservation.close()
            self.reservation = None

    def write_config(self):
        (self.directory / "config.json").write_text(json.dumps(self.config, indent=2) + "\n")

    def logs(self):
        path = self.directory / "node.log"
        if not path.exists():
            return []
        events = []
        for line in path.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # A concurrent log append may expose a partial final line.
                continue
        return events

    def start(self, strict_startup=False):
        # These lifecycle fixtures assert fixed provider/peer latency. Select
        # throughput explicitly; dynamic may throttle on a busy shared host.
        profile=self.directory/'resource-profile.json'
        if not profile.exists():
            write_receipt(profile,{'profile':'heavy','custom':None})
        self.event_offset = len(self.logs())
        self.release_port()
        result = self.trial.start(self, strict_startup=strict_startup)
        assert result["running"]
        self.capture_process()
        event = self.trial.wait(lambda: next((event for event in self.logs()
            [self.event_offset:] if event.get("event") == "starting"), None))
        if self.peer is not None:
            assert self.peer == event["peer_id"], "restart changed the runtime peer identity"
        self.peer = event["peer_id"]
        assert self.trial.call(self, "status")["running"]
        return result

    def capture_process(self):
        receipt = json.loads((self.directory / "control.json").read_text())
        current = process_identity(receipt["pid"])
        assert current is not None, "start returned without a live daemon"
        assert current["pid"] == current["group"] == current["session"], "node does not own an independent OS session"
        assert str(self.trial.binary) in current["command"], current
        startup_record = self.startup_record
        retained = startup_record.get("daemon")
        assert startup_record["capture_pending"] or retained == current, "native custody requires an explicit current start attempt"
        if retained is not None:
            assert current == retained, "ready endpoint replaced retained startup child identity"
        startup_record["capture_pending"] = False
        startup_record["daemon"] = current
        self.process = current
        write_receipt(self.trial.output / f"node-{self.index}.process.json", current)
        self.trial.summary["processes"].append({"node": self.index, **current})

    def ids(self):
        return {object["artifact_id"] for object in stored_objects(SimpleNamespace(directory=self.directory))}

    def stop(self, cleanup=False):
        status = self.trial.call(self, "stop", cleanup=cleanup)
        assert not status["running"], status
        assert not process_group(self.process), "stop returned before the owned OS process group exited"
        if self.process is not None:
            assert sum(event.get("event") == "stopped" for event in
                       self.logs()[self.event_offset:]) == 1, "graceful stop event missing or duplicated"
        assert self.trial.call(self, "stop", cleanup=cleanup) == status, "repeated stop changed persistent status"
        assert self.trial.call(self, "status", cleanup=cleanup) == status, "stopped status disagrees with stop"
        assert status["accepted_artifacts"] == len(self.ids()), "persistent unique ProofId count mismatch"
        self.reserve_port()
        return status

    def emergency_cleanup(self):
        # Safety cleanup only for our still-identical detached daemon/session.
        record = stop_owned_group(self.process)
        self.trial.summary.setdefault("node_emergency_cleanup", []).append(record)
        assert record["owned_group_empty"], "node fallback left its owned process group active"


def guardian_fixture_worker():
    """An actual driver which the probe deliberately kills after startup."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--guardian-fixture-worker", action="store_true", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--relay-binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()
    trial = Trial(args.binary, args.output, 30, args.profile, "guardian-probe")
    trial.summary["node_count"] = 1
    try:
        node = Node(trial, 0)
        write_receipt(trial.output / "research-processes.json", [])
        node.config["runtime"]["question_interval_ms"] = 100
        node.config["runtime"]["jobs"] = {"finding": {"mock": {
            "steps": 0, "cpu_ms": 20000, "descendant": True}}}
        node.write_config()
        node.start()
        trial.wait(lambda: any(event.get("event") == "research_working"
            and event.get("phase") == "cpu_active" for event in node.logs()), maximum=5)
        research = [process_identity(event["pid"]) for event in node.logs()
            if event.get("event") in {"research_started", "research_worker", "research_descendant"}]
        assert len(research) == 3 and all(research), "active research group identities missing"
        write_receipt(trial.output / "research-processes.json", research)
        worker_pid = next(event["pid"] for event in node.logs() if event.get("event") == "research_worker")
        worker = next(identity for identity in research if identity["pid"] == worker_pid)
        before_sample = process_cpu_sample(worker)
        cpu_witness = {"worker": worker_pid, "worker_identity": worker,
            "before_sample": before_sample, "before_seconds": before_sample["cpu_seconds"],
            "measurement_source": before_sample["measurement_source"]}
        write_receipt(trial.output / "driver-loss-cpu-witness.json", cpu_witness)
        trial.call(node, "status"); time.sleep(.15)
        after_sample = process_cpu_sample(worker)
        cpu_witness.update(after_sample=after_sample, after_seconds=after_sample["cpu_seconds"])
        write_receipt(trial.output / "driver-loss-cpu-witness.json", cpu_witness)
        assert cpu_witness["after_seconds"] > cpu_witness["before_seconds"], "active research had no positive CPU delta before driver loss"
        relay = Relay(trial, args.relay_binary.resolve())
        write_receipt(trial.output / "probe-ready.json", {
            "node": node.process, "node_port": node.port,
            "relay": relay.identity, "relay_port": relay.port,
            "guardian": trial.guardian_identity,
            "research": research,
        })
        while time.monotonic() < trial.deadline:
            time.sleep(0.1)
        trial.summary["result"] = "fail"
        trial.summary["error"] = "probe did not interrupt its driver within the bounded lifetime"
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, "guardian-worker", args.profile)
    return 1


def guardian_loss_probe():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guardian-loss-probe", action="store_true", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--relay-binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    deadline = started + args.timeout
    summary = {"fixture": "ordinary_driver_loss_guardian", "profile": args.profile,
        "driver_sha256": digest(__file__), "binary_sha256": digest(args.binary),
        "relay_binary_sha256": digest(args.relay_binary), "timeout_seconds": args.timeout,
        "claim": "finite real driver-loss, suspended-daemon fallback and direct-child relay reap evidence"}
    worker_output = output / "worker"
    log = (output / "driver-loss-worker.log").open("w")
    worker = subprocess.Popen([
        sys.executable, str(Path(__file__).resolve()), "--guardian-fixture-worker",
        "--binary", str(args.binary.resolve()), "--relay-binary", str(args.relay_binary.resolve()),
        "--output", str(worker_output), "--profile", args.profile,
    ], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    ready = None
    relay_trial = None
    try:
        summary["driver"] = process_identity(worker.pid)
        def started_worker():
            assert worker.poll() is None, "guardian fixture driver exited before the loss probe"
            path = worker_output / "probe-ready.json"
            return json.loads(path.read_text()) if path.exists() else None
        ready = wait_until(started_worker, min(deadline, time.monotonic() + 15))
        summary["owned_processes"] = ready
        altered = dict(ready["node"])
        altered["kernel_birth"] = list(altered["kernel_birth"])
        altered["kernel_birth"][-1] += 1
        refused = stop_owned_group(altered)
        assert not refused["signals"] and "refused" in refused
        assert process_identity(ready["node"]["pid"]) == ready["node"], "birth mismatch affected the live daemon"
        summary["changed_birth_refusal"] = refused
        os.kill(ready["node"]["pid"], signal.SIGSTOP)
        summary["injected_node_signal"] = "SIGSTOP"
        worker.kill()
        worker.wait(timeout=2)
        summary["driver_exit_code"] = worker.returncode
        summary["driver_reaped"] = True
        assert worker.returncode == -signal.SIGKILL
        receipt_path = worker_output / "guardian-receipt.json"
        receipt = wait_until(lambda: json.loads(receipt_path.read_text()) if receipt_path.exists() else None,
            min(deadline, time.monotonic() + 15))
        assert receipt["reason"] == "driver_lifeline_closed" and not receipt["errors"], receipt
        cleanup = receipt["nodes"][0]["cleanup"]
        assert receipt["nodes"][0].get("stop_error"), "suspended daemon did not exercise stop failure"
        assert cleanup["identity_match"] and cleanup["owned_group_empty"]
        assert cleanup["signals"] == ["SIGTERM", "SIGKILL"], cleanup
        assert receipt["relay_cleanup"]["owned_group_empty"]
        assert receipt["research_cleanup"]["retained_processes"] == 3
        assert receipt["research_cleanup"]["remaining_groups"] == []
        assert all(not process_group(identity) for identity in ready["research"])
        wait_until(lambda: all(not process_group(ready[role]) for role in ["node", "relay", "guardian"]),
            min(deadline, time.monotonic() + 5))
        assert not process_group(summary["driver"])
        summary["guardian_receipt"] = receipt
        for port in [ready["node_port"], ready["relay_port"]]:
            with socket.socket() as reservation:
                reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                reservation.bind(("127.0.0.1", port))
                reservation.listen(1)
        summary["lost_driver_owned_groups_empty_and_ports_released"] = True

        # The relay remains a direct Popen child in this second finite case;
        # cleanup must both terminate its exact session and actually wait/reap.
        relay_trial = Trial(args.binary, output / "relay-timeout", 15, args.profile, "guardian-probe")
        relay_trial.summary["node_count"] = 0
        relay = Relay(relay_trial, args.relay_binary.resolve())
        assert process_identity(relay.process.pid) == relay.identity
        os.kill(relay.process.pid, signal.SIGSTOP)
        try:
            relay.stop()
        except subprocess.TimeoutExpired:
            relay.emergency_cleanup()
        else:
            raise AssertionError("suspended direct relay did not exercise wait timeout")
        assert relay.emergency_record["child_reaped"] and relay.emergency_record["owned_group_empty"]
        assert relay.process.returncode == -signal.SIGKILL
        summary["relay_timeout_parent_cleanup"] = relay.emergency_record
        relay_trial.summary["result"] = "pass"
        relay_trial.close()
        assert relay_trial.summary["result"] == "pass", relay_trial.summary
        relay_trial = None
        assert time.monotonic() < deadline, "guardian qualification deadline exceeded"
        summary["result"] = "pass"
    except Exception as error:
        summary["result"] = "fail"
        summary["error"] = str(error)
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait(timeout=2)
        identities = ([ready[role] for role in ["node", "relay", "guardian"]]
            if ready is not None else [json.loads(path.read_text()) for path in
                [*worker_output.glob("node-*.process.json"), worker_output / "relay-process.json",
                 worker_output / "guardian-process.json"] if path.exists()])
        if ready is None and identities:
            try:
                wait_until(lambda: all(not process_group(identity) for identity in identities),
                    time.monotonic() + 15)
            except AssertionError:
                pass
        summary["final_cleanup"] = [stop_owned_group(identity) for identity in identities]
        if not all(record["owned_group_empty"] for record in summary["final_cleanup"]):
            summary["result"] = "fail"
            summary.setdefault("cleanup_errors", []).append("a retained owned process group remains")
        if relay_trial is not None:
            relay_trial.close()
        log.close()
        summary["execution_seconds"] = time.monotonic() - started
        retain_evidence(output, summary, "guardian-probe", args.profile)
    print(json.dumps({"result": summary["result"], "output": str(output)}))
    return 0 if summary["result"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path, help="ordinary naome executable")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--mode", choices=["direct", "mdns", "dht", "relay"], default="direct")
    parser.add_argument("--relay-binary", type=Path, help="developer relay infrastructure executable")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("this supported-platform lifecycle qualification requires POSIX")
    if args.mode == "relay" and args.relay_binary is None:
        parser.error("relay qualification requires an explicit relay infrastructure executable")
    trial = Trial(args.binary, args.output, args.timeout, args.profile, args.mode)
    try:
        sender, receiver = Node(trial, 0), Node(trial, 1)
        seed = Node(trial, 2) if args.mode == "dht" else None
        for node in trial.nodes:
            assert trial.call(node, "status") == {"running": False, "accepted_artifacts": 0, "artifact_verification": "not_run", "computation": "stopped", "computation_reason": None}
            assert node.start() == {"running": True, "accepted_artifacts": 0, "artifact_verification": "checked", "computation": "running", "computation_reason": None}
            key = node.directory / "identity.key"
            assert key.exists(), "first start failed to initialize identity"
            node.identity_sha256 = digest(key)
            original = dict(node.process)
            assert trial.call(node, "start") == {"running": True, "accepted_artifacts": 0, "artifact_verification": "checked", "computation": "running", "computation_reason": None}
            assert process_identity(original["pid"]) == original, "duplicate start replaced the node owner"
            assert json.loads((node.directory / "control.json").read_text())["pid"] == original["pid"]
            alias = trial.output / f"alias-{node.index}"
            alias.symlink_to(node.directory, target_is_directory=True)
            alias_node = SimpleNamespace(directory=alias, index=node.index)
            assert trial.call(alias_node, "status") == {"running": True, "accepted_artifacts": 0, "artifact_verification": "checked", "computation": "running", "computation_reason": None}
            assert trial.call(alias_node, "start") == {"running": True, "accepted_artifacts": 0, "artifact_verification": "checked", "computation": "running", "computation_reason": None}
            assert process_identity(original["pid"]) == original, "path alias created a second node owner"
            assert trial.call(alias_node, "stop") == {"running": False, "accepted_artifacts": 0, "artifact_verification": "not_run", "computation": "stopped", "computation_reason": None}
            node.stop()
        trial.summary["scenarios"]["automatic_initialization_detached_start_and_single_owner"] = {"result": "pass"}
        for verb in ["run", "init", "relay", "contract", "proof", "question"]:
            trial.call(sender, verb, success=False)
        trial.summary["scenarios"]["ordinary_cli_excludes_developer_verbs"] = {"result": "pass"}
        if args.mode == "direct":
            for node, other in [(sender, receiver), (receiver, sender)]:
                node.config["peers"] = [{"id": other.peer, "address": f"/ip4/127.0.0.1/tcp/{other.port}"}]
        elif args.mode == "mdns":
            for node in trial.nodes:
                node.config["listen"] = f"/ip4/0.0.0.0/tcp/{node.port}"
                node.config["discovery"] = {"mdns": True, "dht": False}
        elif args.mode == "dht":
            for node in trial.nodes:
                node.config["discovery"] = {"mdns": False, "dht": True, "internet": False, "allow_private_addresses": True,
                    "external_addresses": [f"/ip4/127.0.0.1/tcp/{node.port}"],
                    "bootstrap": [] if node is seed else [{"id": seed.peer, "address": f"/ip4/127.0.0.1/tcp/{seed.port}"}]}
        elif args.mode == "relay":
            relay = Relay(trial, args.relay_binary.resolve())
            endpoint = {"id": relay.peer, "address": f"/ip4/127.0.0.1/tcp/{relay.port}"}
            for node in trial.nodes:
                node.config["discovery"] = {"mdns": False, "dht": True, "internet": False, "allow_private_addresses": True,
                    "bootstrap": [endpoint], "relays": [endpoint],
                    "relay_only": True, "hole_punch": False}
        sender.config["runtime"]["question_interval_ms"] = 100
        for node in trial.nodes:
            node.write_config()
        if seed is not None:
            seed.start()
        receiver.start()
        sender.event_offset = len(sender.logs())
        sender.release_port()
        trial.begin_functional_start(sender,"concurrent_start")
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(lambda _: trial.call(sender, "start"), range(2)))
        assert all(status["running"] for status in statuses)
        sender.capture_process()
        trial.wait(lambda: any(event.get("event") == "starting" and event["peer_id"] == sender.peer
            for event in sender.logs()[sender.event_offset:]))
        assert sum(event.get("event") == "starting" for event in sender.logs()[sender.event_offset:]) == 1, "concurrent start created more than one runtime owner"
        trial.summary["scenarios"]["concurrent_start_keeps_one_node_owner"] = {"result": "pass", "pid": sender.process["pid"]}
        def expected_status(node):
            return {"running": True, "accepted_artifacts": 3,
                "artifact_verification": "checked", "computation": "running", "computation_reason": None}

        def converged():
            own, remote = sender.ids(), receiver.ids()
            if len(own) != 3 or own != remote or any(node.ids() != own for node in trial.nodes):
                return False
            remote_accepted = {event["id"] for event in receiver.logs()
                if event.get("event") == "accepted" and event.get("source") == "fetch"}
            if not own.issubset(remote_accepted):
                return False
            # Durable admission precedes publication of the passive status snapshot.
            # Wait for both observations within the existing convergence deadline.
            if any(trial.call(node, "status") != expected_status(node) for node in trial.nodes):
                return False
            return own
        accepted = trial.wait(converged, maximum=40 if args.mode != "direct" else 20)
        assert not any(event.get("event") == "question_generated" for event in receiver.logs()), "receiver generated local fixtures before exchange qualification"
        assert sum(event.get("event") == "proof_generated" for event in sender.logs()) == 3
        assert any(event.get("event") == "exchange_response" and event.get("kind") == "object" for event in receiver.logs()), "no real root payload response observed"
        if args.mode == "mdns":
            assert all(node.config["peers"] == [] for node in trial.nodes)
            assert any(event.get("event") == "discovered" and event.get("source") == "mdns"
                and event.get("peer") == sender.peer for event in receiver.logs()), "autonomous receiver did not discover the unlisted sender over mDNS"
        elif args.mode == "dht":
            assert all(node.config["peers"] == [] for node in trial.nodes)
            trial.wait(lambda: any(event.get("event") == "dht_participant" and event.get("peer") == sender.peer
                for event in receiver.logs()), maximum=25)
            trial.wait(lambda: any(event.get("event") == "identified" and event.get("peer") == sender.peer
                for event in receiver.logs()), maximum=10)
        elif args.mode == "relay":
            connections = {event["connection_id"] for event in receiver.logs()
                if event.get("event") == "connected" and event.get("peer") == sender.peer and event.get("relayed") is True}
            assert connections, "no actual relay-circuit peer connection"
            fetched = {event["object_id"] for event in receiver.logs()
                if event.get("event") == "exchange_response" and event.get("kind") == "object"
                and event.get("peer") == sender.peer and event.get("relayed") is True
                and event.get("connection_id") in connections}
            assert accepted.issubset(fetched), "accepted roots did not all travel over the actual relay connection"
            assert not any(event.get("event") == "connected" and event.get("peer") == sender.peer
                and event.get("relayed") is False for event in receiver.logs()), "relay-only qualification used a direct shortcut"
            trial.summary["relayed_connection_ids"] = sorted(connections)
        assert all(trial.call(node, "status") == expected_status(node) for node in trial.nodes)
        trial.summary["accepted_ids"] = sorted(accepted)
        trial.summary["scenarios"][f"scheduled_mock_generation_real_validation_and_{args.mode}_exchange"] = {
            "result": "pass", "root_proofs": 3, "receiver_generated_questions": 0,
            "receiver_accepted_source": "fetch", "mocked": ["question generation", "proof generation"]}
        trial.wait(lambda: sum(event.get("event") == "question_generated" for event in sender.logs()) >= 6, maximum=5)
        assert sender.ids() == accepted and receiver.ids() == accepted
        assert all(trial.call(node, "status") == expected_status(node) for node in trial.nodes)
        generated, resolved = set(), set()
        for event in sender.logs():
            if event.get("event") == "proof_generated":
                resolved.add(event["resolution_id"])
            elif event.get("event") == "question_generated":
                resolution = event["resolution_id"]
                assert resolution not in resolved, "a checked answer was generated again"
                assert resolution not in generated, "pending admission duplicated finding work"
                generated.add(resolution)
        assert len(generated) >= 6 and len(generated - resolved) >= 3
        trial.summary["scenarios"]["new_obligations_continue_without_duplicate_admission_or_answers"] = {
            "result": "pass", "unique_proofs": 3, "distinct_questions": len(generated),
            "unanswered_research_questions": len(generated - resolved)}
        for node in trial.nodes:
            assert node.stop() == {"running": False, "accepted_artifacts": 3, "artifact_verification": "not_run", "computation": "stopped", "computation_reason": None}
            assert digest(node.directory / "identity.key") == node.identity_sha256
            node.config["runtime"]["question_interval_ms"] = 3600000
            node.write_config()
            node.start()
            assert digest(node.directory / "identity.key") == node.identity_sha256
            assert node.ids() == accepted
            assert trial.call(node, "status") == expected_status(node)
            node.stop()
        trial.summary["scenarios"]["restart_revalidates_persistent_proofs_and_preserves_identity"] = {"result": "pass", "unique_proofs": 3}
        member = sorted(accepted)[0]
        saved = bytes.fromhex(next(value["payload"] for value in stored_objects(receiver) if value["artifact_id"] == member))
        # Preserve SQL widths while invalidating the authenticated content.
        original = replace_catalog_payload(receiver, member, bytes([saved[0] ^ 1]) + saved[1:])
        try:
            assert trial.call(receiver, "status") == {"running": False, "accepted_artifacts": 3,
                "artifact_verification": "not_run", "computation": "stopped", "computation_reason": None}
            offset = len(receiver.logs())
            receiver.release_port()
            trial.call(receiver, "start", success=False)
            failures = [event for event in receiver.logs()[offset:] if event.get("event") == "fatal_error"]
            assert len(failures) == 1 and "catalog" in failures[0].get("error", ""), failures
            assert not any(event.get("event") == "ready" for event in receiver.logs()[offset:])
        finally:
            replace_catalog_payload(receiver, member, original)
            receiver.reserve_port()
        assert trial.call(receiver, "status") == {"running": False, "accepted_artifacts": 3, "artifact_verification": "not_run", "computation": "stopped", "computation_reason": None}
        trial.summary["scenarios"]["offline_status_reports_unverified_admissions_but_start_rejects_corrupt_payloads"] = {"result": "pass"}
        trial.summary["scenarios"]["graceful_idempotent_stop_releases_owned_process_groups"] = {"result": "pass"}
        trial.summary["result"] = "pass"
    except Exception as error:
        trial.summary["result"] = "fail"
        trial.summary["error"] = str(error)
        traceback.print_exc()
        trial.summary["failure_statuses"] = []
        for node in trial.nodes:
            try:
                status = trial.call(node, "status")
                trial.summary["failure_statuses"].append({"node": node.index, "status": status})
            except Exception as status_error:
                trial.summary["failure_statuses"].append({"node": node.index, "error": str(status_error)})
    finally:
        trial.close()
        retain_evidence(trial.output, trial.summary, args.mode, args.profile)
    print(json.dumps({"result": trial.summary["result"], "output": str(trial.output)}))
    return 0 if trial.summary["result"] == "pass" else 1


if __name__ == "__main__":
    if "--guardian" in sys.argv[1:]:
        result = guardian_main()
    elif "--guardian-fixture-worker" in sys.argv[1:]:
        result = guardian_fixture_worker()
    elif "--guardian-loss-probe" in sys.argv[1:]:
        result = guardian_loss_probe()
    else:
        result = main()
    sys.exit(result)
