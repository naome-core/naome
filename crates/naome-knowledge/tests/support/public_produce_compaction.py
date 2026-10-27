#!/usr/bin/env python3
"""One bounded public-process mechanism screen; no scale or cold qualification.

The ordinary QA owner supplies the existing host-pressure/aggregate512MiB,
inclusive8GiB/free20GiB/reserve64MiB controls. This case adds no observer.
It keeps the single direct Node Popen, bounded IO and an unchanged600s+10s
cutoff; output and test data belong inside that owner's admitted namespace.
"""
import argparse
from collections import deque
import gzip
import hashlib
import json
import math
from pathlib import Path
import re
import resource
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import traceback

from proof_network import Driver, Node, content_root, artifact_id

COUNT, FIRST = 4096, 8100
LARGE_COUNT = 12288
LINE_LIMIT, SOURCE_LIMIT = 524288, 65536
RAW_LIMIT = 256 * 1024**2
EXPECTED_METADATA_MESSAGE = "question limit exceeded: question source bytes"


def streaming_digest(path):
    hashed = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            hashed.update(chunk)
    return hashed.hexdigest()


def fixture(index, count=COUNT):
    """Fixed R10 source spelling and independent primitive bytes for either count."""
    assert count in (COUNT, LARGE_COUNT)
    assert FIRST <= index < FIRST + count
    bindings = ["large0 = not(not(not(all(x,eq(x,x)))))"]
    formula = b"\x02" * 3 + b"\x04\x00" + (b"\x01" + bytes(4)) * 2
    for level in range(1, 10):
        bindings.append(f"large{level} = imp(large{level - 1},large{level - 1})")
        formula = b"\x03" + formula + formula
    previous = "large9"
    for position, bit in enumerate(format(index, "017b")):
        name = f"index{position}"
        bindings.append(f"{name} = " + (f"not({previous})" if bit == "1" else f"all(z,{previous})"))
        formula = (b"\x02" if bit == "1" else b"\x04") + formula
        previous = name
    source = ("let:\n    " + "\n    ".join(bindings)
              + f"\ngoal = imp({previous},imp({previous},{previous}))"
              + f"\nproof:\n    p0 = simp({previous},{previous})\n    return p0\n")
    length = len(formula).to_bytes(4, "big")
    canonical = bytes.fromhex("0000000100") + length + formula + length + formula
    conclusion = b"\x03" + formula + b"\x03" + formula + formula
    assert len(canonical) == 16429 and len(conclusion) == 24626
    foundation = b"naome:zfc"
    statement = hashlib.sha256(b"naome:statement\0" + len(foundation).to_bytes(4, "big")
                               + foundation + len(conclusion).to_bytes(4, "big") + conclusion).hexdigest()
    return source, canonical, conclusion, statement, artifact_id(statement, "00" + canonical.hex())


class EventTail(deque):
    """The inherited startup path slices once; this case never restarts a Node."""
    def __getitem__(self, item):
        return list(self)[item]


class PublicNode(Node):
    def __init__(self, *args):
        super().__init__(*args)
        self.events = EventTail(maxlen=16)
        self.pending = None
        self.reader_errors = []
        self.command_lock = threading.Lock()
        self.stopping = False

    def reader_health(self):
        assert not self.reader_errors, "bounded reader failed: " + "; ".join(self.reader_errors)

    def read(self, name, stream, log):
        raw_bytes = 0
        try:
            with gzip.open(Path(str(log) + ".gz"), "xb") as output:
                while True:
                    raw = stream.buffer.readline(LINE_LIMIT + 1)
                    if not raw:
                        break
                    raw_bytes += len(raw)
                    assert raw_bytes <= self.driver.raw_limit, "bounded raw log ceiling"
                    output.write(raw)
                    output.flush()
                    assert len(raw) <= LINE_LIMIT and raw.endswith(b"\n"), "bounded complete response line"
                    if name != "stdout":
                        continue
                    event = json.loads(raw)
                    assert isinstance(event, dict), "stdout event must be an object"
                    with self.condition:
                        if event.get("event") == "response":
                            request = event.get("request")
                            assert self.pending is not None and request == self.pending and request not in self.responses, "unsolicited/duplicate response"
                            self.responses[request] = event
                        if event.get("event") in ("starting", "ready", "stopped"):
                            self.events.append(event)
                        self.condition.notify_all()
        except Exception as error:
            with self.condition:
                if not self.reader_errors:
                    self.reader_errors.append(name + ": " + str(error))
                self.condition.notify_all()
        finally:
            with self.condition:
                self.condition.notify_all()

    def wait_event(self, predicate, timeout=10, since=0):
        deadline = min(self.driver.deadline, time.monotonic() + timeout)
        with self.condition:
            while True:
                self.reader_health()
                for event in reversed(self.events[since:]):
                    if predicate(event):
                        return event
                assert self.process.poll() is None, "owned Node exited before lifecycle event"
                remaining = deadline - time.monotonic()
                assert remaining > 0, "startup/shared deadline"
                self.condition.wait(min(remaining, .05))

    def command(self, command, timeout=10, **fields):
        with self.command_lock:
            if not self.stopping:
                self.driver.check_deadline()
            self.reader_health()
            self.serial += 1
            request = f"{self.index}-{self.generation}-{self.serial}"
            value = {"command": command, "request": request, **fields}
            encoded = (json.dumps(value) + "\n").encode()
            assert len(encoded) <= LINE_LIMIT, "bounded command bytes"
            end = self.driver.stop_deadline if self.stopping else self.driver.deadline
            deadline = min(end, time.monotonic() + min(timeout, 10))
            with self.condition:
                assert self.pending is None and not self.responses
                self.pending = request
            try:
                with (self.driver.output / "commands.jsonl").open("a") as output:
                    output.write(json.dumps({"sent_monotonic_ns": time.monotonic_ns(), "value": value}) + "\n")
                self.process.stdin.write(encoded.decode())
                self.process.stdin.flush()
                with self.condition:
                    while request not in self.responses:
                        self.reader_health()
                        assert self.process.poll() is None, "owned Node exited before response"
                        remaining = deadline - time.monotonic()
                        assert remaining > 0, "command/shared deadline: " + command
                        self.condition.wait(min(remaining, .05))
                    response = self.responses.pop(request)
                    self.pending = None  # A duplicate racing after take must fail closed.
                self.reader_health()
                assert time.monotonic() < deadline, "late response"
                assert "error" not in response, "public command error: " + str(response.get("error"))[:4096]
                return response["result"]
            finally:
                with self.condition:
                    self.pending = None

    def stop(self):
        if self.process is None:
            return
        self.stopping = True
        self.driver.stop_deadline = min(self.driver.deadline + 10, time.monotonic() + 10)
        def left(cap):
            remaining = self.driver.stop_deadline - time.monotonic()
            assert remaining > 0, "original cleanup cutoff expired"
            return min(cap, remaining)
        stop_failure = None
        if self.process.poll() is None:
            try:
                self.command("stop", timeout=min(3, left(3)))
                self.process.wait(timeout=left(3))
            except Exception as stop_error:
                stop_failure = stop_error
                self.driver.summary["stop_command_error"] = type(stop_error).__name__ + ": " + str(stop_error)[:4096]
                try:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=left(2))
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=left(2))
                except Exception as cleanup_error:
                    raise RuntimeError(f"stop command failed: {stop_error}; owned fallback incomplete: {cleanup_error}") from cleanup_error
        for thread in self.threads:
            thread.join(timeout=left(2))
            assert not thread.is_alive(), "raw reader join unresolved"
        self.threads = []
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()
        self.reader_health()
        assert self.process.returncode == 0, "owned Node unexpected stop: " + str(self.process.returncode)
        if stop_failure is not None:
            raise RuntimeError("stop command failed despite completed fallback: " + str(stop_failure)) from stop_failure


class Screen(Driver):
    def __init__(self, args):
        # Avoid Driver's read_bytes-based binary hash; keep its actual init/run API.
        self.binary, self.output = args.binary.resolve(), args.output.resolve()
        self.count = args.count
        self.raw_limit = RAW_LIMIT if self.count == COUNT else 2 * RAW_LIMIT
        self.deadline = time.monotonic() + args.timeout
        self.stop_deadline = self.deadline + 10
        self.nodes = []
        self.output.mkdir(parents=True, exist_ok=False)
        contract = json.loads(self.helper_output([str(self.binary), "contract"]))
        assert contract["limits"]["proof_bytes"] == SOURCE_LIMIT
        assert contract["limits"]["command_bytes"] == LINE_LIMIT
        self.summary = {"schema": 1, "result": "running", "node_count": 1,
                        "contract": contract, "commands": [], "processes": [],
                        "binary": str(self.binary), "binary_sha256": streaming_digest(self.binary),
                        "source_sha256": streaming_digest(__file__),
                        "support_sha256": streaming_digest(Path(__file__).with_name("proof_network.py")),
                        "profile": args.profile,
                        "count": self.count, "first_index": FIRST, "active_seconds": args.timeout,
                        "host_resources": "External ordinary QA owner; no new host observer in this case.",
                        "claim": "Public warm single-node mechanism screen only; no full-scale/cold/installed claim."}
        if self.count == LARGE_COUNT:
            self.summary.update({"raw_stream_limit_bytes": self.raw_limit,
                                 "generation_observation": "Nonatomic filesystem samples; unknown or changed identities cannot qualify a handoff. No reachability or causality claim.",
                                 "generation_size_fields": ["logical_bytes", "allocated_bytes"],
                                 "required_completed_generation_bytes": 64 * 1024**2})

    def check_deadline(self):
        super().check_deadline()
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        assert peak * (1 if sys.platform == "darwin" else 1024) <= 64 * 1024**2, "generator64MiB ceiling"


def generations(directory):
    """One non-atomic filesystem observation, outside the roundtrip timer."""
    result = {}
    for path in directory.iterdir():
        if not re.fullmatch(r"\.checked-context-[0-9]+\.sqlite3", path.name):
            continue
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None  # A racing deletion is unobserved, never a synthetic handoff.
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "owned generation must be a regular single-link file"
        result[path.name] = [info.st_dev, info.st_ino, info.st_size, info.st_blocks * 512]
    assert len(result) <= 6, "checked generation count bound"
    return result


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--profile", choices=["release"], default="release")
    parser.add_argument("--count", type=int, choices=(COUNT, LARGE_COUNT), default=COUNT)
    args = parser.parse_args()
    assert 0 < args.timeout <= 600
    driver = Screen(args)
    node = None
    reservation = None
    whole_begin = first_call = whole_end = None
    first_start = handoff = None
    large_copy = large_handoff = None
    completed = payload = 0
    identifiers, timings = [], []
    primary = cleanup_error = None
    interrupted = [False]
    def interrupt(number, frame):
        if not interrupted[0]:
            interrupted[0] = True
            raise InterruptedError("owned screen interrupted by signal " + str(number))
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, interrupt)
    try:
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        directory = driver.output / "node"
        node = PublicNode(driver, 0, directory, driver.init_identity(directory), reservation.getsockname()[1])
        driver.nodes = [node]
        reservation.close()
        node.start(selection=None, test_controls=False)
        previous = generations(directory)
        assert previous is not None and len(previous) == 1
        compatibility = driver.summary["contract"]["compatibility"]
        with (driver.output / "timings-and-generations.jsonl").open("x") as output:
            whole_begin = time.monotonic_ns()  # Before first source planning, as in R10.
            for sequence, index in enumerate(range(FIRST, FIRST + args.count), 1):
                driver.check_deadline()
                source, canonical, conclusion, statement, identifier = fixture(index, args.count)
                assert len(source.encode()) <= SOURCE_LIMIT
                row = {"sequence": sequence, "index": index, "artifact_id": identifier,
                       "statement_id": statement, "proof_bytes": len(canonical),
                       "conclusion_bytes": len(conclusion), "roundtrip_ns": None, "validated": False}
                call_error = None
                mark = time.monotonic_ns()
                if first_call is None:
                    first_call = mark
                try:
                    try:
                        result = node.command("produce", source=source)
                    finally:
                        duration = time.monotonic_ns() - mark
                        row["roundtrip_ns"] = duration
                    assert result["result"] == {"status": "accepted", "id": identifier}
                    envelope = result["object"]
                    assert set(envelope) == {"artifact_id", "statement_id", "compatibility", "payload", "obligation_proof"}
                    assert envelope["artifact_id"] == identifier and envelope["statement_id"] == statement
                    assert envelope["compatibility"] == compatibility
                    assert bytes.fromhex(envelope["payload"]) == b"\0" + canonical
                    assert result["metadata"] is None, result
                    error = result["metadata_error"]
                    assert error["schema_version"] == 1 and error["code"] == "input.invalid", error
                    assert error["message"] == EXPECTED_METADATA_MESSAGE, error
                    assert error["retryable"] is False and error["fatal"] is False, error
                    identifiers.append(identifier)
                    timings.append(duration)
                    completed, payload = sequence, payload + len(canonical)
                    observed = generations(directory)
                    if args.count == LARGE_COUNT:
                        # Keep the old default path unchanged. This larger-only
                        # matcher consumes the same bounded filesystem sample.
                        if observed is not None and any(
                            observed[name][:2] != previous[name][:2]
                            for name in set(observed) & set(previous)
                        ):
                            observed = None
                        if observed is None:
                            large_copy = None
                            previous = {}  # Unknown intervals cannot bridge a handoff.
                        else:
                            names, prior_names = set(observed), set(previous)
                            if len(prior_names) == 1 and len(names) == 2 and prior_names < names:
                                source_name = next(iter(previous))
                                target_name = next(iter(names - prior_names))
                                large_copy = {"source": source_name, "target": target_name,
                                              "source_identity": previous[source_name][:2],
                                              "target_identity": observed[target_name][:2],
                                              "start_sequence": sequence}
                            elif large_copy is not None:
                                source_name, target_name = large_copy["source"], large_copy["target"]
                                pair = {source_name, target_name}
                                if (prior_names == pair and names == {target_name}
                                        and previous[source_name][:2] == large_copy["source_identity"]
                                        and previous[target_name][:2] == large_copy["target_identity"]
                                        and observed[target_name][:2] == large_copy["target_identity"]):
                                    logical, allocated = observed[target_name][2:]
                                    event = {**large_copy, "sequence": sequence,
                                             "logical_bytes": logical, "allocated_bytes": allocated,
                                             "observed_ns": time.monotonic_ns()}
                                    row["completed_generation_handoff"] = event
                                    if large_handoff is None and min(logical, allocated) >= 64 * 1024**2:
                                        large_handoff = event
                                    large_copy = None
                                elif names != pair:
                                    large_copy = None
                        row["generation_sizes"] = None if observed is None else {
                            name: {"logical_bytes": info[2], "allocated_bytes": info[3]}
                            for name, info in observed.items()
                        }
                    if observed is not None:
                        names = set(observed)
                        for name in names & set(previous):
                            assert observed[name][:2] == previous[name][:2], "generation identity changed"
                        if first_start is None and len(previous) == 1 and len(names) == 2 and set(previous) < names:
                            first_start = {"sequence": sequence, "source": next(iter(previous)),
                                           "target": next(iter(names - set(previous))), "observed_ns": time.monotonic_ns()}
                        if first_start is not None and handoff is None and first_start["source"] not in names and first_start["target"] in names:
                            handoff = {"sequence": sequence, "observed_ns": time.monotonic_ns()}
                        previous = observed
                    row.update(validated=True, metadata_error=result["metadata_error"], generations=observed)
                except Exception as error:
                    call_error = error
                    row["error"] = type(error).__name__ + ": " + str(error)[:4096]
                finally:
                    try:
                        encoded = json.dumps(row) + "\n"
                        assert len(encoded) <= 8192, "bounded observation row"
                        output.write(encoded)
                        output.flush()
                    except Exception as error:
                        if call_error is None:
                            raise
                        driver.summary["secondary_observation_error"] = str(error)[:4096]
                if call_error is not None:
                    raise call_error
        assert completed == args.count and len(set(identifiers)) == args.count
        assert payload == (67293184 if args.count == COUNT else 201879552)
        status = node.status_snapshot()
        expected_root = content_root(compatibility, identifiers)
        assert status["ids"] == sorted(identifiers)
        assert status["accepted_artifacts"] == args.count and status["root"] == expected_root
        driver.summary.update({"accepted_count": completed, "canonical_payload_bytes": payload,
                               "root": expected_root, "complete_ids_verified": True,
                               "first_generation_start": first_start, "first_generation_handoff": handoff,
                               "writes_after_observed_handoff": args.count - handoff["sequence"] if handoff else None,
                               "roundtrip_ns": {"n": len(timings), "min": min(timings), "max": max(timings),
                                                "p95_nearest_rank": sorted(timings)[math.ceil(.95 * args.count) - 1]}})
        if args.count == LARGE_COUNT:
            driver.summary.update({"large_generation_handoff": large_handoff,
                                   "writes_after_large_generation_handoff": args.count - large_handoff["sequence"] if large_handoff else None})
    except Exception as error:
        primary = type(error).__name__ + ": " + str(error)
        driver.summary["error"] = primary
        driver.summary["traceback"] = traceback.format_exc()[-8192:]
    finally:
        interrupted[0] = True  # Repeated TERM cannot interrupt the bounded cleanup.
        if reservation is not None:
            reservation.close()
        try:
            if node is not None:
                node.stop()
        except Exception as error:
            cleanup_error = type(error).__name__ + ": " + str(error)
            driver.summary["cleanup_error"] = cleanup_error
        whole_end = time.monotonic_ns()
        driver.summary.update({"completed": completed, "partial_payload_bytes": payload,
                               "interval_begin_ns": whole_begin, "first_roundtrip_begin_ns": first_call,
                               "cleanup_end_ns": whole_end,
                               "planning_through_cleanup_ns": whole_end - whole_begin if whole_begin is not None else None,
                               "first_call_through_cleanup_ns": whole_end - first_call if first_call is not None else None,
                               "interval_includes": "planning, validation, filesystem observations, waits, all queued maintenance, complete status oracle and owned stop/join",
                               "cleanup": {"direct_reaped": node is not None and node.process is not None and node.process.poll() is not None,
                                           "returncode": node.process.returncode if node is not None and node.process is not None else None,
                                           "reader_threads_alive": [thread.is_alive() for thread in node.threads] if node else []}})
        qualifying_handoff = handoff if args.count == COUNT else large_handoff
        mechanism = qualifying_handoff is not None and args.count - qualifying_handoff["sequence"] >= 128
        functional = primary is None and completed == args.count
        clean = cleanup_error is None and driver.summary["cleanup"]["direct_reaped"]
        result = "PASS" if functional and clean and mechanism else "INCONCLUSIVE" if functional and clean else "FAIL"
        driver.summary["result"] = result
        driver.summary["orderly_stop_completed"] = clean
        driver.summary["orderly_stop_end_ns"] = whole_end if clean else None
        driver.summary["mechanism_observation"] = "observed start/handoff and >=128 later writes" if mechanism else "required transition not observed within fixed4096; no extension"
        if args.count == LARGE_COUNT:
            driver.summary["mechanism_observation"] = (
                "observed stable-identity completed handoff with logical/allocated>=64MiB and >=128 later writes"
                if mechanism else "required large handoff not observed within fixed12288; no extension")
        raw = (json.dumps(driver.summary, indent=2) + "\n").encode()
        assert len(raw) <= 65536, "bounded summary"
        (driver.output / "summary.json").write_bytes(raw)
        print(json.dumps({"result": result, "completed": completed, "summary": str(driver.output / "summary.json")}), flush=True)
    return 0 if result == "PASS" else 2 if result == "INCONCLUSIVE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
