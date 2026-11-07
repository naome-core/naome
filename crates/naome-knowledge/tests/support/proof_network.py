#!/usr/bin/env python3
"""Finite four-process proof-network acceptance driver; no inference provider."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import sqlite3
import subprocess
import threading
import time
import traceback


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_metadata(repo, helper_output):
    """Report absent archive metadata honestly; existing Git errors stay fatal."""
    try:
        (Path(repo) / ".git").lstat()
    except FileNotFoundError:
        return {"revision": None, "dirty": None,
                "source_metadata_status": "unavailable_without_git_metadata"}
    return {
        "revision": helper_output(["git", "rev-parse", "HEAD"], cwd=repo).strip(),
        "dirty": bool(helper_output(["git", "status", "--porcelain"], cwd=repo).strip()),
        "source_metadata_status": "available_from_git_metadata",
    }


def proof_id(statement, proof):
    foundation = b"naome:zfc"
    data = bytes.fromhex(proof)
    return hashlib.sha256(
        b"naome:proof\0" + len(foundation).to_bytes(4, "big") + foundation
        + bytes.fromhex(statement) + len(data).to_bytes(4, "big") + data
    ).hexdigest()


def artifact_id(statement, payload):
    data = bytes.fromhex(payload)
    if data[0] == 0:
        identity = bytes.fromhex(proof_id(statement, data[1:].hex()))
        domain = b"naome:artifact:proof:v0\0"
    elif data[0] == 1:
        certificate = data[1:]
        foundation = b"naome:zfc"
        framed = len(foundation).to_bytes(4,"big") + foundation + len(certificate).to_bytes(4,"big") + certificate
        identity = hashlib.sha256(b"naome:definition:v1\0" + framed).digest()
        domain = b"naome:artifact:definition:v1\0"
    else:
        raise AssertionError("unknown artifact type")
    return hashlib.sha256(domain + identity).hexdigest()


def citation_id(object):
    return proof_id(object["statement_id"], object["payload"][2:])


def proof_metadata(object, question):
    return {"artifact_id": object["artifact_id"], "proof_id": citation_id(object),
            "statement_id": object["statement_id"], "question": question}


def program_artifact_id(manifest):
    return hashlib.sha256(b"naome:artifact:proof:v0\0" + bytes.fromhex(program_id(manifest))).hexdigest()


def program_id(manifest):
    framed=b"naome:program-proof\0"+b"naome:zfc"
    framed+=manifest['commands'].to_bytes(8,'big')+manifest['input_bytes'].to_bytes(8,'big')
    for field in ['program_hash','stream_root','conclusion','statement']:
        framed+=bytes(manifest[field])
    return hashlib.sha256(framed).hexdigest()


def program_integer(data, offset):
    value = 0
    for shift in range(0, 64, 7):
        byte = data[offset]
        offset += 1
        assert shift < 63 or byte <= 1
        value |= (byte & 127) << shift
        if byte < 128:
            assert shift == 0 or byte != 0
            return value, offset
    raise AssertionError("program integer overflow")


def program_manifest(data):
    commands, offset = program_integer(data, 0)
    size, offset = program_integer(data, offset)
    assert commands > 0 and size > 0 and len(data) == offset + 128
    manifest = {"commands": commands, "input_bytes": size}
    for index, field in enumerate(("program_hash", "stream_root", "conclusion", "statement")):
        manifest[field] = list(data[offset + 32 * index:offset + 32 * (index + 1)])
    return manifest


def verify_program_record(data):
    tag = data[0]
    if tag == 18:
        verify_scope_record(data)
        return
    fields = {
        0: "vv", 1: "vv", 2: "r", 3: "rr", 4: "r",
        5: "ha", 6: "tt", 7: "tt", 8: "r", 9: "rr", 10: "tr",
        11: "ttr", 12: "rr", 13: "rrr", 14: "rr", 15: "trr", 16: "r",
        17: "ttr", 19: "rt", 20: "t", 21: "ttr",
        22: "z", 23: "h", 24: "rttt", 25: "rttttt", 26: "rr",
        27: "rt", 28: "r", 29: "r",
    }[tag]
    offset = 1
    for field in fields:
        if field == "h":
            offset += 32
        elif field == "z":
            assert data[offset] <= 6
            offset += 1
        else:
            value, offset = program_integer(data, offset)
            if field == "t":
                assert value < (1 << 32)
            elif field == "v":
                assert value & 1 or value >> 1 < (1 << 32)
            elif field == "a":
                assert value <= 256
                for _ in range(value):
                    argument, offset = program_integer(data, offset)
                    assert argument < (1 << 32)
    assert offset == len(data)


def verify_scope_record(data):
    offset = 1

    def integer(maximum):
        nonlocal offset
        value, offset = program_integer(data, offset)
        assert value <= maximum
        return value

    assumptions = integer(32)
    assert assumptions > 0
    for _ in range(assumptions):
        integer((1 << 64) - 1)
    actions = integer(32)
    for index in range(actions):
        tag = data[offset]
        offset += 1
        earlier = assumptions + index - 1
        integer(earlier)
        if tag == 0:
            integer((1 << 32) - 1)
            for _ in range(integer(8)):
                integer(earlier)
        else:
            assert tag == 1
            integer(earlier)
    integer(assumptions + actions - 1)
    assert offset == len(data)


def verify_program_input(catalog,manifest):
    identity=bytes.fromhex(program_artifact_id(manifest))
    saved=catalog.execute('SELECT manifest,received,input_bytes,hash,remaining FROM programs WHERE id=?',(identity,)).fetchone()
    assert saved is not None and program_manifest(saved[0])==manifest
    assert saved[1:]==(manifest['commands'],manifest['input_bytes'],bytes(manifest['program_hash']),bytes(32))
    previous=bytes(32);count=0;size=0
    for position,command,chain in catalog.execute('SELECT position,command,hash FROM program_input WHERE id=? ORDER BY position',(identity,)):
        assert position==count and 0<len(command)<=4096
        verify_program_record(command)
        previous=hashlib.sha256(b'naome:proof-program'+previous+len(command).to_bytes(8,'big')+command).digest()
        assert chain==previous
        count+=1;size+=len(command)
    assert (count,size,previous)==(manifest['commands'],manifest['input_bytes'],bytes(manifest['program_hash']))
    remaining=bytes(32)
    for command,suffix in catalog.execute('SELECT command,suffix FROM program_input WHERE id=? ORDER BY position DESC',(identity,)):
        remaining=hashlib.sha256(b'naome:program-stream\0'+len(command).to_bytes(8,'big')+command+remaining).digest()
        assert suffix==remaining
    assert remaining==bytes(manifest['stream_root'])


def content_root(compatibility, ids):
    def leaf(key):
        return hashlib.sha256(b"naome:checked-map:leaf:v1\0" + key).digest()
    def branch(bit, left, right):
        return hashlib.sha256(b"naome:checked-map:branch:v1\0" + bytes([bit]) + left + right).digest()
    pending = []
    previous = None
    current = bytes(32)
    ordered = sorted(bytes.fromhex(identity) for identity in ids)
    assert len(set(ordered)) == len(ordered)
    for key in ordered:
        if previous is not None:
            difference = int.from_bytes(previous, "big") ^ int.from_bytes(key, "big")
            bit = 256 - difference.bit_length()
            while pending and pending[-1][0] >= bit:
                level, left = pending.pop()
                current = branch(level, left, current)
            pending.append((bit, current))
        current, previous = leaf(key), key
    while pending:
        bit, left = pending.pop()
        current = branch(bit, left, current)
    return hashlib.sha256(b"naome:knowledge:set\0" + bytes.fromhex(compatibility)
        + len(ordered).to_bytes(8, "big") + current).hexdigest()


def u32(value):
    return value.to_bytes(4, "big")


def implication(left, right):
    return b"\x03" + left + right


def negate(formula):
    return b"\x02" + formula


def conjunction(left, right):
    return negate(implication(left, negate(right)))


def atom(tag, left, right, bound):
    kind = b"\x01" if bound else b"\x00"
    return bytes([tag]) + kind + u32(left) + kind + u32(right)


def member_self():
    return b"\x04" + atom(1, 0, 0, True)


def formula_field(formula):
    return u32(len(formula)) + formula


def certificate(steps):
    return (b"\x00" + u32(len(steps)) + b"".join(steps)).hex()


def simplify(premise, extra):
    return b"\x00" + formula_field(premise) + formula_field(extra)


def mp(premise, implication):
    return b"\x20" + u32(premise) + u32(implication)


def quantified_reflexivity(count, padding=0):
    offset = padding // 5
    return certificate([b"\x06" + u32(0)] * (offset + 1) + [
        b"\x21" + u32(offset + step) + u32(step) for step in range(count)
    ])


def separation_formula():
    # Beneath forall(s), exists(r), forall(e), the roles have indices 2, 1, 0.
    left = atom(1, 0, 1, True)
    right = conjunction(atom(1, 0, 2, True), atom(0, 0, 0, True))
    return b"\x04\x02\x04\x02\x04" + conjunction(
        implication(left, right), implication(right, left))


def fixture_premise(index):
    formula = member_self()
    for bit in format(index, "b"):
        formula = (b"\x02" if bit == "1" else b"\x04") + formula
    return formula


def question_fixture(index):
    return implication(fixture_premise(index), separation_formula()).hex()


def source(index, padding=0):
    premise = separation_formula()
    steps = [b"\x06" + u32(0)] * (padding // 5)
    start = len(steps)
    steps += [
        b"\x11" + formula_field(atom(0, 0, 0, False)) + u32(0) + u32(1) + u32(2) + u32(0),
        simplify(premise, fixture_premise(index)),
        mp(start, start + 1),
    ]
    return certificate(steps)


def cite_and_weaken(proof_id, premise, extra):
    return certificate([b"\x30" + bytes.fromhex(proof_id), simplify(premise, extra), mp(0, 1)])


def inventory_source(depth, used):
    return source(100 + depth * (depth - 1) // 2 + used)


def stored_objects(node):
    """Independent transactional catalog oracle; stored bytes grant no validity."""
    database = node.directory / "proof-corpus.sqlite3"
    receipt = node.directory / "proof-corpus.format"
    if not database.exists():
        assert not receipt.exists(), "activated catalog is missing"
        return []
    assert receipt.is_file(), "catalog lineage receipt required"
    format_bytes = receipt.read_bytes()
    assert len(format_bytes) == 72 and format_bytes[:8] == b"NAOCORP\0"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as catalog:
        catalog.execute("BEGIN")
        assert catalog.execute("PRAGMA application_id").fetchone()[0] == 0x4e414f43
        assert catalog.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert catalog.execute("PRAGMA foreign_key_check").fetchall() == []
        assert [row[0] for row in catalog.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )] == ["artifacts", "commits", "dependencies", "members", "meta", "program_input", "programs"], "current catalog schema required"
        assert catalog.execute(
            "SELECT name,tbl_name FROM sqlite_schema WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall() == [
            ("artifacts_by_origin_commit", "artifacts"),
            ("commits_by_root", "commits"),
            ("dependencies_by_target", "dependencies"),
        ], "foreign-key child indexes required"
        identity, state, root, count, total = catalog.execute(
            "SELECT database_id,state,corpus_root,corpus_count,payload_bytes FROM meta WHERE singleton=1"
        ).fetchone()
        assert identity == format_bytes[40:]
        if state == "initializing":
            # Offline controls may create an unverified empty catalog. It has
            # no admitted set until the first successful checked graph opens.
            assert root is None and count == total == 0
            for table in ["artifacts", "commits", "members", "dependencies"]:
                assert catalog.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
            return []
        assert state == "active"
        rows = catalog.execute(
            "SELECT id,statement,compatibility,payload,payload_length,payload_digest,origin_commit,replay_order,obligation FROM artifacts ORDER BY id"
        ).fetchall()
        assert len(rows) == count
        ordinals = {row[0]: row[7] for row in rows}
        assert sorted(ordinals.values()) == list(range(1, count + 1)), "complete replay order required"
        objects = []
        by_id = {}
        payload_bytes = 0
        for id, statement, compatibility, payload, length, checksum, commit, ordinal, obligation in rows:
            assert len(id) == len(compatibility) == len(checksum) == len(commit) == 32
            assert compatibility == format_bytes[8:40]
            assert 1 <= len(payload) == length <= 65536 and hashlib.sha256(payload).digest() == checksum
            object = {"artifact_id": id.hex(), "statement_id": statement.hex() if statement is not None else None,
                "obligation_proof": obligation.hex() if obligation is not None else None,
                "compatibility": compatibility.hex(), "payload": payload.hex()}
            if payload.startswith(b'\xffNAOP\0'):
                manifest=program_manifest(payload[len(b'\xffNAOP\0'):])
                assert program_artifact_id(manifest)==object['artifact_id'] and bytes(manifest['statement'])==statement
                verify_program_input(catalog,manifest)
                object['program_manifest']=manifest
            else:
                assert artifact_id(object["statement_id"], object["payload"]) == object["artifact_id"]
            objects.append(object)
            by_id[id] = (statement, compatibility, length, checksum, commit, obligation)
            payload_bytes += length
        assert len(by_id) == count and payload_bytes == total
        assert bytes.fromhex(content_root(format_bytes[8:40].hex(), [object["artifact_id"] for object in objects])) == root
        represented = set()
        for commit, batch_root, members, question in catalog.execute("SELECT id,root,member_count,question FROM commits ORDER BY id"):
            ids = [row[0] for row in catalog.execute("SELECT artifact_id FROM members WHERE commit_id=? ORDER BY artifact_id", (commit,))]
            assert 1 <= len(ids) == members <= 4096 and batch_root in ids
            assert sum(by_id[id][2] for id in ids) <= 64 * 1024 * 1024, "per-commit payload bound"
            framed = b"naome:knowledge:catalog-commit:v1\0" + batch_root + len(ids).to_bytes(4, "big")
            assert question is None or 1 <= len(question) <= 16384
            source = question or b""
            framed += len(source).to_bytes(4, "big") + source
            for id in ids:
                assert id in by_id and id not in represented
                represented.add(id)
                statement, compatibility, length, checksum, origin, obligation = by_id[id]
                assert origin == commit
                dependencies = catalog.execute("SELECT ordinal,target FROM dependencies WHERE artifact_id=? ORDER BY ordinal", (id,)).fetchall()
                assert [ordinal for ordinal, _ in dependencies] == list(range(len(dependencies)))
                targets = [target for _, target in dependencies]
                assert targets == sorted(set(targets)) and len(targets) <= 32
                assert all(target in by_id and ordinals[target] < ordinals[id] for target in targets), "dependency precedes replay consumer"
                framed += id
                for optional in [statement, obligation]:
                    framed += bytes([optional is not None]) + (optional or b"")
                framed += compatibility + length.to_bytes(4, "big") + checksum
                framed += len(targets).to_bytes(4, "big") + b"".join(targets)
            assert hashlib.sha256(framed).digest() == commit
        assert represented == set(by_id), "every immutable payload belongs to one complete commit"
        return objects


def replace_catalog_payload(node, id, payload):
    with sqlite3.connect(node.directory / "proof-corpus.sqlite3") as catalog:
        catalog.execute("PRAGMA ignore_check_constraints=ON")
        original = catalog.execute("SELECT payload FROM artifacts WHERE id=?", (bytes.fromhex(id),)).fetchone()[0]
        assert catalog.execute("UPDATE artifacts SET payload=? WHERE id=?", (payload, bytes.fromhex(id))).rowcount == 1
        return original


class Node:
    def __init__(self, driver, index, directory, identity, port):
        self.driver, self.index, self.directory = driver, index, directory
        self.identity, self.port = identity, port
        self.resource_config = None
        self.process = None
        self.events, self.responses = [], {}
        self.condition = threading.Condition()
        self.serial, self.generation = 0, 0
        self.threads = []

    def start(self, producer_artifacts=(), command_input=True, test_controls=True, network_config=None):
        assert self.process is None or self.process.poll() is not None
        self.generation += 1
        event_offset = len(self.events)
        config = {
            "directory": str(self.directory),
            "listen": f"/ip4/127.0.0.1/tcp/{self.port}",
            "peers": [{"id": other.identity, "address": f"/ip4/127.0.0.1/tcp/{other.port}"}
                      for other in self.driver.nodes if other is not self],
            "producer_artifacts": list(producer_artifacts),
            "discovery": {"mdns": False, "dht": False},
        }
        if network_config is not None:
            config.update(network_config)
        path = self.driver.output / f"node-{self.index}-{self.generation}.config.json"
        path.write_text(json.dumps(config, indent=2) + "\n")
        command = [str(self.driver.binary), "run", str(path)]
        if test_controls:
            command.append("--test-controls")
        env = os.environ.copy()
        if self.resource_config is not None:
            env["NAOME_RESOURCE_CONFIG"] = str(self.resource_config)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE if command_input else subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1, env=env)
        self.driver.summary["commands"].append({"command": command, "pid": self.process.pid})
        self.driver.summary["processes"].append({"node": self.index, "generation": self.generation,
                                               "pid": self.process.pid, "peer_id": self.identity,
                                               "directory": str(self.directory), "endpoint": config["listen"],
                                               "network_config": {key: config[key] for key in ["listen", "peers", "discovery"]},
                                               "config_bytes": path.stat().st_size,
                                               "config_sha256": digest(path),
                                               "command_input": "pipe" if command_input else "closed",
                                               "producer_source_count": len(config["producer_artifacts"]),
                                               "producer_source_bytes": sum(len(s) // 2 for s in config["producer_artifacts"])})
        for name, stream in [("stdout", self.process.stdout), ("stderr", self.process.stderr)]:
            log = self.driver.output / f"node-{self.index}-{self.generation}.{name}.jsonl"
            thread = threading.Thread(target=self.read, args=(name, stream, log), daemon=True)
            thread.start()
            self.threads.append(thread)
        self.wait_event(lambda event: event.get("event") == "ready", timeout=15, since=event_offset)

    def read(self, name, stream, log):
        with log.open("w") as output:
            for line in stream:
                output.write(line)
                output.flush()
                if name != "stdout":
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                event["observed_monotonic"] = time.monotonic()
                with self.condition:
                    self.events.append(event)
                    if event.get("event") == "response":
                        self.responses[event["request"]] = event
                    self.condition.notify_all()
        with self.condition:
            self.condition.notify_all()

    def command(self, command, timeout=10, **fields):
        deadline = min(self.driver.deadline, time.monotonic() + timeout)
        while True:
            response = self._command_once(command, deadline, fields)
            if "error" not in response:
                return response["result"]
            if response.get("retryable") is not True or time.monotonic() >= deadline:
                raise AssertionError(f"node {self.index} {command}: {response['error']}")
            # Retry transient publication revocation under the original cutoff.
            time.sleep(min(0.02, max(0, deadline - time.monotonic())))

    def _command_once(self, command, deadline, fields):
        self.driver.check_deadline()
        self.serial += 1
        request = f"{self.index}-{self.generation}-{self.serial}"
        value = {"command": command, "request": request, **fields}
        transcript = self.driver.output / "commands.jsonl"
        with transcript.open("a") as out:
            out.write(json.dumps({"node": self.index, "generation": self.generation,
                                  "sent_monotonic": time.monotonic(), "value": value}) + "\n")
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()
        with self.condition:
            while request not in self.responses:
                if self.process.poll() is not None:
                    raise AssertionError(f"node {self.index} exited {self.process.returncode}")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"node {self.index} command timeout: {command}")
                self.condition.wait(min(remaining, 0.5))
            response = self.responses.pop(request)
        return response


    def status_snapshot(self, timeout=10):
        """Explicit complete-ID oracle assembled from bounded keyset responses."""
        deadline = min(self.driver.deadline, time.monotonic() + timeout)
        maximum = self.driver.summary["contract"]["limits"]["status_page_ids"]
        while time.monotonic() < deadline:
            first = self.command("status")
            count, root = first["accepted_artifacts"], first["root"]
            page, ids, after = first, [], None
            while True:
                limit = page["status_page_ids"]
                assert type(limit) is int and 0 < limit <= maximum, "status page limit exceeds contract"
                values = page["ids"]
                assert len(values) <= limit and values == sorted(set(values)), "bounded monotonic status page"
                assert not values or after is None or values[0] > after, "status cursor must advance"
                if page["accepted_artifacts"] != count or page["root"] != root:
                    break  # Accepted state changed between requests; restart.
                ids.extend(values)
                assert len(ids) <= count, "status page exceeds accepted count"
                cursor = page["next_after"]
                assert cursor == (values[-1] if len(values) == limit else None), "status continuation mismatch"
                if cursor is None:
                    assert len(ids) == count, "status claimed complete before all accepted IDs were read"
                    return {**first, "ids": ids, "next_after": None, "ids_complete": True}
                after = cursor
                if time.monotonic() >= deadline:
                    break
                page = self.command("status", after=after)
        raise AssertionError(f"node {self.index} did not provide one stable complete status inventory")

    def ids(self):
        return self.status_snapshot()["ids"]

    def wait_event(self, predicate, timeout=10, since=0):
        deadline = min(self.driver.deadline, time.monotonic() + timeout)
        with self.condition:
            while True:
                matches = [event for event in self.events[since:] if predicate(event)]
                if matches:
                    return matches[-1]
                if self.process.poll() is not None:
                    raise AssertionError(f"node {self.index} exited before expected event")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.driver.check_deadline()
                    raise AssertionError(f"node {self.index} event timeout")
                self.condition.wait(min(remaining, 0.5))

    def stop(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                if self.process.stdin is None:
                    self.process.terminate()
                else:
                    self.command("stop", timeout=3)
                self.process.wait(timeout=5)
            except (AssertionError, BrokenPipeError, subprocess.TimeoutExpired):
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        for thread in self.threads:
            thread.join(timeout=2)
        self.threads = []
        assert self.process.returncode == 0, f"node {self.index} unexpected stop: {self.process.returncode}"
        for stream in [self.process.stdin, self.process.stdout, self.process.stderr]:
            if stream is not None:
                stream.close()


class Driver:
    """Real transport qualification through the explicitly enabled developer harness."""
    def __init__(self, binary, output, timeout, profile):
        self.binary, self.output = binary.resolve(), output.resolve()
        self.deadline = time.monotonic() + timeout
        self.nodes = []
        output.mkdir(parents=True, exist_ok=False)
        contract = json.loads(self.helper_output([str(self.binary), "contract"]))
        repo = Path(__file__).resolve().parents[4]
        self.summary = {
            "schema": 1, "result": "running", "node_count": 4, "physical_host_count": 1,
            "producer": "finite deterministic formal source queues and checked-context authoring; no LLM inference",
            "contract": contract, "scenarios": {}, "commands": [], "processes": [], "proofs": {},
            **source_metadata(repo, self.helper_output),
            "profile": profile, "binary": str(self.binary), "binary_sha256": digest(self.binary),
            "driver_sha256": digest(__file__), "environment": platform.uname()._asdict(),
            "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "timeout_seconds": timeout,
        }

    def check_deadline(self):
        if time.monotonic() >= self.deadline:
            raise AssertionError("whole demonstration deadline exceeded")

    def helper_output(self, command, **arguments):
        self.check_deadline()
        return subprocess.check_output(command, text=True,
                                       timeout=max(0.001, self.deadline - time.monotonic()),
                                       **arguments)

    def init_identity(self, directory):
        command = [str(self.binary), "init", str(directory)]
        self.summary["commands"].append({"command": command})
        return json.loads(self.helper_output(command))["peer_id"]

    def topology(self, groups):
        for group in groups:
            for index in group:
                self.nodes[index].command("links", peers=[self.nodes[other].identity for other in group if other != index])
        expected = {index: {self.nodes[other].identity for other in group if other != index}
                    for group in groups for index in group}
        deadline = min(self.deadline, time.monotonic() + 15)
        statuses = {}
        while time.monotonic() < deadline:
            statuses = {index: self.nodes[index].command("status") for index in expected}
            if all(set(statuses[index]["connected"]) == peers for index, peers in expected.items()):
                return
            time.sleep(0.1)
        self.check_deadline()
        diagnostics = {
            str(index): {"connected": statuses.get(index, {}).get("connected"),
                         "expected": sorted(peers),
                         "events": [event for event in self.nodes[index].events
                                    if event.get("event") in ["connected", "disconnected", "dial_failed", "request_failed", "inbound_failed"]][-10:]}
            for index, peers in expected.items()
        }
        raise AssertionError(f"topology did not match configured partition: {json.dumps(diagnostics)}")

    def convergence(self, name, indices, expected, started, timeout=25, interval=0.1):
        expected = set(expected)
        root = content_root(self.summary["contract"]["compatibility"], expected)
        deadline = min(self.deadline, started + timeout)
        times, final = {}, {}
        while time.monotonic() < deadline:
            for index in indices:
                node = self.nodes[index]
                status = node.command("status")
                # Read the complete ID oracle once the bounded status can match it.
                # Repeated full scans during catch-up compete with the transfer itself.
                if status["accepted_artifacts"] != len(expected) or status["root"] != root or status["pending"]:
                    times.pop(str(index), None)
                    final.pop(str(index), None)
                    continue
                status = node.status_snapshot()
                if set(status["ids"]) == expected and status["root"] == root and not status["pending"]:
                    times.setdefault(str(index), time.monotonic() - started)
                    final[str(index)] = status
                else:
                    times.pop(str(index), None)
                    final.pop(str(index), None)
            if len(times) == len(indices):
                result = {"result": "pass", "ids": sorted(expected), "root": root,
                          "all_node_seconds": max(times.values()), "per_node_seconds": times,
                          "statuses": final}
                self.summary["scenarios"][name] = result
                print(f"{name}: all {len(indices)} nodes converged in {result['all_node_seconds']:.3f}s", flush=True)
                return
            time.sleep(interval)
        counts = {str(index): self.nodes[index].command("status")["accepted_artifacts"] for index in indices}
        raise AssertionError(f"{name}: all-node convergence timeout; accepted_counts={counts}")

    def retain_proof(self, label, object):
        assert artifact_id(object["statement_id"], object["payload"]) == object["artifact_id"]
        assert object["compatibility"] == self.summary["contract"]["compatibility"]
        path = self.output / f"{label}.envelope.json"
        path.write_text(json.dumps(object, indent=2) + "\n")
        self.summary["proofs"][label] = {"artifact_id": object["artifact_id"], "statement_id": object["statement_id"],
                                           "path": str(path), "sha256": digest(path)}
        return object["artifact_id"]

    def produce(self, node, depth, label):
        result = self.nodes[node].command("produce", artifact=source(depth))
        assert result["result"]["status"] == "accepted"
        object = result["object"]
        self.retain_proof(label, object)
        return object

    def large_inventory(self):
        """Fetch ten real inventory pages from an initially disconnected supplier."""
        reservations = []
        try:
            self.summary["node_count"] = 2
            # Keep the ten-page protocol scenario stable across hardware
            # calibrations. The default capacity advertises 64 IDs per page.
            resource_config = self.output / "inventory-resource-config.json"
            resource_config.write_text(json.dumps({
                "version": 1,
                "memory_bytes": 512 * 1024 * 1024,
                "workers": [1, 2, 2, 2],
                "tuning": {"id_page": 128, "inventory_page": 64, "fetches": 128},
            }, indent=2) + "\n")
            for index in range(2):
                directory = self.output / f"node-{index}"
                identity = self.init_identity(directory)
                reservation = socket.socket()
                reservation.bind(("127.0.0.1", 0))
                reservations.append(reservation)
                self.nodes.append(Node(self, index, directory, identity, reservation.getsockname()[1]))
                self.nodes[-1].resource_config = resource_config
            reservations[0].close()
            self.nodes[0].start()
            self.nodes[0].command("links", peers=[])
            ids = []
            for depth in range(1, 35):
                for used in range(depth):
                    self.check_deadline()
                    result = self.nodes[0].command("produce", artifact=inventory_source(depth, used))
                    assert result["result"]["status"] == "accepted"
                    ids.append(result["object"]["artifact_id"])
            assert len(ids) == len(set(ids)) == 595
            reservations[1].close()
            self.nodes[1].start()
            self.nodes[1].command("links", peers=[])
            assert self.nodes[1].command("status")["accepted_artifacts"] == 0
            started = time.monotonic()
            self.topology([[0, 1]])
            self.convergence("ten_page_inventory_complete_content_catchup", range(2), ids,
                             started, timeout=210, interval=0.5)
            pages = [event for event in self.nodes[1].events if event.get("event") == "inventory_page"]
            assert any(event["page"] >= 9 for event in pages)
            assert all(len(stored_objects(node)) == 595 for node in self.nodes)
            self.nodes[1].stop()
            self.nodes[1].start()
            self.convergence("ten_page_complete_batch_restart", range(2), ids, time.monotonic(), timeout=15)
            self.summary["scenarios"]["inventory_tail_discovery"] = {
                "result": "pass", "object_count": 595, "page_size": 64,
                "pages": pages, "tail_proof_id": max(ids),
                "receiver_tail_present": max(ids) in self.nodes[1].ids(),
            }
            self.summary["accepted_ids"] = sorted(ids)
            self.summary["content_root"] = content_root(self.summary["contract"]["compatibility"], ids)
            self.summary["result"] = "pass"
        finally:
            for reservation in reservations:
                reservation.close()

    def run(self):
        reservations = []
        try:
            for index in range(4):
                directory = self.output / f"node-{index}"
                identity = self.init_identity(directory)
                reservation = socket.socket()
                reservation.bind(("127.0.0.1", 0))
                reservations.append(reservation)
                self.nodes.append(Node(self, index, directory, identity, reservation.getsockname()[1]))
            initial = []
            for index, node in enumerate(self.nodes):
                reservations[index].close()
                producer_source = source(index + 1, padding=64000)
                node.start([producer_source])
                node.command("links", peers=[])
            assert len({node.identity for node in self.nodes}) == 4
            assert len({node.process.pid for node in self.nodes}) == 4
            for index, node in enumerate(self.nodes):
                event = node.wait_event(lambda event: event.get("event") == "producer_result")
                id = event["result"]["id"]
                status = node.status_snapshot()
                assert status["ids"] == [id]
                object = node.command("object", id=id)["object"]
                initial.append(self.retain_proof(f"independent-{index}", object))
            assert len(set(initial)) == 4
            padded = source(1, padding=64000)
            duplicate = self.nodes[0].command("produce", artifact=padded)
            assert duplicate["result"]["status"] == "duplicate"
            assert duplicate["object"]["artifact_id"] == initial[0]
            self.summary["scenarios"]["large_canonical_command_normalizes_duplicate"] = {
                "result": "pass", "input_bytes": len(padded) // 2,
                "artifact_id": initial[0], "status": "duplicate",
            }
            started = time.monotonic()
            self.topology([[0, 1, 2, 3]])
            self.convergence("independent_producers", range(4), initial, started)

            # The parent bytes are fetched first, then its actual cited helper.
            # A missing helper leaves no checked/pending/durable orphan.
            self.topology([[0], [1, 3], [2]])
            parent = self.produce(0, 7, "delayed-parent")
            premise = bytes.fromhex(question_fixture(7))
            child_source = cite_and_weaken(citation_id(parent), premise, member_self())
            compiled_child = self.nodes[0].command("produce", artifact=child_source)
            child = compiled_child["object"]
            metadata = compiled_child["metadata"]
            self.retain_proof("dependent", child)
            before = len(self.nodes[3].events)
            self.nodes[1].command("test_offer", peer=self.nodes[3].identity, metadata=metadata, object=child)
            self.nodes[3].wait_event(lambda event: event.get("event") == "proof_skipped" and "required dependency missing" in event.get("error", {}).get("message", ""), since=before)
            status = self.nodes[3].status_snapshot()
            assert not status["pending"] and set(status["ids"]) == set(initial)
            assert len(stored_objects(self.nodes[3])) == len(initial)
            self.summary["scenarios"]["dependent_before_parent"] = {"result": "pass", "isolated_failed_closure": status, "no_orphan": True}
            started = time.monotonic()
            parent_metadata = self.nodes[0].command("describe", id=parent["artifact_id"])["metadata"]
            self.nodes[1].command("test_offer", peer=self.nodes[3].identity, metadata=parent_metadata, object=parent)
            self.nodes[1].command("test_offer", peer=self.nodes[3].identity, metadata=metadata, object=child)
            union = initial + [parent["artifact_id"], child["artifact_id"]]
            self.convergence("dependency_resolution", [1, 3], union, started)
            self.topology([[0, 1, 2, 3]])
            self.convergence("dependency_all_node_union", range(4), union, time.monotonic())

            self.topology([[0, 1], [2, 3]])
            left = self.produce(0, 8, "partition-left")
            right = self.produce(2, 9, "partition-right")
            self.convergence("partition_left", [0, 1], union + [left["artifact_id"]], time.monotonic())
            self.convergence("partition_right", [2, 3], union + [right["artifact_id"]], time.monotonic())
            assert right["artifact_id"] not in self.nodes[0].ids()
            assert left["artifact_id"] not in self.nodes[2].ids()

            # Payload controls use distinct unresolved questions and real
            # metadata approval/Get. A forged typed address is rejected earlier,
            # before it can authorize any payload request.
            baseline = self.nodes[1].status_snapshot()
            controls = []
            for index, label in enumerate(["malformed", "claimed_id", "compatibility", "mathematical", "statement"]):
                proof_source = source(50 + index)
                object = self.nodes[0].command("test_check", artifact=proof_source)["object"]
                q = question_fixture(50 + index)
                if label == "malformed":
                    object["payload"] = "0000000001ff"
                    expected_error = "malformed certificate"
                elif label == "claimed_id":
                    object["artifact_id"] = "00" * 32
                    expected_error = "description proof address differs"
                elif label == "compatibility":
                    object["compatibility"] = "00" * 32
                    expected_error = "compatibility mismatch"
                elif label == "mathematical":
                    object["payload"] = "0000000004" + "0600000000" + "210000000000000000" + "210000000100000001" + "200000000100000002"
                    expected_error = "mp.expected_implication"
                else:
                    unrelated_source = source(60)
                    unrelated = self.nodes[0].command("test_check", artifact=unrelated_source)["object"]
                    object["statement_id"] = unrelated["statement_id"]
                    q = question_fixture(60)
                    expected_error = "checked identity mismatch"
                if label != "claimed_id":
                    object["artifact_id"] = artifact_id(object["statement_id"], object["payload"])
                metadata = proof_metadata(object, q)
                offset = len(self.nodes[1].events)
                sender_offset = len(self.nodes[0].events)
                self.nodes[0].command("test_offer", peer=self.nodes[1].identity, metadata=metadata, object=object)
                expected_event = "rejected" if label == "claimed_id" else "proof_skipped"
                event = self.nodes[1].wait_event(lambda event: event.get("event") == expected_event and (
                    (event.get("error", {}).get("diagnostic") or {}).get("failure", {}).get("code") == expected_error
                    if label == "mathematical" else expected_error in event.get("error", {}).get("message", "")), since=offset)
                if label == "claimed_id":
                    assert not any(event.get("event") == "exchange_request" and event.get("kind") == "get"
                                   and event.get("object_id") == object["artifact_id"]
                                   for event in self.nodes[0].events[sender_offset:]), "invalid metadata must not authorize payload retrieval"
                status = self.nodes[1].status_snapshot()
                assert status["ids"] == baseline["ids"] and status["root"] == baseline["root"] and not status["pending"]
                assert len(stored_objects(self.nodes[1])) == len(baseline["ids"])
                self.summary["scenarios"][f"reject_{label}"] = {"result": "pass", "error": event["error"], "unchanged_root": status["root"], "metadata_first": True}
                time.sleep(0.2)
            offset = len(self.nodes[0].events)
            self.nodes[0].command("test_offer", peer=self.nodes[1].identity,
                                 metadata=self.nodes[0].command("describe", id=left["artifact_id"])["metadata"],
                                 test_compatibility="00" * 32)
            self.nodes[0].wait_event(lambda event: event.get("event") == "peer_error" and event.get("error") == "compatibility mismatch", since=offset)
            self.summary["scenarios"]["reject_transport_compatibility"] = {"result": "pass"}
            for _ in range(3):
                offset = len(self.nodes[0].events)
                self.nodes[0].command("offer", peer=self.nodes[1].identity, id=left["artifact_id"])
                self.nodes[0].wait_event(lambda event: event.get("event") == "offer_result" and event.get("status") == "duplicate", since=offset)
                self.nodes[0].command("announce", id=left["artifact_id"])
                time.sleep(0.2)
            status = self.nodes[1].status_snapshot()
            assert status["root"] == baseline["root"] and status["ids"] == baseline["ids"]
            self.summary["scenarios"]["duplicate_delivery_and_announcements"] = {"result": "pass", "deliveries": 3, "announcements": 3, "unchanged_root": status["root"]}
            started = time.monotonic()
            self.topology([[0, 1, 2, 3]])
            union += [left["artifact_id"], right["artifact_id"]]
            self.convergence("partition_reconnection_union", range(4), union, started)

            self.nodes[2].stop()
            new = self.produce(0, 10, "while-offline")
            union.append(new["artifact_id"])
            self.convergence("offline_remaining_nodes", [0, 1, 3], union, time.monotonic())
            started = time.monotonic()
            self.nodes[2].start()
            self.convergence("restart_catchup", range(4), union, started)

            for node in self.nodes:
                node.stop()
            old_identity = self.nodes[3].identity
            self.nodes[3].directory = self.output / "new-node-3"
            self.nodes[3].identity = self.init_identity(self.nodes[3].directory)
            assert old_identity != self.nodes[3].identity
            started = time.monotonic()
            for node in self.nodes:
                node.start()
            self.convergence("new_identity_empty_store_catchup", range(4), union, started)
            for node in self.nodes:
                # Checked-context generations are disposable; audit durable files after owner shutdown.
                node.stop()
                assert sorted(path.name for path in node.directory.iterdir()) == [
                    "identity.key", "knowledge.lock", "proof-corpus.format",
                    "proof-corpus.sqlite3", "question-registry.initialized", "research"]
                assert sorted(path.name for path in (node.directory / "research").iterdir()) == [
                    ".disposable-questions.lock", "proof-backlog.initialized",
                    "proof-backlog.sqlite3", "questions.sqlite3"]
                assert len(stored_objects(node)) == len(union)
            self.summary["scenarios"]["economy_independence"] = {"result": "pass", "storage": "identity, exclusive locks, immutable binary proof catalog, durable local question/proof queues and initialization receipts; no ledger, reward or balance state"}
            self.summary["accepted_ids"] = sorted(union)
            self.summary["content_root"] = content_root(self.summary["contract"]["compatibility"], union)
            self.summary["result"] = "pass"
        finally:
            for reservation in reservations:
                reservation.close()

    def finish(self):
        cleanup_errors = []
        for node in self.nodes:
            try:
                node.stop()
            except Exception as error:
                cleanup_errors.append(str(error))
        self.summary["cleanup"] = {"all_processes_exited": all(node.process is None or node.process.poll() is not None for node in self.nodes), "errors": cleanup_errors}
        if cleanup_errors:
            self.summary["result"] = "fail"
        # Keep transport identities private; digest only public reproduction inputs/evidence.
        files = [path for path in self.output.iterdir() if path.is_file() and path.name != "summary.json"]
        self.summary["artifacts"] = {str(path): digest(path) for path in sorted(files)}
        (self.output / "summary.json").write_text(json.dumps(self.summary, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True, help="developer-tools naome-knowledge-dev executable")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--profile", default="test")
    parser.add_argument("--large-inventory", action="store_true")
    args = parser.parse_args()
    driver = Driver(args.binary, args.output, args.timeout, args.profile)
    try:
        if args.large_inventory:
            driver.large_inventory()
        else:
            driver.run()
    except Exception as error:
        driver.summary["result"] = "fail"
        driver.summary["error"] = str(error)
        traceback.print_exc()
    finally:
        driver.finish()
    print(json.dumps({"result": driver.summary["result"], "summary": str(driver.output / "summary.json")}))
    return 0 if driver.summary["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
