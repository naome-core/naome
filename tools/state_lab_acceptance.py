#!/usr/bin/env python3
"""Run real LAB-window research acceptance with four independent local processes.

This is local network simulation, not multi-machine qualification. The default
requires a real Codex agenda review. Nothing is mocked or clock-accelerated.
Private keys, reveal material, histories and archives remain in a mode-0700
temporary directory. Only acceptance-report.json is suitable for publication.
Run after building naome with the repository-pinned Rust toolchain.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import platform
from pathlib import Path
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time


REPO = Path(__file__).resolve().parents[1]
EXAMPLES = REPO / "examples/state-workflow"
HELPER = "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73"
AGREEMENT_FIELDS = ("state", "head", "height", "accounts", "reserve_atoms",
                    "claims", "library_root", "paid_completions", "authority",
                    "validators", "join_queue", "consumed_claims")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def retirement_indices(path):
    indices = json.loads(path.read_text())
    require(isinstance(indices, list) and len(indices) == 4
            and all(type(index) is int for index in indices)
            and sorted(indices) == [0, 1, 2, 3],
            "retirement order must list node indices 0, 1, 2, 3 exactly once")
    return indices


class Lab:
    def __init__(self, args):
        self.args = args
        self.binary = args.binary.resolve(strict=True)
        self.validator = args.validator.resolve(strict=True)
        self.verifier = args.verifier.resolve(strict=True)
        self.root = Path(tempfile.mkdtemp(prefix="nml-", dir="/tmp"))
        os.chmod(self.root, 0o700)
        self.nodes = {}
        self.generations = [0] * 4
        self.lock = threading.Lock()
        self.started = time.monotonic()
        self.report = {
            "version": 1, "result": "running",
            "qualification": "four independent local processes using authenticated TCP; not multi-machine evidence",
            "timing": {"profile": "lab", "voting_seconds": 300,
                       "commitment_seconds": 120, "reveal_seconds": 120},
            "run_records": 128, "compact": True,
            "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(), "logical_cpus": os.cpu_count()},
            "binary": str(self.binary),
            "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "executables": {name: {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
                            for name, binary in (("naome", self.binary), ("naome-validator", self.validator), ("naome-verifier", self.verifier))},
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "commands": [], "observations": [], "checks": {},
        }
        source_paths = [REPO / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")]
        source_paths += [p for p in (REPO / "crates").rglob("*") if p.is_file() and p.suffix in (".rs", ".toml")]
        source_paths += list(EXAMPLES.glob("*")) + [REPO / "tools/state_lab_acceptance.py", REPO / "tools/agenda_agent_codex.py"]
        source_manifest = {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in sorted(set(source_paths)) if p.is_file()}
        source_bytes = (json.dumps(source_manifest, sort_keys=True, indent=2) + "\n").encode()
        self.file("source-manifest.json").write_bytes(source_bytes)
        self.report["source_snapshot"] = {
            "file_count": len(source_manifest), "manifest_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
            "scope": "Cargo manifests/lock, pinned toolchain, Rust crate sources, research Python tools and example fixtures at runner startup; includes uncommitted files",
            "provider_sha256": hashlib.sha256(args.provider.resolve(strict=True).read_bytes()).hexdigest(),
        }
        self.base = self.free_ports()
        self.save()

    def free_ports(self):
        for _ in range(1000):
            base = 20000 + int.from_bytes(os.urandom(2), "big") % 40000
            held = []
            try:
                for index in range(8):
                    s = socket.socket()
                    held.append(s)
                    s.bind(("127.0.0.1", base + index))
                return base
            except OSError:
                pass
            finally:
                for s in held:
                    s.close()
        raise RuntimeError("cannot reserve eight local TCP endpoints")

    def file(self, name):
        if name == "genesis.bin":
            return self.root / "network" / name
        return self.root / name

    def config(self, index):
        return self.root / "network" / f"node-{index}/node.json"

    def key(self, index):
        return self.root / "network" / f"accounts/account-{index}.key"

    def public_path(self, value):
        return str(value).replace(str(self.root), "$RUN").replace(str(REPO), "$REPO")

    def save(self):
        temporary = self.file("acceptance-report.next")
        temporary.write_text(json.dumps(self.report, indent=2) + "\n")
        temporary.replace(self.file("acceptance-report.json"))

    def record_command(self, command, elapsed, returncode):
        with self.lock:
            self.report["commands"].append({
                "argv": [self.public_path(arg) for arg in command],
                "elapsed_seconds": round(elapsed, 3), "exit_code": returncode,
            })
            self.save()

    def run(self, *args, timeout=40, tolerate=False, log=True):
        binary = self.verifier if args and args[0] == "verify" else self.binary
        command = [str(binary), *map(str, args)]
        start = time.monotonic()
        result = subprocess.run(command, capture_output=True, timeout=timeout)
        if log:
            self.record_command(command, time.monotonic() - start, result.returncode)
        if result.returncode:
            if tolerate:
                return None
            # Raw diagnostics remain private and are deliberately not copied to
            # the public report; no provider output or secret bytes are printed.
            self.file("last-command.stderr").write_bytes(result.stderr)
            raise RuntimeError(f"CLI {args[0]} failed with exit code {result.returncode}; see private diagnostics")
        return json.loads(result.stdout)

    def observe(self, label, value=None):
        observation = {"event": label, "elapsed_seconds": round(time.monotonic() - self.started, 3),
                       "free_bytes": shutil.disk_usage(self.root).free}
        if value is not None:
            observation["evidence"] = value
        self.report["observations"].append(observation)
        self.save()
        print(json.dumps(observation), flush=True)

    def start(self, index):
        require(index not in self.nodes, "node already started")
        generation = self.generations[index]
        self.generations[index] += 1
        command = [str(self.validator), "start", str(self.config(index))]
        with self.file(f"node-{index}-{generation}.events").open("wb") as out, \
                self.file(f"node-{index}-{generation}.errors").open("wb") as err:
            self.nodes[index] = subprocess.Popen(command, stdout=out, stderr=err)
        self.record_command(command, 0, None)

    def status(self, index):
        return self.run("status", self.config(index), tolerate=True, log=False)

    def wait(self, index, predicate, description, timeout=720):
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            for number, child in self.nodes.items():
                require(child.poll() is None, f"node {number} exited unexpectedly; private logs retained")
            status = self.status(index)
            if status is not None and predicate(status):
                return status
            time.sleep(0.25)
        raise RuntimeError(f"timeout waiting for {description} on node {index}")

    def stop(self, index):
        self.run("shutdown", self.config(index))
        child = self.nodes.pop(index)
        require(child.wait(timeout=20) == 0, f"node {index} did not stop cleanly")

    def cleanup(self):
        for child in self.nodes.values():
            if child.poll() is None:
                child.terminate()
        for child in self.nodes.values():
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        self.nodes.clear()

    def receipt(self, index, operation):
        start = time.monotonic()
        while time.monotonic() - start < 90:
            result = self.run("receipt", self.config(index), operation, log=False)
            if result["status"] == "finalized":
                self.observe("finalized_receipt", {"operation": operation, **result})
                return result
            require(result["status"] != "rejected", "operation preview rejected; inspect private node state")
            time.sleep(0.25)
        raise RuntimeError("operation did not finalize within 90 seconds")

    def phase(self, index, phase):
        result = self.wait(index, lambda s: (s.get("active") or {}).get("phase") == phase,
                           f"LAB {phase} phase")
        self.observe("phase", {"node": index, "phase": phase, "height": result["height"],
                               "certified_time": result["time"], "deadline": result["active"]["deadline"]})
        return result

    def submit(self, index, author, source, label):
        return self.run("submit", self.config(index), self.key(author), source,
                        f"Reusable foundational mathematical result {label}", self.file(f"{label}.submit"))["operation"]

    def approve(self, indices, label, agent=False):
        for index in indices:
            self.phase(index, "Voting")
        def vote(index):
            if agent and index == 0:
                result = self.run("agent-vote", self.config(index), self.key(index),
                                  self.file(f"{label}-agent.action"), self.file(f"{label}-agent.report"),
                                  self.args.provider.resolve(), timeout=150)
                review = result["agent_review"]
                require(review["decision"]["decision"] in ("YES", "NO"), "actual agent returned no valid agenda decision")
                with self.lock:
                    self.report["checks"]["actual_agent_review"] = review
                    self.save()
                return review["operation"]
            return self.run("vote", self.config(index), self.key(index), "YES",
                            self.file(f"{label}-vote-{index}.action"))["operation"]
        with ThreadPoolExecutor(max_workers=3) as pool:
            operations = list(pool.map(vote, indices))
        for index, operation in zip(indices, operations):
            self.receipt(index, operation)

    def package(self, author, source, label, *inputs):
        output = self.file(f"{label}.package")
        result = self.run("package", self.file("genesis.bin"), self.key(author), output, source, *inputs)
        return output, result

    def commit(self, index, author, package, label):
        result = self.run("commit", self.config(index), self.key(author), package,
                          self.file(f"{label}.secret"), self.file(f"{label}.commit"))
        receipt = self.receipt(index, result["operation"])
        return result["operation"], receipt

    def reveal(self, index, author, label):
        result = self.run("reveal", self.config(index), self.key(author),
                          self.file(f"{label}.secret"), self.file(f"{label}.reveal"))
        return self.receipt(index, result["operation"])

    def agreement(self, indices, expected):
        for index in indices:
            status = self.wait(index, lambda s: s["state"] == expected["state"], "identical finalized state", 180)
            require(all(status[f] == expected[f] for f in AGREEMENT_FIELDS), "state/account/claim agreement failed")
        self.observe("agreement", {f: expected[f] for f in AGREEMENT_FIELDS})

    def completed(self, index, count):
        return self.wait(index, lambda s: s["paid_completions"] == count, f"completion {count}")

    def source(self, name, text):
        output = self.file(name)
        output.write_text(text)
        return output

    def execute(self):
        plan = self.file("retirement-order.json")
        plan.write_text(json.dumps(self.args.retirement_indices) + "\n")
        configured = self.run("setup", self.root / "network", "lab", "128", self.base, plan, "compact")
        self.report["genesis"] = configured["genesis"]
        self.report["profile"] = configured["profile"]
        self.report["required_storage_bytes"] = configured["required_storage_bytes"]
        self.report["immutable_profile"] = self.run("profile-info", self.file("genesis.bin"))
        selected = configured["retirement_order"]
        require(len(selected) == 4 and len(set(selected)) == 4
                and self.report["immutable_profile"]["retirement_order"] == selected,
                "profile-info retirement order differs from setup output")
        self.report["checks"]["bootstrap_retirement_order"] = {
            "node_indices": self.args.retirement_indices, "validator_ids": selected,
        }
        configs = [json.loads(self.config(i).read_text()) for i in range(4)]
        for field in ("history", "history_anchor", "signer", "signer_anchor", "custody", "custody_anchor", "handoff", "handoff_anchor", "consensus_key", "transport_key", "control_socket"):
            require(len({config[field] for config in configs}) == 4, f"nodes share a {field} path")
        self.report["checks"]["independent_process_custody"] = {
            "validators": 4, "separate_histories": True, "separate_signer_journals": True,
            "separate_consensus_keys": True, "separate_transport_keys": True,
        }
        self.observe("configured", configured | {"directory": "$RUN/network"})
        preference = self.source("operator-profile.txt", "Prioritize precise foundational mathematics and reusable equality lemmas. Approve well-defined formal questions that build a reusable library; reject unrelated or unclear questions.\n")
        self.run("profile", self.config(0), preference)
        require(self.run("profile-info", self.file("genesis.bin")) == self.report["immutable_profile"],
                "editing operator preferences changed the immutable genesis profile")
        self.report["checks"]["local_profile_edit"] = {"operator": 0, "text": preference.read_text(), "immutable_profile_unchanged": True}
        a_alternate = self.source("a-alternate.nao", '''foundation = "naome:zfc"
formulas:
    a = forall(y, forall(x, equal(x, x)))
statement = a
proof:
    p0 = cite("''' + HELPER + '''")
    p1 = generalization(p0, y)
    p2 = simplification(a, a)
    p3 = modus_ponens(p1, p2)
    p4 = modus_ponens(p1, p3)
    return p4
''')
        a4, a4_info = self.package(4, EXAMPLES / "solution-a.nao", "a4", "--helper", EXAMPLES / "helper-h.nao")
        a5, a5_info = self.package(5, a_alternate, "a5", "--helper", EXAMPLES / "helper-h.nao")
        require(a4_info["root"] != a5_info["root"], "A alternatives must be different checked proofs")
        for index in range(4):
            self.start(index)
        for index in range(4):
            self.wait(index, lambda s: s["height"] == 0, "genesis startup", 120)
        a = self.submit(0, 4, EXAMPLES / "question-a.nao", "A")
        # The actual agenda judgment remains unchanged, including a possible NO.
        # Three independently signed fixture-owner YES votes exercise approval.
        self.approve([0, 1, 2, 3], "A", agent=True)
        self.phase(0, "Commit")
        first_commit, first_receipt = self.commit(0, 4, a4, "a4")
        after_commit = self.status(0)
        retried_commit, retried_receipt = self.commit(0, 4, a4, "a4")
        require((retried_commit, retried_receipt) == (first_commit, first_receipt),
                "durable commitment retry changed its operation or finalized receipt")
        require(self.status(0)["accounts"] == after_commit["accounts"], "commitment retry consumed another nonce")
        self.report["checks"]["durable_commitment_retry"] = {"operation": first_commit, "receipt": first_receipt, "unchanged_accounts_and_nonces": True}
        later_commit, later_receipt = self.commit(0, 5, a5, "a5")
        coordinate = lambda r: (r["height"], r["operation_index"])
        require(coordinate(first_receipt) < coordinate(later_receipt), "A commitment order not established")
        self.phase(0, "Reveal")
        self.reveal(0, 5, "a5")
        self.reveal(0, 4, "a4")
        require(self.status(0)["active"]["reveals"] == 2, "both A reveals must be finalized before settlement")
        first = self.completed(0, 1)
        self.agreement(range(4), first)
        a_question = self.run("question", self.config(0), a)
        require(a_question["outcome"] == "PROVED", "A must settle as PROVED")
        require(a_question["normalization"]["winning_commit"]["operation"] == first_commit,
                "earliest commitment did not win reversed reveal order")
        self.report["checks"]["AB02_reverse_reveal"] = {"earlier_commit": first_commit, "later_commit": later_commit,
                                                       "different_roots": [a4_info["root"], a5_info["root"]], "question": a_question}
        self.stop(0)
        remote_index = next(v["index"] for v in first["validators"]
                            if v["endpoint"] == f"127.0.0.1:{self.base + 2}")
        h = self.run("fetch-proof-from", self.config(1), remote_index, HELPER, self.file("h.proof"), timeout=60)
        require(h.get("retrieval") == "authenticated peer-to-peer network" and h.get("source_validator") == remote_index,
                "H retrieval did not use the selected remote validator")
        self.run("check-proof", self.file("genesis.bin"), self.file("h.proof"))
        b_package, b_info = self.package(5, EXAMPLES / "solution-b-original.nao", "b5",
                                       "--reference", self.file("h.proof"), "--helper", EXAMPLES / "helper-h-duplicate.nao")
        b = self.submit(1, 5, EXAMPLES / "question-b.nao", "B")
        self.approve([1, 2, 3], "B")
        self.phase(1, "Commit")
        self.commit(1, 5, b_package, "b5")
        self.phase(1, "Reveal")
        self.reveal(1, 5, "b5")
        second = self.completed(1, 2)
        self.agreement([1, 2, 3], second)
        b_question = self.run("question", self.config(1), b)
        require(b_question["outcome"] == "REFUTED", "B must settle as REFUTED")
        normalization = b_question["normalization"]
        require(normalization["substitutions"], "B duplicate helper was not substituted")
        require(normalization["original_hash"] == b_info["original_hash"], "B original not preserved")
        require(any(p["recipient"] == h["recipient"] and int(p["atoms"]) > 0 for p in normalization["citation_payments"]),
                "B did not pay H's original recipient")
        h_again = self.run("fetch-proof", self.config(2), HELPER, self.file("h-again.proof"))
        require(all(h_again[f] == h[f] for f in ("author", "recipient", "height", "operation_index")), "H provenance changed")
        require(next(x["balance_atoms"] for x in second["accounts"] if x["account"] == h["recipient"]) == "800000000",
                "A author did not receive 700M completion plus 100M citation")
        c = self.submit(1, 4, EXAMPLES / "question-c.nao", "C")
        self.wait(1, lambda s: s["active"] is None and s["queued"] == 0 and s["height"] > second["height"], "C known-unpaid classification")
        c_question = self.run("question", self.config(1), c)
        require(c_question["status"] == "KnownUnpaid" and c_question["completion_reward_atoms"] == "0", "C incorrectly rewarded")
        self.report["checks"]["helper_normalization_citation_known"] = {"helper": {k: v for k, v in h.items() if k != "saved"}, "B": b_question, "C": c_question}
        self.start(0)
        settled = self.status(1)
        self.agreement(range(4), settled)
        validators = settled["validators"]
        canonical = [next(v["index"] for v in validators
                          if v["endpoint"] in (f"127.0.0.1:{self.base + n}",
                                                f"127.0.0.1:{self.base + n + 4}"))
                     for n in range(4)]
        for local in range(4):
            for remote in range(4):
                if local // 2 != remote // 2:
                    self.run("peer", self.config(local), canonical[remote], "off")
        d_statement = "forall(z, forall(y, forall(x, equal(x, x))))"
        d_question_source = self.source("question-d.nao", f'foundation = "naome:zfc"\nstatement = {d_statement}\n')
        d = self.submit(0, 4, d_question_source, "D")
        time.sleep(5)
        require(all(self.status(i)["state"] == settled["state"] for i in range(4)), "2:2 partition finalized a record")
        self.observe("partition_no_progress", {"seconds": 5, "state": settled["state"]})
        for local in range(4):
            for remote in range(4):
                if local // 2 != remote // 2:
                    self.run("peer", self.config(local), canonical[remote], "on")
        self.approve([0, 1, 2], "D")
        d_base = f'''foundation = "naome:zfc"
formulas:
    d = {d_statement}
statement = d
proof:
    p0 = cite("{HELPER}")
    p1 = generalization(p0, y)
    p2 = generalization(p1, z)
'''
        d4, d4_info = self.package(4, self.source("d4.nao", d_base + "    return p2\n"), "d4", "--reference", self.file("h.proof"))
        d5, d5_info = self.package(5, self.source("d5.nao", d_base + "    p3 = simplification(d, d)\n    p4 = modus_ponens(p2, p3)\n    p5 = modus_ponens(p2, p4)\n    return p5\n"), "d5", "--reference", self.file("h.proof"))
        require(d4_info["root"] != d5_info["root"], "D alternatives must be different checked proofs")
        self.phase(0, "Commit")
        missing_commit, missing_receipt = self.commit(0, 4, d4, "d4")
        valid_commit, valid_receipt = self.commit(0, 5, d5, "d5")
        require(coordinate(missing_receipt) < coordinate(valid_receipt), "D commitment order not established")
        self.phase(0, "Reveal")
        self.reveal(0, 5, "d5")
        third = self.completed(0, 3)
        require(len(third["claims"]) == 3, "expected exactly three one-time eligibility claims")
        require(sum(int(account["balance_atoms"]) for account in third["accounts"])
                + int(third["reserve_atoms"]) == 3_000_000_000, "three-completion issuance conservation failed")
        d_question = self.run("question", self.config(0), d)
        require(d_question["normalization"]["winning_commit"]["operation"] == valid_commit,
                "later valid reveal failed to win when earlier reveal was absent")
        self.report["checks"]["AB02_missing_earlier"] = {"missing_commit": missing_commit, "winning_commit": valid_commit,
                                                        "different_roots": [d4_info["root"], d5_info["root"]], "question": d_question}
        self.agreement(range(4), third)
        for index in range(4):
            self.stop(index)
        for index in range(4):
            self.start(index)
        self.agreement(range(4), third)
        archive = self.file("observer")
        self.run("export", self.config(2), archive, timeout=180)
        verified = self.run("verify", self.file("genesis.bin"), archive, timeout=180)
        require(all(verified[f] == third[f] for f in AGREEMENT_FIELDS), "independent replay differs")
        dependencies = [self.file("h.proof")]
        for label, operation, question in [("A", a, a_question), ("B", b, b_question), ("D", d, d_question)]:
            inspection = self.run("inspect", self.file("genesis.bin"), archive, operation, self.file(f"inspect-{label}"), timeout=180)
            require(inspection == question, "offline question inspection differs")
            root = question["normalization"]["normalized_root"]
            proof = self.file(f"{label}.proof")
            self.run("fetch-proof", self.config(2), root, proof)
            checked = self.run("check-proof", self.file("genesis.bin"), proof, *dependencies)
            require(checked["proof"] == root, "independent normalized proof check differs")
            dependencies.append(proof)
        frame = archive / "00000001.finality"
        original = frame.read_bytes()
        frame.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        try:
            require(self.run("verify", self.file("genesis.bin"), archive, tolerate=True, timeout=180) is None,
                    "corrupt export was accepted")
        finally:
            frame.write_bytes(original)
        for index in range(4):
            self.stop(index)
        self.report["checks"]["partition_restart_export"] = {"partition_seconds": 5, "cold_restart_nodes": 4,
                                                               "verified_state": verified["state"], "corrupt_export_rejected": True}
        self.report["final_state"] = {f: third[f] for f in AGREEMENT_FIELDS}
        self.report["result"] = "passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=REPO / "target/debug/naome")
    parser.add_argument("--validator", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--provider", type=Path, default=REPO / "tools/agenda_agent_codex.py")
    parser.add_argument("--retirement-order", type=Path, required=True,
                        help="JSON permutation of generated node indices 0, 1, 2, 3")
    args = parser.parse_args()
    try:
        args.retirement_indices = retirement_indices(args.retirement_order)
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))
    os.umask(0o077)
    lab = Lab(args)
    print(json.dumps({"private_run_directory": str(lab.root), "mode": "real lab windows; actual agent required"}), flush=True)
    code = 0
    try:
        lab.execute()
    except Exception as error:
        code = 1
        lab.report["result"] = "failed"
        lab.report["failure"] = lab.public_path(error)
    finally:
        lab.cleanup()
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        lab.report["resources"] = {"elapsed_seconds": round(time.monotonic() - lab.started, 3),
                                   "children_user_cpu_seconds": usage.ru_utime, "children_system_cpu_seconds": usage.ru_stime,
                                   "children_maxrss_native_units": usage.ru_maxrss, "platform": sys.platform,
                                   "retained_file_bytes": sum(p.stat().st_size for p in lab.root.rglob("*") if p.is_file()),
                                   "free_bytes_end": shutil.disk_usage(lab.root).free}
        lab.save()
        print(json.dumps({"result": lab.report["result"], "public_report": str(lab.file("acceptance-report.json")),
                          "private_state_retained": str(lab.root)}), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
