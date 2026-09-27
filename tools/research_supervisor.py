#!/usr/bin/env python3
"""Restartable operator policy runner over the NAOME CLI's saved-action boundary.

This process never owns node custody or selected history. See docs/mvp/operator-supervisor.md.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time

TERMINAL = {"Completed", "KnownUnpaid", "NotApproved", "Unresolved", "Expired", "CapacityEnd"}
HEX = set("0123456789abcdef")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def private_directory(path):
    path = Path(path).absolute()
    if not path.exists():
        path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077,
            f"private directory required: {path}")
    return path.resolve()


def private_file(path):
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077,
                f"private regular file required: {path}")


def atomic_json(path, value):
    private_file(path)
    fd, name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(value, out, sort_keys=True, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def absolute_file(value):
    path = Path(value)
    require(path.is_absolute() and path.is_file(), f"existing absolute file required: {value}")
    return str(path.resolve())


def load_plan(path):
    raw = Path(path).read_bytes()
    plan = json.loads(raw)
    require(plan.get("version") == 1 and isinstance(plan.get("questions"), list)
            and plan["questions"], "plan requires version 1 and a nonempty question list")
    plan["genesis"] = absolute_file(plan["genesis"])
    plan["node"] = absolute_file(plan["node"])
    labels = set()
    for q in plan["questions"]:
        require(isinstance(q, dict) and isinstance(q.get("label"), str)
                and q["label"].isascii() and q["label"].replace("-", "").replace("_", "").isalnum()
                and q["label"] not in labels and len(q["label"]) <= 40,
                "questions need unique ASCII labels")
        labels.add(q["label"])
        require(isinstance(q.get("purpose"), str) and 0 < len(q["purpose"]) <= 4096,
                "question purpose required")
        for field in ("source", "author_key", "solution"):
            q[field] = absolute_file(q[field])
        require(isinstance(q.get("votes"), list) and q["votes"], "explicit owner vote policies required")
        for vote in q["votes"]:
            vote["node"] = absolute_file(vote["node"])
            vote["owner_key"] = absolute_file(vote["owner_key"])
            node = json.loads(Path(vote["node"]).read_text())
            owner = Path(node["account_key"])
            if not owner.is_absolute():
                owner = Path(vote["node"]).parent / owner
            require(owner.resolve() == Path(vote["owner_key"]), "vote key must be configured node owner")
            require(vote.get("policy") in ("YES", "NO", "agent"), "vote policy must be YES, NO, or agent")
            if vote["policy"] == "agent":
                vote["provider"] = absolute_file(vote["provider"])
                if "provider_config" in vote:
                    vote["provider_config"] = absolute_file(vote["provider_config"])
            else:
                require("provider" not in vote and "provider_config" not in vote,
                        "manual vote cannot configure a provider")
        require(len({v["owner_key"] for v in q["votes"]}) == len(q["votes"]), "duplicate owner vote")
        for field in ("helpers", "references"):
            require(isinstance(q.get(field, []), list), f"{field} must be a list")
        q["helpers"] = [absolute_file(value) for value in q.get("helpers", [])]
        for proof in q.get("references", []):
            require(isinstance(proof, str) and len(proof) == 64 and set(proof) <= HEX,
                    "reference must be a lowercase ProofId")
        q["references"] = q.get("references", [])
    return plan


def input_hash(plan):
    """Bind the already supplied agenda and proof bytes for every restart."""
    files = [plan["genesis"], plan["node"]]
    for q in plan["questions"]:
        files.extend(q[field] for field in ("source", "author_key", "solution"))
        files.extend(q["helpers"])
        for vote in q["votes"]:
            files.extend((vote["node"], vote["owner_key"]))
            for field in ("provider", "provider_config"):
                if field in vote:
                    files.append(vote[field])
    return {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in sorted(set(files))}


class Runner:
    def __init__(self, args):
        self.root = private_directory(args.private_dir)
        self.lock = self.root / "supervisor.lock"
        private_file(self.lock)
        self.lock_fd = os.open(self.lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.plan = load_plan(args.plan)
        self.bin = absolute_file(args.bin)
        self.verifier = absolute_file(args.verifier)
        self.poll = args.poll
        require(0.1 <= self.poll <= 30, "poll must be between 0.1 and 30 seconds")
        self.plan_hash = hashlib.sha256(json.dumps(self.plan, sort_keys=True).encode()).hexdigest()
        self.inputs = input_hash(self.plan)
        self.executables = {"naome": hashlib.sha256(Path(self.bin).read_bytes()).hexdigest(),
                            "naome-verifier": hashlib.sha256(Path(self.verifier).read_bytes()).hexdigest()}
        self.genesis = self.call("profile-info", self.plan["genesis"])["genesis"]
        self.path = self.root / "supervisor.json"
        private_file(self.path)
        if self.path.exists():
            self.state = json.loads(self.path.read_text())
            require(self.state["plan_sha256"] == self.plan_hash and self.state["genesis"] == self.genesis,
                    "plan or genesis changed; preserve this run and start a new private directory")
            require(self.state["inputs"] == self.inputs, "supplied question, proof, key, or policy bytes changed")
            require(self.state["executables"] == self.executables,
                    "operator or verifier executable changed during the retained run")
        else:
            require(not [p for p in self.root.iterdir()
                         if p.name != "supervisor.lock" and not p.name.startswith(".state-")],
                    "private action storage exists without supervisor.json; preserve it for recovery")
            self.state = {"version": 1, "plan_sha256": self.plan_hash, "genesis": self.genesis,
                          "inputs": self.inputs, "executables": self.executables,
                          "questions": [{} for _ in self.plan["questions"]], "stop": None}
            self.save()
        self.checked_archives = set()

    def save(self):
        atomic_json(self.path, self.state)

    def call(self, *args, verifier=False):
        # Full-history export and replay grow with the immutable record bound.
        timeout = 1800 if args[0] in ("export", "verify") else 150 if args[0] == "agent-vote" else 90
        result = subprocess.run([self.verifier if verifier else self.bin, *map(str, args)],
                                capture_output=True, timeout=timeout)
        if result.returncode:
            # CLI diagnostic may contain private data; leave it in the private store.
            path = self.root / "last-error.txt"
            private_file(path)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(result.stderr[-8192:])
            raise RuntimeError(f"{args[0]} failed; private diagnostics in {path}")
        return json.loads(result.stdout)

    def status(self):
        value = self.call("status", self.plan["node"])
        require(value["status"] == "finalized" and value["genesis"] == self.genesis,
                "node status disagrees with pinned genesis")
        return value

    def vote_ingress(self, vote):
        # The bounded agent adapter checks its configured node owner. Manual
        # signed ballots may use the common local intake after that owner's
        # policy and key have been pinned by the plan.
        return vote["node"] if vote["policy"] == "agent" else self.plan["node"]

    def action(self, entry, name, command, config, *arguments):
        require(input_hash(self.plan) == self.inputs,
                "supplied question, proof, key, or policy bytes changed during the run")
        path = self.root / f"{entry['label']}-{name}.action"
        private_file(path)
        if name in entry["state"].get("actions", {}):
            self.check_action(entry, name)
            return entry["state"]["actions"][name]
        if path.exists() and command not in ("commit", "reveal"):
            answer = self.call("send", config, path)
        else:
            answer = self.call(command, *arguments)
        require(answer.get("vote_signed") is not False,
                "owner agent requested REVIEW; an operator decision is required")
        operation = (answer.get("operation") or answer.get("retained_vote")
                     or answer.get("agent_review", {}).get("operation"))
        require(isinstance(operation, str) and len(operation) == 64 and set(operation) <= HEX,
                f"{command} did not return an operation ID")
        require(path.exists(), f"{command} did not retain a signed action")
        entry["state"].setdefault("actions", {})[name] = operation
        entry["state"].setdefault("action_sha256", {})[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.save()
        return operation

    def check_action(self, entry, name):
        path = self.root / f"{entry['label']}-{name}.action"
        private_file(path)
        require(path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()
                == entry["state"]["action_sha256"][name], f"retained {name} action changed")

    def receipt(self, entry, name, config):
        operation = entry["state"].get("actions", {}).get(name)
        if not operation:
            return False
        result = self.call("receipt", config, operation)
        if result["status"] == "finalized":
            entry["state"].setdefault("receipts", {})[name] = result
            self.save()
            return True
        if result["status"] == "rejected":
            reason = result.get("reason", "")
            if (name.startswith("vote-") or name in ("commit", "reveal")) and any(
                closed in reason for closed in ("phase already closed", "operation outside open parent phase")
            ):
                # A deadline loss is a terminal outcome for this exact action,
                # not authority to sign a replacement. Reconcile it at the
                # question's terminal status and continue with the next plan item.
                entry["state"].setdefault("late_actions", {})[name] = result
                self.save()
                return False
            raise RuntimeError(f"{name} rejected: {reason}")
        # Intake is volatile. Resend the exact action after deferral or a lost reply.
        last = entry["state"].setdefault("last_send", {}).get(name, 0)
        if time.monotonic() - last > 3:
            self.check_action(entry, name)
            self.call("send", config, self.root / f"{entry['label']}-{name}.action")
            entry["state"]["last_send"][name] = time.monotonic()
        return False

    def package(self, entry):
        require(input_hash(self.plan) == self.inputs,
                "supplied question, proof, key, or policy bytes changed during the run")
        q, label = entry["plan"], entry["label"]
        output = self.root / f"{label}.package"
        private_file(output)
        inputs = []
        for n, proof in enumerate(q["references"]):
            path = self.root / f"{label}-reference-{n}.proof"
            if not path.exists():
                self.call("fetch-proof", self.plan["node"], proof, path)
            self.call("check-proof", self.plan["genesis"], path)
            inputs += ["--reference", path]
        for helper in q["helpers"]:
            inputs += ["--helper", helper]
        self.call("package", self.plan["genesis"], q["author_key"], output, q["solution"], *inputs)
        return output

    def archive(self, entry):
        index = entry["index"]
        target = self.root / f"archive-{index:03}"
        if not target.exists():
            # `naome export` creates its output directory itself.
            scratch = self.root / f".archive-{index:03}-{secrets.token_hex(8)}"
            try:
                self.call("export", self.plan["node"], scratch)
                self.call("verify", self.plan["genesis"], scratch, verifier=True)
                os.rename(scratch, target)
                fd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                if scratch.exists():
                    shutil.rmtree(scratch)
        verified = self.call("verify", self.plan["genesis"], target, verifier=True)
        require(verified["genesis"] == self.genesis, "archive genesis mismatch")
        entry["state"]["archive"] = str(target)
        entry["state"]["archive_state"] = verified["state"]
        self.save()

    def recheck_completed(self, index):
        saved = self.state["questions"][index]
        target = Path(saved["archive"])
        require(target == self.root / f"archive-{index:03}", "unexpected archive path")
        verified = self.call("verify", self.plan["genesis"], target, verifier=True)
        require(verified["genesis"] == self.genesis and verified["state"] == saved["archive_state"],
                "retained archive changed or failed independent replay")
        for name, operation in saved["actions"].items():
            self.check_action({"label": self.plan["questions"][index]["label"], "state": saved}, name)
            receipt = self.call("receipt", self.plan["node"], operation)
            prior = saved["final_action_receipts"][name]
            if prior["status"] == "finalized":
                require(receipt == prior, f"final receipt for {name} changed after restart")
            else:
                saved["final_action_receipts"][name] = receipt
        self.save()
        self.checked_archives.add(index)

    def recover_actions(self, entry):
        """Recover the crash gap between durable CLI files and our state write."""
        q, label, saved = entry["plan"], entry["label"], entry["state"]
        names = ["submit"] + [f"vote-{n}" for n in range(len(q["votes"]))] + ["commit", "reveal"]
        for name in names:
            path = self.root / f"{label}-{name}.action"
            if name in saved.get("actions", {}):
                self.check_action(entry, name)
                continue
            if name == "commit" and (self.root / f"{label}.secret").exists():
                # This also validates that the retained bundle matches the
                # checked package, even if the action-file write was lost.
                self.action(entry, name, "commit", self.plan["node"], self.plan["node"],
                            q["author_key"], self.root / f"{label}.package",
                            self.root / f"{label}.secret", path)
            elif path.exists():
                config = self.vote_ingress(q["votes"][int(name.split("-")[1])]) if name.startswith("vote-") else self.plan["node"]
                if name == "reveal":
                    self.action(entry, name, "reveal", config, config, q["author_key"],
                                self.root / f"{label}.secret", path)
                else:
                    self.action(entry, name, "send", config, config, path)

    def advance(self, entry):
        q, saved, label = entry["plan"], entry["state"], entry["label"]
        self.recover_actions(entry)
        status = self.status()
        if "submit" not in saved.get("actions", {}):
            if status["terminated"]:
                self.state["stop"] = "terminal capacity"
                self.save()
                return "stop"
            if status["active"] is not None or status["queued"] or status["remaining_records"] <= status["reserved_records"] + 1:
                if status["remaining_records"] <= status["reserved_records"] + 1 and not status["active"] and not status["queued"]:
                    self.state["stop"] = "no ordinary record headroom"
                    self.save()
                    return "stop"
                return "wait"
            path = self.root / f"{label}-submit.action"
            self.action(entry, "submit", "submit", self.plan["node"],
                        self.plan["node"], q["author_key"], q["source"], q["purpose"], path)
            return "progress"
        if status["terminated"]:
            final = self.call("receipt", self.plan["node"], saved["actions"]["submit"])
            if final["status"] != "finalized":
                saved["terminal_submission_receipt"] = final
                self.state["stop"] = "terminal capacity before submission finalized"
                self.save()
                return "stop"
        if not self.receipt(entry, "submit", self.plan["node"]):
            return "wait"
        question = self.call("question", self.plan["node"], saved["actions"]["submit"])
        if question["status"] in TERMINAL:
            for name, operation in saved["actions"].items():
                receipt = self.call("receipt", self.plan["node"], operation)
                saved.setdefault("final_action_receipts", {})[name] = receipt
            saved["result"] = question
            self.save()
            if "archive" not in saved:
                self.archive(entry)
            print(json.dumps({"event": "result", "label": label, "status": question["status"],
                              "outcome": question.get("outcome"), "archive": saved["archive"]}), flush=True)
            return "done"
        require(not status["terminated"], "terminal state retained a nonterminal question")
        active = status["active"]
        if not active or active["submission"] != saved["actions"]["submit"]:
            return "wait"
        phase = active["phase"]
        if "commit" in saved.get("actions", {}) and phase in ("Commit", "CommitClosedWait", "Reveal", "SettlementPending"):
            self.receipt(entry, "commit", self.plan["node"])
        if "reveal" in saved.get("actions", {}) and phase in ("Reveal", "SettlementPending"):
            self.receipt(entry, "reveal", self.plan["node"])
        if phase == "Voting":
            for n, vote in enumerate(q["votes"]):
                name = f"vote-{n}"
                ingress = self.vote_ingress(vote)
                if name in saved.get("actions", {}):
                    self.receipt(entry, name, ingress)
                    continue
                node_status = self.call("status", ingress)
                if (node_status.get("active") or {}).get("submission") != saved["actions"]["submit"]:
                    continue
                if node_status["active"]["phase"] != "Voting":
                    continue
                path = self.root / f"{label}-{name}.action"
                if vote["policy"] == "agent":
                    args = [ingress, vote["owner_key"], path,
                            self.root / f"{label}-{name}.report", vote["provider"]]
                    if "provider_config" in vote:
                        args += ["--provider-config", vote["provider_config"]]
                    self.action(entry, name, "agent-vote", ingress, *args)
                else:
                    self.action(entry, name, "vote", ingress, ingress,
                                vote["owner_key"], vote["policy"], path)
        if phase == "Commit":
            name = "commit"
            if name not in saved.get("actions", {}):
                package = self.package(entry)
                self.action(entry, name, "commit", self.plan["node"], self.plan["node"],
                            q["author_key"], package, self.root / f"{label}.secret",
                            self.root / f"{label}-commit.action")
                return "progress"
        if phase == "Reveal" and "commit" in saved.get("actions", {}):
            if not self.receipt(entry, "commit", self.plan["node"]):
                return "wait"
            if "reveal" not in saved.get("actions", {}):
                self.action(entry, "reveal", "reveal", self.plan["node"], self.plan["node"],
                            q["author_key"], self.root / f"{label}.secret",
                            self.root / f"{label}-reveal.action")
                return "progress"
        return "wait"

    def run(self):
        while True:
            for i, q in enumerate(self.plan["questions"]):
                entry = {"index": i, "label": q["label"], "plan": q, "state": self.state["questions"][i]}
                if "archive" in entry["state"]:
                    if i not in self.checked_archives:
                        self.recheck_completed(i)
                    continue
                outcome = self.advance(entry)
                if outcome == "stop":
                    print(json.dumps({"event": "stopped", "reason": self.state["stop"]}), flush=True)
                    return
                if outcome == "done":
                    break
                time.sleep(self.poll)
                break
            else:
                self.state["stop"] = "plan complete"
                self.save()
                print(json.dumps({"event": "stopped", "reason": "plan complete"}), flush=True)
                return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", help="JSON plan of supplied questions, proofs and owner policies")
    parser.add_argument("private_dir", help="private persistent state and action directory")
    parser.add_argument("--bin", required=True, help="naome operator CLI")
    parser.add_argument("--verifier", required=True, help="independent naome-verifier")
    parser.add_argument("--poll", type=float, default=0.5)
    args = parser.parse_args()
    try:
        Runner(args).run()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"research-supervisor: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
