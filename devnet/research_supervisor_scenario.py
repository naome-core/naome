#!/usr/bin/env python3
"""Two-result one-host operator interruption and independent replay scenario.

Uses four actual validators and the explicitly accelerated short-test profile.
All output, including signing keys, signed actions, and archives, remains private.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "examples/state-workflow"
HELPER = "c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73"


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(binary, *args):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=90)
    require(result.returncode == 0, f"{Path(binary).name} {args[0]} failed: {result.stderr[-1200:]!r}")
    return json.loads(result.stdout)


def ports():
    for _ in range(100):
        base = 20000 + int.from_bytes(os.urandom(2), "big") % 35000
        sockets = []
        try:
            for i in range(8):
                item = socket.socket()
                item.bind(("127.0.0.1", base + i))
                sockets.append(item)
            return base
        except OSError:
            pass
        finally:
            for item in sockets:
                item.close()
    raise RuntimeError("no eight consecutive local ports")


def run(args):
    root = args.directory.absolute()
    root.mkdir(mode=0o700)
    require(root.stat().st_mode & 0o077 == 0, "scenario directory must be private")
    bin = args.bin_dir.resolve() / "naome"
    validator = args.bin_dir.resolve() / "naome-validator"
    verifier = args.bin_dir.resolve() / "naome-verifier"
    require(all(path.is_file() for path in (bin, validator, verifier)), "build all three binaries first")
    order = root / "retirement-order.json"
    order.write_text("[2,0,3,1]\n")
    run_dir = root / "run"
    configured = command(bin, "setup", run_dir, "short-test", 128, ports(), order, "compact")
    genesis = run_dir / "genesis.bin"
    configs = [run_dir / f"node-{i}/node.json" for i in range(4)]
    accounts = [run_dir / f"accounts/account-{i}.key" for i in range(6)]
    children = []
    logs = []
    supervisor = None
    started = time.monotonic()
    report = {"profile": "short-test", "accelerated": True, "nodes": 4,
              "genesis": configured["genesis"], "results": [], "checks": {}}
    report["source_snapshot"] = {
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "sha256": {str(path.relative_to(REPO)): hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in (Path(__file__).resolve(), REPO / "tools/research_supervisor.py",
                                REPO / "rust-toolchain.toml")},
        "executables_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                               for path in (bin, validator, verifier)},
        "note": "source file hashes include uncommitted edits at scenario start",
    }
    try:
        for i in range(4):
            log = (root / f"node-{i}.log").open("wb")
            logs.append(log)
            children.append(subprocess.Popen([str(validator), "start", str(configs[i])],
                                             stdout=log, stderr=log))
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            require(all(child.poll() is None for child in children), "validator exited before genesis status")
            try:
                command(bin, "status", configs[0])
                break
            except RuntimeError:
                time.sleep(.2)
        else:
            raise RuntimeError("validators did not start")
        plan = {"version": 1, "genesis": str(genesis), "node": str(configs[0]), "questions": []}
        for label, author, question, solution, helpers, references in (
            ("A", 4, "question-a.nao", "solution-a.nao", ["helper-h.nao"], []),
            ("B", 5, "question-b.nao", "solution-b-original.nao", ["helper-h-duplicate.nao"], [HELPER]),
        ):
            plan["questions"].append({"label": label, "source": str(FIXTURES / question),
                "purpose": f"Operator supplied reusable result {label}",
                "author_key": str(accounts[author]), "solution": str(FIXTURES / solution),
                "helpers": [str(FIXTURES / helper) for helper in helpers], "references": references,
                "votes": [{"node": str(configs[i]), "owner_key": str(accounts[i]), "policy": "YES"}
                          for i in range(4)]})
        plan_path = root / "plan.json"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n")
        private = root / "operator"
        argv = [sys.executable, "-B", str(REPO / "tools/research_supervisor.py"), str(plan_path),
                str(private), "--bin", str(bin), "--verifier", str(verifier), "--poll", "0.2"]
        operator_log = (root / "operator.log").open("a")
        logs.append(operator_log)
        supervisor = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=operator_log, text=True, bufsize=1)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            require(all(child.poll() is None for child in children), "validator exited during first result")
            ready, _, _ = select.select([supervisor.stdout], [], [], .5)
            if ready:
                line = supervisor.stdout.readline()
                require(line, "operator exited before first result")
                event = json.loads(line)
                report["results"].append(event)
                if event.get("event") == "result" and event.get("label") == "A":
                    break
            require(supervisor.poll() is None, "operator stopped before first result")
        else:
            raise RuntimeError("first result timed out")
        supervisor.terminate()
        supervisor.wait(timeout=20)
        report["checks"]["operator_interrupted_after_first_result"] = True
        # Emulate the power-loss interval after the CLI has durably saved a
        # signed submit action but before this runner saved its operation ID.
        action = private / "B-submit.action"
        retained = json.loads((private / "supervisor.json").read_text())
        if action.exists():
            previous = command(bin, "send", configs[0], action)["operation"]
            retained["questions"][1].get("actions", {}).pop("submit", None)
            retained["questions"][1].get("action_sha256", {}).pop("submit", None)
            retained["questions"][1].get("receipts", {}).pop("submit", None)
            (private / "supervisor.json").write_text(json.dumps(retained, indent=2) + "\n")
        else:
            previous = command(bin, "submit", configs[0], accounts[5],
                               FIXTURES / "question-b.nao", plan["questions"][1]["purpose"],
                               action)["operation"]
        # The node processes and their signing stores stay running. The operator
        # reopens only its private action/receipt store and resumes the plan.
        with (root / "operator-resumed.log").open("wb") as out:
            completed = subprocess.run(argv, stdout=out, stderr=subprocess.STDOUT, timeout=300)
        require(completed.returncode == 0, "resumed operator failed; see private log")
        saved = json.loads((private / "supervisor.json").read_text())
        require(saved["questions"][1]["actions"]["submit"] == previous,
                "crash-gap recovery changed the exact B submission")
        report["checks"]["saved_action_crash_gap_recovered"] = True
        require(saved["stop"] == "plan complete", "operator did not complete the supplied plan")
        require([item["result"]["status"] for item in saved["questions"]] == ["Completed", "Completed"],
                "both questions must settle")
        first, second = [item["result"] for item in saved["questions"]]
        require(first["outcome"] == "PROVED" and second["outcome"] == "REFUTED", "unexpected outcomes")
        require(any(entry["replacement"] == HELPER for entry in second["normalization"]["substitutions"]),
                "B did not reuse the selected H helper")
        require(any(entry["proof"] == HELPER and int(entry["atoms"]) > 0
                    for entry in second["normalization"]["citation_payments"]),
                "B did not pay a citation to H")
        report["checks"]["two_successive_results_and_helper_citation"] = True
        expected = command(bin, "status", configs[0])
        deadline = time.monotonic() + 90
        for i in range(1, 4):
            while time.monotonic() < deadline:
                actual = command(bin, "status", configs[i])
                if actual["state"] == expected["state"]:
                    break
                time.sleep(.2)
            else:
                raise RuntimeError(f"node {i} did not converge to the final selected state")
        snapshots = []
        for i in range(4):
            destination = root / f"independent-{i}"
            command(bin, "export", configs[i], destination)
            snapshots.append(command(verifier, "verify", genesis, destination))
        require(len({(item["head"], item["state"], item["height"]) for item in snapshots}) == 1,
                "independent archive replay disagrees")
        report["checks"]["four_independent_archive_replays_agree"] = True
        report["final"] = {field: snapshots[0][field] for field in ("height", "state", "paid_completions")}
        report["outcome"] = "passed"
        return report
    finally:
        if supervisor is not None and supervisor.poll() is None:
            supervisor.terminate()
            supervisor.wait(timeout=10)
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for log in logs:
            log.close()
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (root / "scenario-report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    options = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(run(options), indent=2))
    except Exception as error:
        print(f"scenario failed: {error}; private artifacts retained in {options.directory}", file=sys.stderr)
        sys.exit(1)
