#!/usr/bin/env python3
"""Create, exercise, verify, and clean up one bounded fixed-validator devnet."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import sys
import time
import urllib.error

from agent import atomic
from backend import DockerBackend, ProcessBackend, command


class Qualification:
    def __init__(self, args):
        self.args = args
        self.root = args.directory.resolve()
        self.root.mkdir(mode=0o700)
        self.backend = (DockerBackend if args.backend == "docker" else ProcessBackend)(args, self.root)
        self.started = time.monotonic()
        self.deadline = self.started + args.deadline_seconds
        self.expected = {}
        self.latest = {}
        self.samples = {}
        self.offline = None
        self.heal_at = None
        self.report = {
            "schema_version": 0, "outcome": "running", "backend": self.backend.kind,
            "requested_heights": args.heights, "delay_ms_each_direction_per_chunk": args.delay_ms,
            "deadline_seconds": args.deadline_seconds, "height_timeout_seconds": args.height_timeout,
            "source_stores_initially_empty": None, "shared_validator_inbox": False,
            "consensus_commands_sent": 0, "workload": "on-demand bounded synthetic proofs",
            "heights": [], "faults": [], "verified": [], "resources": {},
            "limits": {"role_disk_bytes_sampled": 512 * 1024 * 1024,
                       "container_memory_bytes": 512 * 1024 * 1024 if args.backend == "docker" else None},
        }

    def save(self):
        self.report["elapsed_seconds"] = round(time.monotonic() - self.started, 3)
        self.report["resources"] = self.samples
        atomic(self.root / "report.json", self.report)

    def observe(self, names, starting=False):
        current = {}
        for name in names:
            try:
                value = self.backend.status(name)
            except (urllib.error.URLError, TimeoutError, OSError):
                if starting:
                    continue
                raise RuntimeError(f"{name}: status endpoint unavailable")
            if value["errors"] or value["child_exit"] is not None:
                raise RuntimeError(f"{name}: stopped or failed: {value['errors']} exit={value['child_exit']}")
            if not value["ready"] or not value["resources"]:
                continue
            if value["stalled"] and not starting:
                raise RuntimeError(f"{name}: finality stalled")
            resources = value["resources"]
            if resources["disk_bytes"] > self.report["limits"]["role_disk_bytes_sampled"]:
                raise RuntimeError(f"{name}: sampled disk cap exceeded")
            if self.args.backend == "docker" and resources["rss_bytes"] is None:
                raise RuntimeError(f"{name}: Linux process resource sample unavailable")
            peak = self.samples.setdefault(name, {"sample_count": 0, "peak_rss_bytes": None, "peak_disk_bytes": 0, "max_connected_peers": 0})
            peak["sample_count"] += 1
            if resources["rss_bytes"] is not None:
                peak["peak_rss_bytes"] = max(peak["peak_rss_bytes"] or 0, resources["rss_bytes"])
            peak["peak_disk_bytes"] = max(peak["peak_disk_bytes"], resources["disk_bytes"])
            peak["max_connected_peers"] = max(peak["max_connected_peers"], len(value["connected_peers"]))
            prior = self.latest.get(name)
            previous_events = prior["events"] if prior and prior["generation"] == value["generation"] else {}
            totals = peak.setdefault("observed_events", {})
            for event, count in value["events"].items():
                totals[event] = totals.get(event, 0) + max(0, count - previous_events.get(event, 0))
            if not value["publisher"]:
                height = value["finalized_height"]
                if height and self.expected.get(height) != value["head"]:
                    raise RuntimeError(f"{name}: unexpected finalized head at height {height}")
                prior = self.latest.get(name)
                if prior and height < prior["finalized_height"]:
                    raise RuntimeError(f"{name}: finalized height regressed across restart")
            self.latest[name] = current[name] = value
        return current

    def wait(self, label, names, predicate, starting=False):
        limit = min(self.deadline, time.monotonic() + self.args.height_timeout)
        while time.monotonic() < limit:
            if self.offline is not None and time.monotonic() >= self.heal_at:
                name = self.offline
                self.backend.heal(name)
                self.offline = None
                self.report["faults"].append({"operation": "partition_healed", "role": name, "after_seconds": self.args.partition_seconds})
            current = self.observe(names, starting=starting)
            if len(current) == len(names) and predicate(current):
                return current
            time.sleep(0.5)
        raise RuntimeError(f"deadline: {label}")

    def restart(self, name, force):
        previous = self.backend.status(name)["generation"]
        self.backend.stop([name], force=force)
        self.backend.start([name])
        values = self.wait(f"{name} strict reopen", [name], lambda v: v[name]["generation"] != previous and v[name]["startup_mode"] == "open", starting=True)
        self.report["faults"].append({"operation": "sigkill_and_strict_reopen" if force else "graceful_restart", "role": name, "resumed_height": values[name]["finalized_height"]})
        self.save()

    def run(self):
        plan = self.backend.plan()
        atomic(self.root / "plan.json", plan)
        initialized = json.loads(command([self.args.bin_dir / "naome-devnet", "init", self.root / "plan.json", self.root / "roles"]))
        if initialized.get("event") != "devnet_initialized":
            raise RuntimeError("unexpected provisioning result")
        deployment = json.loads((self.root / "roles" / "deployment.json").read_text())
        for name in self.backend.roles[:4]:
            for store in ("candidates", "payloads"):
                if any((self.backend.role_dir(name) / store).iterdir()):
                    raise RuntimeError("validator sources were not initially empty")
        self.report["source_stores_initially_empty"] = True
        peers = {r["name"]: r["peer_id"] for r in deployment["roles"]}
        try:
            source = Path(__file__).resolve().parent.parent
            self.report["source_commit"] = command(["git", "-C", source, "rev-parse", "HEAD"]).strip()
            self.report["source_worktree_clean"] = not command(["git", "-C", source, "status", "--porcelain"]).strip()
        except RuntimeError:
            self.report["source_commit"] = None
            self.report["source_worktree_clean"] = None
        self.report["binary_sha256"] = {name: hashlib.sha256((self.args.bin_dir / name).read_bytes()).hexdigest() for name in ("naome-devnet", "naome-validator")}
        self.backend.start()
        self.report["image_id"] = getattr(self.backend, "image_id", None)
        self.report["runtime_binary_sha256"] = getattr(self.backend, "runtime_binary_sha256", self.report["binary_sha256"])
        self.wait("initial healthy processes", self.backend.roles, lambda v: all(s["publisher"] or s["finalized_height"] == 0 for s in v.values()), starting=True)
        for height in range(1, self.args.heights + 1):
            beginning = time.monotonic()
            first = self.backend.tool("publisher-0", "publish", height)
            self.expected[height] = first["head"]
            receipts = {"publisher-0": first["offer_sha256"]}
            if self.args.faults and height == 2:
                candidates = [(i + 1).to_bytes(32, "big").hex() for i in range(32)]
                atomic(self.backend.role_dir("publisher-1") / "offer.json", {"candidates": candidates, "bundle_file": None})
                wire = bytes.fromhex(first["chain_id"]) + bytes([32]) + b"".join(bytes.fromhex(value) for value in candidates)
                receipts["publisher-1"] = hashlib.sha256(wire).hexdigest()
            else:
                second = self.backend.tool("publisher-1", "publish", height)
                if second["head"] != first["head"]:
                    raise RuntimeError("independent publishers produced different workloads")
                receipts["publisher-1"] = second["offer_sha256"]
            validators = [name for name in self.backend.roles[:4] if name != self.offline]
            active = validators + self.backend.roles[4:]

            def reached(values):
                return all(values[name]["finalized_height"] == height and values[name]["head"] == first["head"] for name in validators) and all(
                    all(values[publisher]["last_receipts"].get(peers[name]) == digest for name in validators)
                    for publisher, digest in receipts.items())

            self.wait(f"height {height} finality and durable intake receipts", active, reached)
            if self.args.faults and height == 2:
                self.report["faults"].append({"operation": "invalid_candidate_offer", "count": 32, "receivers_acked": len(validators)})
            self.report["heights"].append({"height": height, "head": first["head"], "seconds": round(time.monotonic() - beginning, 3), "validators": validators})
            print(json.dumps({"event": "devnet_height", **self.report["heights"][-1]}), flush=True)
            if self.args.faults and height == 3:
                self.offline = "validator-3"
                kind = self.backend.cut(self.offline)
                self.heal_at = time.monotonic() + self.args.partition_seconds
                self.report["faults"].append({"operation": kind, "role": self.offline, "at_height": height})
            if self.args.faults and height == 4:
                self.wait("bounded outage duration", active, lambda _: self.offline is None)
                self.wait("returning validator catches up", self.backend.roles, lambda v: all(v[name]["finalized_height"] == height for name in self.backend.roles[:4]), starting=True)
                self.report["faults"].append({"operation": "healed_and_caught_up", "role": "validator-3", "height": height})
            if self.args.faults and height == self.args.heights // 2:
                self.restart("publisher-0", force=True)
            if self.args.faults and height == self.args.heights * 3 // 4:
                self.restart("validator-0", force=False)
            self.save()
            if self.args.interval_seconds and height != self.args.heights:
                time.sleep(self.args.interval_seconds)
        self.backend.stop()
        verified = [self.backend.tool(name, "verify", self.args.heights) for name in self.backend.roles[:4]]
        if len({(v["height"], v["head"], v["ancestry_sha256"]) for v in verified}) != 1:
            raise RuntimeError("replayed validator histories disagree")
        self.report["verified"] = verified
        if not any(v["observed_events"].get("acquisition_complete", 0) for v in self.samples.values()):
            raise RuntimeError("no completed network acquisition was observed")
        self.report["outcome"] = "passed"
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True, help="new private directory; retained after cleanup")
    parser.add_argument("--backend", choices=("docker", "process"), default="docker")
    parser.add_argument("--bin-dir", type=Path, required=True, help="native binaries built with the pinned toolchain")
    parser.add_argument("--image", default="naome-devnet:local")
    parser.add_argument("--subnet", default="172.30.88.0/24")
    parser.add_argument("--heights", type=int, default=100)
    parser.add_argument("--height-timeout", type=int, default=180)
    parser.add_argument("--deadline-seconds", type=int, default=3600)
    parser.add_argument("--interval-seconds", type=float, default=0)
    parser.add_argument("--delay-ms", type=int, default=50)
    parser.add_argument("--partition-seconds", type=int, default=30)
    parser.add_argument("--no-faults", dest="faults", action="store_false")
    args = parser.parse_args()
    args.bin_dir = args.bin_dir.resolve(strict=True)
    if not 4 <= args.heights <= 128 or (args.faults and args.heights < 8):
        parser.error("heights must be 4..128, with at least 8 for the fault schedule")
    if not 10 <= args.height_timeout <= 3600 or not 60 <= args.deadline_seconds <= 86_400 or not 0 <= args.interval_seconds <= 60 or not 0 <= args.delay_ms <= 1000:
        parser.error("invalid duration/delay bounds")
    if not 1 <= args.partition_seconds < args.height_timeout:
        parser.error("partition duration must be positive and below the height timeout")
    qualification = Qualification(args)

    def interrupted(*_):
        raise KeyboardInterrupt("qualification interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    success = False
    try:
        qualification.run()
        success = True
    except BaseException as error:
        qualification.report["outcome"] = "failed"
        qualification.report["failure"] = str(error)[:2000]
    finally:
        try:
            qualification.backend.cleanup()
            qualification.report["cleanup"] = "complete"
        except BaseException as error:
            qualification.report["cleanup"] = "failed"
            qualification.report["cleanup_error"] = str(error)[:2000]
            qualification.report["outcome"] = "failed"
            success = False
        qualification.save()
    print(json.dumps({"outcome": qualification.report["outcome"], "report": str(qualification.root / "report.json"), "failure": qualification.report.get("failure"), "cleanup": qualification.report["cleanup"]}), flush=True)
    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"naome-devnet-qualification: {error}", file=sys.stderr)
        sys.exit(1)
