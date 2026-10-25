#!/usr/bin/env python3
"""Compare exact refs with identical fixtures, profiles and bounded workloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).with_suffix("")


def command(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def prepare(ref, destination):
    raw = subprocess.check_output(["git", "archive", ref], cwd=ROOT)
    # Git produces repository-relative paths; use the platform archive reader
    # so the comparison also runs with the system Python on supported macOS.
    subprocess.run(["tar", "-x", "-C", str(destination)], input=raw, check=True)
    for package, fixture in [("naome-checker", "checker.rs"), ("naome-knowledge", "knowledge.rs")]:
        owner = destination / "crates" / package / "src" / "question.rs"
        owner.write_text(owner.read_text() + "\n#[cfg(test)]\nmod prefilter_comparison;\n")
        shutil.copyfile(FIXTURES / fixture, owner.with_suffix("") / "prefilter_comparison.rs")
    question = destination / "crates/naome-checker/src/question"
    shutil.copyfile(ROOT / "crates/naome-checker/src/question/fixtures.rs", question / "fixtures.rs")
    (question / "fixtures").mkdir(exist_ok=True)
    shutil.copyfile(ROOT / "crates/naome-checker/src/question/fixtures/conjunction.hex", question / "fixtures/conjunction.hex")
    owner = question.with_suffix(".rs")
    if "mod fixtures;" not in owner.read_text():
        owner.write_text(owner.read_text() + "\n#[cfg(test)]\nmod fixtures;\n")


def build(source, destination, environment):
    started = time.monotonic()
    log = destination / "build.log"
    artifacts = {}
    with log.open("w") as stderr:
        result = command(["cargo", "test", "-p", "naome-checker", "-p", "naome-knowledge", "--profile", "release", "--lib", "--locked", "--no-run", "--message-format=json"], cwd=source, env=environment, stdout=subprocess.PIPE, stderr=stderr)
    for line in result.stdout.splitlines():
        event = json.loads(line)
        if event.get("reason") == "compiler-artifact" and event.get("executable") and event.get("profile", {}).get("test"):
            name = event["target"]["name"]
            path = destination / name
            shutil.copyfile(event["executable"], path)
            path.chmod(0o755)
            artifacts[name] = path
    if set(artifacts) != {"naome_checker", "naome_knowledge"}:
        raise RuntimeError(f"missing comparison executables: {artifacts}")
    return artifacts, time.monotonic() - started


def measure(binary, log, environment):
    with log.open("w") as output:
        process = subprocess.Popen([str(binary), "prefilter_comparison::", "--ignored", "--nocapture", "--test-threads=1"], env=environment, stdout=output, stderr=subprocess.STDOUT)
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
    if process.returncode:
        raise RuntimeError(f"comparison failed; inspect {log}")
    rows = []
    for line in log.read_text().splitlines():
        if "PREFILTER_MEASUREMENT " in line:
            rows.append(json.loads(line.split("PREFILTER_MEASUREMENT ", 1)[1]))
    if not rows:
        raise RuntimeError(f"comparison emitted no results: {log}")
    rss_bytes = usage.ru_maxrss if platform.system() == "Darwin" else usage.ru_maxrss * 1024
    return rows, {"peak_rss_bytes":rss_bytes, "user_cpu_seconds":usage.ru_utime, "system_cpu_seconds":usage.ru_stime}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", default="HEAD")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    if args.rounds < 3 or args.jobs < 1:
        parser.error("at least three rounds and one build job are required")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_TARGET_DIR=str(args.target_dir.resolve()), CARGO_BUILD_JOBS=str(args.jobs))
    refs = {label: subprocess.check_output(["git", "rev-parse", ref], cwd=ROOT, text=True).strip() for label, ref in [("baseline", args.base), ("candidate", args.candidate)]}
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [FIXTURES / "checker.rs", FIXTURES / "knowledge.rs", ROOT / "crates/naome-checker/src/question/fixtures.rs", ROOT / "crates/naome-checker/src/question/fixtures/conjunction.hex"]}
    result = {"refs":refs,"fixture_sha256":hashes,"platform":platform.platform(),"machine":platform.machine(),"cpu_count":os.cpu_count(),"profile":"release","cargo_incremental":False,"build_jobs":args.jobs,"rounds":args.rounds,"resource_environment":{name:os.environ[name] for name in ("NAOME_RESOURCE_CONFIG", "NAOME_EFFECTIVE_RESOURCES") if name in os.environ},"toolchain":subprocess.check_output(["rustc", "--version", "--verbose"], cwd=ROOT, text=True),"build_seconds":{},"samples":[],"processes":[]}
    with tempfile.TemporaryDirectory(prefix="prefilter-comparison-", dir=output) as temporary:
        temporary = Path(temporary)
        binaries = {}
        for label, ref in refs.items():
            source = temporary / label
            source.mkdir()
            prepare(ref, source)
            logs = output / label
            logs.mkdir(exist_ok=True)
            binaries[label], result["build_seconds"][label] = build(source, logs, environment)
            print(f"built {label} {ref}", flush=True)
        for sample in range(args.rounds):
            labels = ["baseline", "candidate"] if sample % 2 == 0 else ["candidate", "baseline"]
            for label in labels:
                for name, binary in binaries[label].items():
                    rows, usage = measure(binary, output / label / f"{name}-{sample}.log", environment)
                    result["samples"].extend(dict(row, label=label, sample=sample) for row in rows)
                    result["processes"].append(dict(usage, label=label, sample=sample, binary=name))
            (output / "raw.json").write_text(json.dumps(result, indent=2) + "\n")
            print(f"completed round {sample + 1}/{args.rounds}", flush=True)
    summary = {}
    for row in result["samples"]:
        key = (row["label"], row["group"])
        summary.setdefault(key, []).append(row)
    result["summary"] = {}
    for (label, group), rows in summary.items():
        timings = [row["elapsed_ns"] / row["evaluations"] for row in rows]
        counts = {key: value for key,value in rows[0].items() if key not in {"elapsed_ns", "label", "sample"}}
        for row in rows[1:]:
            assert all(row[key] == value for key,value in counts.items()), f"non-deterministic result counts: {group}"
        result["summary"].setdefault(group, {})[label] = dict(counts, median_ns_per_assessment=statistics.median(timings), min_ns_per_assessment=min(timings), max_ns_per_assessment=max(timings))
    (output / "raw.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
