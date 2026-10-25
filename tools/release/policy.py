"""Release identity and qualification rules, shared by preparation and publication."""

import re
import subprocess
import tomllib
from pathlib import Path

REPOSITORY = "naome-core/naome"
TARGETS = ("x86_64-unknown-linux-musl", "aarch64-apple-darwin")
REQUIRED_CHECKS = {"Rust quality", "Rust platform (Linux x86_64)", "Rust platform (macOS ARM64)", "Rust CI"}
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(alpha|beta|rc)\.([1-9][0-9]*))?")
ROOT = Path(__file__).resolve().parents[2]


def version_key(version):
    match = VERSION.fullmatch(version)
    if not match:
        raise ValueError("version must be X.Y.Z or X.Y.Z-{alpha,beta,rc}.N (no leading zeros)")
    major, minor, patch, channel, number = match.groups()
    return (int(major), int(minor), int(patch), {"alpha": 0, "beta": 1, "rc": 2, None: 3}[channel], int(number or 0))


def identity(version, root=ROOT):
    version_key(version)
    cargo = tomllib.loads((root / "Cargo.toml").read_text())
    if cargo["workspace"]["package"]["version"] != version:
        raise ValueError("requested version does not match workspace.package.version")
    return {"version": version, "tag": f"v{version}", "prerelease": "-" in version}


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def check_source(sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or git("rev-parse", "HEAD") != sha:
        raise ValueError("checkout does not match the workflow source commit")
    if git("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("tracked release sources have changed")


def successful_run(runs, workflow, sha):
    # Only the newest run/attempt is authoritative; an old success cannot hide a
    # pending or failed rerun. Names alone do not identify a trusted workflow.
    candidates = [run for run in runs if run.get("path") == f".github/workflows/{workflow}"
                  and run.get("event") == "push" and run.get("head_branch") == "main"
                  and run.get("head_sha") == sha
                  and run.get("head_repository", {}).get("full_name") == REPOSITORY]
    if not candidates:
        raise ValueError(f"no main push qualification for {workflow} at {sha}")
    run = max(candidates, key=lambda value: (value["run_number"], value["run_attempt"]))
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError(f"{workflow} has not succeeded: {run.get('html_url')}")
    return {"id": run["id"], "attempt": run["run_attempt"], "url": run["html_url"]}


def check_request(api, release, sha, *, resume_marker=None):
    repository = api.get("")
    if repository["full_name"] != REPOSITORY or repository["default_branch"] != "main" or repository["private"]:
        raise ValueError("publication requires the canonical public repository and main branch")
    branch = api.get("/branches/main")
    if branch["commit"]["sha"] != sha:
        raise ValueError("main moved; qualify and release its new head instead")
    if branch.get("protected") is not True:
        raise ValueError("main must remain protected")
    rules = api.get("/rules/branches/main")
    kinds = {rule["type"] for rule in rules}
    if not {"pull_request", "required_status_checks", "deletion", "non_fast_forward"} <= kinds:
        raise ValueError("main is missing required release source protections")
    if not any(rule["type"] == "pull_request" and rule["parameters"].get("required_review_thread_resolution") is True for rule in rules):
        raise ValueError("main must require review-thread resolution")
    checks = {(check["context"], check.get("integration_id")) for rule in rules if rule["type"] == "required_status_checks"
              for check in rule["parameters"]["required_status_checks"]}
    if not {(name, 15368) for name in REQUIRED_CHECKS} <= checks:
        raise ValueError("main must enforce all expected checks from GitHub Actions")
    for source in {rule["ruleset_id"] for rule in rules}:
        ruleset = api.get(f"/rulesets/{source}")
        if ruleset.get("enforcement") != "active" or ruleset.get("bypass_actors") != []:
            raise ValueError("main rulesets must be active without bypass actors")
    if api.get("/immutable-releases").get("enabled") is not True:
        raise ValueError("enable GitHub immutable releases before publishing (Settings > General > Releases)")
    runs = api.pages(f"/actions/workflows/ci.yml/runs?branch=main&event=push&head_sha={sha}", "workflow_runs")
    qualifications = {"ci.yml": successful_run(runs, "ci.yml", sha)}
    existing = None
    for previous in api.pages("/releases"):
        if previous["tag_name"] == release["tag"]:
            if not (resume_marker and previous["draft"] and resume_marker in (previous.get("body") or "")
                    and previous["target_commitish"] == sha):
                raise ValueError("release version already exists; published assets are never replaced")
            existing = previous
        if not previous["draft"] and previous["tag_name"].startswith("v"):
            version = previous["tag_name"][1:]
            if VERSION.fullmatch(version) and version_key(version) >= version_key(release["version"]):
                raise ValueError("release versions must advance monotonically across both channels")
    tag = api.get(f"/git/ref/tags/{release['tag']}", missing=True)
    if tag and not (existing and tag["object"]["type"] == "commit" and tag["object"]["sha"] == sha):
        raise ValueError("release tag already exists or does not match the owned draft")
    return qualifications, existing


def check_publication(api, release, sha, run_id, *, resume_marker=None):
    qualifications, existing = check_request(api, release, sha, resume_marker=resume_marker)
    if not str(run_id).isdecimal():
        raise ValueError("invalid full qualification run identity")
    run = api.get(f"/actions/runs/{run_id}")
    if (str(run.get("id")) != str(run_id) or run.get("head_sha") != sha
            or run.get("path") != ".github/workflows/release.yml"
            or run.get("event") != "workflow_dispatch" or run.get("head_branch") != "main"
            or run.get("head_repository", {}).get("full_name") != REPOSITORY
            or (run.get("status"), run.get("conclusion")) not in {
                ("in_progress", None), ("completed", "success")}):
        raise ValueError("full qualification must belong to this canonical main release run")
    prefix = "Full source qualification / "
    expected = {
        f"{prefix}Cargo ({platform}, {profile}) / Full workspace": runner
        for platform, runner in (("Linux x86_64", "ubuntu-24.04"), ("macOS ARM64", "macos-15"))
        for profile in ("test", "release")
    }
    expected[prefix + "Full Cargo results"] = "ubuntu-24.04"
    jobs = list(api.pages(f"/actions/runs/{run_id}/jobs?filter=latest", "jobs"))
    evidence = []
    for name, runner in expected.items():
        selected = [job for job in jobs if job.get("name") == name]
        if len(selected) != 1:
            raise ValueError(f"missing or duplicate full qualification job: {name}")
        job = selected[0]
        if (job.get("head_sha") != sha or str(job.get("run_id")) != str(run_id)
                or job.get("status") != "completed" or job.get("conclusion") != "success"
                or job.get("labels") != [runner]):
            raise ValueError(f"full qualification job has not succeeded on its standard runner: {name}")
        evidence.append({"id": job["id"], "name": name, "url": job["html_url"]})
    qualifications["full-cargo.yml"] = {
        "id": run["id"], "attempt": run["run_attempt"], "url": run["html_url"], "jobs": evidence,
    }
    return qualifications, existing
