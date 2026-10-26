"""Deterministic archives and strict verification of the downloadable product."""

import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path

from policy import REPOSITORY, ROOT, TARGETS, check_source, git, identity
from installation import instructions

FILES = {"naome", "LICENSE", "THIRD_PARTY_LICENSES.html", "SYSTEM_LICENSES.txt", "INSTALL.txt", "Cargo.lock", "sbom.cdx.json", "build.json"}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def archive(path, name, files, epoch):
    # Sorting, fixed ownership/modes/timestamps and an empty gzip filename make
    # packaging deterministic for identical inputs. This is not a claim that
    # native compiler/SDK outputs are independently bit-reproducible.
    with path.open("xb") as output, gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for filename, data in sorted(files.items()):
                entry = tarfile.TarInfo(f"{name}/{filename}")
                entry.size = len(data)
                entry.mode = 0o755 if filename == "naome" else 0o644
                entry.mtime = epoch
                tar.addfile(entry, io.BytesIO(data))


def lifecycle(run, directory):
    directory.mkdir(mode=0o700)
    write_json(directory / "config.json", {"directory": str(directory), "listen": "/ip4/127.0.0.1/tcp/0", "peers": [],
                                          "producer_sources": [], "discovery": {"mdns": False, "dht": False, "internet": False}})
    def command(name, *arguments):
        return json.loads(run("--json", name, *arguments))
    try:
        if not command("start")["running"]:
            raise ValueError("extracted node failed to start")
        status = command("status")
        computation = status.get("computation")
        reason = status.get("computation_reason")
        valid_computation = ((computation == "running" and reason is None)
                             or (computation in ("pausing", "paused") and isinstance(reason, str) and bool(reason.strip())))
        if status.get("running") is not True or status.get("artifact_verification") != "checked" or not valid_computation:
            raise ValueError("extracted node is not ready with a valid computation state")
        if command("interest", "Release smoke test")["interest"] != "Release smoke test":
            raise ValueError("extracted node did not persist owner interest")
    finally:
        stopped = command("stop")
        if stopped["running"] or stopped["computation"] != "stopped":
            raise ValueError("extracted node shutdown was not confirmed")
    persisted = command("status")
    if persisted["running"] or persisted["artifact_verification"] != "not_run" or persisted["interest"] != "Release smoke test":
        raise ValueError("extracted node did not retain interest across daemon shutdown")


def smoke(binary, version, *, start=False):
    with tempfile.TemporaryDirectory(prefix="naome-release-smoke-") as directory:
        node = Path(directory) / "uncreated-node"
        environment = {**os.environ, "NAOME_NODE_DIR": str(node)}
        def run(*arguments):
            return subprocess.check_output([str(binary.resolve()), *arguments], env=environment, text=True, timeout=60).strip()
        if run("--version") != f"naome {version}" or "naome start" not in run("--help"):
            raise ValueError("packaged executable has incorrect version/help")
        expected = {"running": False, "computation": "stopped", "artifact_verification": "not_run", "accepted_artifacts": 0, "interest": ""}
        status = json.loads(run("--json", "status"))
        if any(status.get(key) != value for key, value in expected.items()) or node.exists():
            raise ValueError("packaged status must not create state or start a node")
        for command in ("publish", "pause", "resume", "resources"):
            rejected = subprocess.run([str(binary.resolve()), command], env=environment, capture_output=True, timeout=30)
            if rejected.returncode == 0 or node.exists():
                raise ValueError("packaged product accepts an invalid command or creates state for a stopped node")
        if start:
            lifecycle(run, node)


def build_package(target, version, output, notices, sbom, system_licenses):
    release = identity(version)
    if target not in TARGETS:
        raise ValueError("unsupported distribution target")
    sha = os.environ["GITHUB_SHA"]
    check_source(sha)
    binary = ROOT / "target" / target / "release/naome"
    if binary.is_symlink() or not binary.is_file() or not binary.stat().st_mode & stat.S_IXUSR:
        raise ValueError("missing regular executable")
    smoke(binary, version)
    bom = json.loads(sbom.read_bytes())
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.5" or not bom.get("components"):
        raise ValueError("missing CycloneDX dependency inventory")
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    metadata = {**release, "schema": 1, "repository": REPOSITORY, "commit": sha, "target": target,
                "features": [], "profile": "release", "rust_toolchain": toolchain,
                "rustc": subprocess.check_output(["rustc", "--version", "--verbose"], text=True).strip(),
                "release_tools": tomllib.loads((ROOT / "tools/release/toolchain.toml").read_text()),
                "cargo_lock_sha256": digest(ROOT / "Cargo.lock"), "binary_sha256": digest(binary),
                "runner_image": {key: os.environ.get(key, "unknown") for key in ("ImageOS", "ImageVersion")},
                "run_url": f"https://github.com/{REPOSITORY}/actions/runs/{os.environ['GITHUB_RUN_ID']}",
                "minimum_macos": "13.0" if target.endswith("darwin") else None,
                "linkage": "system" if target.endswith("darwin") else "static-musl"}
    files = {"naome": binary.read_bytes(), "LICENSE": (ROOT / "LICENSE").read_bytes(),
             "Cargo.lock": (ROOT / "Cargo.lock").read_bytes(), "sbom.cdx.json": sbom.read_bytes(),
             "INSTALL.txt": instructions(version, sha).encode(),
             "THIRD_PARTY_LICENSES.html": notices.read_bytes(), "SYSTEM_LICENSES.txt": system_licenses.read_bytes(),
             "build.json": (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode()}
    if any(not data for data in files.values()):
        raise ValueError("empty release payload")
    name = f"naome-{version}-{target}"
    output.mkdir(parents=True, exist_ok=True)
    path = output / f"{name}.tar.gz"
    archive(path, name, files, int(git("show", "-s", "--format=%ct", "HEAD")))
    # Verify the actual final archive, not only its staging inputs.
    verify_package(path, version, sha, execute=True)


def verify_package(path, version, sha, *, execute=False):
    target = next((target for target in TARGETS if path.name == f"naome-{version}-{target}.tar.gz"), None)
    if target is None or path.is_symlink():
        raise ValueError("unexpected release archive")
    name = path.name.removesuffix(".tar.gz")
    with tarfile.open(path, "r:gz") as tar:
        entries = tar.getmembers()
        expected = {f"{name}/{filename}" for filename in FILES}
        if len(entries) != len(expected) or {entry.name for entry in entries} != expected:
            raise ValueError("archive has missing, duplicate or unexpected paths")
        if any(not entry.isfile() or entry.mode != (0o755 if entry.name.endswith("/naome") else 0o644)
               or entry.size > 256 * 1024 * 1024 for entry in entries):
            raise ValueError("archive contains a link, invalid permissions or oversized member")
        files = {entry.name.rsplit("/", 1)[1]: tar.extractfile(entry).read() for entry in entries}
    build = json.loads(files["build.json"])
    if files["INSTALL.txt"] != instructions(version, sha).encode():
        raise ValueError("installation instructions differ from the reviewed release source")
    for key, value in {**identity(version), "schema": 1, "repository": REPOSITORY, "commit": sha,
                       "target": target, "features": [], "profile": "release"}.items():
        if build.get(key) != value:
            raise ValueError(f"package identity mismatch: {key}")
    if hashlib.sha256(files["naome"]).hexdigest() != build["binary_sha256"]:
        raise ValueError("binary digest mismatch")
    if hashlib.sha256(files["Cargo.lock"]).hexdigest() != build["cargo_lock_sha256"] or build["cargo_lock_sha256"] != digest(ROOT / "Cargo.lock"):
        raise ValueError("lockfile digest mismatch")
    if execute:
        with tempfile.TemporaryDirectory(prefix="naome-release-extracted-") as directory:
            binary = Path(directory) / "naome"
            binary.write_bytes(files["naome"])
            binary.chmod(0o755)
            smoke(binary, version, start=True)
    return build


def assemble(directory, version, sha, run_id):
    expected = {f"naome-{version}-{target}.tar.gz" for target in TARGETS}
    if {path.name for path in directory.iterdir()} != expected:
        raise ValueError("both platforms and only the expected archives must be present")
    builds = [verify_package(directory / filename, version, sha) for filename in sorted(expected)]
    write_json(directory / "release.json", {**identity(version), "schema": 1, "repository": REPOSITORY,
               "commit": sha, "run_id": str(run_id), "builds": builds})
    names = sorted(expected | {"release.json"})
    (directory / "SHA256SUMS").write_text("".join(f"{digest(directory / name)}  {name}\n" for name in names))


def verify_assets(directory, version, sha, run_id):
    expected = {f"naome-{version}-{target}.tar.gz" for target in TARGETS} | {"release.json", "cargo-audit.json"}
    actual = {path.name for path in directory.iterdir()}
    if actual != expected | {"SHA256SUMS", "provenance.sigstore.json"}:
        raise ValueError("final asset set differs from the release contract")
    if any(path.is_symlink() or not path.is_file() for path in directory.iterdir()):
        raise ValueError("irregular release asset")
    lines = (directory / "SHA256SUMS").read_text().splitlines()
    hashes = {}
    for line in lines:
        checksum, name = line.split("  ")
        if name not in expected or name in hashes or checksum != digest(directory / name):
            raise ValueError("invalid, duplicate or mismatched release checksum")
        hashes[name] = checksum
    if hashes.keys() != expected:
        raise ValueError("missing checksum")
    verify_audit(json.loads((directory / "cargo-audit.json").read_text()))
    manifest = json.loads((directory / "release.json").read_text())
    if manifest["commit"] != sha or manifest["version"] != version or manifest["run_id"] != str(run_id):
        raise ValueError("release manifest does not belong to this workflow")
    builds = [verify_package(directory / f"naome-{version}-{target}.tar.gz", version, sha) for target in TARGETS]
    if sorted(manifest["builds"], key=lambda value: value["target"]) != sorted(builds, key=lambda value: value["target"]):
        raise ValueError("release manifest and packaged build identities disagree")
    return {path.name: digest(path) for path in directory.iterdir()}


def verify_audit(report):
    scanner = tomllib.loads((ROOT / "tools/release/toolchain.toml").read_text())["cargo-audit"]
    if (report.get("naome") != {"cargo_lock_sha256": digest(ROOT / "Cargo.lock"), "scanner": f"cargo-audit {scanner}"}
            or not re.fullmatch(r"[0-9a-f]{40}", report.get("database", {}).get("last-commit", ""))
            or report.get("vulnerabilities") != {"found": False, "count": 0, "list": []}
            or report.get("warnings", {}).get("unsound")
            or report.get("settings", {}).get("ignore") != []
            or "unsound" not in report["settings"].get("informational_warnings", [])
            or report["settings"].get("severity") is not None
            or report["settings"].get("target_arch") != []
            or report["settings"].get("target_os") != []):
        raise ValueError("missing, filtered, suppressed or failed RustSec qualification")
