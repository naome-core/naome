"""Fresh RustSec qualification of the authoritative lockfile, without suppressions."""

import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import tomllib

from pinned_tool import executable

ASSETS = {
    ("Linux", "x86_64"): ("x86_64-unknown-linux-musl", "7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428"),
    ("Darwin", "arm64"): ("aarch64-apple-darwin", "ec7ca4263769593df4d909be85b94a6b79efa2897be5d2bb8ebd516e823175af"),
}


def main():
    root = Path(__file__).resolve().parents[2]
    version = tomllib.loads((root / "tools/release/toolchain.toml").read_text())["cargo-audit"]
    target, checksum = ASSETS[(platform.system(), platform.machine())]
    name = f"cargo-audit-{target}-v{version}"
    url = f"https://github.com/rustsec/rustsec/releases/download/cargo-audit/v{version}/{name}.tgz"
    lockfile = root / "Cargo.lock"
    before = hashlib.sha256(lockfile.read_bytes()).hexdigest()
    # A fresh directory avoids ambient audit.toml, cached/stale advisory data,
    # or inherited allowlists. The official DB is fetched on every release.
    with executable(url, checksum, f"{name}/cargo-audit") as binary, tempfile.TemporaryDirectory(prefix="naome-rustsec-") as name:
        configuration = Path(name) / ".cargo"
        configuration.mkdir()
        # cargo-audit gives this local config precedence over ~/.cargo/audit.toml.
        (configuration / "audit.toml").write_text("[advisories]\nignore = []\n")
        result = subprocess.run([str(binary), "audit", "--file", str(lockfile), "--db", str(Path(name) / "advisory-db"),
                                 "--url", "https://github.com/RustSec/advisory-db.git", "--deny", "unsound", "--json"],
                                cwd=name, capture_output=True, text=True, timeout=240)
        if result.stderr:
            print(result.stderr)
        report = json.loads(result.stdout)
    if hashlib.sha256(lockfile.read_bytes()).hexdigest() != before:
        raise ValueError("audit changed the authoritative lockfile")
    report["naome"] = {"cargo_lock_sha256": before, "scanner": f"cargo-audit {version}"}
    output = root / ".local/release-audit/cargo-audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for item in report["vulnerabilities"]["list"]:
        print(f"{item['advisory']['id']}: {item['package']['name']} {item['package']['version']}: {item['advisory']['title']}")
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    print(f"RustSec passed at {report['database']['last-commit']}; full report: {output}")


if __name__ == "__main__":
    main()
