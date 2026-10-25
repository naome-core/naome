"""Validate Actions syntax and expressions with a checksum-pinned actionlint."""

from pathlib import Path
import platform
import subprocess

from pinned_tool import executable

VERSION = "1.7.12"
# Upstream immutable release asset digests, reviewed with the tool version.
SHA256 = {
    ("Linux", "x86_64"): ("linux_amd64", "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"),
    ("Darwin", "arm64"): ("darwin_arm64", "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f"),
}


def main():
    host, expected = SHA256[(platform.system(), platform.machine())]
    url = f"https://github.com/rhysd/actionlint/releases/download/v{VERSION}/actionlint_{VERSION}_{host}.tar.gz"
    with executable(url, expected, "actionlint") as binary:
        root = Path(__file__).resolve().parents[2]
        subprocess.run([str(binary), "-shellcheck=", *map(str, sorted((root / ".github/workflows").glob("*.yml")))], check=True, cwd=root)


if __name__ == "__main__":
    main()
