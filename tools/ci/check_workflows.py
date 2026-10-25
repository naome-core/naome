"""Validate Actions syntax and expressions with a checksum-pinned actionlint."""

import hashlib
import io
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION = "1.7.12"
# Upstream immutable release asset digests, reviewed with the tool version.
SHA256 = {
    ("Linux", "x86_64"): ("linux_amd64", "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"),
    ("Darwin", "arm64"): ("darwin_arm64", "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f"),
}


def main():
    host, expected = SHA256[(platform.system(), platform.machine())]
    url = f"https://github.com/rhysd/actionlint/releases/download/v{VERSION}/actionlint_{VERSION}_{host}.tar.gz"
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("actionlint download checksum mismatch")
    with tempfile.TemporaryDirectory(prefix="naome-actionlint-") as name:
        binary = Path(name) / "actionlint"
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            entry = archive.getmember("actionlint")
            if not entry.isfile():
                raise ValueError("unexpected actionlint archive member")
            binary.write_bytes(archive.extractfile(entry).read())
        binary.chmod(0o700)
        root = Path(__file__).resolve().parents[2]
        subprocess.run([str(binary), "-shellcheck=", *map(str, sorted((root / ".github/workflows").glob("*.yml")))], check=True, cwd=root)


if __name__ == "__main__":
    main()
