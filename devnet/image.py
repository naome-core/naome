#!/usr/bin/env python3
"""Package already-tested Linux binaries without sending the workspace to Docker."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--tag", default="naome-devnet:local")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("native packaging requires Linux; use devnet/Dockerfile for a source build")
    here = Path(__file__).resolve().parent
    source = here.parent
    provenance = {
        "source_commit": subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip(),
        "worktree_clean": not subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True).strip(),
        "binary_sha256": {},
    }
    with tempfile.TemporaryDirectory(prefix="naome-devnet-image-") as temporary:
        context = Path(temporary)
        for name in ("naome-devnet", "naome-validator"):
            binary = args.bin_dir / name
            with binary.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    raise RuntimeError(f"{name}: Linux ELF binary required")
            provenance["binary_sha256"][name] = hashlib.sha256(binary.read_bytes()).hexdigest()
            shutil.copy2(binary, context / name)
        for name in ("agent.py", "proxy.py"):
            shutil.copy2(here / name, context / name)
        shutil.copy2(here / "Dockerfile.runtime", context / "Dockerfile")
        (context / "provenance.json").write_text(json.dumps(provenance, sort_keys=True))
        subprocess.run(["docker", "build", "--tag", args.tag, str(context)], check=True)
    print(json.dumps(provenance, sort_keys=True))


if __name__ == "__main__":
    main()
