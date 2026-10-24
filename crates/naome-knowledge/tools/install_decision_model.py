#!/usr/bin/env python3
"""Install pinned public d1-3B Q8 weights and native runtime; never run inference."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import tarfile
import tempfile
from urllib.request import urlopen


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def matches(path, asset):
    if "link" in asset:
        return path.is_symlink() and os.readlink(path) == asset["link"]
    return (not path.is_symlink() and path.is_file()
            and path.stat().st_size == asset["bytes"] and digest(path) == asset["sha256"])


def publish(temporary, target, asset):
    if not matches(temporary, asset):
        raise RuntimeError("Asset integrity verification failed: " + asset["file"])
    try:
        os.link(temporary, target)
    except FileExistsError:
        if not matches(target, asset):
            raise RuntimeError("Existing asset differs; use a new directory: " + str(target))


def download(url, output):
    with urlopen(url, timeout=60) as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            output.write(chunk)
    output.flush()
    os.fsync(output.fileno())


def model_assets(directory, model):
    for asset in model["files"] + model["provenance"]:
        target = directory / asset["file"]
        if target.exists() or target.is_symlink():
            if not matches(target, asset):
                raise RuntimeError("Existing model asset differs: " + str(target))
            continue
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=directory, prefix=".download-", delete=False) as output:
                temporary = Path(output.name)
                download("https://huggingface.co/" + model["repository"] + "/resolve/"
                         + model["revision"] + "/" + asset["file"], output)
            publish(temporary, target, asset)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        print("Installed " + asset["file"], flush=True)


def runtime_assets(directory, runtime, selected):
    assets = selected["files"]
    if all(matches(directory / a["file"], a) for a in assets):
        return
    with tempfile.TemporaryFile(dir=directory) as archive:
        download("https://github.com/" + runtime["repository"] + "/releases/download/"
                 + runtime["release"] + "/" + selected["archive"], archive)
        archive.seek(0)
        checksum = hashlib.sha256()
        for chunk in iter(lambda: archive.read(1024 * 1024), b""):
            checksum.update(chunk)
        if checksum.hexdigest() != selected["sha256"]:
            raise RuntimeError("Runtime archive integrity verification failed")
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r:gz") as source:
            for asset in assets:
                target = directory / asset["file"]
                if target.exists() or target.is_symlink():
                    if not matches(target, asset):
                        raise RuntimeError("Existing runtime asset differs: " + str(target))
                    continue
                member = source.getmember("llama-" + runtime["release"] + "/" + asset["file"])
                if "link" in asset:
                    if not member.issym() or member.linkname != asset["link"]:
                        raise RuntimeError("Runtime archive link differs")
                    try:
                        os.symlink(asset["link"], target)
                    except FileExistsError:
                        if not matches(target, asset):
                            raise RuntimeError("Concurrent runtime link differs")
                else:
                    if not member.isfile() or member.size != asset["bytes"]:
                        raise RuntimeError("Runtime archive file differs")
                    temporary = None
                    try:
                        with tempfile.NamedTemporaryFile(dir=directory, prefix=".extract-", delete=False) as output:
                            temporary = Path(output.name)
                            contents = source.extractfile(member)
                            for chunk in iter(lambda: contents.read(1024 * 1024), b""):
                                output.write(chunk)
                            output.flush()
                            os.fsync(output.fileno())
                        os.chmod(temporary, 0o755 if asset["file"] != "LICENSE" else 0o644)
                        publish(temporary, target, asset)
                    finally:
                        if temporary is not None:
                            temporary.unlink(missing_ok=True)
                print("Installed " + asset["file"], flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="New or identical model directory")
    parser.add_argument("--runtime-directory", type=Path, required=True,
                        help="New or identical directory for the native platform runtime")
    args = parser.parse_args()
    manifest = json.loads((Path(__file__).resolve().parents[1]
                           / "src/decision/liquid_assets.json").read_text())
    system = platform.system().lower()
    machine = platform.machine().lower()
    name = system + "-" + machine
    if name not in manifest["runtime"]["platforms"]:
        raise RuntimeError("Supported targets are macOS ARM64 and Linux x86_64")
    for directory in (args.directory, args.runtime_directory):
        directory.mkdir(parents=True, exist_ok=True)
    model_assets(args.directory, manifest["model"])
    runtime_assets(args.runtime_directory, manifest["runtime"], manifest["runtime"]["platforms"][name])
    for directory in (args.directory, args.runtime_directory):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    print(json.dumps({"model": manifest["model"]["repository"], "revision": manifest["model"]["revision"],
                      "runtime": manifest["runtime"]["source"], "platform": name,
                      "model_directory": str(args.directory.resolve()),
                      "runtime_directory": str(args.runtime_directory.resolve())}))


if __name__ == "__main__":
    main()
