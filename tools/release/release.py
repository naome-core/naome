#!/usr/bin/env python3
"""Prepare, package, verify, and publish an immutable NAOME release."""

import argparse
import json
import os
import subprocess
import tomllib
from pathlib import Path

from github import GitHub
from package import assemble, build_package, digest, verify_assets
from policy import REPOSITORY, ROOT, check_publication, check_source, identity


def context():
    sha, run_id = os.environ["GITHUB_SHA"], os.environ["GITHUB_RUN_ID"]
    check_source(sha)
    if not run_id.isdecimal():
        raise ValueError("invalid workflow run identity")
    return sha, run_id


def publication_context():
    sha, run_id = context()
    if (os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"):
        raise ValueError("publication requires an explicit dispatch of the canonical main workflow")
    return sha, run_id


def notes(release):
    path = ROOT / "docs/releases" / f"{release['version']}.md"
    text = path.read_text().strip()
    if not text.startswith(f"# {release['tag']}\n") or len(text.splitlines()) < 3:
        raise ValueError("publication requires reviewed version-specific release notes")
    return text


def prepare(version, publish):
    sha, _ = context()
    if publish:
        publication_context()
        if not version:
            raise ValueError("publication requires the exact version as explicit confirmation")
    version = version or tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    release = identity(version)
    if publish:
        notes(release)
        check_publication(GitHub(), release, sha)
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"version={version}\n")
    print(f"Validated {'publication' if publish else 'candidate build'} of {release['tag']} at {sha}")


def attestations(directory, sha):
    # Verify signature, repository, workflow identity, source ref and source
    # digest before granting the files to the publication API.
    for path in sorted(directory.iterdir()):
        if path.name == "provenance.sigstore.json":
            continue
        subprocess.run(["gh", "attestation", "verify", str(path), "--bundle", str(directory / "provenance.sigstore.json"),
                        "--repo", REPOSITORY, "--signer-workflow", f"{REPOSITORY}/.github/workflows/release.yml",
                        "--source-ref", "refs/heads/main", "--source-digest", sha, "--deny-self-hosted-runners"], check=True)


def asset_matches(asset, path, checksum):
    if asset.get("state") != "uploaded" or asset.get("size") != path.stat().st_size or asset.get("digest") != f"sha256:{checksum}":
        raise ValueError(f"uploaded asset differs from verified bytes: {path.name}")


def require_current_audit(directory):
    recorded = json.loads((directory / "cargo-audit.json").read_text())["database"]["last-commit"]
    remote = subprocess.check_output(["git", "ls-remote", "https://github.com/RustSec/advisory-db.git", "HEAD"], text=True, timeout=60).split()
    if remote != [recorded, "HEAD"]:
        raise ValueError("RustSec database changed since the audit; obtain fresh security qualification before publishing")


def publish(directory, version):
    sha, run_id = publication_context()
    release = identity(version)
    hashes = verify_assets(directory, version, sha, run_id)
    attestations(directory, sha)
    require_current_audit(directory)
    marker = f"<!-- naome-release:{run_id}:{sha} -->"
    api = GitHub()
    qualifications, draft = check_publication(api, release, sha, resume_marker=marker)
    body = notes(release) + f"\n\nSource: `{sha}`.\n\n"
    body += "\n".join(f"- [{name}]({run['url']}) (attempt {run['attempt']})" for name, run in qualifications.items())
    body += f"\n\nBuild and provenance: https://github.com/{REPOSITORY}/actions/runs/{run_id}\n\n"
    body += "See [download verification and installation](https://github.com/" + REPOSITORY + f"/blob/{sha}/tools/release/DOWNLOAD.md).\n\n{marker}\n"
    if draft is None:
        draft = api.request("/releases", method="POST", body={"tag_name": release["tag"], "target_commitish": sha,
                            "name": f"NAOME {release['tag']}", "body": body, "draft": True, "prerelease": release["prerelease"]})
    release_id = draft["id"]
    existing = {asset["name"]: asset for asset in api.pages(f"/releases/{release_id}/assets")}
    if existing.keys() - hashes.keys():
        raise ValueError("owned draft contains unexpected assets; inspect it manually")
    for name, checksum in sorted(hashes.items()):
        path = directory / name
        if name in existing:
            asset_matches(existing[name], path, checksum)
        else:
            asset = api.request(f"/releases/{release_id}/assets?name={name}", method="POST", upload=path)
            asset_matches(asset, path, checksum)
    remote = list(api.pages(f"/releases/{release_id}/assets"))
    if len(remote) != len(hashes) or {asset["name"] for asset in remote} != hashes.keys():
        raise ValueError("draft asset set is incomplete")
    for asset in remote:
        asset_matches(asset, directory / asset["name"], hashes[asset["name"]])
    # Repeat the live gate after all uploads. Only an owned unpublished draft
    # may be resumed; no asset is replaced and no published release is edited.
    check_publication(api, release, sha, resume_marker=marker)
    tag_path = f"/git/ref/tags/{release['tag']}"
    if api.get(tag_path, missing=True) is None:
        api.request("/git/refs", method="POST", body={"ref": f"refs/tags/{release['tag']}", "sha": sha})
    check_publication(api, release, sha, resume_marker=marker)
    require_current_audit(directory)
    result = api.request(f"/releases/{release_id}", method="PATCH", body={"draft": False, "body": body,
                         "prerelease": release["prerelease"], "make_latest": "false" if release["prerelease"] else "true"})
    if result.get("immutable") is not True or result.get("draft") is not False or api.get(tag_path)["object"]["sha"] != sha:
        raise ValueError("published release immutability/source could not be confirmed; inspect the release immediately")
    final = list(api.pages(f"/releases/{release_id}/assets"))
    if len(final) != len(hashes) or {asset["name"] for asset in final} != hashes.keys():
        raise ValueError("published release asset set could not be confirmed")
    for asset in final:
        asset_matches(asset, directory / asset["name"], hashes[asset["name"]])
    print(result["html_url"])
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write(f"Published [{release['tag']}]({result['html_url']}) from `{sha}` with immutable assets.\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("prepare")
    preflight.add_argument("--version", default="")
    preflight.add_argument("--publish", action="store_true")
    package = commands.add_parser("package")
    package.add_argument("--target", required=True)
    package.add_argument("--version", required=True)
    package.add_argument("--notices", type=Path, required=True)
    package.add_argument("--sbom", type=Path, required=True)
    package.add_argument("--system-licenses", type=Path, required=True)
    package.add_argument("--directory", type=Path, required=True)
    for name in ("assemble", "publish"):
        command = commands.add_parser(name)
        command.add_argument("--version", required=True)
        command.add_argument("--directory", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.command == "prepare":
        prepare(arguments.version, arguments.publish)
    elif arguments.command == "package":
        build_package(arguments.target, arguments.version, arguments.directory, arguments.notices, arguments.sbom, arguments.system_licenses)
    elif arguments.command == "assemble":
        sha, run_id = context()
        assemble(arguments.directory, arguments.version, sha, run_id)
    else:
        publish(arguments.directory, arguments.version)


if __name__ == "__main__":
    main()
