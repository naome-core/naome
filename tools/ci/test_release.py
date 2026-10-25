"""Release behavior: qualification, distribution integrity and resumable publication."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/release"))
import package
import policy
import release
from github import GitHub

SHA = "a" * 40
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]


def qualified_run(workflow, **changes):
    return {"id": 10, "run_number": 1, "run_attempt": 1, "path": f".github/workflows/{workflow}",
            "head_repository": {"full_name": "naome-core/naome"}, "event": "push", "head_branch": "main",
            "head_sha": SHA, "status": "completed", "conclusion": "success", "html_url": "https://github.com/naome-core/naome/actions/runs/10", **changes}


class Repository:
    def __init__(self):
        self.sha = SHA
        self.immutable = True
        self.runs = {name: [qualified_run(name)] for name in ("ci.yml", "full-cargo.yml")}
        self.releases = []
        self.tag = None
        self.assets = []
        self.mutations = []
        self.fail_upload = None
        self.protected = True
        self.bypass = []

    def get(self, path, missing=False):
        if path == "":
            return {"full_name": "naome-core/naome", "default_branch": "main", "private": False}
        if path == "/branches/main":
            return {"commit": {"sha": self.sha}, "protected": self.protected}
        if path == "/rules/branches/main":
            return [{"type": "pull_request", "ruleset_id": 1, "parameters": {"required_review_thread_resolution": True}},
                    {"type": "required_status_checks", "ruleset_id": 1, "parameters": {"required_status_checks": [
                        {"context": name, "integration_id": 15368} for name in ["Rust quality", "Rust platform (Linux x86_64)", "Rust platform (macOS ARM64)", "Rust CI"]]}},
                    {"type": "deletion", "ruleset_id": 1}, {"type": "non_fast_forward", "ruleset_id": 1}]
        if path == "/rulesets/1":
            return {"enforcement": "active", "bypass_actors": self.bypass}
        if path == "/immutable-releases":
            return {"enabled": self.immutable}
        if path.startswith("/git/ref/tags/"):
            return self.tag
        raise AssertionError(path)

    def pages(self, path, key=None):
        if path == "/releases":
            return copy.deepcopy(self.releases)
        if path.endswith("/assets"):
            return copy.deepcopy(self.assets)
        for name, runs in self.runs.items():
            if path.startswith(f"/actions/workflows/{name}/runs?"):
                return copy.deepcopy(runs)
        raise AssertionError(path)

    def request(self, path, *, method, body=None, upload=None):
        self.mutations.append((method, path, body))
        if path == "/releases" and method == "POST":
            draft = {**body, "id": 1, "html_url": "https://github.com/naome-core/naome/releases/tag/vtest"}
            self.releases.append(draft)
            return copy.deepcopy(draft)
        if path.startswith("/releases/1/assets?name="):
            if self.fail_upload == len(self.assets):
                raise RuntimeError("injected upload failure")
            name = path.split("?name=")[1]
            asset = {"name": name, "size": upload.stat().st_size, "state": "uploaded", "digest": "sha256:" + hashlib.sha256(upload.read_bytes()).hexdigest()}
            self.assets.append(asset)
            return copy.deepcopy(asset)
        if path == "/git/refs":
            self.tag = {"object": {"type": "commit", "sha": body["sha"]}}
            return self.tag
        if path == "/releases/1" and method == "PATCH":
            self.releases[0].update(body, immutable=self.immutable)
            return copy.deepcopy(self.releases[0])
        raise AssertionError((method, path))


class QualificationTests(unittest.TestCase):
    def test_only_canonical_versions_and_ordering(self):
        ordered = ["0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0-beta.1", "0.1.0-rc.1", "0.1.0", "0.1.1", "1.0.0"]
        self.assertEqual(sorted(ordered, key=policy.version_key), ordered)
        for value in ["v1.2.3", "1.2", "01.2.3", "1.02.3", "1.2.3-rc.0", "1.2.3-rc.01", "1.2.3+build", "1.2.3\n", "$(touch file)", "../1.2.3"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.version_key(value)

    def test_version_and_manifest_must_agree(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "Cargo.toml").write_text('[workspace.package]\nversion = "1.2.3-rc.1"\n')
            self.assertEqual(policy.identity("1.2.3-rc.1", root), {"version": "1.2.3-rc.1", "tag": "v1.2.3-rc.1", "prerelease": True})
            with self.assertRaises(ValueError):
                policy.identity("1.2.3", root)

    def test_latest_attempt_not_an_old_success_is_authoritative(self):
        old = qualified_run("full-cargo.yml")
        for state in ["failure", "cancelled", "skipped", None]:
            for changes in [{"run_number": 2}, {"run_attempt": 2}]:
                with self.subTest(state=state, changes=changes), self.assertRaises(ValueError):
                    policy.successful_run([old, {**old, **changes, "conclusion": state}], "full-cargo.yml", SHA)
        with self.assertRaises(ValueError):
            policy.successful_run([old, {**old, "run_attempt": 2, "status": "in_progress"}], "full-cargo.yml", SHA)

    def test_spoofed_workflow_fork_branch_event_or_commit_does_not_qualify(self):
        for changes in [{"path": ".github/workflows/spoof.yml"}, {"head_repository": {"full_name": "attacker/naome"}},
                        {"event": "pull_request"}, {"head_branch": "candidate"}, {"head_sha": "b" * 40}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                policy.successful_run([qualified_run("ci.yml", **changes)], "ci.yml", SHA)

    def test_both_complete_qualifications_and_immutable_main_are_required(self):
        release_id = {"version": "1.2.3", "tag": "v1.2.3", "prerelease": False}
        api = Repository()
        self.assertEqual(set(policy.check_publication(api, release_id, SHA)[0]), {"ci.yml", "full-cargo.yml"})
        for attribute, value in [("sha", "b" * 40), ("immutable", False), ("protected", False), ("bypass", [{"actor_id": 1}])]:
            broken = Repository()
            setattr(broken, attribute, value)
            with self.subTest(attribute=attribute), self.assertRaises(ValueError):
                policy.check_publication(broken, release_id, SHA)
        for workflow in api.runs:
            broken = Repository()
            broken.runs[workflow] = []
            with self.subTest(workflow=workflow), self.assertRaises(ValueError):
                policy.check_publication(broken, release_id, SHA)
        self.assertEqual(api.mutations, [])

    def test_reuse_and_downgrade_are_rejected(self):
        release_id = {"version": "1.2.3-rc.1", "tag": "v1.2.3-rc.1", "prerelease": True}
        for previous in [{"tag_name": "v1.2.3-rc.1", "draft": False}, {"tag_name": "v1.2.3", "draft": False},
                         {"tag_name": "v2.0.0-alpha.1", "draft": False}]:
            api = Repository()
            api.releases = [previous]
            with self.subTest(previous=previous), self.assertRaises(ValueError):
                policy.check_publication(api, release_id, SHA)
        api = Repository()
        api.tag = {"object": {"type": "commit", "sha": SHA}}
        with self.assertRaises(ValueError):
            policy.check_publication(api, release_id, SHA)

    def test_dispatch_from_a_branch_fork_or_event_cannot_publish(self):
        environment = {"GITHUB_REPOSITORY": "naome-core/naome", "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch"}
        with patch.object(release, "context", return_value=(SHA, "42")), patch.dict(os.environ, environment):
            self.assertEqual(release.publication_context(), (SHA, "42"))
            for key, value in [("GITHUB_REPOSITORY", "fork/naome"), ("GITHUB_REF", "refs/heads/topic"), ("GITHUB_EVENT_NAME", "pull_request")]:
                with self.subTest(key=key), patch.dict(os.environ, {key: value}), self.assertRaises(ValueError):
                    release.publication_context()

    def test_policy_read_credential_is_not_used_for_release_writes(self):
        with patch.dict(os.environ, {"GH_TOKEN": "job-token", "RELEASE_POLICY_TOKEN": "read-only-policy-token"}):
            with patch("urllib.request.urlopen", return_value=io.BytesIO(b"{}")) as opened:
                GitHub().get("/immutable-releases")
                self.assertEqual(opened.call_args.args[0].get_header("Authorization"), "Bearer read-only-policy-token")
            with patch("urllib.request.urlopen", return_value=io.BytesIO(b"{}")) as opened:
                GitHub().request("/releases", method="POST", body={"draft": True})
                self.assertEqual(opened.call_args.args[0].get_header("Authorization"), "Bearer job-token")
            for path in ["/immutable-releases", "/rulesets/123"]:
                with self.subTest(path=path), self.assertRaises(ValueError):
                    GitHub().request(path, method="PUT", body={})


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def payload(self, target):
        binary = f'#!/bin/sh\ncase "$*" in\n--version) echo "naome {VERSION}";;\n--help) echo "naome start";;\n"--json status") echo \'{{"running":false,"accepted_proofs":0,"interest":""}}\';;\n*) exit 1;;\nesac\n'.encode()
        lockfile = (ROOT / "Cargo.lock").read_bytes()
        build = {"schema": 1, "repository": "naome-core/naome", "commit": SHA, "target": target, "profile": "release",
                 "features": [], "version": VERSION, "tag": f"v{VERSION}", "prerelease": "-" in VERSION,
                 "binary_sha256": hashlib.sha256(binary).hexdigest(), "cargo_lock_sha256": hashlib.sha256(lockfile).hexdigest()}
        return {name: b"notice" for name in package.FILES} | {"naome": binary, "build.json": json.dumps(build).encode(), "Cargo.lock": lockfile}

    def make_archive(self, target=None, files=None, directory=None):
        target = target or policy.TARGETS[0]
        directory = directory or self.directory
        name = f"naome-{VERSION}-{target}"
        path = directory / f"{name}.tar.gz"
        package.archive(path, name, files or self.payload(target), 1_700_000_000)
        return path

    def complete_set(self):
        for target in policy.TARGETS:
            self.make_archive(target)
        package.assemble(self.directory, VERSION, SHA, "42")
        report = {"database": {"last-commit": "c" * 40}, "vulnerabilities": {"found": False, "count": 0, "list": []},
                  "settings": {"ignore": [], "severity": None, "target_arch": [], "target_os": [], "informational_warnings": ["unmaintained", "unsound", "notice"]},
                  "naome": {"cargo_lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(),
                            "scanner": "cargo-audit " + tomllib.loads((ROOT / "tools/release/toolchain.toml").read_text())["cargo-audit"]}}
        path = self.directory / "cargo-audit.json"
        path.write_text(json.dumps(report))
        with (self.directory / "SHA256SUMS").open("a") as output:
            output.write(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  cargo-audit.json\n")
        (self.directory / "provenance.sigstore.json").write_text("signature fixture")

    def test_archive_is_deterministic_and_extracted_executable_works_without_state(self):
        path = self.make_archive()
        first = path.read_bytes()
        path.unlink()
        second = self.make_archive()
        self.assertEqual(first, second.read_bytes())
        build = package.verify_package(second, VERSION, SHA, execute=True)
        self.assertEqual(build["target"], "x86_64-unknown-linux-musl")
        with tarfile.open(second) as tar:
            for entry in tar.getmembers():
                self.assertEqual((entry.uid, entry.gid, entry.mtime), (0, 0, 1_700_000_000))

    def test_tampered_binary_lockfile_identity_and_extra_paths_are_rejected(self):
        for mutation in [lambda files: files.update(naome=b"changed"), lambda files: files.update({"Cargo.lock": b"changed"}),
                         lambda files: files.update({"build.json": files["build.json"].replace(SHA.encode(), b"b" * 40)}),
                         lambda files: files.update({"../escape": b"outside"})]:
            files = self.payload(policy.TARGETS[0])
            mutation(files)
            with tempfile.TemporaryDirectory() as name:
                path = self.make_archive(files=files, directory=Path(name))
                with self.assertRaises(ValueError):
                    package.verify_package(path, VERSION, SHA)

    def test_symlink_members_and_duplicate_paths_are_not_extracted(self):
        name = f"naome-{VERSION}-{policy.TARGETS[0]}"
        for link in [True, False]:
            path = self.directory / f"{name}.tar.gz"
            with tarfile.open(path, "w:gz") as tar:
                for filename, data in self.payload(policy.TARGETS[0]).items():
                    entry = tarfile.TarInfo(f"{name}/{filename}")
                    entry.mode = 0o755 if filename == "naome" else 0o644
                    if link and filename == "naome":
                        entry.type, entry.linkname = tarfile.SYMTYPE, "/tmp/outside"
                        tar.addfile(entry)
                    else:
                        entry.size = len(data)
                        tar.addfile(entry, io.BytesIO(data))
                if not link:
                    tar.addfile(tarfile.TarInfo(f"{name}/naome"), io.BytesIO())
            with self.subTest(link=link), self.assertRaises(ValueError):
                package.verify_package(path, VERSION, SHA, execute=True)

    def test_missing_platform_and_foreign_archives_cannot_form_a_release(self):
        self.make_archive()
        with self.assertRaises(ValueError):
            package.assemble(self.directory, VERSION, SHA, "42")
        self.make_archive(policy.TARGETS[1])
        (self.directory / "unexpected.tar.gz").write_bytes(b"extra")
        with self.assertRaises(ValueError):
            package.assemble(self.directory, VERSION, SHA, "42")

    def test_final_asset_digests_and_workflow_identity_must_agree(self):
        self.complete_set()
        self.assertEqual(len(package.verify_assets(self.directory, VERSION, SHA, "42")), 6)
        with self.assertRaises(ValueError):
            package.verify_assets(self.directory, VERSION, SHA, "43")
        path = self.directory / "SHA256SUMS"
        path.write_text(path.read_text() + path.read_text().splitlines()[0] + "\n")
        with self.assertRaises(ValueError):
            package.verify_assets(self.directory, VERSION, SHA, "42")

    def test_publication_stages_complete_draft_then_locks_and_never_replaces(self):
        self.complete_set()
        api = Repository()
        with patch.object(release, "publication_context", return_value=(SHA, "42")), patch.object(release, "GitHub", return_value=api), \
             patch.object(release, "attestations"), patch.object(release, "notes", return_value="Reviewed notes"), \
             patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(self.directory / "summary")}):
            release.publish(self.directory, VERSION)
        self.assertEqual(len(api.assets), 6)
        self.assertTrue(api.releases[0]["immutable"])
        self.assertFalse(api.releases[0]["draft"])
        self.assertEqual(api.releases[0]["make_latest"], "false" if "-" in VERSION else "true")
        self.assertEqual(api.mutations[-2][1], "/git/refs")
        self.assertEqual(api.mutations[-1][0:2], ("PATCH", "/releases/1"))
        before = list(api.mutations)
        with self.assertRaises(ValueError):
            policy.check_publication(api, policy.identity(VERSION), SHA, resume_marker=f"<!-- naome-release:42:{SHA} -->")
        self.assertEqual(api.mutations, before)

    def test_failed_upload_can_resume_only_the_owned_draft_without_replacement(self):
        self.complete_set()
        api = Repository()
        api.fail_upload = 1
        with patch.object(release, "publication_context", return_value=(SHA, "42")), patch.object(release, "GitHub", return_value=api), \
             patch.object(release, "attestations"), patch.object(release, "notes", return_value="Reviewed notes"), \
             patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(self.directory.parent / "unused-release-summary")}):
            with self.assertRaises(RuntimeError):
                release.publish(self.directory, VERSION)
            self.assertTrue(api.releases[0]["draft"])
            self.assertIsNone(api.tag)
            self.assertEqual(len(api.assets), 1)
            uploaded = copy.deepcopy(api.assets[0])
            with self.assertRaises(ValueError):
                policy.check_publication(api, policy.identity(VERSION), SHA, resume_marker="foreign run")
            api.fail_upload = None
            # Keep the summary outside the immutable asset directory.
            with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(Path(name) / "summary")}):
                release.publish(self.directory, VERSION)
            self.assertEqual(api.assets[0], uploaded)
            self.assertEqual(len(api.releases), 1)
            self.assertEqual(len(api.assets), 6)
            self.assertFalse(api.releases[0]["draft"])

    def test_vulnerable_suppressed_filtered_or_foreign_lockfile_audit_cannot_publish(self):
        self.complete_set()
        report = json.loads((self.directory / "cargo-audit.json").read_text())
        package.verify_audit(report)
        for mutate in [lambda value: value["vulnerabilities"].update(found=True, count=1, list=[{"advisory": "vulnerable"}]),
                       lambda value: value["settings"].update(ignore=["RUSTSEC-2026-0001"]),
                       lambda value: value["settings"].update(informational_warnings=[]),
                       lambda value: value["settings"].update(target_os=["linux"]),
                       lambda value: value["naome"].update(cargo_lock_sha256="b" * 64),
                       lambda value: value["database"].update({"last-commit": ""}),
                       lambda value: value.update(warnings={"unsound": [{}]})]:
            broken = copy.deepcopy(report)
            mutate(broken)
            with self.assertRaises(ValueError):
                package.verify_audit(broken)


if __name__ == "__main__":
    unittest.main()
