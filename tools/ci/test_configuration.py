"""Regression coverage for CI result gates and the shared Rust toolchain."""

import ast
import hashlib
import io
import pathlib
import tarfile
import tomllib
import unittest
from unittest.mock import patch

from check_results import require_success
from pinned_tool import executable

ROOT = pathlib.Path(__file__).resolve().parents[2]


class ResultGateTests(unittest.TestCase):
    def test_all_expected_dependencies_must_succeed(self):
        require_success({"linux": {"result": "success"}, "macos": {"result": "success"}}, ["linux", "macos"])

    def test_failure_skip_cancellation_and_missing_dependency_are_rejected(self):
        for result in ["failure", "cancelled", "skipped", "pending", None]:
            with self.subTest(result=result), self.assertRaises(ValueError):
                require_success({"linux": {"result": "success"}, "macos": {"result": result}}, ["linux", "macos"])
        with self.assertRaises(ValueError):
            require_success({"linux": {"result": "success"}}, ["linux", "macos"])

    def test_an_added_dependency_cannot_be_silently_ignored(self):
        with self.assertRaises(ValueError):
            require_success({"linux": {"result": "success"}, "new_check": {"result": "failure"}}, ["linux"])

    def test_an_empty_gate_cannot_pass(self):
        with self.assertRaises(ValueError):
            require_success({}, [])


class BuildContractTests(unittest.TestCase):
    def test_bazel_node_version_matches_the_cargo_release_identity(self):
        version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        module = ast.parse((ROOT / "crates/naome-knowledge/BUILD.bazel").read_text())
        libraries = [node.value for node in module.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "rust_library"]
        self.assertEqual(len(libraries), 1)
        keywords = {item.arg: item.value for item in libraries[0].keywords}
        self.assertEqual(ast.literal_eval(keywords["version"]), version)

    def test_bazel_and_cargo_use_the_same_pinned_rust(self):
        pinned = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        module = ast.parse((ROOT / "MODULE.bazel").read_text())
        configs = [node.value for node in module.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "toolchain"]
        self.assertEqual(len(configs), 1)
        keywords = {item.arg: ast.literal_eval(item.value) for item in configs[0].keywords}
        self.assertEqual(keywords["versions"], [pinned])
        self.assertEqual(keywords["rustfmt_version"], pinned)

    def test_pinned_bazel_has_checksums_for_both_ci_hosts(self):
        version = (ROOT / ".bazelversion").read_text().strip()
        entries = [line.split() for line in (ROOT / "tools/ci/bazel.sha256").read_text().splitlines()]
        self.assertEqual({name for _, name in entries}, {f"bazel-{version}-linux-x86_64", f"bazel-{version}-darwin-arm64"})
        for digest, _ in entries:
            self.assertEqual(len(bytes.fromhex(digest)), 32)


class PinnedToolTests(unittest.TestCase):
    def payload(self, *, link=False):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            entry = tarfile.TarInfo("tool")
            if link:
                entry.type, entry.linkname = tarfile.SYMTYPE, "/tmp/untrusted"
                archive.addfile(entry)
            else:
                entry.size = 5
                archive.addfile(entry, io.BytesIO(b"bytes"))
        return output.getvalue()

    def test_verified_executable_is_isolated_and_removed_after_use(self):
        payload = self.payload()
        with patch("urllib.request.urlopen", return_value=io.BytesIO(payload)):
            with executable("https://example.test/tool", hashlib.sha256(payload).hexdigest(), "tool") as path:
                self.assertEqual(path.read_bytes(), b"bytes")
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            self.assertFalse(path.exists())

    def test_modified_download_or_link_is_rejected_before_execution(self):
        for link in [False, True]:
            payload = self.payload(link=link)
            expected = hashlib.sha256(payload).hexdigest() if link else "0" * 64
            with self.subTest(link=link), patch("urllib.request.urlopen", return_value=io.BytesIO(payload)), self.assertRaises(ValueError):
                with executable("https://example.test/tool", expected, "tool"):
                    self.fail("untrusted executable was accepted")


if __name__ == "__main__":
    unittest.main()
