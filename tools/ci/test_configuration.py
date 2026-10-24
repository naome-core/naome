"""Regression coverage for CI result gates and the shared Rust toolchain."""

import ast
import pathlib
import tomllib
import unittest

from check_results import require_success

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


if __name__ == "__main__":
    unittest.main()
