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
    def test_knowledge_training_group_reuses_the_complete_test_binary(self):
        module = ast.parse((ROOT / "crates/naome-knowledge/BUILD.bazel").read_text())
        rules = {}
        for node in module.body:
            if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)):
                continue
            values = {item.arg: item.value for item in node.value.keywords}
            if "name" in values:
                rules[ast.literal_eval(values["name"])] = (node.value.func.id, values)
        self.assertEqual([name for name, (rule, _) in rules.items() if rule == "rust_test"], ["unit_tests"])
        ordinary = rules["unit_tests"][1]
        rule, training = rules["preservation_tests"]
        self.assertEqual(rule, "native_test")
        self.assertEqual(ast.literal_eval(training["src"]), ":unit_tests")
        group = "learning::model::preservation::tests::"
        self.assertEqual(ast.literal_eval(ordinary["args"]), [f"--skip={group}"])
        self.assertEqual(ast.literal_eval(training["args"]), [group])
        self.assertEqual(ast.literal_eval(training["tags"]), ["exclusive"])
        for values in (ordinary, training):
            self.assertEqual(ast.literal_eval(values["size"]), "medium")
            self.assertEqual(ast.literal_eval(values["env"]), {"RUST_TEST_THREADS": "2"})
        suite = ast.parse((ROOT / "BUILD.bazel").read_text())
        tests = next(node.value for node in suite.body if isinstance(node, ast.Expr)
                     and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                     and node.value.func.id == "test_suite")
        labels = next(ast.literal_eval(item.value) for item in tests.keywords if item.arg == "tests")
        for name in ("unit_tests", "preservation_tests"):
            self.assertIn(f"//crates/naome-knowledge:{name}", labels)

    def test_bazel_optimized_ci_retains_debug_and_overflow_checks(self):
        lines = (ROOT / ".bazelrc").read_text().splitlines()
        self.assertIn("build:ci --compilation_mode=opt", lines)
        self.assertIn("build:ci --@rules_rust//rust/settings:extra_rustc_flag=-Copt-level=1", lines)
        for flag in ("debug-assertions", "overflow-checks"):
            self.assertIn(f"build:ci --@rules_rust//rust/settings:extra_rustc_flag=-C{flag}=yes", lines)
        self.assertIn("test:ci --test_arg=--test-threads=2", lines)
        self.assertIn("test:ci --flaky_test_attempts=1", lines)

    def test_bazel_crypto_optimization_and_checks_match_the_cargo_test_profile(self):
        profiles = tomllib.loads((ROOT / "Cargo.toml").read_text())["profile"]["test"]["package"]
        module = ast.parse((ROOT / "MODULE.bazel").read_text())
        annotations = {}
        for node in module.body:
            if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "annotation"):
                values = {item.arg: ast.literal_eval(item.value) for item in node.value.keywords}
                if values.get("version") == "*":
                    annotations[values["crate"]] = values
        for package, profile in profiles.items():
            with self.subTest(package=package):
                self.assertIn(package, annotations)
                flags = dict(flag.removeprefix("-C").split("=", 1) for flag in annotations[package]["rustc_flags"])
                self.assertEqual(flags["opt-level"], str(profile["opt-level"]))
                for setting in ("debug-assertions", "overflow-checks"):
                    self.assertEqual(flags[setting], "yes" if profile[setting] else "no")

    def test_bazel_node_and_checker_versions_match_the_cargo_release_identity(self):
        version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        for crate in ("naome-knowledge", "naome-checker"):
            with self.subTest(crate=crate):
                module = ast.parse((ROOT / "crates" / crate / "BUILD.bazel").read_text())
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

    def test_shared_numerical_kernels_retain_optimization_and_runtime_guards(self):
        prefix = "--@rules_rust//rust/settings:per_crate_rustc_flag="
        profiles = {}
        for line in (ROOT / ".bazelrc").read_text().splitlines():
            words = line.split()
            if len(words) == 2 and words[1].startswith(prefix):
                self.assertEqual(words[0], "build", "build, test and Clippy must reuse one kernel configuration")
                selector, flag = words[1].removeprefix(prefix).split("@", 1)
                profiles.setdefault(selector, []).append(flag)
        self.assertTrue(profiles)
        for selector, flags in profiles.items():
            with self.subTest(selector=selector):
                self.assertTrue(selector.endswith("crates__gemm"))
                self.assertEqual([f for f in flags if f.startswith("-Copt-level=")], ["-Copt-level=2"])
                self.assertEqual([f for f in flags if f.startswith("-Cdebug-assertions=")], ["-Cdebug-assertions=on"])
                self.assertEqual([f for f in flags if f.startswith("-Coverflow-checks=")], ["-Coverflow-checks=on"])

    def test_ci_builds_both_aggregates_before_running_tests(self):
        workflow = " ".join((ROOT / ".github/workflows/bazel-tests.yml").read_text().split())
        build = ("run: >- bazel build --config=ci "
                 "--aspects=@rules_rust//rust:defs.bzl%rust_clippy_aspect "
                 "--output_groups=+clippy_checks //:mr_build //:mr_tests //crates/... //vendor/...")
        execute = "run: bazel test --config=ci //:mr_tests"
        self.assertIn(build, workflow)
        self.assertIn(execute, workflow)
        self.assertLess(workflow.index(build), workflow.index(execute))
        self.assertEqual(workflow.count("bazel build --config=ci"), 1)
        self.assertIn("timeout-minutes: 20", workflow)
        self.assertIn("build --jobs=4", (ROOT / ".bazelrc").read_text().splitlines())
        self.assertIn("build:ci --@rules_rust//rust/settings:clippy_flag=-Dwarnings",
                      (ROOT / ".bazelrc").read_text().splitlines())


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
