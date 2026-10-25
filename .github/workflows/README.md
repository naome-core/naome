# CI strategy

The public repository uses standard GitHub-hosted Linux x86_64 and macOS ARM64
runners. Bazel runs locally on those runners. No remote execution, build service,
service account, paid runner, or additional subscription is configured.

## Before merge

`ci.yml` runs on pull requests, merge groups, and pushes to `main`:

- `Rust quality`: CI contract tests, Cargo formatting, warning-denied documentation,
  and documentation tests.
- `bazel-tests.yml`: native product build, the explicit `//:mr_tests` suite, and
  Clippy for the ordinary product and Bazel test targets on both platforms.
- Stable platform checks and `Rust CI` fail unless their dependencies succeed.

Bazel covers the ordinary product configuration. The suite includes library
regressions and the checker and authoring integration tests. `system-tests`
selects expensive large-history and load regressions; it is absent from the MR
suite. Developer-tool feature combinations and the long process, discovery,
network, and recovery suites run in the full Cargo workflow.

Cargo manifests and `Cargo.lock` remain the dependency authority. `crate_universe`
provides external dependencies; the three patched libp2p crates are native Bazel
workspace targets. CI checks Bazel's Rust version against `rust-toolchain.toml`.
Bazel binaries are version-pinned and SHA-256 verified before execution.

## After merge and on demand

`full-cargo.yml` runs the existing complete Cargo workflow after every push to
`main`: Linux/macOS times `test`/`release`, with all targets and all features.
`--all-features` includes `system-tests`. Each profile retains the compile-before-
execute barrier, ordinary-product checks, all-feature binary restoration, macOS
multicast preflight, native process serialization, and discovery evidence.
Existing explicitly ignored research screens remain manual.

Full Cargo checks are not part of the MR gate. A failed run is a main regression,
not a passed full qualification. Main runs are not cancelled by later pushes.

The full workflow can be dispatched directly. To exercise both paths on a branch
before merge, dispatch the existing `CI` workflow with `full_cargo=true` (an
explicit opt-in). All four complete Cargo jobs must succeed in that run.

## Local commands

Install Bazel from the pinned upstream release using `bash tools/ci/install-bazel.sh`.
Outside GitHub Actions the script writes `.local/naome-tools/bin/bazel`; add that
directory to `PATH`, or invoke it directly. An existing Bazelisk installation also
honors `.bazelversion`.

```sh
bazel build --config=ci //:mr_build
bazel test --config=ci //:mr_tests
bazel build --config=ci --aspects=@rules_rust//rust:defs.bzl%rust_clippy_aspect --output_groups=+clippy_checks --@rules_rust//rust/settings:clippy_flag=-Dwarnings //crates/... //vendor/...
python3 -m unittest discover -s tools/ci -p 'test_*.py' -v
```

The CI contract tests require Python 3.11 or newer. For the full matrix, use the
Cargo commands and profile instructions in the root `AGENTS.md`.

## Downloadable releases

`release.yml` validates read-only candidates when release infrastructure changes
and provides an explicit manual publication path. Both stable and prerelease
publication require successful main-push CI and the complete Full Cargo matrix
at the exact source commit. Native package builds have no publication or signing
rights; attestation and immutable publication run in separate jobs. See
[release operations](../../docs/releases/README.md) and
[download verification](../../tools/release/DOWNLOAD.md).

The Bazel disk and repository caches live under `~/.cache/naome-bazel` and use the
existing GitHub Actions cache allowance. Successful main pushes alone save caches.
Caches are optional accelerators; full Cargo commands always execute. No billing
settings or storage allowances are increased by these workflows.
