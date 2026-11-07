# Vendored Burn dispatch

Source: `burn-dispatch` 0.22.1 from crates.io, archive SHA-256 `64d255d7609901f7aaf2138b394a6fe8dd8c7b526d1ed2736ba2c643944028fa`. Upstream: https://github.com/tracel-ai/burn/tree/v0.22.1/crates/burn-dispatch. Retain both upstream licenses.

NAOME uses the upstream CPU Flex and autodiff implementations. This copy removes the unused deprecated LibTorch dependency from the manifest, which otherwise introduces vulnerable ZIP/zstd packages into the full lockfile even without an active LibTorch feature. Selecting `tch` fails explicitly; no model or tensor operation is replaced. The Cargo package is excluded from workspace-wide all-feature selection because NAOME does not support every upstream backend. Bazel selects the same `std`, `flex`, and `autodiff` features.

Keep this dependency patch narrow and verify the actual model/Adam continuation and native process tests after changes. Do not suppress the repository dependency audit.
