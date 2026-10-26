# Vendored Burn tensor

Source: `burn-tensor` 0.22.1 from crates.io, archive SHA-256 `1b81a08d2ba73d346e29c245e3c31a41a8af98f54810ac796cadf453e01ec81f`. Upstream: https://github.com/tracel-ai/burn/tree/v0.22.1/crates/burn-tensor. Retain both upstream licenses.

This copy removes the optional `colored` dependency and ANSI styling from the standalone tensor-closeness reporting helper. Its comparisons and text remain intact. NAOME does not use that helper. Tensor operations, autodiff, model initialization, optimizer behavior and the selected `std`/CPU Flex/SIMD features are unchanged. The upstream package is MIT OR Apache-2.0; the removed dependency's MPL-2.0 license is outside NAOME's permissive-only release policy.

Keep the patch limited to the manifest and reporting helper. Compare all remaining source bytes with the pinned archive, and verify native model/Adam continuation and package license generation. Cargo and Bazel must select this same checkout-relative source. The package is excluded from workspace-wide all-feature selection, matching the supported backend boundary.
