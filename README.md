# naome

NAOME is a decentralized protocol for formally verified mathematical knowledge. It enables proofs, definitions, and dependencies to be validated, content-addressed, referenced, and economically rewarded on an open proof network.

## Workspace

- `naome-foundation` defines the immutable syntax, logical calculus, and ZFC axiom boundary for Foundation V0.

The normative Foundation V0 contract lives in [`specs/foundation-v0.md`](specs/foundation-v0.md).

## Development

The repository uses the Rust toolchain pinned in `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked --no-fail-fast
```
