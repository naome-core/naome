# NAOME

[![CI](https://github.com/naome-core/naome/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/naome-core/naome/actions/workflows/ci.yml)

NAOME is a protocol for a blockchain of machine-verifiable mathematical proofs.
Deterministic checking decides mathematical validity. Blockchain consensus will
govern ordering, inclusion, and provenance; it must not redefine proof truth.

The repository implements deterministic proof identity and checking, one
crash-consistent selected proof chain, and bounded caller-driven exchange with
statically authorized peers. Peer-reported heads and fetched ancestry are
untrusted inputs until explicit local validation and selection.

## Architecture

Crates build in this direction:

```text
foundation -> proof -> checker -> ledger -> chain
                                            |-> storage -> network
                                            `-> naome   -> network
```

`A -> B` means that `B` builds on `A`. The layers own, respectively: Foundation
syntax and rules; canonical proofs and identities; deterministic checking;
atomic ledger transitions; authenticated proof state, transitions, and blocks;
the selected-chain journal; transport-neutral messages; and bounded libp2p
transport, orchestration, and peer-address management. A crate may also
depend directly on an earlier contract it uses.

The following boundaries are invariant:

- external proof admission is decode, canonicality, checking, expected-address
  comparison, then registration;
- the journal is the sole durable selected-state owner;
- peer heads, blocks, ancestry, records, and receipts confer no consensus or
  selection authority; and
- learned address records never authorize proof sessions.

## Delivery gates

1. Proof truth and identity.
2. Local selected state and deterministic replay.
3. Bounded caller-driven transport and import.
4. Global chain identity, genesis, competing-history, selection, and
   reorganization contract.
5. Fork-aware storage and reorganization.
6. Automatic synchronization.
7. Checkpoints and finality.
8. Settlement and economic policy.

The implementation currently reaches gate 3. Each subsequent gate requires a
normative contract and deterministic validation before implementation. Human
authoring syntax, parsing, conservative definitions, and theorem libraries are
a parallel product track; no source syntax is stable yet.

## Protocol contracts

- [Foundation](specs/foundation.md) defines the mathematical language, axioms,
  schemas, and inference rules.
- [Proof Protocol](specs/proof-protocol.md) defines canonical proofs,
  identities, selected proof state, transitions, and blocks.
- [Proof Chain Journal](specs/proof-chain-journal.md) defines durable selected
  state, replay, recovery, and corruption handling.
- [Proof Network Transport](specs/proof-network-transport.md) defines proof,
  block, and head messages plus authenticated transport and serving limits.
- [Caller-Selected Orchestration](specs/caller-selected-orchestration.md)
  defines explicit pull, import, ancestry, and broadcast workflows.
- [Peer Addressing](specs/peer-addressing.md) defines signed peer records,
  address storage, issuance, and authenticated exchange.

Specifications are normative for mathematical, protocol, wire, and storage
semantics. Rustdoc owns the Rust API surface; the crates are executable
reference implementations. This README and its delivery sequence are
non-normative.

The repository is prerelease. An incompatible V0 change replaces its
identifier, protocol, or local format cleanly; it does not add a legacy parser
unless a stable compatibility commitment exists.

## Local validation

The repository pins its Rust toolchain in `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked --no-fail-fast
```

## License

[MIT](LICENSE)
