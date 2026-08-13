# NAOME

[![CI](https://github.com/naome-core/naome/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/naome-core/naome/actions/workflows/ci.yml)

NAOME is a protocol for a blockchain of machine-verifiable mathematical proofs.
Deterministic checking decides mathematical validity. Blockchain consensus will
govern ordering, inclusion, and provenance; it must not redefine proof truth.

The repository implements deterministic proof identity and checking, one
crash-consistent selected proof chain, a chain-scoped durable store of canonical
structural block candidates, a separate durable archive of canonical payloads
admitted from accepted proof records, and bounded caller-driven exchange,
multi-peer head surveys, and caller-selected proof-chain catch-up among
statically authorized peers. Stored candidates, archived payloads, peer-reported
heads, and fetched ancestry remain inputs that require explicit target-context
validation before selection. One exact direct-child block and its addressed
proof closure can be validated against current selected state without changing
that state; durable application repeats the complete validation.

A prerelease `.nao` compiler provides a bounded, complete source-authoring path
from one named closed theorem, including chained implication and Q1-Q3
quantifier proofs, to checked canonical proof bytes and IDs:

```sh
cargo run -p naome-authoring --bin naome -- proof compile examples/quantifier-instantiation.nao
```

Each local chain begins from a canonical definition that binds its deployment,
the current Foundation identity, and the empty authenticated proof state before
deriving the chain address and virtual genesis.

## Architecture

Crates build in this direction:

```text
foundation -> proof -> checker -> ledger -> chain
                         |                  |-> storage -> network
                         |                  `-> naome   -> network
                         `-> authoring
```

`A -> B` means that `B` builds on `A`. The layers own, respectively: Foundation
syntax and rules; canonical proofs and identities; deterministic checking;
atomic ledger transitions; authenticated proof state, transitions, and blocks;
the selected-chain journal, chain-scoped structural-candidate store, and
Foundation-scoped canonical-payload archive; transport-neutral messages; and
bounded libp2p transport, orchestration, and peer-address management. The
authoring layer owns prerelease source lowering into checked canonical proofs.
A crate may also depend directly on an earlier contract it uses.

The following boundaries are invariant:

- external proof admission is decode, canonicality, checking, expected-address
  comparison, then registration;
- the journal is the sole durable selected-state owner;
- the block-candidate store preserves canonical structural blocks but confers
  no ancestry, proof-validity, execution, or selection authority;
- the payload archive preserves accepted canonical bytes but confers no reusable
  checking or selection authority;
- successful read-only block validation is local and state-relative; it creates
  no durable, transferable, selection, or consensus authority;
- peer heads, blocks, ancestry, records, and receipts confer no consensus or
  selection authority; and
- learned address records never authorize proof sessions.

## Protocol contracts

- [Foundation](specs/foundation.md) defines the mathematical language, axioms,
  schemas, and inference rules.
- [Proof Authoring](specs/proof-authoring.md) defines the deliberately small,
  prerelease `.nao` source compiler and its non-authoritative output boundary.
- [Proof Protocol](specs/proof-protocol.md) defines canonical proofs,
  identities, selected proof state, transitions, and blocks.
- [Proof Chain Journal](specs/proof-chain-journal.md) defines durable selected
  state, replay, recovery, and corruption handling.
- [Proof Block Candidate Store](specs/proof-block-candidate-store.md) defines
  chain-scoped structural block retention without execution or selection.
- [Canonical Proof Payload Store](specs/canonical-proof-payload-store.md)
  defines the separate Foundation-scoped payload archive, integrity checks,
  recovery, and revalidation boundary.
- [Proof Network Transport](specs/proof-network-transport.md) defines proof,
  block, and head messages plus authenticated transport and serving limits.
- [Caller-Selected Orchestration](specs/caller-selected-orchestration.md)
  defines explicit head survey, head broadcast, direct-child import, ancestry
  pull, ancestry import, and catch-up workflows.
- [Peer Addressing](specs/peer-addressing.md) defines signed peer records,
  address storage, issuance, and authenticated exchange.

Specifications are normative for mathematical, authoring, protocol, wire, and
storage semantics. Rustdoc owns the Rust API surface; the crates are executable
reference implementations. This README is non-normative.

The repository is prerelease. An incompatible change replaces its identifier,
protocol, or local format cleanly; it does not add a compatibility parser unless
a stable compatibility commitment exists.

## Local validation

The repository pins its Rust toolchain in `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked --no-fail-fast
```

## License

[MIT](LICENSE)
