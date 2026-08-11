# NAOME

[![CI](https://github.com/naome-core/naome/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/naome-core/naome/actions/workflows/ci.yml)

NAOME is a protocol for a blockchain of machine-verifiable mathematical proofs.
This repository currently implements deterministic proof checking, selected
proof state, canonical linear proof blocks with crash-consistent exact-head
persistence and exact-ID historical lookup, transport-neutral addressed proof
and block exchange, authenticated static proof and exact-ID block transport,
and bounded local peer-address management. The network layer includes a
transport-neutral atomic record batch, a dedicated outbound-only authenticated
bootstrap pull client, a separate bounded inbound-only responder for one
immutable operator publication, and identity-bound durable sequence issuance
for standard self-signed peer records. It does not yet define block
announcements, ancestry synchronization, competing-fork storage, a bundled seed
list, dynamic learned peer sessions, consensus, finality, fork choice,
settlement, rewards, or fees.

## Architecture

The crate dependency direction is:

```text
foundation -> proof -> checker -> ledger -> chain -> storage -> naome -> network
```

`A -> B` means that `B` builds on `A`. The layers respectively define the ZFC
object language and rules, canonical proof certificates and identities,
deterministic mathematical checking, atomic selected-state transitions, the
authenticated proof DAG with canonical root-to-root transitions and linear
proof-block context, the sole crash-consistent local proof-chain journal,
transport-neutral addressed proof and block exchange, and the concrete bounded
libp2p proof and exact-ID block transport. The chain journal durably commits
each exact-parent block together with its transition's ordered proof payloads,
strictly reconstructs the head and proof state on open, and retains decoded
committed blocks for exact-ID lookup. Later crates may also depend directly on
an earlier crate whose types remain part of their contract. The network layer
also owns the separate persisted peer-address candidate store and bounded peer-
record batch wrapper; learned routing candidates do not become static proof
peers.
The local peer-record issuer durably advances one caller-owned identity's
explicit sequence watermark before returning a newly signed record; it never
persists the private key or publishes by itself.
The bootstrap client and responder run in separate dedicated swarms that cannot
negotiate the proof protocol. The responder serves only its explicit immutable
operator-supplied batch and never exports the local peer-address store;
authenticated record provenance therefore remains routing input, not proof
authorization.

## Protocol contracts

- [ZFC Foundation](specs/foundation.md)
- [Proof Certificate](specs/proof-certificate.md)
- [Ledger State](specs/ledger-state.md)
- [Authenticated Proof Set](specs/authenticated-proof-set.md)
- [Proof-State Transition](specs/proof-state-transition.md)
- [Proof Block](specs/proof-block.md)
- [Proof Chain Journal](specs/proof-chain-journal.md)
- [Addressed Proof Block Exchange](specs/addressed-proof-block-exchange.md)
- [Authenticated Proof Block Transport](specs/authenticated-proof-block-transport.md)
- [Addressed Proof Exchange](specs/addressed-proof-exchange.md)
- [Authenticated Proof Transport](specs/authenticated-proof-transport.md)
- [Peer Address Management](specs/peer-address-management.md)
- [Local Peer Record Issuance](specs/local-peer-record-issuance.md)
- [Peer Record Exchange](specs/peer-record-exchange.md)
- [Authenticated Peer Record Pull](specs/authenticated-peer-record-pull.md)
- [Authenticated Peer Record Responder](specs/authenticated-peer-record-responder.md)

The specifications are normative. The Rust crates are executable reference
implementations of their stated boundaries.

## Local validation

The repository pins its Rust toolchain in `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked --no-fail-fast
```

## License

[MIT](LICENSE)
