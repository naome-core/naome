# NAOME

[![CI](https://github.com/naome-core/naome/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/naome-core/naome/actions/workflows/ci.yml)

NAOME is a protocol for a blockchain of machine-verifiable mathematical proofs.
This repository currently implements the deterministic proof, selected-state,
local-persistence, authenticated static-transport, and bounded local
peer-address-management layers, including a transport-neutral atomic record
batch, a dedicated outbound-only authenticated bootstrap pull client, and a
separate bounded inbound-only responder for one immutable operator publication.
The network layer also provides identity-bound durable sequence issuance for
standard self-signed peer records. It does not yet define a bundled seed list,
dynamic learned peer sessions, consensus, finality, fork choice, settlement,
rewards, or fees.

## Architecture

The crate dependency direction is:

```text
foundation -> proof -> checker -> ledger -> chain -> storage -> naome -> network
```

`A -> B` means that `B` builds on `A`. The layers respectively define the ZFC
object language and rules, canonical proof certificates and identities,
deterministic mathematical checking, atomic selected-state transitions, the
authenticated proof DAG, its crash-consistent local journal, transport-neutral
addressed exchange, and the concrete bounded libp2p transport. Later crates may
also depend directly on an earlier crate whose types remain part of their
contract. The network layer also owns the separate persisted peer-address
candidate store and bounded peer-record batch wrapper; learned routing
candidates do not become static proof peers.
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
- [Proof DAG Journal](specs/proof-dag-journal.md)
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
