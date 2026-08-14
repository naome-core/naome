# NAOME

[![CI](https://github.com/naome-core/naome/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/naome-core/naome/actions/workflows/ci.yml)

NAOME is a protocol for a blockchain of machine-verifiable mathematics. One
fixed block selects exactly one typed artifact: either a checked proof or a
conservative mathematical definition. Deterministic checking decides
Foundation-relative validity. Future consensus may decide ordering, inclusion,
and provenance; it must not redefine mathematical truth.

Definitions let large proofs use ordinary mathematical vocabulary without
replacing it with primitive ZFC at every citation. Relations are eliminable
formula abbreviations. Constants and functions are graph definitions backed by
exact earlier selected proofs of unique or total-unique existence. Proofs and
definitions may use only dependencies selected by earlier blocks in the same
chain ancestry. Local files, archives, candidates, network responses, the same
block, and forward references never authorize resolution.

The implementation currently provides:

- canonical proof, definition, and tagged-artifact codecs and identities;
- deterministic proof checking and bounded conservative definition expansion;
- atomic mixed-artifact admission and an authenticated `ArtifactId` set;
- one exact-parent, fixed 128-byte artifact block per selected transition;
- crash-consistent mixed proof/definition journal replay;
- separate non-authoritative block-candidate and payload stores;
- bounded caller-selected static-peer exchange, ancestry, and catch-up; and
- a Python-shaped prerelease `.nao` authoring language.

Consensus, fork choice, finality, reorganization, incentives, and recursive
definitions are not implemented.

## Authoring

The single CLI command compiles either a proof or a definition:

```sh
cargo run -p naome-authoring --bin naome -- proof examples/reflexive-relation.nao
```

A dependency-free relation definition is compact:

```python
foundation = "naome:zfc"

definition self_equal = relation(value):
    equal(value, value)
```

Selected definitions receive source-only names, while the blockchain identity
remains the exact 64-character lowercase hex address:

```python
foundation = "naome:zfc"

definitions:
    self_equal = "8f4506222901bb6e087615063e7d1db49be6842d96e7e1adfbcd01c84ff28018"

statement = forall(
    x,
    implies(equal(x, x), implies(self_equal(x), self_equal(x))),
)

proof:
    p0 = equality_substitution(x, x, self_equal(x))
    p1 = generalization(p0, x)
    return p1
```

Proof citations use `cite("<ProofId>")`. Definition aliases and citations are
accepted only by the selected-state compiler adapter borrowing immutable
`ArtifactState` from a healthy `ArtifactChainJournal`. Compilation never
fetches, selects, registers, or mutates an artifact. The standalone CLI uses an
empty state, so it accepts dependency-free artifacts and rejects reachable
selected dependencies.

Successful proof output contains `statement_id`, `derivation_id`, `proof_id`,
the block-addressable `artifact_id`, and canonical proof bytes. Successful
definition output contains `definition_id`, `artifact_id`, and canonical
definition bytes. Diagnostics are bounded and carry stable codes plus UTF-8
source positions when available.

The `.nao` language is prerelease and source-first. Human names, formula aliases,
derived connectives, and term-shaped constant/function calls are presentation
syntax; canonical external bytes and content identities remain the protocol
boundary.

## Architecture

Crates build in this direction:

```text
foundation -> proof -> checker -> ledger -> chain
                         |                  |-> storage -> network
                         |                  `-> naome   -> network
                         `-> authoring
storage -> authoring
```

The layers own, respectively: primitive ZFC syntax and rules; canonical proof,
definition, and artifact representations; deterministic checking; atomic
artifact admission; authenticated selected state and single-artifact blocks;
selected persistence plus non-authoritative archives; transport-neutral
messages; bounded libp2p transport and caller orchestration; and source
authoring.

Invariant boundaries are:

- external admission is exact tagged decode, canonicality, checking, typed
  identity comparison, then atomic registration;
- one selected block admits exactly one proof or definition;
- every dependency must be selected by an earlier ancestry block;
- only successful block application or verified journal replay supplies proof
  and definition resolution authority;
- candidate and payload stores retain bytes without execution or selection;
- peer heads, blocks, ancestry, payloads, records, and receipts confer no
  consensus or selection authority; and
- read-only validation is local and state-relative and creates no transferable
  authority.

## Protocol contracts

- [Foundation](specs/foundation.md) defines primitive mathematical syntax,
  axioms, schemas, and inference rules.
- [Mathematical Definitions](specs/mathematical-definitions.md) defines graph
  definitions, exact obligations, expansion, and typed artifact identity.
- [Proof Protocol](specs/proof-protocol.md) defines canonical proof semantics,
  identities, artifact admission, authenticated state, and blocks.
- [Proof Authoring](specs/proof-authoring.md) defines `.nao` source and its
  non-authoritative compilation boundary.
- [Artifact Chain Journal](specs/artifact-chain-journal.md) defines durable
  selected state, strict mixed replay, recovery, and poisoning.
- [Artifact Block Candidate Store](specs/artifact-block-candidate-store.md)
  defines structural block retention without execution or selection.
- [Canonical Artifact Payload Store](specs/canonical-artifact-payload-store.md)
  defines the separate Foundation-scoped byte archive.
- [Artifact Network Transport](specs/artifact-network-transport.md) defines
  artifact, block, head, and announcement messages and bounded transport.
- [Caller-Selected Orchestration](specs/caller-selected-orchestration.md)
  defines survey, broadcast, direct import, ancestry, and catch-up.
- [Peer Addressing](specs/peer-addressing.md) defines signed peer records,
  address persistence, issuance, and authenticated exchange.

Specifications are normative for mathematical, source, codec, storage, and wire
semantics. Rustdoc owns exact Rust APIs; crates are executable references. This
README is non-normative.

The repository is prerelease. The `single-artifact-v0` chain, journal, archive,
and network formats replace their proof-only predecessors cleanly. There is no
legacy decoder or local migration; old local data must be recreated. Existing
primitive proof bytes and `ProofId`, `DerivationId`, and `StatementId` values
remain unchanged.

## Local validation

The Rust toolchain is pinned in `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked --no-fail-fast
```

## License

[MIT](LICENSE)
