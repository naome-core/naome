# NAOME

[![CI](https://github.com/naome-core/naome/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/naome-core/naome/actions/workflows/ci.yml)

NAOME is a protocol for a blockchain of machine-verifiable mathematics. One
fixed block selects exactly one typed artifact: either a checked proof or a
conservative mathematical definition. Deterministic checking decides
Foundation-relative validity. Future consensus may decide ordering, inclusion,
and provenance; it must not redefine mathematical truth.

Definitions let large proofs use ordinary mathematical vocabulary without
replacing it with primitive ZFC at every citation. Relations are eliminable
formula abbreviations. Functions are graph definitions backed by an exact
earlier selected total-and-unique existence statement; the particular proof is
not part of the function's identity. Standalone constants are deliberately not
definition artifacts. Proofs may use only dependencies selected by earlier
blocks in the same chain ancestry. Local files, archives, candidates, network
responses, the same block, and forward references never authorize resolution.

## Why NAOME

Mathematical results are easy to publish but difficult to verify, identify, and
reuse across independent systems. NAOME makes each checked theorem or
conservative definition a content-addressed artifact with deterministic
validation and explicit ancestry. It is intended for formal-mathematics tools,
researchers, and protocol builders that need independently reproducible results
rather than trust in a publisher or validator majority.

## Current status

The prerelease reference implementation provides:

- canonical proof, definition, and tagged-artifact codecs and identities;
- deterministic proof checking, exact checked-proof direct-dependency projection, and bounded conservative definition expansion;
- atomic mixed-artifact admission and an authenticated `ArtifactId` set;
- one exact-parent, fixed 128-byte artifact block per selected transition;
- caller-supplied numeric height-to-epoch projection, position-scoped immutable active-weight snapshots, and strict weighted quorum arithmetic;
- exact caller-supplied numeric artifact base-fee and non-artifact operation-fee floor qualification, conserved fee-partition, checked validator-pool aggregation, and equal citation-pool allocation arithmetic;
- exact ordinary Knowledge-Weight origin-batch conversion and 730-epoch decay arithmetic;
- exact caller-supplied citation-reward maturity-to-live-weight projection;
- exact caller-supplied numeric validator-bond floor and agreement-weight cap arithmetic;
- exact caller-supplied aggregate validator-pool share and signer-list allocation projections over an immutable active-weight snapshot;
- exact pairwise caller-supplied artifact-inclusion priority ordering by higher bid and then lower `ArtifactId`;
- crash-consistent mixed proof/definition journal replay;
- separate non-authoritative block-candidate and payload stores;
- bounded caller-selected static-peer exchange, ancestry, and catch-up; and
- a Python-shaped prerelease `.nao` authoring language.

Consensus messages and state transitions, fork choice, finality,
reorganization, incentives, and recursive definitions are not implemented.

The `canonical-definition-v1` chain, journal, archive, and network context
replaces the earlier prerelease artifact context cleanly. Old local data must be
recreated; existing primitive proof bytes and `ProofId`, `DerivationId`, and
`StatementId` values remain unchanged.

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

The end-to-end model is deliberately small:

1. Author one proof or definition in prerelease, source-first `.nao`.
2. Lower it to canonical bytes and check it deterministically against the
   Foundation and already selected dependencies.
3. Derive its typed content identity and admit exactly that artifact in one
   selected block.
4. Replay the selected chain to reconstruct the same checked artifact state.
5. Later definitions use its exact `DefinitionId`; later proofs cite its exact
   `ProofId` or use selected definitions by exact ID.

Compilation never fetches, selects, registers, or mutates artifacts. The
standalone CLI therefore accepts dependency-free sources; selected dependencies
require the immutable selected-state compiler adapter. See the compact
[definition-and-citation proof](examples/definitions-long-proof.nao), the real
[identity-function definition](examples/identity-function.nao) backed by its
independently checked total-and-unique existence theorem, and the large
[empty-set theorem](examples/empty-set-obligation.nao), which remains a proof
rather than a standalone constant artifact. Exact source grammar, output
fields, and diagnostics are specified in
[Proof Authoring](specs/proof-authoring.md).

## Architecture

Crates build in this direction:

```text
foundation -> proof -> checker -> ledger -> chain
                         |                  |-> storage -> network
                         |                  `-> naome   -> network
                         `-> authoring
storage -> authoring
consensus -> naome
economy   -> naome
```

The layers own, respectively: primitive ZFC syntax and rules; canonical proof,
definition, and artifact representations; deterministic checking; atomic
artifact admission; authenticated selected state and single-artifact blocks;
selected persistence plus non-authoritative archives; transport-neutral
messages; bounded libp2p transport and caller orchestration; and source
authoring.

The dependency-free consensus kernel currently owns caller-supplied numeric
height-to-epoch projection, position-scoped active agreement snapshots, and
strict weighted quorum arithmetic. Canonical height encoding, genesis and
finality authority, validator selection, signatures, messages, persistence,
and consensus state transitions remain later layers.

The dependency-free economy kernel currently owns numeric floor qualification
for caller-supplied artifact base-fee and non-artifact operation-fee atoms,
exact partitions of caller-supplied artifact and non-artifact fee atoms,
checked summation of caller-supplied partitions' validator pools, one-to-one
conversion of already-matured citation atoms into initial Knowledge Weight, and
exact 730-epoch origin-batch decay. Qualification proves only the respective
five-atom or one-atom comparison, while raw partition arithmetic remains
available for every amount. Pool aggregation establishes no input completeness,
provenance, or canonical count bound. Fee calculation, resource adequacy,
classification, payment authorization, balances, actual burn and credit,
reward eligibility and settlement, maturity, ownership, delegation, penalties,
height-farming safety, state transitions, and consensus use remain later
protocol work.

The root integration crate can order two caller-supplied artifact identities
and numeric inclusion bids by higher bid and then lower `ArtifactId`. This
pairwise ordering establishes no candidate validity or availability, bid
authorization or payment, proposer selection, inclusion, or state authority.

The root integration crate can project caller-supplied citation-reward atoms
from caller-supplied earning and evaluation epochs into current live Knowledge
Weight. It can also compare caller-supplied NAO atoms with the numeric
validator-bond floor and cap caller-supplied agreement weight at the exact
bond-backed limit. It can also project one active key's exact share of a
caller-supplied already-aggregated validator pool using the snapshot's unchanged
total weight, or project the same shares over a bounded caller-supplied signer
list with an exact unassigned arithmetic remainder. Citation-reward projection
neither consumes reward value nor returns, records, or persists an origin batch.
The share projections do not establish validator-pool provenance or
completeness, certificate inclusion or signer-list completeness, actual
unassigned-atom burn, entitlement, credit, claim, or settlement. These
integrations establish no reward earning, canonical maturation, beneficiary,
balance, escrow, registration, delegation, active-set, economic state, or
consensus authority.

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
  novelty, canonical graph meaning, exact function obligations, and typed
  artifact identity.
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

## Local validation

The Rust toolchain is pinned in `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked --no-fail-fast
```

## License

[MIT](LICENSE)
