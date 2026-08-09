# NAOME Ledger State V0

## Status and scope

This document defines the deterministic in-memory transition from one accepted
NAOME proof state to the next. It is a prerelease protocol contract and may
change before the first stable protocol release.

One transition processes exactly one Foundation V0 proof certificate. Ledger
V0 provides both an owned-certificate authoring path and a strict canonical
proof-byte admission path. It does not define a block envelope, block
identifier, persistence, undo, reorganization, pruning, rewards, fees,
networking, or human-readable source syntax.

## State

Ledger State V0 owns one checked `ProofStateV0`. That state contains:

- one `ProofId -> DerivationId` entry for every accepted concrete proof;
- one `DerivationId -> StatementId` entry for every accepted inference DAG;
- one canonical closed conclusion for every accepted `StatementId`; and
- the canonical conclusion length required by deterministic reference-work
  accounting.

Only a successfully checked proof may add entries. Existing entries are never
replaced. Identity conflicts fail closed.

## Single-proof transition

Given one structurally valid `ProofCertificateV0` and the accepted
pre-transition state, Ledger V0 applies this order:

1. derive the certificate's canonical root-proof normal form;
2. mathematically check that normal form exactly once while resolving every
   reachable `ProofReference` exclusively from the unchanged pre-transition
   state;
3. compute its `StatementId`, `DerivationId`, and `ProofId` as specified by
   Proof Certificate V0;
4. register the checked proof without replacing any existing state; and
5. return an immutable accepted-proof record containing the canonical proof
   payload, its direct proof dependencies, and the three identities.

The candidate proof is not visible during step 2. A reference succeeds if and
only if its exact `ProofId` is present in the unchanged pre-transition state.

The existing Proof Certificate V0 limits bound the only proof processed by a
transition. Ledger V0 adds no batch or caller-configurable resource limit.

## Strict canonical byte admission

The strict byte entry point processes external proof-certificate bytes in this
order:

1. structurally decode exactly one complete V0 certificate from its canonical
   wire encoding;
2. derive its canonical root-proof normal form;
3. require the submitted bytes to equal the encoded normal form exactly;
4. retain the submitted bytes as the normal-form payload only after that
   exact equality has been established;
5. mathematically check that normal form exactly once against the unchanged
   pre-transition state; and
6. atomically register the checked proof through the same state transition
   described above.

Structural decoding errors precede canonicality, checking, and registration
errors. A structurally valid mismatch returns `NonCanonicalProof` before any
mathematical step or external proof reference is evaluated. Checker errors then
precede state-registration errors. Every failure leaves the state unchanged.

The owned-certificate authoring path continues to normalize its input before
checking. It must not be used as a substitute for the strict external-byte
boundary.

## Accepted proof record

Every successful transition returns one `AcceptedProofRecordV0`. Its intrinsic
proof content consists of:

- the exact canonical root-proof-normal-form certificate bytes;
- the checked `ProofId`, `DerivationId`, and `StatementId`; and
- every directly cited `ProofId`, exactly once, in canonical normal-form step
  order.

Direct dependencies are derived only from root-reachable `ProofReference`
leaves in the checked normal form. They do not include local inference-step
indices or transitive dependencies. Exact duplicate reference leaves have
already been interned by normalization. The dependency order is deterministic
but has no additional priority or execution meaning.

Because every direct dependency must already belong to the unchanged
pre-transition state, records accepted through any valid transition sequence
form an acyclic proof-dependency graph. This graph describes mathematical
proof reuse only. It does not define consensus order, fork choice, snapshot
selection, or the topology of a future block protocol.

The record has no public constructor, and neither its bytes nor dependencies
are mutable. It is a transition result and proof-payload record, not a block
envelope, proof-state snapshot, persistence format, or evidence of consensus
inclusion. Replaying or importing its bytes must execute strict canonical byte
admission again; the redundant identities and dependency index must be derived
again rather than trusted.

## Atomicity and errors

Normalization and mathematical checking do not mutate the pre-transition state.
Registration validates every proof, dependency, derivation, and statement
identity condition before inserting anything. Consequently, every error leaves
the state exactly unchanged and a successful call inserts exactly one checked
proof.

The strict byte path follows the decode, canonicality, checking, and
registration order specified above. The authoring path follows normalization,
checking, and registration. Within checking and registration, the deterministic
error order defined by Proof Certificate V0 remains unchanged. Ledger errors
retain the complete underlying source error when one exists.

## Future block boundary

A future `BlockV0` contains exactly one proof. It must validate that proof
against an immutable accepted proof-state snapshot selected by the future
consensus protocol. A proof merely received from the network, or otherwise
absent from that selected state, is unavailable to resolve a reference.

The consensus topology and the rule that selects or combines accepted
proof-state snapshots remain outside this V0 contract. This includes whether
proof blocks form a linear history or a DAG; either choice remains separate
from the already-defined acyclic proof-dependency graph.

Whether a `StatementId` is new to a consensus-selected state is future block
policy. It is not intrinsic proof content and is therefore absent from the
accepted proof record.

The future block validation transition must pass its single submitted proof
payload through the strict canonical byte admission defined above. Ledger V0
still does not define the surrounding block bytes, and the strict path never
silently repairs the submitted proof payload.
