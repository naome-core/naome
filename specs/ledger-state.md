# NAOME Ledger State

## Status and scope

This document defines the deterministic in-memory transition from one accepted
NAOME proof state to the next. It is a prerelease protocol contract and may
change before the first stable protocol release.

One transition processes exactly one Foundation proof certificate. The ledger
provides an owned-certificate authoring path, a strict canonical proof-byte
admission path, and an addressed strict path that additionally requires the
checked proof to have one caller-supplied expected `ProofId`. It does not define
a block envelope, block identifier, persistence, undo, reorganization, pruning,
rewards, fees, networking, or human-readable source syntax.

## State

Ledger State owns one checked `ProofState`. That state contains:

- one `ProofId -> DerivationId` entry for every accepted concrete proof;
- one `DerivationId -> StatementId` entry for every accepted inference DAG;
- one canonical closed conclusion for every accepted `StatementId`; and
- the canonical conclusion length required by deterministic reference-work
  accounting.

Only a successfully checked proof may add entries. Existing entries are never
replaced. Identity conflicts fail closed.

## Single-proof transition

Given one structurally valid `ProofCertificate` and the accepted
pre-transition state, Ledger applies this order:

1. derive the certificate's canonical root-proof normal form;
2. mathematically check that normal form exactly once while resolving every
   reachable `ProofReference` exclusively from the unchanged pre-transition
   state;
3. compute its `StatementId`, `DerivationId`, and `ProofId` as specified by
   Proof Certificate;
4. for addressed admission, require that checked `ProofId` to equal the
   caller-supplied expected `ProofId`;
5. register the checked proof without replacing any existing state; and
6. return an immutable accepted-proof record containing the canonical proof
   payload, its direct proof dependencies, and the three identities.

The candidate proof is not visible during step 2. A reference succeeds if and
only if its exact `ProofId` is present in the unchanged pre-transition state.

The existing Proof Certificate limits bound the only proof processed by a
transition. Ledger adds no batch or caller-configurable resource limit.

## Strict canonical byte admission

The strict byte entry point processes external proof-certificate bytes in this
order:

1. structurally decode exactly one complete certificate from its canonical
   wire encoding;
2. derive its canonical root-proof normal form;
3. require the submitted bytes to equal the encoded normal form exactly;
4. retain the submitted bytes as the normal-form payload only after that
   exact equality has been established;
5. mathematically check that normal form exactly once against the unchanged
   pre-transition state; and
6. for addressed admission, compare the checked `ProofId` with the expected
   content address; and
7. atomically register the checked proof through the same state transition
   described above.

Structural decoding errors precede canonicality, checking, and registration
errors. A structurally valid representation that differs from its canonical
root-proof normal form returns `NonCanonicalProof` before any mathematical step
or external proof reference is evaluated. Checker errors then precede
`ProofIdMismatch`, which precedes state-registration errors. The identity
mismatch reports both the expected and checked identities. Every failure leaves
the state unchanged.

The expected identity is request context rather than proof content. It is
compared with the `ProofId` derived from the fully checked normal form, never
with a raw hash or caller-supplied identity field, and is not retained in the
accepted record. The unaddressed strict entry point binds no external request
address. Bytes received for a specific requested `ProofId` must use addressed
admission. This binding does not prove peer authenticity, freshness, consensus
selection, or statement novelty.

The owned-certificate authoring path continues to normalize its input before
checking. It must not be used as a substitute for the strict external-byte
boundary.

## Accepted proof record

Every successful transition returns one `AcceptedProofRecord`. Its intrinsic
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

## Retained proof DAG

`ProofDag` owns one `LedgerState` and retains every record returned by its
strict canonical-byte admission in the authenticated set defined by
Authenticated Proof Set. A retained proof is addressed directly by its checked
`ProofId`; it adds no redundant `BlockId`, wrapper encoding, height, or linear
proof-parent field. The canonical proof-certificate bytes are the node payload,
and the record's direct `ProofId` dependencies are its outgoing DAG edges.

The authenticated set directly owns the retained records and provides lookup,
an insertion-order-independent `ProofSetRoot`, and compact membership and
non-membership proofs. It replaces a separate record map rather than adding a
second index that could diverge. The root binds the exact selected `ProofId`
set, not statement novelty, consensus selection, or finality.

The checked ledger and authenticated proof set are private and advance together.
Callers cannot insert records, identities, or dependency edges directly. A
failed decode, canonicality check, mathematical check, expected-identity check,
dependency lookup, or registration leaves both structures unchanged. A
successful admission moves the returned record into the authenticated set
without copying its proof payload.

Every dependency must already belong to the unchanged selected state before a
node is admitted. Starting from an empty state, this dependency-first rule
proves inductively that retained edges are acyclic. Admission creates no
implicit relationship between nodes that do not cite one another. Internal
retention order has no causal or consensus meaning.

Replay means submitting retained canonical proof bytes to a fresh `ProofDag`
in dependency-first order. Records are revalidated rather than imported as
trusted metadata. Out-of-order input fails on its first missing dependency and
may be retried after that dependency is admitted.

This selected proof state is not an order-free mergeable CRDT. Separate states
may accept different proof artifacts with one `DerivationId`; replaying their
union accepts the first artifact and rejects the later derivation duplicate.
Fork selection, state merging, and finality therefore remain consensus policy.

## Atomicity and errors

Normalization and mathematical checking do not mutate the pre-transition state.
Registration validates every proof, dependency, derivation, and statement
identity condition before inserting anything. Consequently, every error leaves
the state, retained record tree, and `ProofSetRoot` exactly unchanged and a
successful call inserts exactly one checked proof.

The strict byte path follows the decode, canonicality, checking, optional
expected-identity comparison, and registration order specified above. The
authoring path follows normalization, checking, and registration. Within
checking and registration, the deterministic error order defined by Proof
Certificate remains unchanged. Ledger errors retain the complete underlying
source error when one exists.

## Future consensus boundary

One proof-DAG node contains exactly one canonical proof. The mathematical proof
graph is fixed by checked `ProofReference` edges and has no global linear
parent. A proof merely received from the network, or otherwise absent from the
selected state, is unavailable to resolve a reference.

The consensus topology and the rule that selects or combines accepted
proof-state snapshots remain outside this contract. A future linear economic
or settlement history is separate from the already-defined acyclic proof DAG.

Whether a `StatementId` is new to a consensus-selected state is future block
policy. It is not intrinsic proof content and is therefore absent from the
accepted proof record.

This ledger-state contract does not define snapshots, external checkpoint
distribution, fork choice, finality, rewards, fees, producer authentication,
or networking. Authenticated Proof Set defines the selected proof-set
commitment. The separate Proof DAG Journal contract defines local
crash-consistent replay storage and exact expected-root verification for one
selected `ProofDag`.
