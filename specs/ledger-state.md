# NAOME Ledger State

## Status and scope

This document defines deterministic in-memory transitions over the selected
NAOME proof state. It is a prerelease protocol contract and may change before
the first stable protocol release.

Ledger provides owned-certificate authoring, strict canonical-byte admission,
expected-address-bound single-proof admission, and bounded atomic rooted proof
transactions. It does not define source syntax, networking, persistence,
blocks, consensus, undo, reorganization, pruning, rewards, or fees.

## Selected state

`LedgerState` owns one checked `ProofState`. That state contains:

- one `ProofId -> DerivationId` entry for every accepted concrete proof;
- one `DerivationId -> StatementId` entry for every accepted inference DAG;
- one canonical closed conclusion for every accepted `StatementId`; and
- the canonical conclusion length required by deterministic reference-work
  accounting.

Only successfully checked proofs may add entries. Existing entries are never
replaced. Proof, derivation, and statement identity conflicts fail closed.

The state is monotonically growing but is not an order-free mergeable CRDT.
Separate states may select different exact proof artifacts for one
`DerivationId`; the first artifact already selected causes a later alternative
to fail as a duplicate derivation. Consensus selection and state merging remain
outside this contract.

## Single-proof transitions

### Owned-certificate authoring

The authoring path accepts one constructed `ProofCertificate` and:

1. derives its canonical root-proof normal form;
2. mathematically checks that normal form once against the unchanged selected
   state;
3. computes its `StatementId`, `DerivationId`, and `ProofId`;
4. registers the checked proof without replacing existing state; and
5. returns its accepted proof record.

The authoring path may normalize representation noise. It is not the external
byte-admission boundary.

### Strict canonical-byte admission

The strict path accepts one owned byte buffer and processes it in this order:

1. decode exactly one structurally valid complete proof certificate;
2. derive its canonical root-proof normal form;
3. require the submitted bytes to equal that normal form's encoding exactly;
4. mathematically check the normal form once against the unchanged selected
   state;
5. for addressed admission, require the checked `ProofId` to equal the
   immutable expected `ProofId`;
6. atomically register the checked proof; and
7. return its accepted proof record.

Structural decoding errors precede `NonCanonicalProof`. Canonicality errors
precede checker errors, checker errors precede `ProofIdMismatch`, and identity
mismatch precedes state-registration errors. The identity mismatch reports both
expected and actual checked IDs.

The expected ID is request context, not proof content. It is compared with the
identity derived from the fully checked normal form, never with a raw byte hash
or caller-supplied field, and is not retained in the accepted record.

The candidate is invisible while checking. Every external proof reference must
resolve from the unchanged selected state. Every error leaves all state
unchanged.

## Atomic rooted proof transactions

A proof transaction admits one bounded dependency closure all-or-none. Two
strict entry points share the same transition:

- the unaddressed path accepts canonical proof byte buffers, derives every
  actual `ProofId`, and is reserved for trusted local construction and journal
  replay; and
- the addressed path accepts one immutable `requested_root` plus
  `AddressedProofCandidate` values that pair each owned canonical byte buffer
  with its immutable expected `ProofId`.

Network-derived closures must use the addressed path. Raw peer-provided bytes
must not be routed through unaddressed admission.

### Bounds and shape

A transaction contains `1..=8` candidates. Each candidate independently
remains subject to the Proof Certificate byte, step, formula-node, and checker
work limits. The maximum implied candidate payload is eight certificates, or
`33_554_432` bytes; there is no caller-configurable batch limit.

The caller supplies dependency-first order. Ledger never sorts, retries,
deduplicates, or partially accepts candidates. In an addressed transaction:

- every expected `ProofId` is unique;
- the final candidate's expected ID equals `requested_root`; and
- the final candidate is the transaction root.

Shape preflight occurs before proof work in this order: reject an empty batch,
reject more than eight candidates, reject the first duplicate expected ID in
input order, then require the requested root to be final.

### Staged checking

After shape preflight, candidates are processed in input order. Candidate `i`
can resolve exact proof references from:

- the immutable selected state that existed before the transaction; and
- successfully checked candidates at indices below `i` in this transaction.

It cannot resolve itself or a later candidate. A missing or forward reference
therefore returns the ordinary checker `UnknownProofReference` at the current
candidate and proof step.

Each candidate follows the strict single-proof order:

1. decode;
2. verify canonical root-proof normal form;
3. mathematically check and derive its three identities;
4. when addressed, compare its actual and expected `ProofId`;
5. validate proof, dependency, derivation, and statement registration against
   the selected base plus earlier staged candidates; and
6. stage its accepted record without mutating selected state.

The error identifies the candidate index, retains its expected ID when one was
provided, and preserves the complete underlying `LedgerError` as its source.
The first candidate error stops processing and discards all staged state.

### Root closure and smuggling resistance

After every candidate succeeds individually, Ledger computes reachability from
the final actual `ProofId` over direct exact-`ProofId` dependencies in the
checked normal forms. Every candidate must be transitively reachable, including
through other candidates. Dependencies already present in selected state are
allowed but are not transaction candidates.

Reachability uses exact `ProofId`, never `StatementId`, `DerivationId`, an
expected address without a matching checked proof, or discarded presentation
steps. The first unreachable candidate in input order returns
`UnreachableCandidate` and discards the complete transaction. Consequently, a
valid unrelated proof cannot be bundled into selected state, even when all
individual proofs are mathematically valid.

The combination of dependency-first resolution and root closure also proves
that a successful transaction adds an acyclic, dependency-closed subgraph.

### Commit and atomicity

Checked candidates are held in a private overlay. The overlay resolves staged
proofs before the immutable base and stores only transaction-local proof,
derivation, and statement entries. It neither clones nor rebuilds the complete
selected state.

Only after candidate checking and root closure both succeed are staged entries
merged into `ProofState`. The corresponding accepted records are then moved
into the authenticated proof set. All insertion failure conditions were
validated while selected state was unchanged, so this final internal merge has
no recoverable failure path.

A successful transaction inserts every candidate exactly once. Any shape,
decode, canonicality, checker, expected-address, registration, or reachability
error leaves all of these unchanged:

- proof, derivation, and statement registries;
- retained records;
- `ProofDag::len`;
- the authenticated Patricia tree;
- `ProofSetRoot`; and
- membership and non-membership witnesses.

Input ownership is consumed by the call even when admission fails; atomicity
applies to selected state, not recovery of caller-owned buffers.

## Accepted proof records

Every successful candidate produces one immutable `AcceptedProofRecord` whose
intrinsic content is:

- the exact canonical root-proof-normal-form certificate bytes;
- its checked `ProofId`, `DerivationId`, and `StatementId`; and
- every directly cited `ProofId`, exactly once, in canonical normal-form step
  order.

Direct dependencies include only root-reachable `ProofReference` leaves. They
exclude transitive dependencies and local inference indices. Exact duplicate
reference leaves have already been interned by normalization.

The record has no public constructor and exposes no mutable bytes or dependency
list. Submitted owned bytes become the retained payload without an explicit
proof-sized clone after exact canonical equality is established. Storage may
compact the allocation while converting ownership; pointer identity is not a
protocol property.

Records are proof-DAG nodes, not block envelopes, state snapshots, consensus
receipts, or evidence of novelty. Replaying their bytes must perform strict
admission again; retained identities and dependency indexes are derived
metadata and are never trusted on import.

## Retained proof DAG and authenticated set

`ProofDag` privately owns one `LedgerState` and one
`AuthenticatedProofSet<AcceptedProofRecord>`. The authenticated set directly
owns records, so there is no second record map that can diverge.

Single-proof success inserts one record. Rooted-transaction success inserts all
records in supplied dependency-first order and returns the final root record.
The resulting `ProofSetRoot` binds the exact selected `ProofId` set and is
independent of insertion order or transaction grouping. Journal digest order
remains a separate local-recovery property.

Callers cannot insert unchecked bytes, identities, dependency edges, or
authenticated-set leaves directly. A successful in-memory transition does not
establish durability; the separate
[Proof DAG Journal](proof-dag-journal.md) defines atomic persistent proof
transactions and crash recovery.

The separate [Proof-State Transition](proof-state-transition.md) contract binds
one addressed rooted batch to exact before-and-after `ProofSetRoot` values. Its
current-root check, exact ordered candidate correlation, and read-only
resulting-root projection all occur before this contract's rooted admission.
It then delegates the exact correlated batch to
`apply_rooted_canonical_proof_batch` once. Ledger remains the sole authority for
certificate validity, dependency order, root closure, identity registration,
and atomic mutation; the transition layer neither duplicates nor weakens those
checks.

## Resource and performance boundary

Every candidate is decoded, canonicality-checked, and mathematically checked
once. The overlay retains at most eight candidates and performs lookups against
the selected base rather than cloning it. Committing staged registry entries is
bounded by transaction size and logarithmic selected-state lookup/insertion;
it must not scan or rebuild unrelated selected state.

Canonical payloads move from caller-owned buffers into accepted records.
Authenticated-set insertion hashes only proof identities. The journal streams
retained slices into one transaction body and digest rather than constructing a
second aggregate proof buffer.

These are implementation obligations, not permission to weaken deterministic
certificate or checker limits.

## Future consensus boundary

Mathematical checking decides whether a proof is valid. A successful local
transaction only adds a root-closed proof dependency subgraph to one selected
local state. It does not establish network availability, peer honesty,
statement novelty, consensus inclusion, finality, rewards, or economic
settlement.

The mathematical graph is fixed by exact checked `ProofReference` edges and has
no implicit linear parent. A future block or checkpoint protocol may commit a
canonical proof-state transition, but parentage and selection policy remain
separate from Ledger State and from the consensus-neutral transition contract.

## Explicit exclusions

This contract defines no automatic dependency fetching, quarantine, retry,
batch network message, unordered topological sort, partial success, dynamic
limit, public arbitrary proof resolver, generic rollback, deletion,
reorganization, snapshot, compaction, pruning, source syntax, networking,
block format, consensus, checkpoint trust, finality, rewards, fees, balances,
or settlement.
