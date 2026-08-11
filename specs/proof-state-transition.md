# NAOME Proof-State Transition

## Status and scope

This document defines the canonical commitment to one bounded change of the
selected NAOME proof state and its atomic application to one exact
`ProofDag`. It is a prerelease protocol contract and may change before the
first stable protocol release.

A `ProofTransition` binds:

- the exact `ProofSetRoot` before application;
- the exact `ProofSetRoot` after successful application; and
- the exact ordered `ProofId` values of one dependency-closed rooted proof
  transaction.

The transition is consensus-neutral. It is not by itself a block, header, vote,
checkpoint, receipt, or claim that any peer has selected or stored the
committed state. The separate [Proof Block](proof-block.md) contract binds one
complete transition to exact linear parent context without changing this
transition's bytes or admission rules. This contract itself defines no parent
block, height, timestamp, chain identifier, proposer, signature, proof of work,
fork choice, finality, network message, persistence format, reward, fee,
balance, or settlement.
The separate [Proof Chain Journal](proof-chain-journal.md) persists a transition
only as part of one exact-parent block together with the transition's ordered
proof payloads.

## Canonical value

A `ProofTransition` contains exactly these fields:

```text
previous_proof_set_root:  ProofSetRoot
resulting_proof_set_root: ProofSetRoot
proof_ids:                1..=8 ProofId values
```

Every `ProofId` in `proof_ids` must be unique. The supplied order is semantic:
it is the dependency-first order consumed by rooted proof admission, and the
final `ProofId` is the transaction root. The transition codec does not inspect
proof certificates and therefore cannot itself prove dependency order or root
closure; atomic rooted admission validates both from the checked proofs.

Implementations must preserve the supplied order. They must not sort,
deduplicate, retry, or otherwise normalize the list. Two different valid
topological presentations are different transition values with different
canonical bytes, even if they result in the same authenticated set root. Under
the transition identity's collision-resistance assumption, they also have
different `ProofTransitionId` values.

## Canonical encoding

One transition has this fixed-field, count-delimited encoding:

```text
Transition = previous_proof_set_root[32]
          || resulting_proof_set_root[32]
          || proof_count_u8
          || proof_ids[proof_count][32]
```

The count is an unsigned one-byte integer and must be in `1..=8`. No version,
tag, length prefix, padding, or checksum is encoded. The complete input-slice
boundary delimits the transition.

The exact encoded length is:

```text
65 + 32 * proof_count bytes
```

It is therefore 97 bytes for one proof and at most 321 bytes for eight proofs.

Decoding is strict and executes this order:

1. reject input longer than 321 bytes before allocating for proof IDs;
2. decode both complete roots and the count, returning an unexpected-end error
   if any of those 65 bytes is absent;
3. reject count zero;
4. reject a count greater than eight;
5. decode exactly the declared number of complete 32-byte `ProofId` values,
   returning an unexpected-end error at the first incomplete value;
6. reject any trailing byte after the declared values; and
7. reject the first duplicate `ProofId` in supplied order.

The decoder must consume the complete input and return no partially decoded
transition. Encoding a decoded value must reproduce its accepted bytes
exactly.

## Transition identity

Every transition identity is SHA-256 over the exact domain bytes, including
the trailing NUL, followed by the canonical transition encoding:

```text
ProofTransitionId = SHA256(
    "naome:proof-transition\0"
    || canonical_transition_bytes
)
```

The exact domain bytes in hexadecimal are:

```text
6e616f6d653a70726f6f662d7472616e736974696f6e00
```

For the transition whose previous root is 32 bytes of `11`, resulting root is
32 bytes of `22`, count is `02`, and ordered proof IDs are 32 bytes of `33`
followed by 32 bytes of `44`, the `ProofTransitionId` is:

```text
7588941422cb2102d8c03f6aa8c1fc2c683d579f67b7f96e22eabd5b68c50070
```

The identity commits to one exact proposed state change. It does not establish
consensus inclusion, finality, freshness, availability, authorship, or
economic value.

## Exact candidate correlation

Application accepts one transition and one owned list of
`AddressedProofCandidate` values. Before reading or checking any candidate
proof bytes, it must require:

1. the candidate count to equal the transition's proof-ID count; and
2. each candidate's immutable expected `ProofId` to equal the transition's
   `ProofId` at the same index.

The first ordered mismatch fails the complete application. Comparing an
unordered set, accepting a permutation, correlating only the final candidate,
or deriving the correlation from untrusted proof bytes is forbidden.

Candidate correlation binds the transition to the work requested from rooted
admission. It does not make a candidate valid. The existing addressed rooted
batch remains responsible for strict certificate decoding, canonicality,
mathematical checking, exact checked-ID comparison, dependency-first
resolution, state-registration conflicts, and root-closure enforcement.

## Read-only resulting-root projection

Before proof checking, application computes the `ProofSetRoot` that would
result from inserting the transition's one to eight `ProofId` values into the
current authenticated proof set. Projection is read-only: it must not mutate
the selected set, retained records, ledger state, or existing witnesses.

The projection must be semantically identical to inserting those exact keys
into the canonical authenticated set. It is bounded by the transition's eight
keys and their Patricia paths. It must not clone, scan, or rebuild the complete
selected set. A key already present projects idempotently; normal rooted proof
admission still rejects an attempt to admit an already selected proof.

The projected root must equal `resulting_proof_set_root`. A mismatch fails
before any certificate is decoded or mathematically checked. Projection
authenticates only the proposed exact key-set change; arbitrary 32-byte values
are not thereby accepted as proofs.

### Local preparation

A local preparation helper may take an ordered proof-ID list, bind the current
`ProofSetRoot` as the previous root, and fill the resulting root from the same
read-only projection. Preparation performs no proof checking or state mutation.
As an authoring convenience, it rejects the first proof ID that already belongs
to the selected set instead of constructing a transition that normal admission
must reject as a duplicate proof.

This convenience error belongs only to local preparation. Applying an already
constructed or decoded transition keeps authenticated-set projection
idempotent and preserves the application precedence below; the existing
rooted batch remains authoritative for duplicate-proof rejection.

## Atomic application

Application to a `ProofDag` is deterministic and executes in this order:

1. require the DAG's current `ProofSetRoot` to equal
   `previous_proof_set_root`, before inspecting candidates;
2. require exact candidate count correlation;
3. require exact ordered candidate-ID correlation, stopping at the first
   mismatch;
4. compute the read-only projected root and require it to equal
   `resulting_proof_set_root`; and
5. invoke the existing atomic addressed rooted-batch admission exactly once,
   using the final transition `ProofId` as `requested_root` and the exact
   correlated candidates in their supplied order.

A current-root mismatch takes precedence over every candidate error. Candidate
count mismatch precedes candidate-ID mismatch; candidate-ID mismatch precedes
resulting-root mismatch; and every transition preflight error precedes rooted
batch decoding or checking errors. A rooted-batch failure is returned without
being reclassified or retried.

The transition layer must not duplicate certificate decoding, mathematical
checking, dependency resolution, reachability, or ledger registration. After
the read-only preflight succeeds, the existing rooted batch is the sole state
mutation boundary. A successful application inserts every checked candidate
exactly once and leaves the DAG at `resulting_proof_set_root`.

Every failure leaves all selected state unchanged, including:

- proof, derivation, and statement registries;
- retained accepted proof records and `ProofDag::len`;
- authenticated-set topology and `ProofSetRoot`; and
- every pre-existing membership or non-membership witness.

No fallible transition check may occur after rooted admission commits. A
caller may retry after any ordinary error against the same unchanged DAG.

## Replay and context boundary

After successful application, replaying the same transition against that DAG
fails at the previous-root comparison before candidate proof work. This is
state-relative replay protection, not global replay protection: the same
transition may validly apply to another DAG that has the declared previous
root.

Roots and transition identities contain no chain position, time, network,
authority, or nonce. The separate [Proof Block](proof-block.md) contract binds
the complete canonical transition to one exact parent and configured linear
chain context without changing this transition's canonical bytes or
mathematical admission rules. That parent binding still establishes no time,
authority, consensus selection, or finality.

The [Proof Chain Journal](proof-chain-journal.md) reconstructs durable selected
state by decoding each stored block and applying its transition through this
same boundary. Journal replay derives expected candidate addresses from the
transition and never treats stored payload order as an independent state
transition.

## Resource boundary

The transition itself commits at most eight 32-byte proof identities and is
never larger than 321 bytes. Decode allocation is bounded by the validated
count. Candidate correlation and duplicate detection are bounded by eight
items. Resulting-root projection performs bounded Patricia-tree work for at
most eight keys and does not scale with the total number of selected proofs by
scanning or copying the set.

Candidate certificate bytes and mathematical work remain subject to the
independent limits in the Proof Certificate and Ledger State contracts. This
transition does not raise, aggregate around, or replace those limits.

## Security boundary

Transition identity and root commitments rely on SHA-256 collision and
second-preimage resistance. The previous root prevents applying the transition
to a different selected key set. Exact ordered candidate correlation prevents
substitution or permutation between a committed transition and the rooted
batch. Projecting the resulting root before mutation prevents a caller from
choosing the post-state commitment after proof work or partial application.
Existing rooted-batch checking prevents invalid-proof admission, forward
dependencies, duplicate identities, and unrelated-proof smuggling.

Neither the previous root nor the resulting root authenticates who selected
it. A transition and all candidate bytes supplied by one untrusted source
establish no provenance, freshness, availability, or consensus authority.

## Explicit exclusions

This transition contract defines no block or header format, block parent,
height, timestamp, chain identifier, proposer identity, signature, proof of
work, validator set, voting, fork choice, reorganization, rollback, finality,
checkpoint trust, data-availability protocol, proof fetching, network message,
peer discovery, source attribution, snapshot, reward, fee, balance, novelty
policy, or settlement. Exact linear parent binding is defined only by the
separate [Proof Block](proof-block.md) contract, and local durable replay only
by the separate [Proof Chain Journal](proof-chain-journal.md).
