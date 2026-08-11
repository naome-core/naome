# NAOME Proof Block

## Status and scope

This document defines the canonical linear block commitment for selected NAOME
proof state and its in-memory exact-head application. It is a prerelease
protocol contract and may change before the first stable protocol release.

A `ProofBlock` binds exactly:

- one parent `ProofBlockId`; and
- one complete canonical [`ProofTransition`](proof-state-transition.md).

The configured `ProofChainId` derives a virtual genesis parent for one
`ProofChainState`. Every admitted block must extend that state's exact current
head, and its transition must apply atomically to the state's privately owned
`ProofDag`.

This is linear block structure, not consensus. Block construction, decoding,
or local application does not establish that any peer, validator, or network
selected the block. This contract defines no competing-fork storage, fork
choice, reorganization, voting, finality, proposer, signature, proof of work,
proof of stake, persistence, networking, discovery, or economy.

## Chain context and virtual genesis

A `ProofChainId` is exactly 32 caller-configured bytes. The chain identifier is
context and domain separation. It does not authenticate an operator, select a
network, establish a canonical genesis configuration, authorize a block, or
prove consensus membership.

An empty `ProofChainState` derives its initial head as:

```text
virtual_genesis_parent = SHA256(
    "naome:proof-chain-genesis\0"
    || proof_chain_id[32]
)
```

The exact genesis-domain bytes in hexadecimal are:

```text
6e616f6d653a70726f6f662d636861696e2d67656e6573697300
```

For a `ProofChainId` containing 32 bytes of `11`, the virtual genesis parent is:

```text
f47ee4acce1f5797ff773e7b620cfc66b101dfadb0b87cb4f83e3b94765c8b98
```

The virtual genesis parent is an anchor, not an admitted `ProofBlock`. It has
no transition, payload, height, stored block record, or independently
selectable state. The first admitted block names this anchor as its ordinary
parent. Every later block names the exact `ProofBlockId` of its admitted
predecessor.

`ProofChainId` is deliberately not repeated in every canonical block. A
standalone block is therefore not self-labeling: its intended chain cannot be
known from its bytes alone. Chain context is established by an externally
configured `ProofChainId` and an unbroken parent ancestry to that identifier's
virtual genesis anchor. Reusing the same ancestry under two distinct configured
chain identifiers fails at the first exact-head comparison unless the virtual
genesis or a subsequent block identity collides.

## Canonical value

A `ProofBlock` contains exactly these fields:

```text
parent_block_id: ProofBlockId
transition:      ProofTransition
```

The transition retains its exact ordered `ProofId` list, previous
`ProofSetRoot`, and resulting `ProofSetRoot`. The block adds only linear parent
context. It does not duplicate the chain identifier, transition identity,
proof count, state roots, or proof identities.

Construction validates no proof payload and establishes no state change. A
constructed or decoded block becomes locally admitted only after exact-head
validation and successful transition application.

## Canonical encoding

One block has this encoding:

```text
Block = parent_block_id[32]
     || canonical_proof_transition[97..321]
```

No version, tag, chain identifier, height, timestamp, transition length,
padding, or checksum is encoded. The parent is always present. The complete
input-slice boundary delimits the block, while the transition's own validated
count determines its exact internal length.

Because a transition contains one through eight proof identities, a canonical
block is 129 through 353 bytes.

`ProofBlock::from_canonical_bytes` reports malformed input through
`ProofBlockDecodeError`. Decoding is strict and executes this order:

1. reject input longer than 353 bytes as `InputTooLong` before allocating for
   transition proof identities;
2. require the complete 32-byte parent, returning `UnexpectedEnd` if it is
   incomplete;
3. decode the complete remaining slice with the canonical `ProofTransition`
   decoder, preserving its validation order and error source in
   `Transition { source }`; and
4. reject the block if the transition decoder rejects truncation, an invalid
   count, trailing bytes, or duplicate proof identities.

The decoder consumes the complete input and returns no partially decoded
block. Encoding a decoded value reproduces its accepted bytes exactly.

## Block identity

Every block identity is SHA-256 over the exact block domain, including its
trailing NUL, followed by the complete canonical block bytes:

```text
ProofBlockId = SHA256(
    "naome:proof-block\0"
    || canonical_block_bytes
)
```

The exact block-domain bytes in hexadecimal are:

```text
6e616f6d653a70726f6f662d626c6f636b00
```

For the `11` chain identifier's virtual genesis parent above and the transition
golden from the Proof-State Transition contract—previous root `11`, resulting
root `22`, count `02`, then proof IDs `33` and `44`—the 161-byte block ID is:

```text
9b1dbade5300bbb36e1b126226dc940395d7ccd742a2bd7a8d6f7cbb9543237f
```

Changing the parent or any canonical transition byte changes the block
identity under SHA-256 collision resistance. The parent recursively commits a
block to its claimed ancestry; successful exact-head application establishes
that ancestry only within the local `ProofChainState`. Block identity does not
prove that the ancestry is available, valid, selected, or finalized.

## Local preparation

`ProofChainState` is initialized from a configured `ProofChainId`, with an
empty private `ProofDag` and the derived virtual genesis parent as its current
head. The chain identifier need not remain duplicated in state after deriving
that head. The state does not accept an arbitrary pre-populated DAG or
caller-selected initial head.

Local preparation takes one ordered list of one through eight `ProofId` values:

1. prepare a `ProofTransition` from the privately owned DAG, preserving the
   existing read-only root projection and validation rules; and
2. construct a block whose parent is the state's exact current head.

Preparation performs no proof checking, block admission, head advancement, or
state mutation. Multiple siblings may be prepared from the same head, but the
linear state can admit at most one of them before its head changes.

## Exact-head atomic application

Application accepts one `ProofBlock` and a separate owned ordered list of
`AddressedProofCandidate` payloads. It executes in this order:

1. require the block's `parent_block_id` to equal the chain state's exact
   current head, before inspecting candidates;
2. compute the block's `ProofBlockId` before state mutation;
3. invoke the existing atomic `ProofDag::apply_proof_transition` exactly once
   with the block's transition and the supplied candidates; and
4. only after transition success, replace the current head with the already
   computed block identity through an infallible assignment.

The delegated transition remains solely responsible for current-root binding,
exact candidate count and ordered identity correlation, read-only resulting-
root projection, strict proof decoding, canonicality, mathematical checking,
dependency resolution, root closure, and atomic proof-state mutation. The
block layer must not duplicate, weaken, reorder, retry, or partially apply
those checks.

Parent mismatch precedes every transition or candidate error. Transition
errors retain their existing precedence and source without reclassification.
`ProofBlockApplyError` reports these cases as `ParentBlockIdMismatch` and
`Transition { source }`, respectively. No fallible operation may occur after
proof-state mutation commits.

Every failure leaves all chain state unchanged, including:

- the current head;
- proof, derivation, and statement registries;
- retained accepted proof records and `ProofDag::len`;
- authenticated-set topology and `ProofSetRoot`; and
- all pre-existing membership and non-membership witnesses.

A successful application admits every transition proof exactly once, leaves
the DAG at the transition's resulting root, and advances the head exactly once
to the applied block identity.

The state exposes its `ProofDag` only immutably. Callers cannot bypass block
parentage by directly mutating the owned selected proof state.

## Replay and fork boundary

After a block succeeds, replaying it immediately fails at the parent comparison
because the current head is now that block's identity rather than its parent.
A prepared sibling with the same old parent fails for the same reason. Both
failures occur before candidate proof work and preserve the selected block.

This exact-head rule implements one append-only local line. It is not a fork
choice rule. The state does not retain competing branches, choose among valid
siblings, roll back proofs, reorganize history, or establish network-wide
ordering. Selecting which eligible child to attempt is a higher-level policy.

## Payload and availability boundary

Canonical block bytes contain the transition commitment but not proof
certificate payloads. Application receives separately supplied addressed
candidates and correlates them through the transition's exact ordered
`ProofId` values. This preserves the existing strict proof admission boundary
without duplicating up to eight independently bounded certificates inside the
block commitment.

Possessing a block does not establish possession or availability of its proof
payloads. This contract defines no block-body transport, proof fetching,
announcement, gossip, erasure coding, availability sampling, source
attribution, or timeout policy.

## Resource and performance boundary

A block adds exactly 32 parent bytes to a 97-to-321-byte transition and is
therefore at most 353 bytes. Decode allocation is inherited from the bounded
transition decoder and holds at most eight proof identities. Block identity
hashing processes the parent and transition directly and need not allocate a
second canonical block buffer.

Exact-head validation and head advancement are constant-size operations.
Preparation and application reuse the existing bounded transition projection,
candidate correlation, and rooted proof-batch path. They must not clone, scan,
or rebuild the complete selected proof set or decode and check a candidate more
than once.

Candidate certificate bytes and mathematical work remain subject to the
independent Proof Certificate and Ledger State limits. The block boundary does
not aggregate around or raise those limits.

## Security boundary

Virtual genesis, block identity, parent ancestry, and transition commitments
rely on SHA-256 collision and second-preimage resistance. Distinct hash domains
separate virtual genesis anchors from admitted block identities. Exact parent
matching prevents local replay and sibling application after one head has
advanced. Transition roots bind the selected proof set before and after the
block, while strict addressed admission prevents proof substitution,
permutation, invalid-proof admission, and unrelated-proof smuggling.

The configured chain identifier is not a secret or authentication key. A
remote party can calculate the same virtual genesis anchor. Neither chain
context, a valid ancestry, a block identity, nor successful local application
authenticates a proposer, proves availability, establishes consensus, measures
novelty, or assigns economic value.

## Explicit exclusions

This contract defines no chain-identifier discovery or trust policy, admitted
genesis block, height, timestamp, proposer, signature, proof of work, proof of
stake, validator set, voting, quorum, competing-fork storage, fork choice,
rollback, reorganization, finality, checkpoint trust, persistent block journal,
snapshot, pruning, payload transport, data-availability protocol, block or
proof gossip, peer discovery, peer authorization, rewards, fees, balances,
novelty policy, issuance, or settlement.
