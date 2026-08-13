# NAOME Caller-Selected Orchestration

## Authority and scope

This document defines six bounded workflows over a caller-driven
[`StaticProofNetwork`](proof-network-transport.md) and, where stated, one
selected [`ProofChainJournal`](proof-chain-journal.md):

- survey one exact chain context across explicit peers;
- broadcast one journal-head snapshot to explicit peers;
- import one exact direct-child block;
- retrieve one exact parent-linked ancestry;
- import a retrieved ancestry in forward order; or
- compose retrieval and import into one caller-selected catch-up.

The caller chooses every peer, recipient, and target. A peer-reported head is
an untrusted observation and never becomes a retrieval or import target without
a new caller decision. Peer authentication attributes transport data; it grants
no proposer, checkpoint, selection, consensus, finality, or economic authority.
Only strict journal application changes selected state.

These workflows add no wire protocol, connection, authorization, storage
format, runtime, or background task. The proof, block, head-pull, and
announcement transports retain their own framing, authentication, timeouts,
and resource limits.

Every in-progress workflow is non-cloneable. Its `accepts_event` predicate is
the routing guard: an event advances a workflow only when its exchange kind,
private request generation, expected authenticated peer, immutable request, and
network-instance identity match the exact pending ticket. An unrelated event
must be routed elsewhere before `on_event` consumes it.

## Head survey

### Caller-selected all-or-none start

A survey sends one immutable `ProofChainHeadRequest` to `1..=8` explicit,
unique, statically authorized peers. The request carries the exact
caller-selected `ProofChainId`; every peer receives that same request. The
workflow does not read a journal, compare a report with local selected state,
or derive a request from local state.

`start_chain_head_survey` performs every fallible preflight before queueing the
first request, in this order:

1. reject an empty peer set as `EmptyPeerSet`;
2. reject more than `MAX_STATIC_PEERS` entries as
   `TooManyPeers { actual, maximum }`;
3. reject the first repeated identity in caller order as
   `DuplicatePeer(peer_id)`;
4. preflight every peer in caller order for static authorization, absence of
   any pending outbound application request for that peer, managed-session
   connectivity, and head-pull-behaviour connectivity;
5. atomically reserve one shared application permit per peer, or return
   `InsufficientCapacity { requested, available, maximum }`; and
6. queue every request and install its tagged pending entry.

Shape checks perform no network work. The first failing peer yields
`RequestStart(UnknownPeer)`, `RequestStart(AlreadyPending)`, or
`RequestStart(PeerDisconnected)` under the existing request-start precedence.
Capacity shortage is reported only as `InsufficientCapacity`; it never
partially acquires permits and never becomes `RequestStartError::GlobalLimit`.

Before step 6, a failure leaves zero new requests, pending entries, or permits.
After atomic reservation, queueing is infallible under the existing libp2p
interface. A successful start therefore queues exactly the full
caller-selected set. All-or-none applies to start, not delivery: later
connectivity, negotiation, timeout, response, or transport failures are
independent per-peer results and do not cancel other peers.

The start error family is:

```text
EmptyPeerSet
TooManyPeers { actual, maximum }
DuplicatePeer(PeerId)
RequestStart(RequestStartError)
InsufficientCapacity { requested, available, maximum }
```

`RequestStart` preserves its typed cause. `available` is the permit count at
the atomic reservation attempt; `maximum` is `MAX_PENDING_REQUESTS`.

### Terminals, observations, and result order

The workflow retains one common request, one exact `ChainHeadRequestTicket` for
each pending peer, and one result slot for each completed peer. `peer_count`
never changes. `pending_peer_count` decreases once for each accepted terminal
and reaches zero only at completion.

An accepted found response becomes `Ok(Some(ProofBlockId))`; an accepted
unavailable response becomes `Ok(None)`. An accepted transport or peer-mismatch
failure becomes that peer's typed failure. Exact ticket correlation precedes
outcome extraction, and peer mismatch is decided before response or transport
interpretation. A failure is result data, not a workflow-wide error.
`AwaitingResponses` retains all remaining tickets; only the final accepted
terminal yields `Complete`.

The completed result stores the common `ProofChainHeadRequest` once and one
ordered row of `(PeerId, found-or-unavailable-or-failure)` per selected peer.
Rows retain caller input order regardless of terminal arrival order. Exact
ticket completion already binds every outcome to the common request, so rows do
not duplicate the request or authenticated response wrapper.

Every successful row is only a source-bound report from its authenticated
peer. `None` does not prove global unavailability. `Some(ProofBlockId)` does not
prove freshness, ancestry, retrievability, mathematical validity, selection,
finality, or authority. The survey neither groups equal heads nor computes a
majority, quorum, score, checkpoint, fork choice, retrieval target, import
target, consensus result, or economic result. Any later retrieval or import
requires a new caller decision.

An unrelated event passed to `on_event` returns
`ProofChainHeadSurveyEventMismatch` with the unchanged survey and complete
event; it does not inspect or discard the unrelated outcome. A second terminal
for a completed peer is not accepted.

### Survey limits and cancellation

Every request uses `/naome/proof-chain-head-exchange`. Its body is 32 bytes; a
response frame is one byte for unavailable or 33 bytes for a found head.

| Resource | Bound |
| --- | ---: |
| Peers | `1..=8`, unique |
| Requests and shared permits | `1..=8` |
| Aggregate request bodies | `32..=256` bytes |
| Aggregate successfully received response frames | `0..=264` bytes |
| Head-pull requests per selected peer | 1 |
| Head-pull streams opened per selected connection | 1 |
| Shared network application permits | 8 |
| Pending outbound application requests per peer | 1 |

Each physical request retains the existing protocol-negotiation and 30-second
negotiated request-response timeouts. The survey adds no aggregate deadline or
retry. Progress requires the caller to keep polling the network.

`cancel` and drop end only the logical survey. Physical requests retain their
peer slots and permits until their terminals arrive. Those later
`OutboundChainHead` events no longer belong to the workflow; the caller must
handle or drop them. A completed result owns no ticket, permit, request
identifier, network token, response channel, journal reference, or transport
response wrapper.

## Head broadcast

### Snapshot and all-or-none start

A broadcast sends one immutable `ProofChainHeadAnnouncement` to `1..=8`
explicit, unique, statically authorized peers. It reads the journal head once;
all peers receive the same `ProofChainId` and `ProofBlockId`, including the
deterministic virtual-genesis head of a healthy empty journal. Later journal
advancement does not change queued requests or results.

`start_chain_head_broadcast_from_journal` performs every fallible preflight
before queueing the first request, in this order:

1. reject an empty recipient set as `EmptyPeerSet`;
2. reject more than `MAX_PROOF_CHAIN_HEAD_BROADCAST_PEERS` entries as
   `TooManyPeers { actual, maximum }`;
3. reject the first repeated identity in caller order as
   `DuplicatePeer(peer_id)`;
4. read the healthy journal head once, preserving
   `ProofChainJournalError` as `Journal`;
5. copy the immutable chain identity and construct the common announcement;
6. preflight every peer in caller order for static authorization, absence of
   any pending outbound application request for that peer, managed-session
   connectivity, and announcement-behaviour connectivity;
7. atomically reserve one shared application permit per peer, or return
   `InsufficientCapacity { requested, available, maximum }`; and
8. queue every announcement and install its tagged pending entry.

Shape checks perform no journal or network work. Journal health precedes peer
preflight. The first failing peer yields `RequestStart(UnknownPeer)`,
`RequestStart(AlreadyPending)`, or `RequestStart(PeerDisconnected)` under the
existing request-start precedence. Capacity shortage is reported only as
`InsufficientCapacity`; it never partially acquires permits and never becomes
`RequestStartError::GlobalLimit`.

Before step 8, a failure leaves zero new requests, pending entries, or permits.
After atomic reservation, queueing is infallible under the existing libp2p
interface. A successful start therefore queues exactly the full caller-selected
set. All-or-none applies to start, not delivery: later connectivity,
negotiation, timeout, receipt, or transport failures are independent per-peer
results and do not cancel other recipients.

The start error family is:

```text
EmptyPeerSet
TooManyPeers { actual, maximum }
DuplicatePeer(PeerId)
Journal(ProofChainJournalError)
RequestStart(RequestStartError)
InsufficientCapacity { requested, available, maximum }
```

`Journal` and `RequestStart` preserve their typed causes. `available` is the
permit count at the atomic reservation attempt; `maximum` is
`MAX_PENDING_REQUESTS`.

### Terminals and result order

The workflow retains one common announcement, one exact
`HeadAnnouncementTicket` for each pending peer, and one result slot for each
completed peer. `peer_count` never changes. `pending_peer_count` decreases once
for each accepted terminal and reaches zero only at completion.

An accepted receipt becomes `Ok(())`. An accepted transport or peer-mismatch
failure becomes that peer's typed failure; peer mismatch is decided by the
ticket before receipt or transport interpretation. A failure is result data,
not a workflow-wide error. `AwaitingReceipts` retains all remaining tickets;
only the final accepted terminal yields `Complete`.

The completed result stores the common announcement once and one ordered row of
`(PeerId, success-or-failure)` per selected peer. Rows retain caller input order
regardless of terminal arrival order. Exact ticket completion already binds the
data-free receipt and common announcement, so rows do not duplicate either.
Success means only that the authenticated peer returned the exact receipt for
that request generation.

An unrelated event passed to `on_event` returns
`ProofChainHeadBroadcastEventMismatch` with the unchanged broadcast and complete
event; it does not inspect or discard the unrelated outcome. A second terminal
for a completed peer is not accepted.

### Broadcast limits and cancellation

Every request uses `/naome/proof-chain-head-announcement`. Its body is 64
bytes and a successful receipt is exactly one byte, `0x01`.

| Resource | Bound |
| --- | ---: |
| Recipients | `1..=8`, unique |
| Journal snapshots after shape preflight | 1 |
| Requests and shared permits | `1..=8` |
| Aggregate request bodies | `64..=512` bytes |
| Aggregate successful receipt bodies | `0..=8` bytes |
| Announcement streams per selected connection | 1 |
| Shared network application permits | 8 |
| Pending outbound application requests per peer | 1 |

Each physical request retains the existing protocol-negotiation and 30-second
negotiated request-response timeouts. Progress requires the caller to keep
polling the network.

`cancel` and drop end only the logical broadcast. Physical requests retain
their peer slots and permits until their terminals arrive. Those later
`OutboundChainHeadAnnouncement` events no longer belong to the workflow; the
caller must handle or drop them. A completed result owns no ticket, permit,
request identifier, network token, response channel, journal reference, or
receipt object.

## Direct-child block import

### State and start precedence

A direct import targets one immutable `ProofBlockId`, initially prefers one
caller-selected static peer, and has exactly one active phase: exact block
retrieval or bounded proof-dependency acquisition for that decoded block.

Proof-peer fallback may change the peer serving a dependency request but never
the target block, its contents, requested root, discovered addresses, deadline,
or request budget.

Starting performs these steps in order:

1. read the healthy journal head;
2. derive the chain's virtual-genesis anchor;
3. reject a target equal to either as `TargetAlreadySelected`;
4. query the committed exact-ID block index and reject a target already on the
   selected line; and
5. request the exact target from the caller's peer.

Journal failure is `SelectedState` and precedes network work. Request start
retains `UnknownPeer`, `AlreadyPending`, `PeerDisconnected`, then `GlobalLimit`
precedence inside `RequestStart`. Absence from the selected index does not imply
validity, availability, direct parentage, or network selection. The block
request uses `/naome/proof-block-exchange`, one per-peer slot, one private
generation, and the shared eight-permit budget; the importer does not retry the
block from another peer.

### Block phase

Only the exact accepted `OutboundBlock` terminal advances the block phase.
Processing order is:

1. reject a different phase, generation, peer, request, or network instance as
   `UnexpectedEvent` before extracting the outcome;
2. complete the ticket, preserving a correlated failure as
   `BlockRequestFailed`;
3. map a successful peer-local empty response to `BlockUnavailable`;
4. retain the strictly decoded block whose computed ID already matches the
   immutable target;
5. require its parent to equal the journal's current head;
6. require its previous `ProofSetRoot` to equal the current selected root;
7. call `ProofChainJournal::prepare_block` with its exact ordered `ProofId`
   values;
8. require its resulting root to equal the locally projected root; and
9. start dependency acquisition for the transition's final root proof,
   preferring the authenticated block peer.

Parent mismatch precedes previous-root comparison and all proof traffic.
Previous-root mismatch precedes local preparation. Preparation preserves the
journal's count, duplicate, already-selected, and authenticated-set projection
rules as `SelectedState`. Resulting-root mismatch follows successful
preparation. No block field is repaired, normalized, reordered, or replaced by
the locally prepared value. Preparation is read-only and does not select the
block.

### Proof phase and commit

The existing dependency acquisition remains authoritative for response
framing, canonical normal form, mathematical checking, reference discovery,
exact identities, cycle detection, fallback, request count, non-resetting
deadline, and cancellation.

For each accepted `OutboundProof` terminal, network-instance and authenticated
peer correlation precede a healthy-head read. A peer-mismatch terminal is
reported before selected-state drift. The journal head must still equal the
block parent before any other proof outcome is interpreted; otherwise
`ParentBlockIdMismatch` terminates the import and quarantined payloads are
dropped.

Completion immediately consumes the opaque `UnselectedProofClosure` through
its strict `apply_block` path. That sole mutation rechecks journal health and
parentage; correlates candidates into exact transition order; and preserves
previous-root, candidate-count, exact-identity, projected-root, canonical
decoding, mathematical checking, dependency order, root closure, registration,
and journal-commit validation. Only successful durable acknowledgement
completes the import. The committed ID is the original caller target.

The direct-import error classes are:

```text
SelectedState
TargetAlreadySelected
RequestStart
UnexpectedEvent
BlockRequestFailed
BlockUnavailable
ParentBlockIdMismatch
PreviousProofSetRootMismatch
ResultingProofSetRootMismatch
ProofAcquisition
```

At start, selected-state health and membership precede request preflight. In the
block phase, correlation precedes failure, which precedes unavailable and all
journal context checks; parent, previous root, preparation, and resulting root
then occur in that order. In the proof phase, correlation and peer mismatch
precede head drift, which precedes dependency-outcome interpretation. Strict
application retains its nested transition, ledger, and storage precedence.

Every ordinary error writes nothing and leaves selected state unchanged. An
ambiguous journal commit error may occur after successful in-memory application,
poison the journal, and leave either the old or new complete entry durable.
Drop and reopen is the only recovery path.

### Direct-import limits and cancellation

| Resource | Bound |
| --- | ---: |
| Caller-selected targets | 1 |
| Block requests | 1, 32-byte body |
| Found block response frame | at most 355 bytes |
| Retained decoded block | at most 353 canonical bytes and 8 proof IDs |
| Retained proof candidates | at most 8 |
| Proof requests | at most 15 |
| Block plus proof requests | at most 16 |
| Retained canonical proof payloads | at most 33,554,432 bytes |
| Shared network permits | 8 across the network |
| Pending proof or block request per peer | 1 |
| Durable entries on success | 1, at most 33,554,855 bytes |
| Journal synchronization barriers | 2 |

The block phase retains its existing request-response timeout. The proof phase
starts one non-resetting 120-second acquisition deadline only after block
preflight. Neither is a wall-time guarantee unless the caller keeps polling.

Cancelling during block retrieval does not cancel the physical request; its
peer slot and permit remain until a later `OutboundBlock` terminal. Cancelling
during proof acquisition immediately releases quarantined candidates and marks
the in-flight request for drain; its terminal releases the remaining slot and
permit through `ProofCancellationDrained`. Cancellation never commits a partial
closure or block.

## Ancestry pull

### Start and retained state

An ancestry pull retrieves a path from one exact caller-selected target back to
the current selected head from one caller-selected static peer. It retains the
captured head, captured root, virtual-genesis address, immutable target, up to
fifteen retrieved descendant blocks in reverse retrieval order, and exactly one
block ticket. It never fetches proof payloads or mutates the journal.

Starting performs these steps in order:

1. read and capture the healthy current head;
2. derive the virtual-genesis address;
3. reject a target equal to either as `TargetAlreadySelected`;
4. reject a target already in the committed exact-ID index;
5. read and capture the healthy current `ProofSetRoot`; and
6. request the exact target from the caller-selected peer.

Every journal failure is `SelectedState` and precedes network work. Request
start preserves `UnknownPeer`, `AlreadyPending`, `PeerDisconnected`, then
`GlobalLimit`. The same peer serves every request; there is no fallback.

### Sequential retrieval and ordering

Exactly one request is active. The first addresses the target; each subsequent
request addresses only the exact parent committed by the preceding matched
block. After a terminal, processing order is:

1. require exact event, request-generation, peer, request, and network-instance
   correlation, or return `UnexpectedEvent`;
2. preserve correlated transport, peer, decode, or identity failure as
   `BlockRequestFailed`;
3. map an empty response to `BlockUnavailable`;
4. require a healthy journal head equal to the captured anchor, or return
   `SelectedState` or `SelectedHeadChanged`;
5. when a descendant exists, require this parent's resulting root to equal that
   child's previous root;
6. when this block names the anchor as parent, require the captured root to
   equal its previous root and complete;
7. reject an already requested parent as `RepeatedBlockId`;
8. reject virtual genesis or a selected historical block reached before the
   anchor as `DivergentAncestry`;
9. if this is block sixteen and its parent is not the anchor, return
   `AncestryLimitExceeded` without a seventeenth request; and
10. otherwise request the exact parent from the same peer, then retain the
    current block.

Failure precedes unavailable; both precede selected-state health and drift.
Head stability precedes root continuity. Root continuity precedes anchor
completion, repetition, divergence, the limit, and a next request. Repetition
precedes divergence; divergence precedes the limit. A selected-state error from
historical-index lookup precedes `DivergentAncestry`.

For forward-adjacent blocks the required relation is:

```text
parent.transition.resulting_proof_set_root
    == child.transition.previous_proof_set_root
```

For the anchor's direct child it is:

```text
captured_selected_proof_set_root
    == child.transition.previous_proof_set_root
```

A mismatch is `TransitionRootMismatch` and identifies the predecessor, expected
root, and child's actual previous root. These checks establish only structural
continuity. They do not project a transition, retrieve or check proofs, or make
the ancestry selected.

Completion yields an opaque `UnselectedProofBlockAncestry` that binds the one
authenticated source peer, captured anchor, exact caller target, and `1..=16`
decoded blocks ordered from the anchor's direct child through the target. Every
parent identity and adjacent transition root is continuous. The result exposes
no proof payload and cannot itself mutate a journal. A later consumer must
revalidate against current selected state.

The ancestry-pull error classes are:

```text
SelectedState
TargetAlreadySelected
RequestStart
UnexpectedEvent
BlockRequestFailed
BlockUnavailable
SelectedHeadChanged
TransitionRootMismatch
DivergentAncestry
RepeatedBlockId
AncestryLimitExceeded
```

### Pull limits and cancellation

| Resource | Bound |
| --- | ---: |
| Targets and serving peers | 1 each |
| Active requests | 1 |
| Total requests and completed blocks | `1..=16` |
| Canonical bytes represented by a completed path | `129..=5,648` |
| Transition proof identities represented | `1..=128` |
| Permits attributable to the pull | at most 1 |
| Journal writes, new files, protocols, connections, or behaviours | 0 |

Each sequential request retains the existing negotiation and 30-second
request-response timeouts; the workflow adds no aggregate deadline. The prior
response permit is released before a next request starts. Parent discovery is
necessarily sequential. Completion reverses at most sixteen retained elements
in place into forward order.

Cancel or drop immediately releases retained decoded blocks but not the
physical request. Its peer slot and permit remain until a later `OutboundBlock`
terminal, which no longer belongs to the pull. Cancellation neither closes the
connection nor starts a replacement.

## Ancestry import

### Start and sequential application

An ancestry import consumes, without cloning or reconstructing, one opaque
`UnselectedProofBlockAncestry`. The value already binds `1..=16` forward-ordered
blocks, the immutable anchor and target, the authenticated ancestry source,
exact identities, parent links, repeated-address exclusion, and adjacent root
continuity.

Starting retains those values, takes the anchor's direct child, and runs the
same direct-child context preflight against the current journal: current parent,
previous root, local preparation, then resulting root. It then starts bounded
proof-dependency acquisition for that block's root proof, preferring the
ancestry source. It performs no block request, target substitution, journal
write, or state mutation. A start failure reports zero committed blocks, the
anchor as the last acknowledged head, the first block as failed, and the exact
nested direct-import error.

Only the exact `OutboundProof` terminal awaited by the current direct-child
import is accepted; ancestry import never accepts `OutboundBlock` because all
blocks are already decoded and identity-matched. The direct-child continuation
retains event, network-instance, peer, generation, parent, dependency,
application, and commit precedence.

At most one block's proof closure exists at a time. On successful durable
acknowledgement the importer:

1. increments the committed-prefix count;
2. records the committed block ID as the last acknowledged head;
3. drops the completed block and proof state;
4. completes if it was the caller target; otherwise
5. takes the next retained block, preflights it against the now-advanced
   journal, and starts its proof acquisition.

Block `n + 1` is neither preflighted nor requested until block `n` returns from
both journal synchronization barriers. Every block undergoes fresh current-state
preflight, canonical and mathematical proof checking, exact payload
correlation, and strict application against the complete acknowledged prefix.

### Committed-prefix failure semantics

Ancestry import is forward-only and atomic per block, not across the ancestry.
If block `n` fails after `n - 1` acknowledgements, blocks `1..n - 1` remain
selected and durable. `ProofBlockAncestryImportError` carries:

```text
committed_block_count
last_acknowledged_head_block_id
target_block_id
failed_block_id
block_import_error
```

For the first block, the count is zero and the acknowledged head is the anchor.
For a later block, metadata describes exactly the prefix acknowledged before
that block began. It does not classify an ambiguous failing commit as
acknowledged and need not equal the journal's head after independent caller
activity.

At every start boundary, parent precedes previous root, local preparation,
resulting root, and proof request start. During proof acquisition, exact event,
driver, and authenticated peer correlation precede head drift. Dependency
acquisition preserves deadline, response, canonicality, identity,
candidate-bound, cycle, and fallback precedence; strict application preserves
transition and storage precedence.

An ambiguous commit failure is terminal: the failing block may or may not be
durable, the journal is poisoned, and the importer must not guess, retry, or
start the next block. Reopen determines the old-or-new durable head. Every other
failure leaves the current block unselected without rolling back the already
acknowledged prefix. Retry requires a new caller decision and a new ancestry
pull anchored to the observed journal head.

### Ancestry-import limits and cancellation

| Resource | Bound |
| --- | ---: |
| Retained blocks | `1..=16` |
| Block requests during import | 0 |
| Active block proof acquisitions | 1 |
| Proof candidates retained at once | at most 8 |
| Proof requests per block | at most 15 |
| Proof requests per complete ancestry | at most 240 |
| Canonical proof payloads retained at once | at most 33,554,432 bytes |
| Shared network permits | 8 across the network |
| Pending proof request per peer | 1 |
| Durable entries on success | `1..=16` |
| Synchronization barriers per block / complete ancestry | 2 / `2..=32` |

Each block receives an independent non-resetting 120-second dependency deadline
because its acquisition starts only after the preceding durable
acknowledgement. There is no ancestry-wide wall-time guarantee without continued
polling.

Cancel drops the current direct-child acquisition. Its guard releases
quarantined candidates and marks the in-flight proof request for drain; the
physical terminal retains its slot and permit until `ProofCancellationDrained`.
Cancellation never rolls back acknowledged blocks, applies a partial closure,
starts a later block, or refetches ancestry. Passing an unrelated event to
`on_event` consumes both values and returns current prefix metadata with nested
`UnexpectedEvent`; it does not reroute the event.

## Composed catch-up

`start_proof_block_catch_up` composes one ancestry pull and its consumed
ancestry import for the exact peer and target chosen by the caller. It delegates
first to `start_proof_block_ancestry_pull`, then consumes a completed ancestry
directly into `start_proof_block_ancestry_import`. The ancestry is never exposed
or reconstructed between phases. Catch-up adds no validation, mutation,
request, retry, or authority beyond the two contracts above.

`ProofBlockCatchUp` has exactly one active phase. During pull,
`committed_block_count` is zero and `last_acknowledged_head_block_id` is the
captured anchor. During import, both accessors delegate to the ancestry
importer's acknowledged-prefix state. `pending_block_id` is the exact block
being fetched during pull and the retained block whose proof closure is being
acquired during import. `pending_peer_id` is the one ancestry source during
pull; during import it is the current proof peer and may change only through
the existing bounded proof fallback. The anchor and caller target remain
immutable across both phases.

Each event is delegated unchanged to the active workflow. All correlation,
selected-state, validation, commit, and failure precedence remains exactly as
specified above; catch-up adds no cross-phase reclassification. The terminal
block response is fully interpreted before import starts, and a successful
handoff returns import progress without another block request. Pull and import
progress remain in their respective phases.
`ProofBlockCatchUpProgress = None` only after the exact target is durably
acknowledged.

The only catch-up error classes and their typed sources are:

| Class | Source |
| --- | --- |
| `AncestryPull` | `ProofBlockAncestryPullError` |
| `AncestryImport` | `ProofBlockAncestryImportError` |

Both preserve their typed source. `AncestryPull` carries no committed-prefix
metadata: pull is read-only, and catch-up has acknowledged zero blocks.
`AncestryImport` preserves the nested exact target, failed block, committed
count, last acknowledged head, and direct-import failure. The failing block,
including one with an ambiguous commit, is not added to that count. Earlier
acknowledged blocks remain durable; an ambiguous current commit poisons the
journal and requires reopen.

Catch-up has the combined sequential envelope of its two phases:

| Resource | Bound |
| --- | ---: |
| Block requests per complete catch-up | `1..=16` |
| Proof requests per complete catch-up | `1..=240` |
| Block plus proof requests per complete catch-up | at most 256 |
| Retained decoded blocks at once | `0..=16` |
| Proof candidates retained at once | at most 8 |
| Canonical proof payloads retained at once | at most 33,554,432 bytes |
| Simultaneous active work | one block request or one proof acquisition |
| Durable entries on success | `1..=16` |
| Synchronization barriers per block / complete catch-up | 2 / `2..=32` |

Block retrieval retains its existing protocol-negotiation and 30-second
request-response timeouts. Each block import receives its own existing
non-resetting 120-second dependency deadline. Catch-up adds no aggregate
deadline; all progress requires continued caller polling.

Cancel or drop delegates to the active phase. During pull it releases retained
blocks while the physical block request drains. During import it preserves the
acknowledged prefix, releases unprocessed blocks and quarantined payloads, and
retains the active proof request's existing drain semantics. Cancellation does
not advance phases, retry, select another target, or roll back a commit.

Catch-up performs no head query or survey, automatic target choice, automatic
retry or resume, multi-peer block fallback, ancestry-wide atomic rollback,
competing-history storage, reorganization, fork choice, consensus, finality,
or economic policy. It adds no protocol, storage format, connection,
authorization, runtime, or background task.

## Trust boundary

Exact content addresses, private generations, authenticated peers, and
network-instance correlation prevent one request or network from satisfying
another. Parent and root continuity prevent silent structural substitution.
Canonical decoding, mathematical checking, exact dependency resolution, and
strict journal application—not peer identity—decide admission.

Broadcast receipts do not establish storage, availability, freshness, quorum,
or agreement. A completed ancestry establishes neither proof validity nor
payload availability. Successful import establishes deterministic local
validity and durable local selection only. Discovery, automatic target choice,
automatic retry or synchronization, competing-history storage, reorganization,
fork choice, consensus, finality, and economic policy remain outside these
workflows.
