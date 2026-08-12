# NAOME Caller-Selected Proof Block Ancestry Pull

## Status and scope

This document defines one bounded, caller-driven pull of a parent-linked
[`ProofBlock`](proof-block.md) path from one exact caller-selected target back
to the current local selected head. It is a prerelease orchestration contract
and may change before the first stable protocol release.

The caller supplies both the exact target `ProofBlockId` and one statically
authorized peer. The pull sequences the existing
[Authenticated Proof Block Transport](authenticated-proof-block-transport.md)
one exact request at a time. It captures the healthy local journal's selected
head and proof-set root as an immutable anchor, follows each retrieved block's
exact parent address, and completes only when at most 16 retrieved blocks form
a root-continuous path to that anchor.

This is bounded retrieval, not synchronization or import. The result remains
unselected and contains no proof payloads. The pull never prepares or applies a
block, acquires a proof dependency, writes the journal, changes selected state,
or chooses a target from a peer-reported head. Authentication identifies the
one peer that supplied the path; it does not establish proof validity,
availability beyond the retrieved commitments, network selection, consensus,
or finality.

The pull defines no new wire message, protocol identifier, libp2p behaviour,
connection, peer authorization, storage format, dependency, or migration.

## Public surface

The public Rust surface is equivalent to:

```text
MAX_PROOF_BLOCK_ANCESTRY_BLOCKS = 16

StaticProofNetwork::start_proof_block_ancestry_pull(
    &mut self,
    selected: &ProofChainJournal,
    peer_id: PeerId,
    target_block_id: ProofBlockId,
) -> Result<ProofBlockAncestryPull, ProofBlockAncestryPullError>

ProofBlockAncestryPull::anchor_block_id(&self) -> ProofBlockId
ProofBlockAncestryPull::target_block_id(&self) -> ProofBlockId
ProofBlockAncestryPull::pending_block_id(&self) -> ProofBlockId
ProofBlockAncestryPull::pending_peer_id(&self) -> PeerId
ProofBlockAncestryPull::accepts_event(&self, event: &NetworkEvent) -> bool
ProofBlockAncestryPull::cancel(self)
ProofBlockAncestryPull::on_event(
    self,
    network: &mut StaticProofNetwork,
    selected: &ProofChainJournal,
    event: NetworkEvent,
) -> Result<ProofBlockAncestryPullProgress, ProofBlockAncestryPullError>

enum ProofBlockAncestryPullProgress {
    AwaitingResponse(ProofBlockAncestryPull),
    Complete(UnselectedProofBlockAncestry),
}

UnselectedProofBlockAncestry::peer_id(&self) -> PeerId
UnselectedProofBlockAncestry::anchor_block_id(&self) -> ProofBlockId
UnselectedProofBlockAncestry::target_block_id(&self) -> ProofBlockId
UnselectedProofBlockAncestry::blocks(&self) -> &[ProofBlock]
UnselectedProofBlockAncestry::into_blocks(self) -> Vec<ProofBlock>
```

`ProofBlockAncestryPull` is non-cloneable and privately retains:

- the selected head and `ProofSetRoot` captured when it started;
- the configured chain's virtual genesis address;
- the caller's immutable target address;
- zero to fifteen already retrieved descendant blocks in reverse retrieval
  order; and
- exactly one generation-safe `BlockRequestTicket`.

`pending_block_id` is the exact address currently requested. It begins as the
caller-selected target and then advances only to the preceding response
block's immutable parent. `pending_peer_id` remains the same caller-supplied
authenticated peer for the complete pull. The workflow exposes no raw response
bytes, libp2p request identifier, response channel, permit, or alternative
target.

`accepts_event` is the routing guard. It accepts only the exact
`NetworkEvent::OutboundBlock` terminal correlated to the retained ticket's
request generation, peer, request, and network-instance identity. `on_event`
consumes that event and the current workflow. `AwaitingResponse` contains the
only continuation after one next-parent request has started; `Complete`
contains the finished unselected path and no active request.

## Starting a pull

`start_proof_block_ancestry_pull` executes these checks in order:

1. read the healthy journal's current head and capture it as the immutable
   anchor;
2. derive the configured chain's virtual genesis address without changing the
   journal;
3. reject the target as `TargetAlreadySelected` when it equals either the
   current head or virtual genesis;
4. otherwise query the journal's exact committed-block index and reject the
   target as `TargetAlreadySelected` when it is already on the selected line;
5. read and capture the healthy journal's current `ProofSetRoot`; and
6. call the existing `request_block` with the caller's peer and exact target,
   preserving its request-start error inside `RequestStart`.

The virtual genesis anchor is chain context rather than an admitted block, but
it still cannot be a pull target. Treating it as already selected prevents a
meaningless block request for an address that deliberately has no canonical
block payload.

Every journal failure, including `Poisoned`, is preserved as `SelectedState`
and precedes network work. Target membership uses the journal's existing
constant-time exact-ID index and performs no file or proof-state scan. A target
absent from that index is not thereby valid, available, related to the anchor,
or selected by any network.

The initial request preserves the existing `RequestStartError` precedence:
`UnknownPeer`, `AlreadyPending`, `PeerDisconnected`, then `GlobalLimit`.
Starting a pull never dials, requests a head, retries another peer, polls,
starts a timer task, or mutates the journal.

## Sequential parent retrieval

One pull has exactly one block request active at a time. A successful found
response was already strictly decoded and matched to the immutable requested
`ProofBlockId` by the existing block transport. The pull therefore trusts
neither raw bytes nor a peer-supplied correlation field and does not duplicate
canonical block decoding.

After an accepted terminal, processing executes in this order:

1. require the event and driver network to belong to the exact retained request
   generation, otherwise `UnexpectedEvent`;
2. preserve a correlated transport, peer, decode, or exact-identity failure as
   `BlockRequestFailed`;
3. convert the authenticated peer's empty response to `BlockUnavailable`;
4. read the journal's healthy current head and require it to equal the captured
   anchor, otherwise `SelectedState` or `SelectedHeadChanged`;
5. when a descendant was already retrieved, require this fetched parent's
   resulting `ProofSetRoot` to equal that child's previous `ProofSetRoot`;
6. if this fetched block names the captured anchor as parent, require the
   captured anchor root to equal the block's previous `ProofSetRoot`, then
   complete;
7. reject a parent address already requested by this pull as
   `RepeatedBlockId`;
8. reject the configured virtual genesis or any committed historical selected
   block reached before the captured head as `DivergentAncestry`;
9. reject as `AncestryLimitExceeded` when the current block is the sixteenth
   retrieved block and its parent is still not the anchor; and
10. otherwise issue the next exact parent request to the same peer and retain
    the current block only after that request starts successfully.

No seventeenth request is issued. A follow-up request preserves the same
`RequestStartError` family and the exact next parent address in `RequestStart`.
There is no peer fallback: one unavailable block or ordinary request failure is
terminal for this source-bound path.

The selected-head recheck occurs only after a usable found response. A
correlated terminal failure therefore precedes `BlockUnavailable`, which
precedes selected-state drift. Once a usable block exists, selected-state
health and head stability precede every ancestry-content check. Adjacent root
continuity precedes anchor completion, repetition, divergence, the block bound,
and a follow-up request. A selected-state error while checking a possible
historical intersection precedes `DivergentAncestry`.

## Parent, root, and selected-line boundary

Parent linkage is content-addressed rather than positional. The first request
uses the caller's target. Every later request uses only the exact
`parent_block_id` committed by the preceding matched block. Because the block
transport validates the response block's computed identity against that
request, a completed path binds every adjacent parent link without introducing
a height, index, range message, or peer-supplied path envelope.

For adjacent blocks in forward order, the required root relation is:

```text
parent.transition.resulting_proof_set_root
    == child.transition.previous_proof_set_root
```

For the anchor's direct child, it is:

```text
captured_selected_proof_set_root
    == child.transition.previous_proof_set_root
```

A mismatch is `TransitionRootMismatch`, identifying the preceding fetched
block or anchor, the expected predecessor root, and its child's actual previous
root. These equality checks are necessary for the blocks ever to be applied
sequentially to the captured selected context. They are only structural
commitment continuity. The pull does not project a transition's resulting
root, inspect proof payloads, check a `ProofId`, establish dependency closure,
or execute mathematical validation. A dishonest peer can therefore supply an
identity-correct and root-continuous path whose transitions later fail strict
block import.

The journal's committed block index represents one replay-checked selected
line. If the backward path reaches a historical block on that line, or reaches
this chain's virtual genesis while the captured head is later, it bypassed the
captured head and cannot be an ancestry to that anchor. `DivergentAncestry`
rejects that relative contradiction before another request. This is neither a
fork-choice rule nor a claim that the fetched branch is globally invalid; it
only proves that the path cannot extend this immutable local anchor.

Exact repeated-address rejection prevents a malformed ancestry from consuming
the complete request bound by revisiting an address. It makes no broader claim
about hash collisions. Security of block and virtual-genesis identity retains
the existing SHA-256 collision and second-preimage assumptions.

## Completed unselected ancestry

Completion produces one `UnselectedProofBlockAncestry` with these invariants:

- `peer_id` is the one authenticated static peer that supplied every block;
- `anchor_block_id` is the selected head captured at start and rechecked after
  the final found response;
- `target_block_id` is exactly the caller-selected target;
- `blocks` contains between one and sixteen decoded `ProofBlock` values;
- blocks are ordered from the anchor's direct child through the target; and
- exact parent identities and adjacent transition roots are continuous from
  the captured anchor through that target.

`blocks` provides borrowed structured access in forward order.
`into_blocks` transfers the same vector without changing order or block
contents. Neither method exposes proof payloads because canonical proof blocks
contain only transition commitments.

The result deliberately remains `Unselected`. It has no method that applies a
block, acquires proofs, changes a journal, or converts the path into an import.
Selected state may advance immediately after completion, so any later consumer
must revalidate its exact parent and complete transition against then-current
state. A completed path proves neither that any proof payload is available nor
that any transition is valid.

## Error family and precedence

`ProofBlockAncestryPullError` has these public classes:

```text
SelectedState { source: Box<ProofChainJournalError> }
TargetAlreadySelected { block_id: ProofBlockId }
RequestStart { block_id: ProofBlockId, source: RequestStartError }
UnexpectedEvent
BlockRequestFailed {
    peer_id: PeerId,
    block_id: ProofBlockId,
    source: Box<OutboundProofBlockFailure>,
}
BlockUnavailable { peer_id: PeerId, block_id: ProofBlockId }
SelectedHeadChanged { expected: ProofBlockId, actual: ProofBlockId }
TransitionRootMismatch {
    preceding_block_id: ProofBlockId,
    expected: ProofSetRoot,
    actual: ProofSetRoot,
}
DivergentAncestry {
    expected_anchor: ProofBlockId,
    encountered: ProofBlockId,
}
RepeatedBlockId { block_id: ProofBlockId }
AncestryLimitExceeded {
    maximum: usize,
    next_block_id: ProofBlockId,
}
```

At start, journal-head health precedes target equality; equality with the head
or virtual genesis precedes committed-index lookup; target membership precedes
anchor-root lookup; and all selected-state work precedes block request
preflights.

During advancement, exact event and network-instance correlation precede
terminal interpretation. `BlockRequestFailed` precedes `BlockUnavailable`;
both precede selected-head health and drift. Selected-head stability precedes
root continuity. Root continuity precedes successful anchor completion and all
next-parent checks. Repetition precedes selected-line divergence; divergence
precedes the fixed limit; and the limit precedes a next request. Every ordinary
error drops the logical workflow and retained unselected blocks without
changing the journal.

## Cancellation and event ownership

`cancel` consumes the pull and releases its retained decoded blocks
immediately. Dropping the pull has the same logical effect. Neither operation
cancels the physical libp2p request because the existing opaque block ticket
owns no transport cancellation mechanism.

The in-flight request keeps its peer slot and one shared application permit
until libp2p emits a response or failure terminal. `next_event` still exposes
that later `OutboundBlock` event, but it can no longer advance the cancelled
workflow. Dropping that event releases a successful response's retained permit.
Cancellation neither closes the managed connection nor starts a replacement
request.

The pull adds no workflow-wide deadline. Each sequential request retains the
existing protocol-negotiation and 30-second negotiated request-response
timeouts. Timeout progress and terminal delivery require the caller to keep
driving `StaticProofNetwork::next_event`; stopping the event loop provides no
wall-time guarantee.

## Resource and performance boundary

The ancestry orchestration adds these bounds without changing the underlying
transport limits:

| Resource | Limit |
| --- | ---: |
| Caller-selected targets per pull | 1 |
| Authenticated serving peers per pull | 1 |
| Active block requests per pull | 1 |
| Total block requests per pull | 1..=16 |
| Blocks in a completed path | 1..=16 |
| Canonical bytes represented by a completed path | 129..=5,648 bytes |
| Transition proof identities represented by a completed path | 1..=128 |
| Shared application permits attributable to one pull | At most 1 |
| New wire protocols, connections, or behaviours | 0 |
| New journal bytes or files | 0 |

The maximum canonical-byte figure is `16 * 353`; decoded in-memory block
representation and each transition's bounded proof-ID allocation remain
implementation details. The pull retains decoded blocks rather than duplicate
canonical response buffers. Completing the path reverses at most sixteen
elements in place to produce forward order.

Parent addresses are discovered sequentially, so the operation intentionally
does not parallelize requests. Journal head, root, and committed-block queries
reuse existing constant-time in-memory access and never scan disk or the proof
set. Root comparisons are fixed-size. Repeated-address detection is bounded by
sixteen blocks and needs no unbounded set.

The pull does not retain a response permit with an already consumed decoded
block. It releases the prior successful event's permit before attempting the
next request, so one pull never raises the shared eight-permit maximum. Other
workflows may still cause a follow-up `RequestStart` failure under the existing
shared per-peer and global limits.

## Compatibility and security boundary

This operation is additive composition over the existing exact-ID block
transport. Canonical blocks, `ProofBlockId`, transition bytes, block request and
response framing, protocol identifiers, connection limits, journal prefix,
journal entries, and proof validation remain unchanged. No compatibility
parser, legacy branch, migration, or local-data recreation is required.

Noise authenticates the configured serving peer. The ticket's private request
generation and network-instance identity bind every terminal, while exact
block content addressing binds every accepted response to the current parent
address. The caller alone selects the target. A peer-reported head may be
presented to caller policy, but neither head transport nor this operation may
silently turn that observation into a target.

Static peer authorization is not proposer, validator, checkpoint, consensus,
or economic authority. Root continuity is not proof validity. Reaching one
local selected anchor is not evidence that another node selected the same
history. The result is suitable only as bounded untrusted input to a future
explicit validation and import policy.

## Explicit exclusions

This contract defines no automatic use of a peer-reported head, target
discovery, periodic polling, retry, peer fallback, hedging, announcement,
subscription, gossip, DHT, height, timestamp, child query, range query, batch
wire message, parallel block fetch, unbounded ancestry walk, proof-payload
request, proof bundle, proof decoding, mathematical checking, transition root
projection, proof dependency acquisition, block preparation, block import,
multi-block atomic commit, partial commit, resume checkpoint, selected-state
mutation, journal format, migration, snapshot, pruning, orphan pool,
competing-fork storage, fork choice, rollback, reorganization, checkpoint
trust, proposer, signature, proof of work, proof of stake, validator set,
voting, quorum, consensus, finality, dynamic learned-peer authorization, peer
scoring, reputation, data-availability guarantee, erasure coding, reward, fee,
balance, novelty policy, issuance, or settlement.

The separate
[Caller-Selected Proof Block Ancestry Import](caller-selected-proof-block-ancestry-import.md)
may consume one completed opaque ancestry and import it strictly forward with
explicit per-block durable-prefix semantics. It does not change this pull's
read-only result or caller-owned target-selection boundary.
