# NAOME Caller-Selected Proof Chain Head Broadcast

## Status and scope

This document defines one bounded, caller-triggered broadcast of one healthy
local [`ProofChainJournal`](proof-chain-journal.md) head to `1..=8` explicit,
unique, statically authorized peers. It is a prerelease orchestration contract
and may change before the first stable protocol release.

The operation snapshots the journal exactly once, then starts the existing
[Authenticated Proof Chain Head Announcement](authenticated-proof-chain-head-announcement.md)
for every caller-selected peer as one all-or-none group. Every peer receives
the identical immutable `ProofChainHeadAnnouncement`. Receipt and failure
terminals may arrive in any order; the completed result contains exactly one
source-bound row per selected peer in the caller's original order.

This is bounded propagation, not discovery or synchronization. The caller
chooses every recipient. The broadcast does not enumerate configured peers,
select a target from peer state, retry a failure, retrieve ancestry, import a
block, mutate either journal, or interpret the number of receipts as a vote or
quorum. Each receipt proves only that its authenticated peer acknowledged the
exact common announcement in that peer's request generation.

The broadcast defines no new wire message, protocol identifier, libp2p
behaviour, connection, peer authorization, storage format, dependency,
migration, or background task.

## Public surface

The public Rust surface is equivalent to:

```text
MAX_PROOF_CHAIN_HEAD_BROADCAST_PEERS = 8

StaticProofNetwork::start_chain_head_broadcast_from_journal(
    &mut self,
    peer_ids: &[PeerId],
    journal: &ProofChainJournal,
) -> Result<ProofChainHeadBroadcast, ProofChainHeadBroadcastStartError>

ProofChainHeadBroadcast::announcement(&self) -> ProofChainHeadAnnouncement
ProofChainHeadBroadcast::peer_count(&self) -> usize
ProofChainHeadBroadcast::pending_peer_count(&self) -> usize
ProofChainHeadBroadcast::accepts_event(&self, event: &NetworkEvent) -> bool
ProofChainHeadBroadcast::cancel(self)
ProofChainHeadBroadcast::on_event(
    self,
    event: NetworkEvent,
) -> Result<
    ProofChainHeadBroadcastProgress,
    Box<ProofChainHeadBroadcastEventMismatch>,
>

enum ProofChainHeadBroadcastProgress {
    AwaitingReceipts(ProofChainHeadBroadcast),
    Complete(CompletedProofChainHeadBroadcast),
}

CompletedProofChainHeadBroadcast::announcement(&self)
    -> ProofChainHeadAnnouncement
CompletedProofChainHeadBroadcast::peer_results(&self)
    -> &[ProofChainHeadBroadcastPeerResult]
CompletedProofChainHeadBroadcast::into_parts(
    self,
) -> (
    ProofChainHeadAnnouncement,
    Vec<ProofChainHeadBroadcastPeerResult>,
)

ProofChainHeadBroadcastPeerResult::peer_id(&self) -> PeerId
ProofChainHeadBroadcastPeerResult::result(
    &self,
) -> Result<(), &OutboundProofChainHeadAnnouncementFailure>
ProofChainHeadBroadcastPeerResult::into_result(
    self,
) -> Result<(), Box<OutboundProofChainHeadAnnouncementFailure>>

ProofChainHeadBroadcastEventMismatch::into_parts(
    self,
) -> (ProofChainHeadBroadcast, NetworkEvent)
```

`MAX_PROOF_CHAIN_HEAD_BROADCAST_PEERS` is exactly `MAX_STATIC_PEERS`. The
non-cloneable in-progress value privately retains the one shared announcement,
one exact existing `HeadAnnouncementTicket` for every pending peer, and one
terminal result slot for every completed peer. `peer_count` is immutable;
`pending_peer_count` decreases by exactly one for each accepted terminal and
reaches zero only on completion.

`accepts_event` is the routing guard. It returns true only for an
`OutboundChainHeadAnnouncement` event accepted by one still-pending exact
ticket. Request generation, expected authenticated peer, complete
announcement, and network-instance token must all match. It rejects inbound
announcements, session transitions, other exchange kinds, terminals belonging
to another broadcast, and a second delivery for an already completed peer.

`on_event` consumes both values. An unrelated event returns a boxed
`ProofChainHeadBroadcastEventMismatch` that preserves the unchanged broadcast
and complete `NetworkEvent` for correct routing. It does not inspect or discard
the unrelated outcome. Callers driving concurrent workflows must check
`accepts_event` before routing.

One accepted receipt becomes `Ok(())`; one accepted transport or peer-mismatch
failure becomes that peer's boxed failure. A terminal failure is result data,
not a workflow-level error, and does not cancel the remaining peers. While any
ticket remains, `on_event` returns `AwaitingReceipts`. Only the final accepted
terminal returns `Complete`.

The completed value stores the common announcement once. Each peer row stores
only its original `PeerId` and success or typed failure. It deliberately does
not duplicate the announcement or the data-free authenticated receipt in all
rows: exact ticket completion has already established both values. The peer ID
and common announcement retain the complete source-bound meaning. Both
`peer_results` and the vector returned by `into_parts` preserve the caller's
input order regardless of terminal arrival order.

## Atomic start and precedence

`start_chain_head_broadcast_from_journal` completes all fallible preflight
before the first request is queued. It evaluates conditions in this exact
order:

1. reject an empty peer slice as `EmptyPeerSet`;
2. reject more than `MAX_PROOF_CHAIN_HEAD_BROADCAST_PEERS` entries as
   `TooManyPeers { actual, maximum }`;
3. scan in caller order and reject the first repeated identity as
   `DuplicatePeer(peer_id)`;
4. read the journal's health-sensitive current head exactly once, preserving
   every `ProofChainJournalError` as `Journal`;
5. after that successful read, copy the journal's immutable `ProofChainId` and
   construct the one exact announcement snapshot;
6. preflight each peer in caller order under the existing request-start
   precedence: static authorization, absence of any pending outbound
   application request for that peer, and both managed-session and
   announcement-behaviour connectivity;
7. atomically reserve exactly one shared application permit per peer, or
   return `InsufficientCapacity { requested, available, maximum }`; and
8. queue all announcement requests and install their existing tagged pending
   entries.

Steps 1 through 3 perform no journal read or network work. Journal health then
precedes every peer check, so a peer error cannot mask a poisoned selected
state. Peer preflights produce `RequestStart(UnknownPeer)`,
`RequestStart(AlreadyPending)`, or `RequestStart(PeerDisconnected)` for the
first failing peer in caller order. This API reports shared-budget shortage
only as `InsufficientCapacity`; it does not partially acquire permits and does
not surface `RequestStartError::GlobalLimit`.

The synchronous start call makes no network progress. Before step 8 it has
queued zero requests, installed zero pending entries, and retained zero new
permits. After the atomic reservation succeeds, request queuing and pending
installation are infallible under the existing libp2p API. Consequently every
ordinary start failure leaves all selected peers untouched, while every
success starts exactly the complete caller-selected set.

Connectivity is a start-time observation, not a delivery guarantee. A session
may fail after preflight, protocol negotiation may fail, or a peer may decline
to receipt. Those conditions become ordinary per-peer terminal failures after
the all-or-none start; they do not roll back, retry, or suppress other results.

The announcement is the journal state observed by the one head read. The
journal may advance immediately afterward, but neither queued request nor
result changes to that later head. The start retains no journal reference and
performs no block lookup, proof work, journal scan, disk write, or selected-
state mutation. A healthy empty journal supplies its deterministic virtual-
genesis head under the existing single-announcement contract.

## Start errors

`ProofChainHeadBroadcastStartError` has these public variants:

```text
EmptyPeerSet
TooManyPeers { actual: usize, maximum: usize }
DuplicatePeer(PeerId)
Journal(ProofChainJournalError)
RequestStart(RequestStartError)
InsufficientCapacity {
    requested: usize,
    available: usize,
    maximum: usize,
}
```

`Journal` and `RequestStart` expose their nested causes through
`Error::source`. Structural errors and insufficient capacity have no nested
source. `available` is the number of shared permits available at the atomic
reservation attempt, and `maximum` is `MAX_PENDING_REQUESTS`.

No start error owns a partially started broadcast, because no request exists
until every fallible condition has succeeded. Terminal announcement failures
remain the existing non-start error family and are retained independently in
the completed peer rows.

## Progress, cancellation, and event ownership

Each accepted terminal is completed through its exact existing
`HeadAnnouncementTicket`. This applies the existing peer-mismatch precedence
before receipt or transport interpretation. A successful event's retained
permit is consumed as it becomes one shared-free result row; a failed physical
request released its permit when the terminal event was formed. Other peers
remain pending and independently routable.

`cancel` consumes the logical broadcast. Dropping the in-progress value has
the same logical effect. Neither operation cancels physical libp2p requests:
the existing pending registry retains each peer slot and shared permit until
that request's terminal arrives. `StaticProofNetwork::next_event` still emits
each later `OutboundChainHeadAnnouncement`, but it no longer belongs to the
cancelled workflow. Handling or dropping those terminal events releases their
retained result state under the existing announcement lifecycle.

The broadcast adds no workflow-wide deadline. Every request retains the
existing protocol-negotiation and 30-second negotiated request-response
timeouts. Timeout progress and terminal delivery require the caller to keep
driving `StaticProofNetwork::next_event`; stopping the event loop provides no
wall-time guarantee.

A completed broadcast owns no shared permit, request ticket, raw request
identifier, response channel, network-instance token, journal reference, or
receipt object. Dropping it releases only its bounded peer-result vector and
any retained failure values.

## Resource and performance boundary

The orchestration adds these exact bounds without changing the underlying
transport limits:

| Resource | Bound |
| --- | ---: |
| Caller-selected peers per broadcast | `1..=8`, unique |
| Journal head snapshots per start attempt after shape preflight | 1 |
| Announcement requests per successful broadcast | `1..=8` |
| Shared application permits per successful broadcast | `1..=8` |
| Request body per peer | 64 bytes |
| Aggregate request bodies | `64..=512` bytes |
| Receipt body per successful peer | 1 byte, exactly `0x01` |
| Aggregate successful receipt bodies | `0..=8` bytes |
| Announcement streams per connection | 1 |
| Aggregate exchange streams per connection | 7 |
| Yamux substreams per connection | 8 |
| Shared pending or retained application permits across the network | 8 |
| Pending outbound application requests per selected peer | 1 |
| New wire protocols, behaviours, connections, or background tasks | 0 |
| New journal bytes, files, or synchronization barriers | 0 |

The request and receipt totals describe complete message bodies; framing and
transport overhead are separate. Because selected peers are unique, a
successful broadcast uses at most one announcement stream on each selected
connection. It may use all eight shared permits across eight connections, but
does not raise any per-connection stream limit.

Shape, duplicate, peer, and capacity preflights are bounded by eight entries.
Terminal routing and result placement are likewise bounded. No unbounded map,
queue, task set, peer enumeration, or journal scan is introduced. Workflow
metadata and completed state store the common `ProofChainHeadAnnouncement`
once. Each required existing ticket and pending transport entry still binds the
same fixed-size value for generation-safe correlation. Successful result
compression removes those ticket, receipt, and announcement copies once
correlation is complete.

## Compatibility and security boundary

Every physical request uses the exact existing
`/naome/proof-chain-head-announcement` protocol, 64-byte request, `0x01`
receipt, Noise-authenticated static-peer session, request-response timeout,
per-peer pending gate, tagged request namespace, and generation-safe terminal
correlation. Single-peer callers and all existing public announcement types
remain valid and unchanged.

Canonical proof bytes, `ProofBlockId`, journal entries, replay, selected-state
validation, peer-address storage, and every other protocol identifier and wire
message remain unchanged. There is no storage version, legacy parser,
migration, or local-data recreation requirement.

All-or-none applies only to starting the selected physical requests. It does
not make delivery or receipt atomic across peers. A completed value may contain
any mixture of successes and failures, and one peer cannot authenticate,
receipt, or fail for another because each row derives from its own private
request generation and authenticated session.

Noise authentication and an exact receipt do not establish that a peer stored,
served, validated, selected, or agreed with the announced head. The count or
identity of successful rows establishes no freshness, availability quorum,
operator independence, Sybil resistance, checkpoint authority, consensus, or
finality.

## Explicit exclusions

This contract defines no automatic journal emission, commit hook,
all-configured-peer enumeration, empty-recipient no-op, duplicate-recipient
coalescing, sequential send, partial start, rollback after start, fail-fast
terminal handling, retry, fallback, hedging, rebroadcast, scheduler, polling,
subscription, gossip, DHT, dynamic learned-peer authorization, peer discovery,
head survey, comparison, ranking, majority, quorum, vote, peer scoring,
reputation, freshness proof, timestamp, height, monotonic sequence, block or
proof request, range or ancestry request, automatic target selection, proof
acquisition, block preparation, import, selected-state mutation, background
synchronization, orphan pool, competing-fork storage, fork choice, rollback,
reorganization, checkpoint trust, proposer, proof of work, proof of stake,
validator set, voting, consensus, finality, reward, fee, balance, issuance, or
settlement.
