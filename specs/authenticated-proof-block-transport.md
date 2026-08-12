# NAOME Authenticated Proof Block Transport

## Status and scope

This document defines one concrete, bounded network binding for the
[Addressed Proof Block Exchange](addressed-proof-block-exchange.md). It is a
prerelease transport contract and may change before the first stable protocol
release.

The binding carries one already known `ProofBlockId` over an existing
[`StaticProofNetwork`](authenticated-proof-transport.md) session. A successful
response is either the exact canonical `ProofBlock` addressed by that request
or the peer-local `Unavailable` value. The caller drives the network event loop
and explicitly responds to inbound requests; the transport starts no runtime or
NAOME-owned background task.

This is exact content retrieval, not block discovery or synchronization. A
retrieved block has no repeated `ProofChainId`, proof payloads, trusted ancestry,
selection authority, or finality. The transport never prepares or applies a
block and never mutates a receiving `ProofChainJournal`.

The separate
[Caller-Selected Proof Block Ancestry Pull](caller-selected-proof-block-ancestry-pull.md)
sequences at most sixteen requests to one caller-chosen peer while preserving
this transport's exact request and trust boundaries. It returns only an
unselected, structurally root-continuous path and adds no wire message or
selection authority.

The separate
[Caller-Selected Proof Block Import](caller-selected-proof-block-import.md)
composes one caller-chosen exact request with existing dependency acquisition
and journal application. That orchestration adds no wire message or selection
authority to this transport.

## Stack and authorization

The stack is:

```text
TCP
  -> Noise
  -> Yamux
  -> /naome/proof-block-exchange
  -> Addressed Proof Block Exchange
```

Block exchange is a second request-response behaviour on the same managed
connection as `/naome/proof-exchange`. It reuses the exact `StaticPeer`
allowlist, authenticated Noise identity, deterministic dial ownership,
connection limits, redial policy, and caller-driven swarm from the
[Authenticated Proof Transport](authenticated-proof-transport.md). It opens no
second TCP connection and a block request never initiates a dial.

The authenticated remote `PeerId` establishes which statically authorized key
participated in the exchange. It does not establish that the peer is honest,
that the block belongs to the caller's configured chain, or that any network
selected or finalized the block.

## Public surface

The public surface is equivalent to:

```text
StaticProofNetwork::request_block(
    &mut self,
    peer_id: PeerId,
    request: ProofBlockRequest,
) -> Result<BlockRequestTicket, RequestStartError>

BlockRequestTicket::peer_id(&self) -> PeerId
BlockRequestTicket::request(&self) -> ProofBlockRequest
BlockRequestTicket::accepts_event(
    &self,
    event: &OutboundProofBlockEvent,
) -> bool
BlockRequestTicket::complete(
    self,
    event: OutboundProofBlockEvent,
) -> Result<
    Result<ProofBlockResponse, Box<OutboundProofBlockFailure>>,
    Box<ProofBlockRequestEventMismatch>,
>

ProofBlockRequestEventMismatch::into_parts(
    self,
) -> (BlockRequestTicket, OutboundProofBlockEvent)

InboundProofBlockRequest::peer_id(&self) -> PeerId
InboundProofBlockRequest::request(&self) -> ProofBlockRequest

StaticProofNetwork::respond_block_from_journal(
    &mut self,
    inbound: InboundProofBlockRequest,
    journal: &ProofChainJournal,
) -> Result<(), RespondError>

OutboundProofBlockEvent::peer_id(&self) -> PeerId
OutboundProofBlockEvent::request(&self) -> ProofBlockRequest
```

`NetworkEvent` adds `InboundBlockRequest`, `OutboundBlock`, and
`InboundBlockFailure`. Proof-block request and event internals remain private.
The transport exposes neither a raw outbound libp2p request identifier nor
unvalidated response bytes. In particular, `OutboundProofBlockEvent` cannot
expose its outcome directly; only the matching ticket can consume it through
`complete`. Inbound request identifiers remain visible where the caller must
route or diagnose an inbound response channel.

`OutboundProofBlockFailure` has these terminal classes:

```text
Transport(request_response::OutboundFailure)
InvalidResponse { source: ProofBlockExchangeWireError }
PeerMismatch { expected: PeerId, actual: PeerId }
```

`RequestStartError` and `RespondError` remain shared with the authenticated
proof transport because the same peer session, application permit, pending-peer
slot, journal health boundary, and response-channel ownership apply.

## Protocol identifier and framing

The libp2p stream protocol identifier is exactly:

```text
/naome/proof-block-exchange
```

One request occupies one request-response substream and contains exactly:

```text
block_id[32]
end of stream
```

The 32 bytes are the complete transport-neutral `ProofBlockRequest`. The reader
requires end-of-stream immediately after them. A shorter request is truncated;
an additional byte is invalid. There is no tag, length, chain identifier,
height, parent, or correlation field in the request body.

One response frame is:

```text
response_length u16 big endian
response        response_length bytes
end of stream
```

`response_length` must be in `0..=353`. Zero is the sole network encoding of
`Unavailable`. A nonzero body is the complete transport-neutral proof-block
response and must ultimately be one canonical block of 129 through 353 bytes.
The two-byte length is transport framing only and is not part of canonical
block bytes or `ProofBlockId`.

The reader rejects a declared length above 353 immediately after its prefix,
before reserving or reading the body. It reserves only the accepted declared
length, reads exactly that many bytes, and requires end-of-stream. A truncated
prefix, truncated body, trailing byte, timeout, or reset before the complete
frame arrives is a transport failure and never becomes `Unavailable`.

The selected asynchronous Yamux stream API can report either clean receive
closure or a reset after the complete frame as end-of-stream. The adapter
accepts that condition only after the exact declared bytes arrived. Strict
block decoding and request-identity validation still run afterward.

For the 161-byte golden block in the Addressed Proof Block Exchange, the exact
request body is:

```text
9b1dbade5300bbb36e1b126226dc940395d7ccd742a2bd7a8d6f7cbb9543237f
```

The exact found response frame is the two-byte length `00a1` followed directly
by these canonical block bytes:

```text
00a1
f47ee4acce1f5797ff773e7b620cfc66b101dfadb0b87cb4f83e3b94765c8b98
1111111111111111111111111111111111111111111111111111111111111111
2222222222222222222222222222222222222222222222222222222222222222
02
3333333333333333333333333333333333333333333333333333333333333333
4444444444444444444444444444444444444444444444444444444444444444
```

Line breaks are presentation only. The exact unavailable response frame is
`0000`.

## Starting a request and shared budgets

`request_block` executes these application preflights before queuing a libp2p
request:

1. require `peer_id` to be one configured static peer, otherwise
   `UnknownPeer`;
2. require that peer to have no pending application-level proof, proof-block,
   proof-chain-head-pull, or proof-chain-head-announcement request, otherwise
   `AlreadyPending`;
3. require the managed session and block-exchange behaviour to be connected,
   otherwise `PeerDisconnected`;
4. acquire one slot from the shared eight-permit application budget, otherwise
   `GlobalLimit`; and
5. queue the immutable request and install its tagged pending entry.

The method never waits for or opens a connection. A peer that supports the
managed Noise session but not the proof-block protocol can still reject
negotiation as an ordinary transport failure.

The pending registry is shared at the application level and explicitly tags
proof, proof-block, proof-chain-head-pull, and proof-chain-head-announcement
request namespaces. Behaviour-local libp2p request identifiers may have equal
numeric representations without aliasing each other. The shared per-peer
preflight prevents requests from different exchange protocols from
simultaneously consuming the same peer slot.

A successful proof-block response retains its permit in the opaque outbound
event until the event is completed with its matching ticket or dropped. A
terminal failure discards any bounded response state and releases its permit
before the failure event is emitted. This preserves the same global bound
across pending proof requests, quarantined proof candidates, completed proof
closures, pending block, head-pull, and head-announcement requests, and
unconsumed successful block, head-pull, and head-announcement events.

## Generation-safe request ticket

Successful start returns one opaque, non-cloneable `BlockRequestTicket`.
It binds:

- the block behaviour's private outbound request identifier;
- the expected authenticated `PeerId`;
- the immutable `ProofBlockRequest`; and
- a private `Arc` identifying the exact `StaticProofNetwork` instance.

The instance identity is required because behaviour-local request identifiers
can repeat after constructing another network. `accepts_event` returns true
only when the event carries the same network-instance identity, block request
identifier, expected peer, and immutable request. A ticket from another network
therefore cannot accept an event merely because local request counters and
public values coincide.

`complete` consumes both the ticket and event. On an exact match, its outer
`Result` succeeds and the inner `Result` exposes either the validated
`ProofBlockResponse` or the event's boxed terminal
`OutboundProofBlockFailure`. A mismatch returns one boxed
`ProofBlockRequestEventMismatch`, which still owns both opaque values.
`into_parts` returns them unchanged so a caller can route the event to the
correct outstanding ticket without losing either request generation. Moving an
ordinary failure out of the event adds no allocation because the event already
stores that failure boxed; only the rare mismatch allocates its one result box.
A mismatched ticket can never inspect or extract the event's private outcome.

Dropping a ticket is explicitly non-cancelling. The ticket owns no request
permit, response channel, swarm state, or cancellation authority. The physical
request remains pending until libp2p emits its response or terminal failure,
and `next_event` still emits the corresponding `OutboundBlock` event. This is
deliberately different from dropping `ProofDependencyAcquisition`, whose
separate cancellation guard tombstones an in-flight proof request.

The block protocol defines no public cancellation operation or separate
absolute acquisition deadline. Its negotiated request-response phase uses the
existing 30-second timeout, after the separately bounded protocol negotiation.
If the caller stops driving `next_event`, terminal delivery and permit release
have no wall-time guarantee.

## Response correlation and validation

The block codec cannot validate a response identity by itself because
libp2p's response decoder does not receive the originating request. It returns
only one private, length-bounded response body to the behaviour. The network
then processes one physical terminal in this order:

1. locate and remove the exact tagged block pending entry by its private
   behaviour-local request identifier;
2. require the terminal event's authenticated peer to equal the retained peer,
   producing `PeerMismatch` before interpreting a response or transport error;
3. preserve a libp2p outbound failure as `Transport`; or
4. for a complete framed response, call
   `ProofBlockResponse::from_wire_bytes` with the retained immutable request.

The final step preserves the Addressed Proof Block Exchange order:

1. empty body becomes `Unavailable`;
2. an oversized body is rejected before block decoding as `ResponseTooLong`
   (the network reader has already enforced the same outer limit);
3. a nonempty body is strictly decoded as one complete canonical `ProofBlock`;
4. the decoded block's `ProofBlockId` is computed exactly once; and
5. it must equal the retained requested identity before the block is exposed.

Strict decode or identity failure becomes `InvalidResponse { source }`. A
canonical block for another request is therefore not a successful response.
Neither raw response bytes nor a partially decoded block are exposed through
`OutboundProofBlockEvent`.

Framing errors arise in the asynchronous codec and are reported as `Transport`.
Canonical block errors arise only after the complete frame and exact pending
request have been correlated, and are reported as `InvalidResponse`. The exact
peer check precedes both classifications. The resulting opaque event remains
bound to the same private request and network instance until its matching ticket
completes it.

`OutboundProofBlockEvent::peer_id` returns the retained expected peer. If
libp2p reports a different authenticated peer, the actual identity is preserved
inside `PeerMismatch`; it does not replace the event's request-generation key.

`Unavailable` is one authenticated peer's answer for one exact request. It is
not proof of global absence, invalidity, non-membership in an ancestry, or
absence from another journal. The transport creates no negative cache and does
not automatically retry another peer.

## Inbound serving and journal ownership

After strict request framing, `next_event` emits one
`InboundBlockRequest` containing the authenticated peer, immutable request, and
private response channel. The caller may pass it with a borrowed
`ProofChainJournal` to `respond_block_from_journal`.

Serving executes in this order:

1. query the healthy journal through the Addressed Proof Block Exchange helper;
2. preserve every `ProofChainJournalError`, including `Poisoned`, rather than
   converting it to `Unavailable`;
3. require the response channel to remain open;
4. encode a found committed block once into an owned canonical response buffer,
   or use an empty buffer for an unknown identity or virtual genesis anchor;
5. transfer that buffer to libp2p's response channel.

The asynchronous response must own its bytes, so serving requires at most one
bounded 353-byte canonical block buffer. The journal is not borrowed across the
write. The helper performs no journal scan, proof lookup, block application, or
state mutation and never exposes an uncommitted or competing block.

A malformed inbound request never produces an `InboundBlockRequest`. When the
pinned libp2p behaviour surfaces an inbound failure, `next_event` exposes it as
`InboundBlockFailure`; the transport does not promise that every pre-delivery
negotiation or request-read failure becomes an application event. If the caller
declines or drops a valid inbound request, libp2p owns the resulting channel-
closure behavior; there is no automatic response or implicit retry.

Serving establishes only that this healthy local journal committed and replayed
the exact block. Authentication identifies the serving static peer but does not
turn local journal membership into network consensus, ancestry proof, or
finality.

## Resource bounds

This protocol adds these exact bounds to the existing static network:

| Resource | Limit |
| --- | ---: |
| Request body | 32 bytes |
| Response length prefix | 2 bytes |
| Canonical response body | 0..=353 bytes |
| Complete response frame | 2..=355 bytes |
| Proof-block request-response streams per connection | 2 |
| Proof request-response streams per connection | 2 |
| Proof-chain-head request-response streams per connection | 2 |
| Proof-chain-head announcement streams per connection | 1 |
| Aggregate exchange streams per connection | 7 |
| Negotiating inbound streams per connection | 2 |
| Yamux substreams per connection | 8 |
| Shared pending or retained application permits | 8 |
| Pending outbound proof, proof-block, proof-chain-head, or announcement requests per peer | 1 |
| Protocol negotiation timeout | 10 seconds, pinned libp2p behaviour |
| Negotiated request-response phase timeout | 30 seconds |

The four request-response behaviours have separate protocol negotiation and
stream state but share the existing managed connection, application permits,
and per-peer pending registry. Their seven aggregate application streams
remain below the hard Yamux limit of eight.

A block response is much smaller than one maximum proof payload. Because each
successful block event consumes one of the same eight permits, adding block
transport does not raise the existing worst-case retained proof-payload bound.
The block codec performs at most one 353-byte response-body allocation. The
shared permits can retain at most eight decoded blocks, whose transitions can
contain at most 64 proof identities in total.

One block request can consume the pinned negotiation interval plus the separate
30-second negotiated exchange phase. It has no additional retry or acquisition
deadline. These timers advance only while the caller continues driving the
network.

These are per-object, concurrent-count, connection, and timeout bounds. They do
not provide rolling bandwidth limits, peer fairness, or protection against an
authorized peer repeatedly issuing valid, invalid, or unavailable requests.

## Security boundary

Noise authenticates the configured peer key. The private request handle and
authenticated peer correlate one physical terminal, the network-instance token
prevents cross-instance ticket aliasing, and the immutable
`ProofBlockRequest` binds successful content by computed identity. Ticket-only
outcome extraction prevents a stale, cross-protocol, or cross-generation event
from being consumed merely because its public peer and request values match.

The security of content addressing still relies on canonical block decoding
and the collision and second-preimage resistance assumptions of
`ProofBlockId`. A valid content match does not prove that the parent ancestry is
available or valid under the caller's configured chain. Static authorization is
not Sybil resistance, validator authority, checkpoint trust, consensus, or
economic identity.

## Explicit exclusions

This contract defines no block announcement, chain-identifier discovery,
height, range, parent, child, or batch query, ancestry walk,
historical membership proof, checkpoint acquisition, negative cache, automatic
retry, peer fallback, hedged request, public request cancellation, block orphan
pool, ancestry synchronization, proof-payload bundle, automatic proof
acquisition, block preparation, block application, selected-state mutation,
competing-fork storage, fork choice, rollback, reorganization, proposer,
signature, proof of work, proof of stake, validator set, voting, quorum,
consensus, finality, dynamic learned-peer authorization, DHT, gossip, reward,
fee, balance, novelty policy, issuance, or settlement.

The separate
[Authenticated Proof Chain Head Pull](authenticated-proof-chain-head-pull.md)
observes one untrusted chain-scoped peer head without changing this exact-ID
block request or granting automatic retrieval, import, or selection authority.
The separate
[Authenticated Proof Chain Head Announcement](authenticated-proof-chain-head-announcement.md)
pushes the sender's untrusted chain-scoped head to one static peer without
changing this exact-ID retrieval protocol or starting a block request.
The separate caller-selected ancestry pull composes this request repeatedly but
does not change the transport protocol or validate proof payloads.
