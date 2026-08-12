# NAOME Authenticated Proof Chain Head Announcement

## Status and scope

This document defines one caller-triggered, receipt-bearing announcement of a
healthy local [`ProofChainJournal`](proof-chain-journal.md) head to one exact
statically authorized peer. It is a prerelease transport contract and may
change before the first stable protocol release.

The sender chooses the peer explicitly. At the instant the caller starts the
operation, the implementation reads one healthy journal's exact
`ProofChainId` and current `ProofBlockId`, binds both values into one immutable
`ProofChainHeadAnnouncement`, and sends it over the existing authenticated
managed session. The receiver either explicitly acknowledges that exact
announcement or declines it by dropping the inbound value. A successful
acknowledgement proves only that the authenticated peer returned the fixed
receipt for this request generation.

The announcement is an untrusted, source-bound availability observation. It is
not a block, ancestry proof, freshness proof, checkpoint, vote, selection
decision, or evidence of consensus or finality. Receipt never requests the
announced block, starts ancestry retrieval, acquires proof payloads, imports
state, or mutates either peer's journal.

## Stack and authorization

The stack is:

```text
TCP
  -> Noise
  -> Yamux
  -> /naome/proof-chain-head-announcement
  -> ProofChainHeadAnnouncement
```

Announcement is a fourth additive request-response behaviour beside proof,
exact-block, and proof-chain-head pull. It reuses the exact
[`StaticProofNetwork`](authenticated-proof-transport.md) peer allowlist, Noise
identity, deterministic dial ownership, managed redial, connection limits,
caller-driven event loop, tagged pending registry, per-peer pending gate, and
shared application permits. It opens no second TCP connection, and starting an
announcement never initiates a dial.

Learned [`DialCandidate`](peer-address-management.md) values do not authorize
this protocol. Only an identity already present in the immutable static proof
peer configuration may send or receive an application-delivered announcement.
Noise authentication identifies that configured key; it does not establish
operator uniqueness, honesty, availability, or chain authority.

## Public surface

The public Rust surface is equivalent to:

```text
PROOF_CHAIN_HEAD_ANNOUNCEMENT_BYTES = 64
MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION = 1
MAX_EXCHANGE_STREAMS_PER_CONNECTION = 7

ProofChainHeadAnnouncement::new(
    chain_id: ProofChainId,
    head_block_id: ProofBlockId,
) -> ProofChainHeadAnnouncement
ProofChainHeadAnnouncement::chain_id(self) -> ProofChainId
ProofChainHeadAnnouncement::head_block_id(self) -> ProofBlockId
ProofChainHeadAnnouncement::to_wire_bytes(self) -> [u8; 64]
ProofChainHeadAnnouncement::from_wire_bytes(bytes: &[u8])
    -> Result<ProofChainHeadAnnouncement, ProofChainHeadAnnouncementWireError>

StaticProofNetwork::announce_chain_head_from_journal(
    &mut self,
    peer_id: PeerId,
    journal: &ProofChainJournal,
) -> Result<HeadAnnouncementTicket, HeadAnnouncementStartError>

HeadAnnouncementTicket::peer_id(&self) -> PeerId
HeadAnnouncementTicket::announcement(&self) -> ProofChainHeadAnnouncement
HeadAnnouncementTicket::accepts_event(
    &self,
    event: &OutboundProofChainHeadAnnouncementEvent,
) -> bool
HeadAnnouncementTicket::complete(
    self,
    event: OutboundProofChainHeadAnnouncementEvent,
) -> Result<
    Result<AuthenticatedProofChainHeadAnnouncementReceipt, Box<OutboundProofChainHeadAnnouncementFailure>>,
    Box<ProofChainHeadAnnouncementEventMismatch>,
>

ProofChainHeadAnnouncementEventMismatch::into_parts(
    self,
) -> (HeadAnnouncementTicket, OutboundProofChainHeadAnnouncementEvent)

AuthenticatedProofChainHeadAnnouncementReceipt::peer_id(&self) -> PeerId
AuthenticatedProofChainHeadAnnouncementReceipt::announcement(&self)
    -> ProofChainHeadAnnouncement

InboundProofChainHeadAnnouncement::peer_id(&self) -> PeerId
InboundProofChainHeadAnnouncement::announcement(&self)
    -> ProofChainHeadAnnouncement

StaticProofNetwork::acknowledge_chain_head_announcement(
    &mut self,
    inbound: InboundProofChainHeadAnnouncement,
) -> Result<(), HeadAnnouncementAcknowledgeError>

OutboundProofChainHeadAnnouncementEvent::peer_id(&self) -> PeerId
OutboundProofChainHeadAnnouncementEvent::announcement(&self)
    -> ProofChainHeadAnnouncement
```

`NetworkEvent` adds `InboundChainHeadAnnouncement`,
`OutboundChainHeadAnnouncement`, and `InboundChainHeadAnnouncementFailure`.
Private outbound libp2p request identifiers, response channels,
network-instance tokens, receipts, pending entries, and terminal outcomes
remain inaccessible except through their typed handles. Inbound request
identifiers are structurally exposed only on inbound failure events, where the
caller needs them to route the failure; the opaque inbound handle also includes
its private identifier in `Debug` output for diagnostics.

`HeadAnnouncementStartError` has exact `Journal(ProofChainJournalError)` and
`RequestStart(RequestStartError)` variants and exposes either nested cause
through `Error::source`. `OutboundProofChainHeadAnnouncementFailure`
preserves an ordinary request-response transport failure or an authenticated
peer mismatch. A `ProofChainHeadAnnouncementEventMismatch` retains both opaque
values so the caller can route the terminal without losing either generation.
`HeadAnnouncementAcknowledgeError` has the exact `ChannelClosed` variant for a
response channel that closed before libp2p accepted the receipt.
`ProofChainHeadAnnouncementWireError` has the exact
`InvalidLength { actual, expected }` variant; all exact 64-byte values decode,
and every other length fails before it can become an announcement.

## Announcement and receipt framing

The libp2p stream protocol identifier is exactly:

```text
/naome/proof-chain-head-announcement
```

One announcement request occupies one Yamux substream and contains exactly:

```text
proof_chain_id[32]
head_block_id[32]
end of stream
```

The first 32 bytes are the raw `ProofChainId`; the next 32 bytes are the raw
`ProofBlockId`. The reader requires exactly 64 bytes and immediate
end-of-stream. Truncation or any trailing byte is invalid and never reaches the
application as an inbound announcement. There is no tag, version, length,
height, timestamp, sequence, signature, state root, proof payload, or block
body. Any two 32-byte values are syntactically valid; decoding makes no claim
that the chain is recognized or the head is available, related, selected, or
valid.

An explicit acknowledgement writes exactly:

```text
01
end of stream
```

`0x01` is the sole valid receipt. An empty response, any other byte, a second
byte, truncation, timeout, absent response, or reset before the complete frame
is a transport failure and never becomes acknowledgement. Both request and
receipt codecs use fixed stack storage and allocate no message body.

The selected asynchronous Yamux stream API can present either a clean receive
closure or a reset after the complete request or receipt frame as
end-of-stream. The adapter accepts that condition only after all exact frame
bytes have arrived; the authenticated peer and generation checks still apply
before a receipt is exposed.

For an announcement whose chain ID is 32 bytes of `11` and whose head ID is 32
bytes of `22`, the exact request body is:

```text
1111111111111111111111111111111111111111111111111111111111111111
2222222222222222222222222222222222222222222222222222222222222222
```

Line breaks are presentation only. The exact successful receipt is `01`.

## Starting from selected storage

`announce_chain_head_from_journal` derives the immutable announcement from the
borrowed journal in this order:

1. read the health-sensitive current head and preserve every
   `ProofChainJournalError`, including `Poisoned`;
2. after that successful health check, copy the journal's immutable
   `ProofChainId`;
3. construct the exact 64-byte announcement value;
4. require the caller-selected peer to be statically authorized, otherwise
   preserve `UnknownPeer` inside `HeadAnnouncementStartError`;
5. require that peer to have no pending proof, block, head-pull, or head-
   announcement request, otherwise preserve `AlreadyPending`;
6. require both the managed session and the announcement behaviour to observe
   the connection, otherwise preserve `PeerDisconnected`; this does not
   pre-negotiate or prove remote support for the announcement protocol;
7. acquire one shared application permit, otherwise preserve `GlobalLimit`;
   and
8. queue the immutable request and install its announcement-tagged pending
   entry.

Selected-state health therefore precedes every network preflight. An unknown or
disconnected peer cannot mask a poisoned journal, and no network work occurs
when the head read fails. Reading constructs only an observation of the
journal state at this call; the journal may advance immediately afterward.
Neither the announcement nor its eventual receipt is updated to a later head.
For a healthy empty journal, the snapped head is that chain's deterministic
virtual-genesis anchor; the announcement does not turn it into a stored block.

The start operation performs no block lookup, scan, encoding, hash, proof work,
journal or selected-state mutation, disk write, or synchronization. The journal
is not retained or borrowed across asynchronous transport work.

## Generation-safe correlation and terminal precedence

The non-cloneable `HeadAnnouncementTicket` binds:

- the announcement behaviour's private outbound request identifier;
- the exact expected authenticated `PeerId`;
- the complete immutable `ProofChainHeadAnnouncement`; and
- a private token identifying the exact `StaticProofNetwork` instance.

Announcement, proof, block, and head-pull behaviours may produce numerically
equal private request identifiers. The shared pending registry tags all four
namespaces, so a terminal from one protocol cannot remove another protocol's
entry. The existing per-peer gate prevents concurrent outbound application
requests of different exchange kinds to the same peer.

One outbound terminal is processed in this order:

1. locate and remove only the exact announcement-tagged pending entry;
2. require the terminal's authenticated peer to equal the retained peer,
   reporting `PeerMismatch` before interpreting a receipt or transport error;
3. preserve an ordinary libp2p, framing, or receipt failure as `Transport`; or
4. retain the valid receipt until the exact ticket consumes it.

In particular, a remote peer that authenticates on the managed connection but
does not negotiate `/naome/proof-chain-head-announcement` produces a terminal
`Transport` failure after start; unsupported protocol is not a start-preflight
error.

`accepts_event` requires equality of the private request generation, expected
peer, complete announcement, and network-instance token. `complete` exposes a
successful `AuthenticatedProofChainHeadAnnouncementReceipt` only after all four
match. A mismatched ticket cannot inspect the private receipt or failure and
returns both values unchanged through
`ProofChainHeadAnnouncementEventMismatch::into_parts`.

The authenticated wrapper proves only that the exact peer returned `0x01` for
the exact announcement generation. It does not prove that the peer stored,
served, requested, validated, selected, or agreed with the announced head.

## Inbound acknowledgement and event ownership

After strict request framing, `next_event` emits one
`InboundChainHeadAnnouncement` containing the authenticated sender, immutable
announcement, and private response channel. The caller may inspect the source
and values, apply its own bounded policy, and explicitly pass the same inbound
value to `acknowledge_chain_head_announcement`.

Acknowledgement requires no journal and performs no chain lookup, local-head
comparison, block request, deduplication, cache insertion, or journal or
selected-state mutation.
It transfers the fixed `0x01` receipt to libp2p through the authoritative
response-channel send. A closed channel returns
`HeadAnnouncementAcknowledgeError::ChannelClosed`. Dropping or declining the
inbound value sends no receipt; the sender eventually observes an ordinary
terminal transport failure.

An inbound framing or stream failure is exposed through
`InboundChainHeadAnnouncementFailure` when the pinned libp2p behaviour reports
it. The transport does not claim that every failure before application
delivery produces such an event.

A successful outbound event retains its shared permit until the matching
ticket completes it or the event is dropped. An ordinary terminal failure
releases bounded request state according to the existing terminal lifecycle.
Dropping the ticket does not cancel the physical request: its peer slot and
permit remain occupied until libp2p emits the terminal event, which remains
visible through `next_event`.

## Composition boundary

Receiving an announcement does not automatically invoke the existing
[Authenticated Proof Block Transport](authenticated-proof-block-transport.md),
[Caller-Selected Proof Block Ancestry Pull](caller-selected-proof-block-ancestry-pull.md),
or [Caller-Selected Proof Block Ancestry Import](caller-selected-proof-block-ancestry-import.md).
The receiver may expose the source-bound observation to caller policy, but only
a later explicit caller choice may use the announced ID as an exact retrieval
or ancestry target.

The announced head must not be passed to
`ProofChainJournal::open_verified` as a trusted expected head solely because
Noise authenticated the sender or the receiver returned a receipt. Establishing
checkpoint authority is a separate consensus or operator-trust contract.

The separate
[Caller-Selected Proof Chain Head Broadcast](caller-selected-proof-chain-head-broadcast.md)
composes this exact single-peer operation across at most eight explicit peers.
It does not change this message, receipt, authentication, correlation, or
terminal contract.

## Resource bounds

The announcement adds these exact bounds to the static network:

| Resource | Limit |
| --- | ---: |
| Announcement request body | 64 bytes |
| Receipt body | 1 byte, exactly `0x01` |
| Announcement streams per connection | 1 |
| Proof exchange streams per connection | 2 |
| Proof-block exchange streams per connection | 2 |
| Proof-chain-head pull streams per connection | 2 |
| Aggregate exchange streams per connection | 7 |
| Negotiating inbound streams per connection | 2 |
| Yamux substreams per connection | 8 |
| Shared pending or retained application permits | 8 |
| Pending outbound application requests per peer | 1 |
| Protocol negotiation timeout | 10 seconds, pinned libp2p behaviour |
| Negotiated request-response phase timeout | 30 seconds |

The fourth behaviour adds separate protocol negotiation and fixed-size stream
state but reuses the same managed connection. Its one stream keeps the maximum
aggregate at seven, below the hard Yamux limit of eight. It does not increase
the maximum retained proof-payload bound because every pending or retained
announcement consumes one of the same eight permits.

These are per-message, concurrent, connection, and timeout bounds. They are not
a rolling request-rate or fairness policy. The shared per-peer gate bounds one
node's outbound application request to a peer, while the announcement
behaviour's one-stream-per-connection limit separately bounds inbound
announcement concurrency. A statically authorized peer may still send repeated
sequential valid announcements; constant-space decoding and those concurrent
bounds do not prevent sustained application-event or bandwidth load. Caller
policy remains responsible for whether to acknowledge successive observations.

## Compatibility and security boundary

The protocol identifier and message are additive. Existing proof, exact-block,
and head-pull protocol identifiers and bytes remain unchanged. Canonical proof
bytes, `ProofBlockId`, journal prefix, entries, replay, and selected-state
validation are unchanged. This feature introduces no storage byte, format
version, legacy parser, migration, or local-data recreation requirement.

Noise authenticates the configured peer. The private request generation,
tagged protocol namespace, complete immutable announcement, and network token
bind one physical receipt. The announcement contains no signature beyond the
live authenticated session and cannot be replayed as evidence that the peer
still has the same head. Static authorization remains neither Sybil resistance
nor validator, proposer, checkpoint, consensus, finality, or economic
authority.

## Explicit exclusions

This single-peer contract defines no automatic journal emission, commit hook,
automatic or all-configured-peer broadcast, head survey, scheduler, polling,
retry, fallback, hedging, rebroadcast, subscription, gossip, DHT, dynamic
learned-peer authorization,
deduplication, cache, persistence, monotonic sequence, timestamp, height,
freshness, ordering between announcements, comparison with the receiver's head,
majority, quorum, vote, peer scoring, reputation, rolling rate limit, block or
proof request, range or ancestry request, automatic target selection, proof
acquisition, block preparation, import, selected-state mutation, background
synchronization, orphan pool, competing-fork storage, fork choice, rollback,
reorganization, checkpoint trust, proposer, signature, proof of work, proof of
stake, validator set, voting, consensus, finality, reward, fee, balance,
novelty policy, issuance, or settlement.
