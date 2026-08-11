# NAOME Authenticated Proof Chain Head Pull

## Status and scope

This document defines one concrete, bounded authenticated transport binding for
the [Proof Chain Head Exchange](proof-chain-head-exchange.md). It is a prerelease
transport contract and may change before the first stable protocol release.

The caller asks one already configured static proof peer for its current local
head in one exact `ProofChainId` context. A complete response is either the raw
observed `ProofBlockId` or peer-local `Unavailable`. The caller drives the
network event loop and explicitly responds to inbound requests; the transport
starts no runtime, polling task, retry loop, or NAOME-owned background task.

This is authenticated source attribution for one pull, not trusted head
discovery, synchronization, announcement, selection, or consensus. The peer may
be stale, ahead, on another history, misconfigured, or dishonest. A found head
is never imported automatically and is never a trusted expected head for
`ProofChainJournal::open_verified`.

## Stack and authorization

The stack is:

```text
TCP
  -> Noise
  -> Yamux
  -> /naome/proof-chain-head-exchange
  -> Proof Chain Head Exchange
```

Head pull is a third, separate request-response behaviour beside
`/naome/proof-exchange` and `/naome/proof-block-exchange`. It reuses the exact
[`StaticProofNetwork`](authenticated-proof-transport.md) peer allowlist, Noise
identity, deterministic dial ownership, connection limits, bounded redial,
caller-driven swarm, shared pending registry, and shared application permits.
It opens no second TCP connection, and a head request never initiates a dial.

The separate protocol preserves the exact-ID block protocol's fixed 32-byte
address request and response validation unchanged. It also permits a peer that
does not yet support head pull to continue negotiating existing proof and block
exchange; an unsupported head protocol is an ordinary head-request transport
failure, not a reason to reinterpret another protocol's bytes.

Learned peer-address records never authorize this protocol. Only an identity
already present in the static proof-peer configuration may participate.

## Public surface

The public Rust surface is equivalent to:

```text
StaticProofNetwork::request_chain_head(
    &mut self,
    peer_id: PeerId,
    request: ProofChainHeadRequest,
) -> Result<ChainHeadRequestTicket, RequestStartError>

ChainHeadRequestTicket::peer_id(&self) -> PeerId
ChainHeadRequestTicket::request(&self) -> ProofChainHeadRequest
ChainHeadRequestTicket::accepts_event(&self, event: &OutboundProofChainHeadEvent)
    -> bool
ChainHeadRequestTicket::complete(
    self,
    event: OutboundProofChainHeadEvent,
) -> Result<
    Result<AuthenticatedProofChainHeadResponse, Box<OutboundProofChainHeadFailure>>,
    Box<ProofChainHeadRequestEventMismatch>,
>

ProofChainHeadRequestEventMismatch::into_parts(
    self,
) -> (ChainHeadRequestTicket, OutboundProofChainHeadEvent)

AuthenticatedProofChainHeadResponse::peer_id(&self) -> PeerId
AuthenticatedProofChainHeadResponse::request(&self) -> ProofChainHeadRequest
AuthenticatedProofChainHeadResponse::is_unavailable(&self) -> bool
AuthenticatedProofChainHeadResponse::head_block_id(&self) -> Option<ProofBlockId>

InboundProofChainHeadRequest::peer_id(&self) -> PeerId
InboundProofChainHeadRequest::request(&self) -> ProofChainHeadRequest

StaticProofNetwork::respond_chain_head_from_journal(
    &mut self,
    inbound: InboundProofChainHeadRequest,
    journal: &ProofChainJournal,
) -> Result<(), RespondError>

OutboundProofChainHeadEvent::peer_id(&self) -> PeerId
OutboundProofChainHeadEvent::request(&self) -> ProofChainHeadRequest
```

`NetworkEvent` adds `InboundChainHeadRequest`, `OutboundChainHead`, and
`InboundChainHeadFailure`. Request handles, response channels, pending-map keys,
network-instance tokens, and response outcomes remain private. Only the exact
matching non-cloneable ticket may extract one terminal outcome.

`RequestStartError` and `RespondError` remain shared because proof, block, and
head exchange use the same authenticated session, per-peer slot, global permit,
journal health boundary, and response-channel ownership.

`OutboundProofChainHeadFailure` has these terminal classes:

```text
Transport(request_response::OutboundFailure)
PeerMismatch { expected: PeerId, actual: PeerId }
```

Every malformed, truncated, trailing, or invalid-length frame fails in the
codec as `Transport`. `PeerMismatch` precedes transport classification in both
response and outbound-failure event paths.

## Framing

The libp2p stream protocol identifier is exactly:

```text
/naome/proof-chain-head-exchange
```

One request-response exchange occupies one Yamux substream. Its request is:

```text
proof_chain_id[32]
end of stream
```

The reader requires exactly 32 bytes and immediate end-of-stream. Truncation or
one trailing byte is invalid and never reaches the application as a request.

The response frame is:

```text
response_length u8
response        response_length bytes
end of stream
```

`response_length` must be exactly `0` or `32`. Zero is `Unavailable`; 32 is one
raw `ProofBlockId`. Every other declared length is rejected before reading or
allocating a body. A missing or truncated prefix, truncated body, trailing byte,
timeout, or reset before the complete declared frame is a transport failure and
never becomes `Unavailable`. The one-byte prefix is transport framing only and
is not part of the transport-neutral response. The codec uses fixed 32-byte
stack storage and allocates no response body.

The selected asynchronous Yamux stream API can present either a clean receive
closure or a reset after a complete frame as end-of-stream. The adapter accepts
that condition only after the exact declared bytes have arrived; subsequent
response decoding and request correlation still apply.

For the 32-byte-`11` chain context in the transport-neutral golden, the exact
request body is the 64 hexadecimal `1` digits shown there. A matching empty
journal's response frame is the hexadecimal one-byte length `20` followed by:

```text
f47ee4acce1f5797ff773e7b620cfc66b101dfadb0b87cb4f83e3b94765c8b98
```

The exact mismatched-chain unavailable frame is `00`.

## Starting a request and shared budgets

`request_chain_head` executes these preflights before queuing libp2p work:

1. require the peer to be statically authorized, otherwise `UnknownPeer`;
2. require that peer to have no pending outbound proof, block, or head request,
   otherwise `AlreadyPending`;
3. require both the managed session and head-exchange behaviour to be connected,
   otherwise `PeerDisconnected`;
4. acquire one slot from the shared eight-permit application budget, otherwise
   `GlobalLimit`; and
5. queue the immutable request and install its chain-head-tagged pending entry.

Proof, block, and head behaviours may produce numerically equal private libp2p
request identifiers. The shared pending map tags all three namespaces, so one
protocol terminal cannot remove another protocol's entry. The shared per-peer
gate prevents simultaneous outbound exchange requests of any of the three kinds
to the same peer.

A successful response retains its permit in the opaque outbound event until the
event is completed by its ticket or dropped. A terminal failure releases its
permit according to the existing terminal lifecycle. Dropping the ticket does
not cancel the physical request; the pending peer slot and permit remain until
libp2p emits its terminal event.

## Generation-safe correlation and response handling

The opaque request ticket binds:

- the head behaviour's private outbound request identifier;
- the expected authenticated `PeerId`;
- the immutable `ProofChainHeadRequest`; and
- a private token identifying the exact `StaticProofNetwork` instance.

An outbound response or failure terminal is processed in this order:

1. locate and remove only the exact chain-head-tagged pending entry;
2. require the terminal's authenticated peer to equal the retained peer,
   reporting `PeerMismatch` before interpreting response bytes or a transport
   error;
3. preserve an ordinary libp2p or codec failure as `Transport`; or
4. retain the already typed empty-or-found response.

The resulting event remains opaque and carries the same request, peer, private
generation, and network-instance identity. `ChainHeadRequestTicket::complete`
checks all four before exposing the response or failure. A wrong-network,
wrong-protocol, wrong-generation, wrong-peer, or wrong-request event cannot be
consumed merely because some public values or private numeric counters happen
to coincide.

`Unavailable` remains one authenticated peer's response for one exact chain
context. A found response remains an untrusted peer observation. Authentication
identifies who supplied the bytes; it does not prove freshness, honesty,
ancestry, availability, network selection, or finality.

## Inbound serving and journal precedence

After strict request framing, `next_event` emits one
`InboundChainHeadRequest` containing the authenticated peer, immutable request,
and private response channel. The caller may pass it with a borrowed
[`ProofChainJournal`](proof-chain-journal.md) to
`respond_chain_head_from_journal`.

Serving executes in this order:

1. query journal health through the transport-neutral helper and preserve every
   `ProofChainJournalError`, including `Poisoned`;
2. compare the immutable requested `ProofChainId` with the journal context;
3. choose `Unavailable` for a mismatch or the exact journal head for a match;
4. require the response channel to remain open;
5. encode only the zero- or 32-byte transport-neutral response; and
6. transfer the bounded frame to libp2p.

Journal poisoning therefore precedes chain mismatch, channel closure, and
response encoding. A matching empty journal returns its virtual genesis parent;
it does not return `Unavailable`. Serving performs no block lookup, scan, hash,
proof work, state mutation, disk write, or synchronization.

## Composition boundary

Completing a head ticket yields only the response to that exact authenticated
pull. The transport does not request the observed block, start proof dependency
acquisition, call `ProofChainJournal::prepare_block` or `apply_block`, or invoke
the [Caller-Selected Proof Block Import](caller-selected-proof-block-import.md).

After applying its own policy, a caller may explicitly use a found ID with the
[Authenticated Proof Block Transport](authenticated-proof-block-transport.md)
or explicitly choose it as the target for the
[Caller-Selected Proof Block Ancestry Pull](caller-selected-proof-block-ancestry-pull.md).
That separate bounded operation retrieves only a structurally root-continuous,
unselected path to the caller's captured local head. The caller may instead
explicitly choose a direct child as a target for the existing importer, which
retains exact block identity, current-parent, proof-root, payload,
mathematical-validation, atomicity, and durable-commit checks. There is no
convenience API that converts `OutboundChainHead` directly into either
operation.

The observation must not be passed to `ProofChainJournal::open_verified` as a
trusted expected head solely because Noise authenticated the serving peer.
Establishing checkpoint authority is a later consensus or operator-trust
contract.

## Resource bounds

This protocol changes the bounded static network totals as follows:

| Resource | Limit |
| --- | ---: |
| Head request body | 32 bytes |
| Head response length prefix | 1 byte |
| Head response body | 0 or 32 bytes |
| Complete head response frame | 1 or 33 bytes |
| Streams per proof exchange per connection | 2 |
| Streams per proof-block exchange per connection | 2 |
| Streams per proof-chain-head exchange per connection | 2 |
| Aggregate exchange streams per connection | 6 |
| Negotiating inbound streams per connection | 2 |
| Yamux substreams per connection | 8 |
| Shared pending or retained application permits | 8 |
| Pending outbound proof, block, or head requests per peer | 1 |
| Protocol negotiation timeout | 10 seconds, pinned libp2p behaviour |
| Negotiated request-response phase timeout | 30 seconds |

The third behaviour adds separate protocol negotiation and bounded stream state
but reuses the same TCP, Noise, and Yamux connection. Six aggregate exchange
streams remain below the Yamux limit of eight. The existing two-stream inbound
negotiation cap remains unchanged.

The application-level pending count remains eight across all three protocols,
and each peer still occupies at most one outbound application request. A head
response retains at most one 32-byte digest plus fixed ticket/event metadata. It
does not increase the maximum retained proof-payload bound and adds no journal
entry, synchronization barrier, storage-format byte, block hash, or proof check.

These are concurrent and per-message limits, not rolling request-rate or
bandwidth quotas. An authorized peer may still issue repeated sequential pulls;
the constant-space journal lookup and fixed response bound limit the work per
pull but do not establish peer fairness.

## Compatibility and security boundary

The new protocol identifier is additive. Existing proof and exact-block
protocol bytes, canonical block bytes, `ProofBlockId`, virtual-genesis
derivation, journal entries, and journal prefix remain unchanged. No storage
migration, compatibility parser, alternate journal, or legacy head message is
introduced.

Noise authenticates the static peer, while the private request generation,
tagged protocol namespace, immutable chain request, and network-instance token
bind the physical terminal. A chain-scoped request catches an honest journal
context mismatch without granting the responder authority over the returned
head. Static authorization remains neither Sybil resistance nor validator,
checkpoint, consensus, or economic authority.

## Explicit exclusions

This contract defines no periodic polling, scheduler, push, block announcement,
subscription, gossip, DHT, dynamic learned-peer authorization, peer scoring,
freshness, timestamp, monotonic head sequence, height, parent query, child query,
range query, ancestry walk, multi-block synchronization, block retry, peer
fallback, hedging, orphan pool, competing-fork storage, automatic block request,
automatic proof acquisition, automatic import, selected-state mutation, trusted
`open_verified` anchor, fork choice, rollback, reorganization, checkpoint
authority, proposer, signature, proof of work, proof of stake, validator set,
voting, quorum, consensus, finality, reward, fee, balance, novelty policy,
issuance, or settlement.
