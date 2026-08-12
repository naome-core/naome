# NAOME Journal-Backed Static Proof Node Service

## Status and scope

This document defines the prerelease V0 caller-driven serving adapter for one
[`StaticProofNetwork`](authenticated-proof-transport.md) and one borrowed
[`ProofChainJournal`](proof-chain-journal.md). It automatically answers the
three journal-backed inbound request families already carried by the static
proof network:

- exact proof retrieval;
- exact committed proof-block retrieval; and
- one chain-scoped local-head pull.

The adapter composes the existing request types, response helpers, codecs,
authenticated connections, and resource limits. It adds no protocol, message,
connection, request slot, retry, runtime, task, or storage format. The caller
still owns the Tokio runtime and drives one event at a time.

This is a serving convenience boundary, not a complete node daemon. In
particular, proof-chain-head announcements remain explicit caller-policy input
and are never acknowledged by this adapter.

## Public surface

The public Rust surface is equivalent to:

```text
StaticProofNetwork::next_journal_service_event(
    &mut self,
    journal: &ProofChainJournal,
) -> impl Future<Output = JournalServiceEvent>

JournalServiceRequest::Proof {
    peer_id: PeerId,
    request: ProofRequest,
}
JournalServiceRequest::Block {
    peer_id: PeerId,
    request: ProofBlockRequest,
}
JournalServiceRequest::ChainHead {
    peer_id: PeerId,
    request: ProofChainHeadRequest,
}

JournalServiceEvent::Served(JournalServiceRequest)
JournalServiceEvent::ServeFailed {
    request: JournalServiceRequest,
    error: RespondError,
}
JournalServiceEvent::Network(NetworkEvent)
```

`next_journal_service_event` is asynchronous. `JournalServiceRequest` is an owned,
channel-free description of the exact request consumed by the service. Every
variant retains the Noise-authenticated, statically authorized requester
`PeerId` and the complete immutable transport-neutral request. It exposes no
libp2p request identifier, response channel, connection identifier, journal
record, or response bytes.

`JournalServiceEvent` is non-exhaustive and must be consumed. `Served` and
`ServeFailed` are the only events introduced by this adapter. The `Network`
variant owns the original event unchanged, including every private ticket,
response channel, retained permit, and typed failure carried by that event.

The existing lower-level `next_event`, `respond_proof_from_journal`,
`respond_block_from_journal`, and `respond_chain_head_from_journal` APIs remain
available. The service is one compact composition of them, not a replacement
protocol or a second event loop.

## Dispatch and event ownership

Each call waits for exactly one externally relevant `NetworkEvent` from the
same `StaticProofNetwork` event loop, then applies this exhaustive dispatch:

| Input event | Action | Returned event |
| --- | --- | --- |
| `InboundProofRequest` | Serve through `respond_proof_from_journal` | `Served(Proof)` or `ServeFailed { request: Proof, error }` |
| `InboundBlockRequest` | Serve through `respond_block_from_journal` | `Served(Block)` or `ServeFailed { request: Block, error }` |
| `InboundChainHeadRequest` | Serve through `respond_chain_head_from_journal` | `Served(ChainHead)` or `ServeFailed { request: ChainHead, error }` |
| Every other `NetworkEvent` | No interpretation or side effect | `Network(original_event)` |

The request description is captured before its private inbound response
channel is consumed. Exactly one service event is returned for each delivered
inbound request. A local serving failure does not terminate the adapter, retry
the request, choose a substitute response, or hide the next network event; the
caller may call `next_journal_service_event` again.

Forwarding covers, without special cases:

- outbound proof, block, head-pull, and head-announcement terminals;
- dependency-acquisition cancellation drains;
- every inbound request-stream failure;
- managed peer-session events;
- listener addresses, errors, and closure; and
- inbound proof-chain-head announcements.

An inbound announcement therefore remains an intact
`NetworkEvent::InboundChainHeadAnnouncement`. Only an explicit later call to
`acknowledge_chain_head_announcement` can send its receipt. Merely driving the
journal service sends no receipt and does not compare the announced head with
the local journal.

The caller must not drive `next_event` and `next_journal_service_event`
concurrently on the same mutable network. Rust's exclusive mutable borrow
prevents this in safe code. The caller may deliberately alternate the two
methods, but any event taken through `next_event` remains the caller's
responsibility.

## Serving semantics and error precedence

All three handled request families retain their existing protocol-specific
serving behavior and ordering. The adapter does not duplicate journal lookup,
encoding, channel checks, or response submission.

For a proof request:

1. query the healthy journal for the exact `ProofId`;
2. preserve any `ProofChainJournalError`;
3. require the response channel to remain open;
4. copy a found immutable canonical proof once into the bounded owned response,
   or construct `Unavailable` for a missing proof; and
5. submit that response to the existing proof-exchange behaviour.

For a block request:

1. query the healthy journal for the exact `ProofBlockId`;
2. preserve any `ProofChainJournalError` and the existing exact-ID invariant;
3. require the response channel to remain open;
4. encode a found committed block once, or construct `Unavailable` for a
   missing block or virtual-genesis anchor; and
5. submit that response to the existing block-exchange behaviour.

For a chain-head request:

1. read the healthy journal head;
2. preserve any `ProofChainJournalError` before interpreting chain context;
3. compare the requested `ProofChainId` with the immutable journal context;
4. choose the exact local head for a match or `Unavailable` for a mismatch;
5. require the response channel to remain open; and
6. submit the existing fixed-size response.

Consequently, `RespondError::Journal` precedes
`RespondError::ChannelClosed`. For chain-head requests, journal health also
precedes chain mismatch. No journal failure becomes `Unavailable`, and no
channel failure becomes a successful service event.

`Served` means only that the response was derived successfully and accepted by
the local libp2p response channel. It does not prove that the peer received,
decoded, retained, trusted, or used the response. A later stream failure may
still be exposed by the underlying network when libp2p reports it.

`ServeFailed` preserves the exact request description and the complete
`RespondError`. The consumed response channel is not returned because retrying
on that generation would violate its single-response ownership. Journal
recovery, reconnect, and any peer retry remain caller responsibilities.

## Journal and trust boundary

The future borrows `&ProofChainJournal` while it waits for the next network
event. If that event is a supported inbound request, all journal work after the
event arrives is one synchronous response lookup. The borrow ends when the
service call returns and is not retained by the asynchronous stream write.
Serving can read journal health, the exact selected proof or block, the
immutable chain context, and the current selected head. It cannot prepare,
apply, import, truncate, reopen, or otherwise mutate the journal.

A response reports only the state of this one healthy local selected journal:

- a proof response establishes only local retention of those exact canonical
  bytes;
- a block response establishes only local commitment of that exact block;
- a head response is only a peer-local, chain-scoped availability observation;
  and
- `Unavailable` is never global absence evidence.

Noise authentication identifies the serving and requesting configured peers.
It does not establish honesty, freshness, mathematical validity beyond the
local admission already represented by the journal, shared chain selection,
finality, or consensus.

## Liveness and resource bounds

The adapter starts no background task. Listener progress, managed-session
redial, protocol negotiation, request reads, response writes, timeouts, and
terminal delivery advance only while the caller continues polling the network
through `next_journal_service_event` or the lower-level `next_event`.

Every existing static-network bound remains authoritative, including at most
eight configured peers, one established connection per peer, the per-protocol
stream caps, the aggregate Yamux cap, and the existing request and timeout
limits. The service adds no queue and retains no request or response between
calls. A returned `JournalServiceRequest` contains fixed-size identities and
content addresses only.

Found-proof serving retains the unavoidable single bounded proof-sized copy
owned by the asynchronous response. Found-block serving retains its one bounded
canonical encoding. Head serving remains fixed-size and allocation-free at the
transport-neutral response boundary. The adapter itself performs no proof
checking, block decoding, hashing, journal scan, or additional payload copy.

## Security boundary and exclusions

V0 provides one fail-closed, caller-driven routing point that consistently
serves valid inbound proof, block, and head pulls from one borrowed healthy
journal and exposes every other event unchanged.

It does not define or perform:

- automatic acknowledgement, caching, deduplication, comparison, retrieval,
  or import in response to a head announcement;
- automatic head broadcast, polling, synchronization, ancestry traversal,
  dependency acquisition, proof selection, or block application;
- request retry, peer fallback, fairness scheduling, response caching,
  snapshots, or a second serving queue;
- peer discovery, dynamic peer authorization, address admission, DHT, mDNS,
  Rendezvous, NAT traversal, relay, or hole punching;
- identity-key persistence, configuration parsing, signal handling, process
  supervision, metrics export, a command-line interface, or a node daemon;
- competing-fork storage, fork choice, checkpoint authority, consensus,
  finality, validator roles, mining, transactions, rewards, fees, or
  settlement; or
- any protocol, codec, message, dependency, migration, or storage-format
  change.

Those responsibilities require separate explicit contracts. In particular, a
later executable may own this service loop, but must add key custody,
configuration, journal lifecycle, startup, and shutdown without weakening the
event and trust boundaries defined here.

## Acceptance contract

The executable reference implementation must demonstrate:

1. exact routing and request descriptors for proof, block, and chain-head
   inbound events;
2. both found and `Unavailable` responses through the unchanged codecs;
3. exact preservation of `RespondError` and request context on local failure;
4. unchanged forwarding of every non-served event family, especially an
   acknowledgement-capable inbound head announcement;
5. no hidden acknowledgement, import, outbound request, connection, retry, or
   task;
6. a real TCP/Noise/Yamux exchange in which independent static swarms
   concurrently retrieve a proof, block, and chain head while the server is
   driven only through `next_journal_service_event`; and
7. byte-identical journal storage and unchanged chain ID, head, proof-set root,
   selected-proof count, and exact proof/block lookups before and after
   serving.

Local unit evidence does not by itself establish multi-process, multi-machine,
WAN, NAT, long-running availability, deployment, or production operability.
