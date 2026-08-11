# NAOME Authenticated Peer Record Pull

## Status and scope

This document defines the prerelease V0 outbound client binding for
[Peer Record Exchange](peer-record-exchange.md). It lets one node pull a
canonical bounded record batch from an operator-configured `BootstrapPeer`
over TCP, Noise, Yamux, and libp2p request-response, then explicitly admit that
batch into the [peer-address store](peer-address-management.md).
A compatible inbound service is defined separately by the
[Authenticated Peer Record Responder](authenticated-peer-record-responder.md).

The client is a dedicated network boundary. It is not a behavior inside
`StaticProofNetwork`, exposes no listener or response API, advertises no
inbound record protocol, and cannot authorize an identity for proof exchange.
The configured bootstrap identity is routing provenance only.

## Configuration and authentication

One `PeerRecordBootstrapClient` has one local libp2p identity and zero to eight
validated `BootstrapPeer` entries. It reuses the exact canonical configuration
rules from Peer Address Management: no local identity, duplicate identity,
unsupported address shape, zero port, overlong address, or ninth bootstrap is
accepted.

Starting a pull first requires the requested `PeerId` in that immutable
configuration. A cold pull gives libp2p exactly the configured `PeerId` and
address. Noise must authenticate that expected identity; reaching the address
with a different key produces a terminal transport failure and no batch.
There is no DNS, learned-address substitution, discovery behavior, or fallback
address in this client.

The protocol identifier is exactly:

```text
/naome/peer-record-exchange
```

It is configured as libp2p `ProtocolSupport::Outbound`. Pending and established
inbound connection limits are zero, inbound substream negotiation capacity is
zero, and the public client surface has no listen or respond operation. The
proof-exchange protocol is not installed in this swarm.

## Request and response

The request and response bodies are exactly the transport-neutral values from
Peer Record Exchange. The request writes zero bytes and closes its write half.
The response is EOF-framed; it adds no outer length prefix:

```text
record_count_u8
record_count * (envelope_length_u16_be || signed_envelope)
end of stream
```

The stream codec reads the count before reserving the response buffer. For
every item, it reads the two-byte declared length, rejects zero or more than
4096 before growing or reading that body, and then reads exactly the declared
bytes. It requires EOF before signature and canonical-batch decoding. This
ordering retains only the bounded raw buffer if a peer sends a complete body
but stalls before closing, and rejects a trailing byte before cryptographic
work. The canonical batch decoder remains authoritative for signatures,
standard-envelope domain, subject identity, address grammar, normalization,
strict subject ordering, duplicates, and exact complete-body validity.

An empty batch means only that this bootstrap returned no records in this
pull. It is not a completeness claim, negative cache entry, or network-wide
absence result.

## Correlation and ownership

Every successfully started pull has one libp2p `OutboundRequestId`, one
expected configured source, and one non-cloneable source permit. Request IDs
are unique within this private request-response behavior. A terminal response
or failure advances state only when its exact request ID remains pending. An
unknown or stale request ID is ignored. The terminal event's authenticated
peer must equal the expected configured source; a mismatch is a typed terminal
failure and never yields a batch.

One source may own exactly one of these states:

```text
idle -> pending wire request -> delivered authenticated batch -> admitted/drop
                         \-> terminal failure -> idle
```

The delivered `AuthenticatedPeerRecordBatch` is intentionally not cloneable
and exposes no bare-batch escape. It privately retains both the verified batch
and authenticated source. Its source permit is released only after the batch
is consumed by `PeerAddressStore::admit_record_batch`—whether admission
succeeds or fails—or after the wrapper is dropped. The permit therefore spans
the complete synchronous durable admission call.

Because configuration contains at most eight unique sources and each source
has one permit bit, active requests plus delivered-but-unadmitted responses
are globally at most eight without a second counter or limit. No source can be
restarted while its prior response is retained.

## Connection lifecycle and limits

A disconnected pull uses libp2p's one-shot exact-address request dial. A pull
on a still healthy authenticated connection reuses it without allocating a
second address vector. The connection carries at most one record-exchange
stream at a time and each source has at most one established connection. There
are at most eight pending outbound connections and eight established outbound
connections for the complete client.

The fixed phase limits are:

| Resource | Limit |
| --- | ---: |
| Configured bootstrap sources | 8 |
| Active or retained pull per source | 1 |
| Active or retained pulls per client | 8, derived from source slots |
| Pending outbound connections | 8 |
| Established outbound connections | 8 |
| Established connections per source | 1 |
| Concurrent record streams per connection | 1 |
| TCP/Noise/Yamux establishment | 10 seconds |
| Outbound record-protocol negotiation | 10 seconds |
| Negotiated request/response phase | 30 seconds |
| Fully idle authenticated connection | 10 seconds |
| Request bytes | 0 |
| Maximum response bytes | 131137 |

There is no application-level keepalive. After all streams and handler work
finish, the explicit ten-second idle timeout closes an unused connection. A
manual follow-up before that closure may reuse the authenticated connection.
The compatible responder likewise permits sequential requests on one healthy
connection while its idle and global valid-request limits allow them. The
client does not assume that reuse will succeed and never retries automatically.
For a cold pull that is continuously polled, the phase ceilings expose up to
ten seconds of connection establishment, then ten seconds of outbound
substream protocol negotiation, then thirty seconds of negotiated exchange.
These are consecutive physical phase limits, not one resettable application
deadline.
The client performs no automatic retry, fallback, periodic refresh, managed
redial, or backoff. A caller may request another pull only after the prior
source permit is released.

With eight maximum wire buffers, declared response bytes are at most
`8 * 131137 = 1049096`. During canonical decode, normalized signed-envelope
storage is at most `8 * 32 * 4096 = 1048576` bytes and decoded binary address
storage at most `8 * 32 * 4 * 256 = 262144` bytes. These bounded payload
components total at most `2359816` bytes, excluding fixed structs, allocator
and libp2p internals, and the bounded one-record protobuf/signature temporary.
Only the normalized batch remains after codec return; the raw stream buffer is
dropped.

All liveness bounds require the caller to continue polling `next_event`.
Stopping the event loop suspends connection progress and timeout delivery.

## Errors and admission

Start-error precedence is:

1. unknown bootstrap identity;
2. source already active or retained.

A separate global-limit error does not exist: under the immutable eight-source
configuration and one-per-source rule it would be unreachable.

For a terminal libp2p event, exact request-ID presence is checked first, then
authenticated peer equality, then response or transport-failure handling.
Transport authentication, dialing, negotiation, timeout, connection closure,
I/O, framing, signature, or canonicality failure never becomes an empty batch
and never mutates the store.

Admission is an explicit consuming operation. It passes the private
authenticated source, the complete verified batch, and one caller-supplied
local receipt time into the existing atomic batch transaction. Store health,
source configuration, receipt time, local-subject, sequence, capacity,
allocation, commit, and poison precedence remain exactly those of Peer Record
Exchange and Peer Address Management. `next_event` itself performs no disk I/O.

## Security boundary and exclusions

V0 authenticates the exact configured bootstrap that supplied one bounded
response, preserves that source through atomic admission, limits concurrent
wire and retained response ownership, and keeps record routing separate from
proof authorization. It does not establish reachability of any signed address
inside the batch, honest operation, operator independence, Sybil resistance,
or eclipse resistance.

This contract does not define or claim:

- record publication or serving selection, store export, pagination, cursor,
  completeness commitment, freshness assertion, or bundled seed list; the
  separate responder serves one immutable operator-supplied batch, whose
  selection the client does not treat as authoritative;
- an inbound record service, push, gossip, subscriptions, periodic pulling,
  automatic retry, multi-bootstrap fallback, scoring, reputation, or bans;
- dynamic sessions to learned candidates, conversion to `StaticPeer`, proof
  authorization, proof exchange on bootstrap connections, or proof gossip;
- DNS, mDNS, Rendezvous, Kademlia, NAT traversal, relay, or hole punching; or
- consensus, fork choice, finality, mining, validator roles, checkpoints,
  transactions, rewards, fees, or settlement.

Dynamic learned-candidate sessions and any proof authorization remain later
separate contracts.
