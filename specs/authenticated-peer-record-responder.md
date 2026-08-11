# NAOME Authenticated Peer Record Responder

## Status and scope

This document defines the prerelease V0 inbound server binding for
[Peer Record Exchange](peer-record-exchange.md). One
`PeerRecordBootstrapResponder` serves exactly one explicit immutable canonical
`PeerRecordBatch` over TCP, Noise, Yamux, and libp2p request-response. It is the
compatible serving boundary for the separate outbound
[Authenticated Peer Record Pull](authenticated-peer-record-pull.md).

The responder is a dedicated inbound-only swarm. It is not part of
`StaticProofNetwork`, does not install the proof-exchange protocol, and does not
read or mutate the [peer-address store](peer-address-management.md). A
requester's authenticated identity is observability and bounded-connection
state only; it grants no proof or publication authority.

## Immutable operator publication

Construction consumes one already verified canonical `PeerRecordBatch` of zero
to 32 records. Before constructing the network swarm, the responder encodes the
complete batch once into the exact Peer Record Exchange response and drops the
decoded batch. It retains one shared immutable encoded buffer for its complete
lifetime. Every successfully served request is queued with those identical
bytes; serving a request clones only shared ownership of that buffer at the
application-codec boundary and does not rebuild or copy the publication there.
An operator may construct one batch entry through the separate
[local peer-record issuer](local-peer-record-issuance.md), but issuance and
batch selection both finish before responder construction.

The public surface exposes the local `PeerId`, the immutable published record
count, one-listener startup, and asynchronous responder events. It exposes no
batch getter, store export, publication replacement, mutation, refresh, or
background-selection operation. Changing the published batch requires
constructing a new responder.

The operator alone selects the constructor input. The responder does not know
when a record was received, does not apply the store's seven-day TTL, and does
not interpret a signed sequence as a clock. The exact encoded batch is complete
only relative to that constructor input. It makes no commitment about the
operator's other records, the responder's wider knowledge, or network-wide
absence. An empty configured publication is a valid canonical response, but no
rejection or transport failure is encoded as an empty response.

Each signed record authenticates only its subject's address claim. Noise
authenticates the responder and requester connection identities. Neither fact
authenticates the operator's serving selection, freshness, completeness,
honesty, independence, reachability, or permission to exchange proofs.

## Protocol and compatibility

The protocol identifier is exactly:

```text
/naome/peer-record-exchange
```

It is configured as libp2p `ProtocolSupport::Inbound`. The request is exactly
zero bytes followed by end of stream. The response is the existing EOF-framed
canonical batch with no outer length prefix:

```text
record_count_u8
record_count * (envelope_length_u16_be || signed_envelope)
end of stream
```

The maximum response is `131137` bytes. A pull client is compatible when it
configures the responder's exact Noise identity and dial address as a
`BootstrapPeer`; the responder itself accepts any successfully Noise-
authenticated requester identity. The responder has no dial API, no outbound
record protocol, and no proof protocol.

The compatible client's `AuthenticatedPeerRecordBatch::source_peer_id` is this
responder's Noise `PeerId`, never a signed record's subject or signer and never
an upstream source from which the operator may have obtained the record. The
wire carries no upstream receipt or provenance. This authenticated source is
routing provenance for local admission, not proof authority or a reachability
claim.

## Authentication, request handling, and errors

Pending inbound TCP connections first cross the connection-limit gate and then
one global pre-authentication token bucket before Noise. That field order is
part of the resource contract: a connection-limit rejection does not consume a
pre-authentication token. The bucket starts with eight tokens, admits eight immediate
attempts, and lazily refills one token per elapsed second using monotonic time up
to a burst of eight. Admission consumes a token even if the later handshake
fails; tokens are not refunded. This is one global load bound, not per-IP
fairness, identity authorization, or a Sybil defense.

After Noise and protocol negotiation, the codec reads one byte only to
distinguish EOF from a malformed nonempty request. A valid empty request crosses
a separate global valid-request token bucket with the same burst of eight and
one-token-per-second refill. Its token is consumed before the fixed response is
queued and is not refunded if the response channel or later write fails.
Malformed, timed-out, or failed reads do not consume a valid-request token, but
they terminate and close their connection.

The public terminal request failures distinguish:

- global valid-request rate exhaustion;
- a nonempty request;
- expiry of the fixed nested request-read timeout;
- request-stream read I/O failure;
- later libp2p inbound transport failure.

Each eager local rejection closes the request's connection without sending a
response. A response-channel closure before enqueue is reported by the later
libp2p transport failure. After a response is enqueued, a later write or close
failure may follow partial or complete remote delivery; the requester's own
terminal event is authoritative for its local result. No rejection or failure
is converted into an empty application response. Immediate typed local
rejection and its later libp2p cleanup are correlated so the responder exposes
one terminal request event, not a duplicate failure.

`ResponseSent` means the immutable bytes were flushed locally for one
authenticated requester. It does not prove that the requester received,
decoded, admitted, retained, or used the batch. Pre-authentication rejection has
no authenticated requester identity and is not reported as a request event.

## Connection lifecycle and resource bounds

One responder owns at most one active TCP listener. A second `listen_on` call
fails while that slot is occupied. `ListenerError` reports an error without
silently releasing the slot; `ListenerClosed` reports closure and releases it,
after which the caller may listen again. Dropping the responder ends its swarm;
there is no detached background task.

The fixed limits are:

| Resource | Limit |
| --- | ---: |
| Active listeners | 1 |
| TCP listen backlog | 16 |
| Pending inbound connections | 8 |
| Established inbound connections | 8 |
| Established connections per authenticated `PeerId` | 1 |
| Pending or established outbound connections | 0 |
| Negotiating inbound application streams per connection | 1 |
| Concurrent record requests per connection | 1 |
| Pre-authentication connection attempts | Global burst 8, refill 1/second |
| Valid requests admitted for response | Global burst 8, refill 1/second |
| TCP/Noise/Yamux establishment | 10 seconds |
| Inbound record-protocol negotiation | 10 seconds |
| Empty request read | 10 seconds, nested in exchange timeout |
| Complete negotiated request/response exchange | 30 seconds |
| Fully idle authenticated connection | 10 seconds |
| Request bytes | 0 |
| Immutable response bytes | 1..=131137, retained once |

For a cold pull, the ten-second protocol-upgrade budget follows the connection-
establishment phase and precedes the 30-second complete exchange budget. The
request-read timeout is the first at-most-ten seconds inside, rather than
consecutive with, that 30-second exchange budget. A healthy authenticated
connection may serve sequential requests while it remains within the ten-
second idle limit. Only one request is active on that connection at a time,
and every valid follow-up still crosses the global response bucket. Rate
rejection closes the connection. There is no keepalive, retry, redial, or
fairness scheduler.

At the application boundary the responder retains at most one `131137`-byte
publication plus at most eight short-lived shared references from the bounded
connections. The transport may maintain its own framing and write buffers;
fixed structs, allocator overhead, kernel buffers, and libp2p internals are
outside this payload accounting.

Pending and established inbound connection limits are separate: the pool may
contain at most eight established connections plus eight pending handshakes,
while only the established connections can own the at-most-eight concurrent
record writes. From a full valid-request bucket, response starts are at most
`8 + floor(t / 1 second)` over an interval beginning at bucket observation. The
first continuously driven 60 seconds therefore authorize at most 68 response
starts and `68 * 131137 = 8917316` publication bytes. An arbitrary 60-second
physical-egress window may additionally begin with eight previously authorized
writes already in flight, for at most 76 bodies and `9966412` publication bytes.
Protocol, Noise, Yamux, TCP, and kernel overhead are separate. The sustained
admitted publication rate after the burst is at most `131137` bytes per second.
The independent pre-authentication bucket bounds handshake admissions rather
than response starts.

Raw TCP attempts rejected before the pre-authentication hook and repeated
unsuccessful multistream negotiations are outside the token-bucket byte and CPU
accounting. They remain subject to the connection, stream, backlog, and timeout
limits and can still occupy all available slots; V0 makes no volumetric
availability guarantee.

All liveness and timeout delivery require the caller to continue polling
`next_event`. Stopping that event loop suspends listener, connection, stream,
response, and timeout progress.

## Security boundary and exclusions

V0 provides an inbound-only protocol boundary, Noise-authenticated requester
identity, one immutable canonical publication, exact compatible framing,
separate global pre-authentication and valid-request rate bounds, bounded
connections and streams, fixed timeouts, typed terminal request failures, and
no error-to-empty-response conversion.

It does not define or claim:

- a bundled seed list, DNS bootstrap, remote configuration, or default
  responder address;
- store export, a store snapshot protocol, publication updates, live reload,
  freshness filtering, record selection, pagination, cursors, deltas, coverage,
  or completeness beyond the exact constructor input;
- signing or issuing peer records inside the responder, advancing an issuer
  watermark, changing signed record content, push, gossip, subscriptions,
  periodic publication, or background refresh; the separate local issuer may
  construct a record only before explicit batch and responder construction;
- dialing, outbound pulls, fallback, retry, managed sessions, learned-candidate
  sessions, conversion to `StaticPeer`, proof authorization, proof transport,
  or proof gossip;
- per-IP fairness, per-requester quotas, operator reputation, bans, Sybil
  resistance, eclipse resistance, or volumetric denial-of-service protection;
- DHT, mDNS, Rendezvous, NAT traversal, relay, or hole punching; or
- consensus, fork choice, checkpoints, finality, mining, validator roles,
  transactions, rewards, fees, or settlement.

Dynamic learned-candidate sessions and any proof-exchange authorization remain
separate later contracts.
