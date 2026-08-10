# NAOME Authenticated Proof Transport

## Status and scope

This document defines one concrete, bounded network binding for the
[addressed proof exchange](addressed-proof-exchange.md). It is a prerelease
transport contract and may change before the first stable protocol release.

The transport connects a fixed set of explicitly configured peers over TCP,
authenticates both endpoints with Noise identity keys, multiplexes exchanges
with Yamux, and carries one proof request per request-response substream. It
provides a safe untrusted-byte path into expected-`ProofId` journal admission.
The caller constructs and drives it on a Tokio runtime with I/O and time drivers
enabled; the crate creates no runtime or background task.

This is not a decentralized peer-discovery system or a consensus protocol.
Static peer identities provide authentication and authorization, not Sybil
resistance, freshness, proof-set selection, or finality.

## Stack and peer authorization

The stack, from outermost connection to application payload, is:

```text
TCP -> Noise -> Yamux -> /naome/proof-exchange -> addressed proof exchange
```

Each node has one libp2p identity key. Its `PeerId` is derived by libp2p from
the public key and is authenticated during the Noise handshake. Construction
accepts at most eight `StaticPeer` values, each containing an expected `PeerId`
and one dial `Multiaddr`.

A local identity cannot appear in its own peer set, and duplicate `PeerId`
entries are rejected. Inbound and outbound connections are allowed only for
the configured peer identities. Dialing a configured address whose Noise
identity differs from the expected `PeerId` fails before any proof request is
delivered.

The configured address is supplied afresh on every request-driven dial. A
transient failed dial may clear libp2p's ephemeral address cache, but it does
not consume or remove the static address from this transport configuration.

The address is routing information, not identity. Possession of an allowed
identity proves neither honest behavior nor uniqueness of a human, machine,
operator, or economic actor.

## Protocol identifier and framing

The libp2p stream protocol identifier is exactly:

```text
/naome/proof-exchange
```

One request occupies one request-response substream. The request body is
exactly the 32 raw bytes of the requested `ProofId`:

```text
proof_id[32]
```

The request reader requires end-of-stream immediately after byte 32. A shorter
request is truncated; an additional byte is invalid. There is no request tag,
length, echoed identity, batch, or correlation identifier. The libp2p request
handle and authenticated peer bind the response to the immutable request.

The response body is:

```text
payload_length u32 big endian
payload        payload_length bytes
end of stream
```

`payload_length = 0` is `Unavailable`. A nonzero length is one untrusted
proof-certificate candidate and must be in
`1..=CERTIFICATE_MAX_BYTES` (`4_194_304`). The reader rejects a larger declared
length immediately after its four-byte prefix, before allocating or reading a
body. It then reads exactly the declared bytes and requires end-of-stream.

Truncated prefixes, truncated bodies, trailing bytes, and a reset or timeout
before all declared frame bytes arrive are transport failures. They must never
be converted to `Unavailable`. The selected asynchronous Yamux stream API
reports both a clean receive close and a reset after the complete frame as
end-of-stream, so this adapter cannot distinguish those two post-frame cases.
It accepts either only after the exact declared bytes have arrived. This does
not bypass strict proof admission, and `Unavailable` remains non-authoritative.
The length prefix is transport framing only and is not part of the canonical
proof bytes or `ProofId`.

## Resource bounds

The initial static implementation fixes these limits:

| Resource | Limit |
| --- | ---: |
| Configured peers | 8 |
| Pending inbound connection attempts | 8 |
| Pending outbound connection attempts | 8 |
| Established connections, total | 8 |
| Established connections per peer | 1 |
| Request-response streams per connection | 2 |
| Negotiating inbound streams per connection | 2 |
| Yamux substreams per connection | 8 |
| Pending outbound proof requests, global | 8 |
| Pending outbound proof requests per peer | 1 |
| TCP listen backlog | 16 |
| Connection establishment timeout | 10 seconds |
| Negotiated request/response phase timeout | 30 seconds |
| Authenticated idle-connection timeout | 30 seconds |

The Yamux cap is intentionally larger than the two proof-exchange streams so
simultaneous bidirectional negotiation can complete while arbitrary mux stream
growth remains bounded. The selected libp2p adapter currently implements this
hard cap through its compatibility configuration; the WAN throughput tradeoff
is not yet measured.

One established connection per peer prevents one identity from concentrating
the node-wide connection budget. The authenticated Yamux connection is
full-duplex: once established, both peers can issue proof requests concurrently
over that connection. Simultaneous initial cross-dial coordination is not part
of this transport contract; a later session coordinator may assign deterministic
dial ownership without weakening this connection bound.

The global outbound permit is acquired before libp2p queues a request and is
held until the resulting response object is admitted or dropped. This bounds
queued requests even when a peer is disconnected and bounds proof payloads
retained by callers after network receipt. The request-response stream and
connection limits bound concurrently owned server responses.

These are concurrent-count and per-object bounds, not connection-rate,
authentication-work, cumulative-bandwidth, or checker-CPU budgets. A remote
endpoint can still repeat TCP/Noise handshakes, and an authorized peer can send
repeated valid, invalid, or expensive proofs over time. Connection-rate policy
belongs to the later session/peer-policy layer; rolling byte, proof work, and
dependency budgets belong to the later admission scheduler.

The connection timeout covers TCP, Noise, and Yamux establishment. The
request-response timeout starts after multistream protocol negotiation; the
pinned libp2p swarm separately bounds that negotiation to 10 seconds. A request
can therefore consume negotiation time plus the 30-second negotiated exchange
phase. Neither timeout is a promise that synchronous proof checking or durable
journal admission can be cancelled.

## Request correlation and admission

For every outbound request, the transport retains the libp2p request handle,
the authenticated expected peer, the immutable `ProofRequest`, and its resource
permit. A response is accepted from the matching handle and peer exactly once.
The public received-response object does not expose its candidate bytes or an
unbound `into_parts` path. Its only admission operation delegates to the
transport-neutral addressed exchange, which calls:

```text
ProofDagJournal::apply_canonical_proof_bytes_with_expected_id(
    candidate_bytes,
    requested_proof_id,
)
```

After the journal health check, the existing admission order remains decode,
canonicality verification, mathematical checking and dependency resolution,
checked-identity comparison, state registration, and durable commit. `Poisoned`
therefore precedes every response outcome; on a healthy handle, a valid proof
body for another request returns `ProofIdMismatch` without changing the ledger,
proof set, root, records, or journal.

`UnknownProofReference` ends the exchange without fetching or retaining an
orphan. The transport never retries with raw unaddressed admission. Duplicate
proof and derivation errors remain state errors; the network does not redefine
the selected-state first-arrival policy.

An `Unavailable` response only reports that this peer returned no payload for
this request. It creates no negative cache and proves no global absence.

## Serving and ownership

The server looks up the requested `ProofId` in a healthy `ProofDagJournal`.
A missing record produces `Unavailable`; a poisoned or unreadable journal
produces its existing error and no successful response.

The journal exposes accepted proof bytes as a borrowed slice, while libp2p's
response channel must own its payload until the asynchronous write completes.
The adapter therefore performs exactly one bounded proof-sized copy when
serving a found response. Avoiding that copy would require changing immutable
record ownership across ledger, DAG, storage, and transport or replacing the
standard request-response behavior. Neither expansion is justified in this
MR. Receiving requests one payload buffer sized to the declared length and
moves it through strict admission without a second proof-sized copy; the Rust
allocator may reserve additional capacity.

## Failure visibility

Outbound request failures and inbound failures after a request was delivered
to the application retain their typed causes in network events. Listener errors
and closure are also observable. The pinned request-response behavior does not
surface every pre-delivery inbound negotiation or request-read failure as an
application event. A dropped or closed response channel is a transport failure,
not `Unavailable`.

Transport framing or authentication failure never reaches proof admission.
Proof validation and journal errors are returned unchanged by received-response
admission. A journal `Commit` or `Poisoned` error is not translated into a peer
response and requires the existing drop-and-reopen recovery procedure.

## Security boundary and exclusions

The transport guarantees authenticated peer identity, static authorization,
exact framing, per-object length preflight, bounded concurrent connections and
requests, immutable request/response correlation, and expected-identity proof
admission.

It does not define or claim:

- identity-key storage, rotation, recovery, or operator enrollment;
- DNS, dynamic bootstrapping, peer discovery, DHTs, address gossip, or NAT
  traversal;
- peer scoring, bans, retries, multi-peer selection, announcements, or proof
  gossip;
- recursive dependency fetching, an orphan pool, quarantine, admission worker,
  request/checker cancellation, or rolling byte/CPU budgets;
- Sybil resistance, eclipse resistance from network diversity, fork choice,
  checkpoints, signatures, finality, or consensus;
- economic transactions, balances, fees, rewards, or settlement; or
- batch transport messages, compression, erasure coding, snapshots, pruning,
  or proof availability guarantees.

The next network slice is a bounded dependency/admission scheduler. It must
quarantine a complete addressed closure and use the journal's atomic rooted
proof transaction rather than admitting fetched dependencies incrementally.
Discovery and peer-diversity policy follow separately. A consensus-selected
checkpoint and linear settlement/economy remain later layers and must not be
inferred from authenticated transport peers.
