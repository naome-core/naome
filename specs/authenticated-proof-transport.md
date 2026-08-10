# NAOME Authenticated Proof Transport

## Status and scope

This document defines one concrete, bounded network binding for the
[addressed proof exchange](addressed-proof-exchange.md). It is a prerelease
transport contract and may change before the first stable protocol release.

The transport connects a fixed set of explicitly configured peers over TCP,
authenticates both endpoints with Noise identity keys, multiplexes exchanges
with Yamux, and carries one proof request per request-response substream. It
provides a caller-driven, bounded path for acquiring one root-reachable proof
closure without selecting any received bytes, followed by one explicit atomic
rooted journal transaction. The caller constructs and drives it on a Tokio
runtime with I/O and time drivers enabled; the crate creates no runtime or
NAOME-owned background task. One caller-driven swarm owns all connection,
session, request, and retry state.

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
identity differs from the expected `PeerId` cannot deliver a proof request to
that endpoint.

For each configured pair, the endpoints lexicographically compare the raw
binary multihash bytes returned by `PeerId::to_bytes`. The lower value is the
sole dial owner. It proactively maintains one connection to the higher value;
the higher endpoint accepts that direction and never dials the lower endpoint.
The configured address is retained and supplied on every managed dial attempt,
including after transient failure. Every dial is bound to one exact libp2p
connection generation, so a stale failure or close event cannot alter a newer
connection.

This deterministic rule requires symmetric static peer configuration, a
reachable configured listener on the higher endpoint, and continuously driven
event loops on both endpoints for useful connectivity. The lower endpoint does
not need a listener for this pair. The rule deliberately has no grace-period
role reversal. A proof request never opens a connection: without an established
managed session it returns `PeerDisconnected` before acquiring a payload permit
or queuing a request.

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
| Managed-session idle expiry | effectively disabled; at most 8 idle sessions remain |
| Outbound redial delay | 1, 2, 4, 8, 16, 32, then 60 seconds |
| Stable-session threshold for backoff reset | 60 seconds |
| Pre-Noise inbound authentication burst | 8 attempts |
| Pre-Noise inbound authentication refill | 1 attempt per second, global |

The Yamux cap is intentionally larger than the two proof-exchange streams so
simultaneous bidirectional negotiation can complete while arbitrary mux stream
growth remains bounded. The selected libp2p adapter currently implements this
hard cap through its compatibility configuration; the WAN throughput tradeoff
is not yet measured.

One established connection per peer prevents one identity from concentrating
the node-wide connection budget. The authenticated Yamux connection is
full-duplex: once the deterministic owner establishes it, both peers can issue
proof requests concurrently over that same connection. There is no initial
cross-dial race and no request-driven second dial.

The owner dials immediately. After successive terminal dial failures or session
closures it waits `1, 2, 4, 8, 16, 32, 60, ...` seconds before trying again.
With instantaneous failures, cumulative backoff waits start at
`0, 1, 3, 7, 15, 31, 63, 123, ...` seconds; each failed connection attempt may
add up to the separate ten-second establishment timeout. Only a session that
remained connected for at least 60 seconds resets the next failure to the
one-second delay; rapid authenticate-and-close churn therefore cannot collapse
the backoff. Idle expiry is effectively disabled with the largest representable
configured duration because a 30-second idle timeout would close every quiet
connection before that stability threshold and create periodic authentication
churn. The fixed eight-peer cap bounds retained idle sockets.

Before Noise work begins, pending connection-count limits run first and a
global token bucket then admits a burst of eight inbound attempts with one
token refilled per second. Starting from a full bucket, at most 68 attempts can
be admitted in 60 seconds. The bucket retains no per-connection or per-source
state. It bounds aggregate admission to authentication work, but it is not
per-IP fairness, upstream DDoS filtering, or Sybil resistance.

The global outbound permit is acquired before libp2p queues a request. During
dependency acquisition it moves with the response into quarantine, then into
the completed closure, and remains held across final synchronous promotion. It
is released only when that candidate is dropped or promotion returns. The same
eight-permit limit therefore bounds pending requests plus received responses,
quarantined candidates, and completed closure candidates for one
`StaticProofNetwork` instance. At most eight proof payload buffers, each at
most 4 MiB, can be retained this way; this 32 MiB figure is a payload-only
bound, not a bound on transient decode or checker memory. The request-response
stream and connection limits separately bound concurrently owned server
responses.

These are concurrent-count, per-object, managed-redial, and global inbound
authentication-rate bounds. They do not provide per-source fairness or
cumulative bandwidth/checker-CPU budgets. An authorized peer can still send
repeated valid, invalid, or expensive proofs over time. Rolling byte and
proof-work budgets remain later policy beyond this fixed eight-candidate
envelope.

The connection timeout covers TCP, Noise, and Yamux establishment. The
request-response timeout starts after multistream protocol negotiation; the
pinned libp2p swarm separately bounds that negotiation to 10 seconds. A request
can therefore consume negotiation time plus the 30-second negotiated exchange
phase. Neither timeout is a promise that synchronous proof checking or durable
journal admission can be cancelled.

## Request correlation and closure acquisition

For every outbound request, the transport retains the libp2p request handle,
the authenticated expected peer, the immutable `ProofRequest`, and its resource
permit. A response is accepted from the matching handle and peer exactly once.
An acquisition also retains the exact outbound request handle it currently
awaits. Callers route an event with `accepts_response` before consuming it, so a
late response for an older request cannot advance a newer acquisition of the
same address. The retained permit identity also binds the acquisition, response,
and follow-up requests to one `StaticProofNetwork` instance; request handles
from separate libp2p behaviours are not treated as globally unique.

One acquisition uses one configured peer and has exactly one request in flight.
It starts only when that peer has an established session and the requested root
is absent from the healthy selected journal. Each correlated nonempty response
is processed as follows:

1. decode one complete structurally bounded `ProofCertificate`;
2. derive its unchecked root-proof normal form and require the supplied bytes
   to match that form exactly;
3. inspect only normal-form `ProofReference` addresses in canonical step order;
4. stop traversal at dependencies already present in the selected journal;
5. deduplicate exact `ProofId` addresses already discovered by this acquisition;
6. reject before another request if the closure would exceed eight candidates;
7. request the next absent dependency sequentially; and
8. after all candidates arrive, reject address-level cycles and emit each unique
   candidate in dependency-first order with the requested root last.

This is structural acquisition, not proof validation. It deliberately cannot
derive a candidate's actual `ProofId` before its referenced conclusions are
available and the proof is mathematically checked. A canonical but invalid or
wrong-address response may therefore reach the completed closure, but it
cannot reach selected state.

The public `UnselectedProofClosure` is non-cloneable and exposes neither proof
buffers nor an unbound candidate list. Its sole consuming transition calls:

```text
ProofDagJournal::apply_rooted_canonical_proof_batch(
    requested_root,
    dependency_first_addressed_candidates,
)
```

Promotion first verifies journal health, then preflights batch count, duplicate
expected addresses, and root-last shape. Each candidate is decoded,
canonicality-checked, mathematically checked against selected state plus earlier
staged candidates, compared with its requested `ProofId`, and staged in input
order. Root reachability is checked only after all candidates pass; the staged
state is then merged and durably committed as one transaction. On a healthy
handle, any ordinary pre-commit failure changes neither the ledger, proof set,
root, records, nor journal. No dependency is selected merely because it was
fetched for a root that later fails.

Selected state may grow after acquisition and before promotion. Promotion does
not prune, refetch, reorder, or reinterpret the closure; the atomic batch
revalidates it against the then-current state and may fail with an existing
duplicate or derivation collision. The transport never retries with raw
unaddressed or incremental single-proof admission and does not redefine the
selected-state first-arrival policy.

An `Unavailable` response reports only that this peer returned no payload for
this request. It terminates the one-peer acquisition, discards its quarantine,
creates no negative cache, and proves no global absence.

There is no separate absolute closure deadline or cancellation protocol in this
slice. Existing connection, negotiation, and per-request timeouts apply to each
of at most eight sequential requests. The caller may drop the acquisition, but
libp2p still owns any already-issued request until a terminal transport event;
later acquisition-job policy may add explicit cancellation tombstones and a
shorter total deadline without changing closure admission.

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
moves it into quarantine and later rooted admission without a deliberate
proof-sized clone; an owned-vector-to-box conversion may legally adjust
capacity. The Rust allocator may reserve additional capacity.

## Failure visibility

Outbound request failures and inbound failures after a request was delivered
to the application retain their typed causes in network events. Listener errors
and closure are also observable. Managed session establishment, dial failure,
and disconnection are separate events; connection identifiers and backoff state
remain private. The pinned request-response behavior does not
surface every pre-delivery inbound negotiation or request-read failure as an
application event. A dropped or closed response channel is a transport failure,
not `Unavailable`.

Transport framing or authentication failure never reaches closure acquisition.
Structural acquisition and final journal errors remain distinct. A journal
`Commit` or `Poisoned` error is not translated into a peer response and requires
the existing drop-and-reopen recovery procedure.

## Security boundary and exclusions

The transport guarantees authenticated peer identity, static authorization,
exact framing, per-object length preflight, bounded concurrent connections and
requests, deterministic connection ownership, bounded managed redial and
global pre-authentication admission, immutable request/response correlation,
bounded unselected closure acquisition, and one explicit expected-identity
rooted promotion.

It does not define or claim:

- identity-key storage, rotation, recovery, or operator enrollment;
- a seed-node list, persisted address manager, DNS or fixed-seed bootstrap,
  dynamic peer discovery, DHTs, address gossip, or NAT traversal;
- peer scoring, bans, proof-request retries, multi-peer selection,
  announcements, or proof gossip;
- parallel dependency fetching, a persistent orphan/cache store, admission
  worker, request/checker cancellation, an absolute closure deadline, or
  rolling byte/CPU budgets or per-source connection-rate policy;
- Sybil resistance, eclipse resistance from network diversity, fork choice,
  checkpoints, signatures, finality, or consensus;
- economic transactions, balances, fees, rewards, or settlement; or
- batch transport messages, compression, erasure coding, snapshots, pruning,
  or proof availability guarantees.

The next network slice is an absolute acquisition deadline with explicit
cancellation tombstones; libp2p owns an issued request until its terminal event,
so cancelling a caller-visible job must not release its peer slot or payload
permit early. Bounded multi-peer fallback follows on that substrate without
resetting total attempt, byte, work, or time budgets. Discovery, bootstrap,
persisted addresses, and peer-diversity policy follow separately. A
consensus-selected checkpoint and linear settlement/economy remain later layers
and must not be inferred from authenticated transport peers.
