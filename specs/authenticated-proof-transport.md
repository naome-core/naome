# NAOME Authenticated Proof Transport

## Status and scope

This document defines one concrete, bounded network binding for the
[addressed proof exchange](addressed-proof-exchange.md). It is a prerelease
transport contract and may change before the first stable protocol release.

The transport connects a fixed set of explicitly configured peers over TCP,
authenticates both endpoints with Noise identity keys, multiplexes exchanges
with Yamux, and carries one proof request per request-response substream. It
provides a caller-driven, bounded path for acquiring one root-reachable proof
closure without selecting any received bytes. Its sole consuming admission
requires a caller-supplied `ProofBlock` and the separate
`ProofChainJournal`; acquisition never prepares or selects that block. The
caller constructs and drives the transport on a Tokio runtime with I/O and time
drivers enabled; the crate creates no runtime or NAOME-owned background task.
One caller-driven swarm owns all connection, session, request, and retry state.
The same swarm carries the separate
[Authenticated Proof Block Transport](authenticated-proof-block-transport.md)
over a second request-response behaviour. That protocol shares authorization,
connections, application permits, and per-peer pending limits but does not
change proof-closure acquisition or promotion.
The separate
[Authenticated Proof Chain Head Pull](authenticated-proof-chain-head-pull.md)
adds a third request-response behaviour on that same swarm. It reports only one
untrusted, chain-scoped peer observation and never starts retrieval or import.
The separate
[Caller-Selected Proof Block Import](caller-selected-proof-block-import.md)
orchestrates those two existing exchanges for one exact direct-child target;
it does not consume the head protocol or grant peer-side selection policy.
The separate
[Caller-Selected Proof Block Ancestry Pull](caller-selected-proof-block-ancestry-pull.md)
retrieves at most sixteen exact parent-linked blocks from one caller-selected
peer without acquiring proof payloads or mutating selected state.

This is not a decentralized peer-discovery system or a consensus protocol.
Static peer identities provide authentication and authorization, not Sybil
resistance, freshness, proof-set selection, or finality.

## Stack and peer authorization

The stack, from outermost connection to application payload, is:

```text
TCP -> Noise -> Yamux -> /naome/proof-exchange -> addressed proof exchange
```

The separate `/naome/proof-block-exchange` behaviour reuses the same
authenticated managed connection. Its exact framing and generation-safe
correlation contract are defined only by the
[Authenticated Proof Block Transport](authenticated-proof-block-transport.md).
The third `/naome/proof-chain-head-exchange` behaviour reuses that connection
under the independent framing and correlation contract in the Authenticated
Proof Chain Head Pull.

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
| Proof request-response streams per connection | 2 |
| Proof-block request-response streams per connection | 2 |
| Proof-chain-head request-response streams per connection | 2 |
| Aggregate proof, proof-block, and proof-chain-head streams per connection | 6 |
| Negotiating inbound streams per connection | 2 |
| Yamux substreams per connection | 8 |
| Shared pending or retained application permits | 8 |
| Pending outbound proof, proof-block, or proof-chain-head requests per peer | 1 |
| TCP listen backlog | 16 |
| Connection establishment timeout | 10 seconds |
| Negotiated request/response phase timeout | 30 seconds |
| Absolute dependency-acquisition deadline | 120 seconds, monotonic |
| Requests issued by one dependency acquisition | 15 |
| Candidate response bodies received by one acquisition | at most 60 MiB |
| Managed-session idle expiry | effectively disabled; at most 8 idle sessions remain |
| Outbound redial delay | 1, 2, 4, 8, 16, 32, then 60 seconds |
| Stable-session threshold for backoff reset | 60 seconds |
| Pre-Noise inbound authentication burst | 8 attempts |
| Pre-Noise inbound authentication refill | 1 attempt per second, global |

The Yamux cap is intentionally larger than the six aggregate proof, proof-block,
and proof-chain-head request-response streams. Each separate behaviour retains a
two-stream cap while arbitrary mux stream growth remains bounded. The selected
libp2p adapter currently
implements the hard Yamux cap through its compatibility configuration; the WAN
throughput tradeoff is not yet measured.

One established connection per peer prevents one identity from concentrating
the node-wide connection budget. The authenticated Yamux connection is
full-duplex: once the deterministic owner establishes it, both peers can issue
proof, proof-block, or proof-chain-head requests over that same connection.
There is
no initial cross-dial race and no request-driven second dial.

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

The global outbound permit is acquired before libp2p queues an application-
level proof, proof-block, or proof-chain-head request. During dependency
acquisition it moves with a proof response into quarantine, then into the
completed closure, and remains
held across final synchronous promotion. A successful proof-block response
instead retains its permit until its opaque outbound event is completed with
the matching request ticket or dropped. A successful proof-chain-head response
uses the same retained-event boundary. The shared eight-permit limit therefore
bounds pending requests, received block or head responses, quarantined proof
candidates, and completed closure candidates for one `StaticProofNetwork`
instance. At most eight proof payload buffers, each at most 4 MiB, can be
retained this way; mixing in block responses of at most 353 bytes or head
responses of 32 bytes cannot raise that 32 MiB concurrent payload-only bound.
This is not a bound on transient decode or checker memory. Request-response
stream and connection limits separately bound concurrently owned server
responses.

One acquisition issues at most fifteen requests across all configured peers.
The bound permits a full eight-candidate closure after up to seven failed
attempts; an incomplete acquisition may spend a larger share of the same fixed
budget on failures. It is never reset when the acquisition changes peer or
proof address. Across those fifteen attempts, declared proof-response body
bytes read, whether complete or partial, are at most 60 MiB. Length prefixes,
protocol negotiation, multiplexing, and other transport overhead are separate.
Structural certificate decoding and normalization run at most eight times:
decode and noncanonical errors are terminal, while successful candidates remain
capped at eight. The 60 MiB ingress envelope and the 32 MiB concurrent
retained-payload bound are different guarantees.

These are concurrent-count, per-object, per-acquisition, managed-redial, and
global inbound authentication-rate bounds. They do not provide per-source
fairness or rolling node-wide bandwidth/checker-CPU budgets across repeated
acquisitions. An authorized peer can still send repeated valid, invalid, or
expensive proofs over time.

The connection timeout covers TCP, Noise, and Yamux establishment. The
request-response timeout starts after multistream protocol negotiation; the
pinned libp2p swarm separately bounds that negotiation to 10 seconds. A request
can therefore consume negotiation time plus the 30-second negotiated exchange
phase. The absolute acquisition deadline is a separate total bound shared by
all sequential dependency requests. None of these timeouts is a promise that
synchronous proof processing or durable journal admission can be preempted.

## Request correlation and closure acquisition

For every outbound request, the transport retains the libp2p request handle,
the authenticated expected peer, the immutable `ProofRequest`, its acquisition
control, and its resource permit. A response or failure is accepted from the
matching handle and peer exactly once. An acquisition also retains the exact
outbound request handle it currently awaits. Callers route the opaque
`OutboundProofEvent` with `accepts_event` before consuming it, so a late response
or failure for an older request cannot advance a newer acquisition of the same
address. The acquisition-control budget identity also binds the acquisition,
event, and follow-up requests to one `StaticProofNetwork` instance; request
handles from separate libp2p behaviours are not treated as globally unique.

One acquisition has exactly one request in flight. The caller supplies an
initial preferred configured peer. For each proof address, that peer is tried
first, followed by every other configured peer in raw `PeerId::to_bytes()`
order. A peer is considered at most once for that address. A disconnected or
already-busy peer is skipped without issuing a request, waiting, or opening a
connection. After one peer supplies a canonical candidate, that peer becomes
the preferred peer for the next dependency. The requested root must be absent
from the healthy selected journal before the first attempt. Each correlated
nonempty response is processed as follows:

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
buffers nor an unbound candidate list. It owns no block and cannot infer one
from the journal's current head. Its sole consuming transition requires:

```text
UnselectedProofClosure::apply_block(
    self,
    selected: &mut ProofChainJournal,
    block: &ProofBlock,
) -> Result<&AcceptedProofRecord, ProofChainJournalError>
```

Internally, promotion correlates the opaque candidates into the block's order
and calls `selected.apply_block(block, addressed_candidates)` exactly once.

The caller, not the acquisition, chooses the supplied block. Promotion first
verifies journal health and exact parentage. The block transition then binds
the exact current root, candidate count and order, expected identities,
requested root, and projected resulting root. Each candidate is decoded,
canonicality-checked, mathematically checked against selected state plus earlier
staged candidates, compared with its requested `ProofId`, and staged in input
order. Root reachability is checked only after all candidates pass. The staged
chain state is then merged and one journal entry durably commits the exact block
and its ordered accepted payloads. On a healthy handle, any ordinary pre-commit
failure changes neither the head, ledger, proof set, root, records, nor journal.
No dependency is selected merely because it was fetched for a root that later
fails.

Acquisition never calls `ProofChainJournal::prepare_block`, substitutes the
current head, constructs an implicit local block, exposes raw candidates, or
falls back to direct proof-DAG admission. Consequently, successful payload
retrieval is availability for a possible block, not authority to select that
block.

The caller-selected import may run journal preparation before starting this
acquisition and may later consume its completed closure through the existing
`apply_block` operation. Those caller-side orchestration checks do not alter
the acquisition's response handling, quarantine, retry, deadline, or promotion
contract.

Selected state may grow after acquisition and before promotion. Promotion does
not prune, refetch, or reinterpret the closure. It may correlate opaque
candidates by immutable requested ID into the supplied transition's exact
order, so independently ordered candidates need not force one block order; it
does not change the block or expose or rewrite payload bytes. The caller-
supplied block and complete addressed closure are revalidated against the
then-current state; a stale parent, previous root, existing proof, identity
collision, or other mismatch fails atomically. The transport never retries
with raw unaddressed or incremental single-proof admission and does not define
a block-selection policy.

An `Unavailable` response reports only that one peer returned no payload for
this request. An ordinary correlated transport failure or `Unavailable`
response may advance to the next unattempted, currently usable configured peer
for the same proof address. The completed response and its permit are dropped
before a replacement request is issued. Certificate decoding failure,
noncanonical candidate bytes, peer-identity mismatch, selected-state failure,
candidate or cycle bounds, deadline, and cancellation remain terminal and do
not rotate peers. Exhausting eligible peers returns the last correlated remote
failure; attempting to issue a sixteenth request returns the explicit
request-limit error. Fallback retains the same immutable request, acquisition
control, quarantine, and absolute deadline, creates no negative cache, and
proves no global absence.

## Absolute acquisition deadline and cancellation

One 120-second monotonic deadline is created after selected-root preflight and
before the root request is issued. Every dependency request inherits that exact
deadline; receiving a response, reconnecting a managed session, or issuing a
follow-up never resets it. Equality expires the acquisition. The deadline
includes request negotiation, response exchange, and in-process structural
acquisition between the first request and completion. It excludes connection
establishment before acquisition starts and excludes promotion of an already
completed `UnselectedProofClosure`.

`StaticProofNetwork::next_event` owns one timer for the earliest of at most
eight active acquisition deadlines. At a deadline it emits one correlated
outbound deadline event and marks the exact pending request as cancelled. A
response or ordinary transport failure that becomes terminal at or after the
deadline is likewise reported as the deadline rather than interpreted as
`Unavailable`, candidate bytes, or a pre-deadline transport failure. When a
physical terminal is processed before the logical deadline event is emitted,
peer-identity mismatch is never replaced by the deadline. If the deadline event
was emitted first, a later mismatched terminal remains visible in
`ProofCancellationDrained`. A synchronous decode already in progress cannot be
interrupted, so the acquisition checks the same deadline again after successful
structural work and issues neither another request nor a completed closure once
it has expired.

Explicitly calling `cancel` or dropping `ProofDependencyAcquisition` marks its
current request as a tombstone. Already quarantined candidates and their
permits are released immediately. libp2p exposes no request-cancellation API,
so the exact in-flight request remains in the pending map and retains one peer
slot and one global payload permit until libp2p emits its terminal response or
failure. That terminal is discarded, releases the retained resources, and is
reported as `ProofCancellationDrained`; it can never advance or complete an
acquisition. Cancelling does not close the shared full-duplex connection or
trigger session redial.

`ProofCancellationDrained` is a capacity-release notification, not an
acknowledgement that follows every `DeadlineExceeded`. If logical expiry was
emitted while libp2p still owned the request, its later physical terminal
produces the drain notification. If the response or failure had already become
physically terminal, the deadline event itself releases the permit and no later
drain exists.

The 120-second value is a fixed initial policy, not a measured WAN optimum. A
request issued immediately before the logical deadline can still require up to
the pinned 10-second negotiation plus 30-second exchange envelope to drain when
the network is continuously polled. A found response may be fully received and
boundedly allocated before the local tombstone discards it. If the caller stops
driving `next_event`, neither logical deadline delivery nor physical request
settlement has a wall-time guarantee.

## Serving and ownership

The server looks up the requested `ProofId` in a healthy `ProofChainJournal`.
A missing record produces `Unavailable`; a poisoned or unreadable journal
produces its existing error and no successful response.

The journal exposes accepted proof bytes as a borrowed slice, while libp2p's
response channel must own its payload until the asynchronous write completes.
The adapter therefore performs exactly one bounded proof-sized copy when
serving a found response. Avoiding that copy would require changing immutable
record ownership across ledger, DAG, storage, and transport or replacing the
standard request-response behavior. Neither expansion is justified in this
MR. Receiving allocates one payload buffer sized to the declared length and
moves it into quarantine and later rooted admission without a deliberate
proof-sized clone; an owned-vector-to-box conversion may legally adjust
capacity. The Rust allocator may reserve additional capacity.

## Failure visibility

Outbound proof responses, request failures, and deadline expiry share one
opaque, exactly correlated outbound event family. Pre-deadline transport
failures and authenticated-peer mismatch retain their typed causes. A later
terminal event for a cancelled request instead reports physical cancellation
drain and can expose its typed failure cause without exposing response bytes.
Inbound failures after a request was delivered to the application, listener
errors, and listener closure are also observable. Managed session
establishment, dial failure, and disconnection are separate events; connection
identifiers and backoff state remain private. The pinned request-response
behavior does not surface every pre-delivery inbound negotiation or request-read
failure as an application event. A dropped or closed response channel is a
transport failure, not `Unavailable`.

Transport framing or authentication failure never reaches closure acquisition.
Structural acquisition and final block/journal errors remain distinct. A
`ProofChainJournalError::Commit` or `ProofChainJournalError::Poisoned` error is
not translated into a peer response and requires the existing drop-and-reopen
recovery procedure.

## Security boundary and exclusions

The transport guarantees authenticated peer identity, static authorization,
exact framing, per-object length preflight, bounded concurrent connections and
requests, deterministic connection ownership, bounded managed redial and
global pre-authentication admission, immutable request/response correlation,
bounded unselected closure acquisition, one non-resetting acquisition deadline,
permit-preserving cancellation tombstones, and one explicit caller-supplied-
block promotion with exact expected-identity correlation.

It does not define or claim:

- identity-key storage, rotation, recovery, or operator enrollment;
- a seed-node list, DNS or fixed-seed bootstrap, dynamic peer discovery, DHTs,
  address gossip, or NAT traversal; the separate bounded
  [peer-address manager](peer-address-management.md) and transport-neutral
  [peer-record exchange](peer-record-exchange.md) feed a dedicated outbound
  [bootstrap client](authenticated-peer-record-pull.md), while a separate
  inbound-only [bootstrap responder](authenticated-peer-record-responder.md)
  serves one immutable operator publication; both record boundaries use
  dedicated swarms without the proof protocol and are not these static proof
  sessions;
- peer scoring, bans, retrying one peer for the same proof address, parallel or
  hedged requests, announcements, or proof gossip;
- parallel dependency fetching, a persistent orphan/cache store, admission
  worker, wire-level request abort, synchronous proof/checker/journal
  cancellation, or rolling cross-acquisition byte/CPU budgets or per-source
  connection-rate policy;
- block construction, automatic block preparation, block announcement,
  competing-block storage, or block-selection policy;
- Sybil resistance, eclipse resistance from network diversity, fork choice,
  checkpoints, signatures, finality, or consensus;
- economic transactions, balances, fees, rewards, or settlement; or
- batch proof-transport messages, compression, erasure coding, snapshots,
  pruning, or proof availability guarantees; the separate peer-record batch
  does not carry proofs.

A later redesign from symmetric static proof sessions to bounded dynamic
learned-candidate sessions must preserve explicit proof authorization and must
not turn signed address claims, responder authentication, or local diversity
policy into a claim of proof authority, Sybil resistance, or eclipse
resistance. A consensus-selected checkpoint and linear settlement/economy
remain later layers and must not be inferred from authenticated transport
peers.
