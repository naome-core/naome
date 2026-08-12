# NAOME Proof Network Transport

## Normative scope

This document defines the transport-neutral proof, proof-block, and
proof-chain-head exchanges; their authenticated static-peer bindings; the
proof-chain-head announcement; and the caller-driven journal serving adapter.
Rustdoc owns exact Rust signatures and field inventories. This specification
owns wire bytes, authentication and correlation requirements, resource
envelopes, error order, cancellation, and trust boundaries.

One `StaticProofNetwork` connects at most eight explicitly configured peers over
TCP, mutually authenticates their libp2p identities with Noise, multiplexes the
four application protocols with Yamux, and is advanced only when its caller
polls the event loop. It creates no runtime, retry task, serving task, or other
NAOME-owned background task.

Proof and block responses are content retrieval. A chain-head pull or
announcement is a source-bound, untrusted availability observation. No exchange
selects a block, imports state, establishes a trusted checkpoint, or grants
consensus, finality, proposer, validator, or economic authority.

## Static authenticated sessions

Each node has one libp2p identity key. A configured `StaticPeer` contains one
expected `PeerId` and one dial `Multiaddr`. The local identity cannot appear in
its own peer set, duplicate peer identities are rejected, and inbound and
outbound application sessions are allowed only for configured identities.
Noise authenticates the public key; a configured address whose authenticated
identity differs from the expected peer cannot deliver an application request.

For each configured pair, the endpoint with the lexicographically lower raw
`PeerId::to_bytes()` value is the sole dial owner. It maintains one connection
to the higher endpoint; the higher endpoint accepts that direction and does not
dial the lower endpoint. The configured address is retained across managed
redial. Every attempt and established session has a private connection
generation, so a stale failure or close cannot alter a newer session. There is
no grace-period role reversal, cross-dial race, or request-triggered connection.
A request without an established managed session fails `PeerDisconnected`
before consuming an application permit.

Useful connectivity therefore requires symmetric static configuration, a
reachable listener on the higher endpoint, and continuously driven event loops.
The address is routing information, not identity. Learned peer records and
`DialCandidate` values never authorize these proof protocols.

The four exact stream protocol identifiers are:

~~~text
/naome/proof-exchange
/naome/proof-block-exchange
/naome/proof-chain-head-exchange
/naome/proof-chain-head-announcement
~~~

Each protocol has an independent framing and tagged pending namespace.
Numerically equal behaviour-local request identifiers from different protocols
must never alias.

## Transport-neutral object exchanges

The enclosing transport supplies one exact message boundary and distinguishes
successful completion from reset, timeout, truncation, or absence.

### Addressed proof

A proof request is exactly:

~~~text
proof_id[32]
~~~

There is no tag, version, length, or second identity. Any 32-byte value is
syntactically valid but proves no existence, validity, availability, or
selection.

One delimited response is:

~~~text
Unavailable = empty message
Found       = candidate_proof_bytes[1..=CERTIFICATE_MAX_BYTES]
~~~

`CERTIFICATE_MAX_BYTES` is `4_194_304`. A found payload is exactly the proof
certificate candidate, with no echoed identity, statement, derivation,
dependency list, root, or wrapper. A successfully completed empty message is
the sole `Unavailable` representation. An announced length above the limit must
be rejected before body allocation. A reset, timeout, absent response, or
truncated declared message is a transport failure, never `Unavailable`.

A nonempty response remains coupled to the immutable requested `ProofId` and is
untrusted until strict promotion. No raw response-to-journal or incremental
admission path exists.

### Addressed proof block

A block request is exactly:

~~~text
block_id[32]
~~~

It has no tag, version, length, chain ID, height, parent, or second identity.
Every shorter or longer complete request is
`InvalidRequestLength { actual, expected: 32 }`.

One delimited response is:

~~~text
Unavailable = empty message
Found       = canonical_proof_block[129..=353]
~~~

The found value is exactly one canonical `ProofBlock`, with no wrapper, echoed
identity, chain ID, height, payload count, proof payload, source, or signature.
A response length above 353 is rejected before body allocation.

A nonempty response is validated in this exact order:

1. reject more than 353 bytes as `ResponseTooLong`;
2. strictly decode the complete slice as one canonical block, preserving
   `ProofBlockDecodeError` as `BlockDecode { source }`;
3. compute the decoded block's `ProofBlockId` exactly once;
4. compare it with the immutable request address; and
5. on mismatch, return `BlockIdMismatch { expected, actual }` without exposing
   the block.

An empty response becomes `Unavailable` before found-response checks. Every
nonempty malformed or sub-129-byte response is a decode error. A canonical
block for another request is an identity mismatch.

For the canonical 161-byte block golden from the `11` discriminator definition,
the request is:

~~~text
474983a016ebf466488b634485b9e6e93f1629bf3d0afa5afa5618f2e04a70f4
~~~

The transport-neutral found response is the direct concatenation of:

~~~text
71ca84dceae51fd23311eb1d79fc97223dba62821d604cd6f4d5701034c5f62d
1111111111111111111111111111111111111111111111111111111111111111
2222222222222222222222222222222222222222222222222222222222222222
02
3333333333333333333333333333333333333333333333333333333333333333
4444444444444444444444444444444444444444444444444444444444444444
~~~

Line breaks are presentation only; unavailable is zero bytes.

### Proof-chain head

A head request is exactly:

~~~text
proof_chain_id[32]
~~~

It has no tag, version, length, height, parent, block ID, or second context.
Every shorter or longer complete request is
`InvalidRequestLength { actual, expected: 32 }`.

One delimited response is:

~~~text
Unavailable = empty message
Found       = head_block_id[32]
~~~

Any 32-byte value is a syntactically valid found value. A nonempty complete
response of any other length is `InvalidResponseLength { actual }` and never
`Unavailable`. The immutable request remains coupled to the response because
the response does not repeat its chain context.

For the canonical chain ID derived from the `11` discriminator definition, the
request is:

~~~text
7174cae86b0cd18e2364805d1bb8da7a34262f3efa6f5e2b723ec6612a9ec15e
~~~

A matching empty journal reports the domain-separated virtual genesis parent:

~~~text
71ca84dceae51fd23311eb1d79fc97223dba62821d604cd6f4d5701034c5f62d
~~~

A healthy journal under a different chain ID reports zero-byte `Unavailable`.
The virtual genesis parent is a head value, not an admitted or retrievable
block.

## Authenticated stream framing

Every request occupies one request-response Yamux substream. Each request reader
requires the exact body below followed immediately by end-of-stream; a shorter
body or one trailing byte is invalid and is never delivered as an application
request.

### Proof stream

`/naome/proof-exchange` carries:

~~~text
request:
    proof_id[32]
    end of stream

response:
    payload_length u32 big endian
    payload        payload_length bytes
    end of stream
~~~

`payload_length = 0` is `Unavailable`; otherwise it is in
`1..=4_194_304`. The four-byte prefix is transport framing and is not part of
canonical proof bytes or `ProofId`.

### Block stream

`/naome/proof-block-exchange` carries:

~~~text
request:
    block_id[32]
    end of stream

response:
    response_length u16 big endian
    response        response_length bytes
    end of stream
~~~

`response_length` is in `0..=353`. Zero is `Unavailable`; a nonzero
body must ultimately be one canonical 129-through-353-byte block. The prefix is
not part of block bytes or `ProofBlockId`. The complete response frame is
2..=355 bytes.

The framed golden is the two-byte length `00a1` followed directly by:

~~~text
71ca84dceae51fd23311eb1d79fc97223dba62821d604cd6f4d5701034c5f62d
1111111111111111111111111111111111111111111111111111111111111111
2222222222222222222222222222222222222222222222222222222222222222
02
3333333333333333333333333333333333333333333333333333333333333333
4444444444444444444444444444444444444444444444444444444444444444
~~~

The exact unavailable frame is `0000`.

### Head-pull stream

`/naome/proof-chain-head-exchange` carries:

~~~text
request:
    proof_chain_id[32]
    end of stream

response:
    response_length u8
    response        response_length bytes
    end of stream
~~~

`response_length` is exactly `0` or `32`. Every other value is rejected
before reading or allocating a body. The codec uses fixed 32-byte stack storage.
For the chain golden above, a matching empty journal returns byte `20` followed
by:

~~~text
71ca84dceae51fd23311eb1d79fc97223dba62821d604cd6f4d5701034c5f62d
~~~

The exact mismatched-chain unavailable frame is `00`. Complete frames are one
or 33 bytes.

### Head-announcement stream

`/naome/proof-chain-head-announcement` carries:

~~~text
request:
    proof_chain_id[32]
    head_block_id[32]
    end of stream

receipt:
    01
    end of stream
~~~

The request is exactly 64 bytes. It has no tag, version, length, height,
timestamp, sequence, signature, state root, proof payload, or block body.
`0x01` is the sole valid one-byte receipt. Empty response, any other byte, a
second byte, truncation, timeout, absence, or reset before the complete frame is
a transport failure, never acknowledgement. Both codecs use fixed stack
storage.

For chain ID `11` repeated 32 times and head ID `22` repeated 32 times, the
request is the direct concatenation:

~~~text
1111111111111111111111111111111111111111111111111111111111111111
2222222222222222222222222222222222222222222222222222222222222222
~~~

The exact successful receipt is `01`.

### Common frame completion

Proof and block readers reject an over-limit declared length immediately after
the prefix, before body reservation or reading. All readers consume exactly the
accepted body and require end-of-stream. Missing or truncated prefixes,
truncated bodies, trailing bytes, timeouts, and resets before completion are
transport failures and never `Unavailable` or acknowledgement.

The selected asynchronous Yamux API reports both clean receive close and reset
after a complete frame as end-of-stream. The adapter accepts either only after
all exact bytes have arrived; canonical decoding, request correlation, and
identity checks still follow.

Message sizes are:

| Protocol | Request body | Response prefix | Response body | Complete response frame |
| --- | ---: | ---: | ---: | ---: |
| Proof | 32 bytes | 4 bytes | 0..=4_194_304 bytes | 4..=4_194_308 bytes |
| Proof block | 32 bytes | 2 bytes | 0..=353 bytes; found is 129..=353 bytes | 2..=355 bytes |
| Head pull | 32 bytes | 1 byte | 0 or 32 bytes | 1 or 33 bytes |
| Head announcement | 64 bytes | none | exactly 1 byte, `0x01` | exactly 1 byte |

## Shared connection and resource envelope

One network instance enforces:

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
| Proof-chain-head announcement streams per connection | 1 |
| Aggregate application-exchange streams per connection | 7 |
| Negotiating inbound streams per connection | 2 |
| Yamux substreams per connection | 8 |
| Shared pending or retained application permits | 8 |
| Pending outbound application requests per peer | 1 |
| TCP listen backlog | 16 |
| Connection establishment timeout | 10 seconds |
| Multistream protocol negotiation | 10 seconds |
| Negotiated request/response phase timeout | 30 seconds |
| Absolute dependency-acquisition deadline | 120 seconds, monotonic |
| Requests issued by one dependency acquisition | 15 |
| Candidate response bodies received by one acquisition | at most 60 MiB |
| Managed-session idle expiry | effectively disabled; at most 8 idle sessions remain |
| Outbound redial delay | 1, 2, 4, 8, 16, 32, then 60 seconds |
| Stable-session threshold for backoff reset | 60 seconds |
| Pre-Noise inbound authentication burst | 8 attempts |
| Pre-Noise inbound authentication refill | 1 attempt per second, global |
| Inbound journal-response attempt burst | 8 per network instance, shared |
| Inbound journal-response attempt refill | 1 token per second per network instance, shared |

The first three request-response behaviours have two streams each and
announcement has one, below the hard eight-substream Yamux cap.

Managed dialing begins immediately. Successive terminal failures or closures
wait `1, 2, 4, 8, 16, 32, 60, ...` seconds; with instantaneous failures the
cumulative waits begin `0, 1, 3, 7, 15, 31, 63, 123, ...` seconds. Each failed
attempt may additionally consume the ten-second establishment timeout. Only a
session connected for at least 60 seconds resets the next delay to one second.
Idle expiry is effectively disabled so a 30-second quiet period cannot churn a
session before that stability threshold; it is configured to the largest
representable duration, and the eight-peer cap bounds idle sockets.

Pending connection-count limits precede the global pre-Noise token bucket. The
bucket starts with eight tokens, refills one per elapsed monotonic second up to
eight, consumes an admitted attempt even when its later handshake fails, and
keeps no per-source state. From full, at most 68 attempts enter authentication
work in 60 continuously driven seconds. This is an aggregate load bound, not
per-IP fairness, upstream DDoS filtering, or Sybil resistance.

The shared outbound permit is acquired before libp2p queues proof, block,
head-pull, or announcement work. A proof permit follows a response into
quarantine, a completed closure, and final synchronous promotion. A successful
block, head, or announcement event retains its permit until its matching ticket
consumes it or the event is dropped. Terminal failure releases its permit before
the failure event is emitted.

The eight permits jointly bound pending requests, proof candidates, completed
closures, decoded blocks, head responses, and announcement receipts. At most
eight 4 MiB proof buffers are retained, for a 32 MiB concurrent payload-only
bound. Mixing block responses of at most 353 bytes, heads of 32 bytes, or fixed
receipts cannot raise it. Eight retained blocks can contain at most 64 proof
identities. These are not bounds on transient decoder or checker memory.

One dependency acquisition issues at most fifteen requests across all peers,
allowing an eight-candidate closure after up to seven failed attempts. The count
never resets on peer or address change. Declared proof-response body bytes read
across those attempts, complete or partial, are at most 60 MiB. Structural
decode and normalization run at most eight times. The 60 MiB ingress envelope
and 32 MiB concurrent retained-payload bound are distinct.

Connection establishment includes TCP, Noise, and Yamux. The pinned libp2p
version supplies the ten-second protocol-negotiation default; NAOME explicitly
configures the 30-second negotiated request/response phase. The 120-second
acquisition deadline is a separate total across sequential dependency requests.
None preempts synchronous proof work or durable journal admission, and all
timers require continued caller polling. A libp2p upgrade must revalidate the
negotiation row above because it is not a NAOME-owned constant.

Outbound exact block and head pulls have no rolling request-rate policy beyond
their message, stream, per-peer, and shared-permit bounds. Inbound announcements
do not consume the journal-response bucket: they are bounded by a 64-byte body,
one announcement stream per connection, and caller polling, but an authorized
peer may still send sustained sequential observations. Caller policy decides
whether to acknowledge them.

## Outbound start, correlation, and tickets

Except for the journal snapshot that precedes announcement start, a direct
outbound application request performs this order before queuing:

1. require a statically configured peer, otherwise `UnknownPeer`;
2. require that peer to have no pending proof, block, head-pull, or announcement
   request, otherwise `AlreadyPending`;
3. require the managed session and selected behaviour to be connected,
   otherwise `PeerDisconnected`;
4. acquire one of the shared eight permits, otherwise `GlobalLimit`; and
5. queue the immutable request and install a protocol-tagged pending entry.

Unsupported remote protocol negotiation is a later `Transport` failure, not a
start error. No start waits for or opens a connection.

Each block, head-pull, or announcement ticket is opaque and non-cloneable. It
binds the request generation, authenticated peer, immutable request, protocol,
and originating network instance. A terminal must match all five before its
transport or response content is interpreted. `PeerMismatch` therefore
precedes `Transport` and response validation.

A ticket from another protocol, request generation, peer, request, or network
instance cannot inspect or consume the outcome even if private numeric counters
or public values coincide. A mismatch preserves both opaque values for correct
routing. Successful events retain their permit until consumed or dropped;
ordinary terminal failures release bounded response state and the permit before
delivery.

Dropping a block, head, or announcement ticket is non-cancelling. The physical
request, peer slot, and permit remain until libp2p emits a terminal event, which
remains visible through the event loop. These direct operations have no public
cancellation and no separate absolute deadline beyond negotiation plus the
30-second exchange phase.

### Block response terminal

After exact pending-entry and peer correlation, an ordinary libp2p or frame
failure is `Transport`. A complete body then preserves this order:

1. empty is `Unavailable`;
2. oversized is `ResponseTooLong` before block decode;
3. nonempty is strict complete canonical `ProofBlock` decode;
4. compute its `ProofBlockId` once; and
5. require equality with the retained requested ID before exposure.

Canonical decode or identity failure is `InvalidResponse { source }`. Raw bytes
and partially decoded or wrong-address blocks are never exposed. The codec
allocates at most one 353-byte response body; success retains the decoded block
rather than a second copy of its input bytes.

### Head-pull terminal

After exact pending-entry and peer correlation, an ordinary libp2p or codec
failure is `Transport`; otherwise the already typed empty-or-found response is
retained for the matching ticket. `Unavailable` remains one peer's answer to
one exact chain request, and a found value remains an untrusted observation.
The transport neither requests that block nor begins ancestry or import.

### Announcement start, receipt, and acknowledgement

Starting an announcement from selected storage performs:

1. read the journal's health-sensitive current head, preserving every
   `ProofChainJournalError` including `Poisoned`;
2. copy the immutable `ProofChainId`;
3. construct the exact 64-byte announcement snapshot;
4. apply `UnknownPeer`, `AlreadyPending`, `PeerDisconnected`, and
   `GlobalLimit` in that order; and
5. queue the immutable announcement with its tagged pending entry.

Journal health therefore precedes every network preflight. The snapshot does
not change if the journal advances later, and the journal is not borrowed across
asynchronous transport work. An empty journal announces its virtual genesis
head without making it a stored block.

An outbound terminal applies the common peer-before-transport precedence. Only
the exact `0x01` receipt under the matching generation becomes a successful
authenticated receipt. It proves only that this peer returned that byte for
that announcement generation.

An inbound announcement is delivered only after exact framing. It is not
acknowledged automatically: caller policy must explicitly submit `0x01` through
the original response channel. A closed channel returns
`HeadAnnouncementAcknowledgeError::ChannelClosed`.
Dropping or declining the inbound value sends no receipt and eventually becomes
an ordinary sender-side transport failure. Acknowledgement reads no journal,
compares no head, starts no retrieval, and mutates no selected state.

## Proof dependency acquisition

Every outbound proof request is correlated to its request generation,
authenticated peer, immutable request, acquisition, originating network
instance, and permit. A response or failure is accepted exactly once only when
all correlation facts match. A late terminal cannot advance a newer request for
the same address; callers must route opaque proof events through the
acquisition's correlation check before consuming them.

An acquisition has one request in flight. The caller chooses an initial
preferred configured peer. For each `ProofId`, it tries that peer first and then
the remaining peers in raw `PeerId::to_bytes()` order, at most once per peer.
Disconnected or already-busy peers are skipped without waiting or dialing. A
peer that returns a canonical candidate becomes preferred for the next
dependency. The requested root must be absent from the healthy selected journal
before the first attempt.

Each correlated nonempty response is processed in order:

1. decode one complete structurally bounded `ProofCertificate`;
2. derive its unchecked root-proof normal form and require exact equality with
   the supplied bytes;
3. inspect only normal-form `ProofReference` addresses in canonical step order;
4. stop at dependencies already present in the selected journal;
5. deduplicate exact addresses already discovered by this acquisition;
6. reject before another request if the closure would exceed eight candidates;
7. fetch the next missing dependency sequentially; and
8. after all arrive, reject address-level cycles and produce unique candidates
   in dependency-first, requested-root-last order.

This stage is structural, not mathematical. A canonical but invalid or
wrong-address candidate can reach the opaque completed closure because its
actual `ProofId` may depend on checked referenced conclusions; it cannot reach
selected state. The reader allocates one declared-length proof buffer and moves
it through quarantine and promotion without another deliberate proof-sized
clone.

The non-cloneable closure exposes neither raw buffers nor an unbound candidate
list and owns no block. Its sole promotion consumes it with a caller-selected
`ProofBlock` and mutable journal. Promotion performs:

1. journal health verification;
2. exact-current-head comparison before candidate work;
3. transition current-root, candidate-count, duplicate expected-address,
   ordered identity, root-last, and projected-resulting-root checks;
4. for each candidate in order, strict decode, canonicality, deterministic
   checking against selected state plus earlier staged dependencies, checked
   `ProofId` comparison with its immutable requested address, and staged
   registration;
5. requested-root reachability over all staged records; and
6. atomic chain-state merge followed by one durable journal entry containing
   the exact block and ordered accepted payloads.

Promotion calls journal block application exactly once. It never prepares,
substitutes, constructs, or selects a block, exposes or rewrites payload bytes,
or falls back to unaddressed or incremental proof admission. Selected-state
growth between acquisition and promotion is handled by complete revalidation;
stale parent/root, existing proof, count, order, identity, or collision errors
fail atomically. Nested journal, block, transition, batch, and ledger error
precedence is preserved. Promotion may correlate opaque candidates by immutable
requested ID into the block transition's exact order, but cannot change the
block or candidate bytes.

An ordinary correlated transport failure or `Unavailable` may rotate to the
next unattempted usable peer for the same immutable address. The old response
and permit are released before replacement. Decode failure, noncanonical bytes,
peer mismatch, selected-state failure, candidate/cycle limit, deadline, and
cancellation are terminal. Exhaustion reports the last correlated remote
failure; a sixteenth issue attempt reports the request-limit error. Rotation
creates no negative cache and proves no global absence.

## Acquisition deadline and cancellation

One 120-second monotonic deadline is created after selected-root preflight and
before the root request. It is inherited unchanged by every dependency request,
expires on equality, and includes protocol negotiation, response exchange, and
in-process structural acquisition. It excludes earlier connection establishment
and promotion of an already completed closure.

The event loop tracks the earliest of at most eight active acquisition
deadlines. At expiry it emits one correlated deadline event and tombstones the
exact pending request. A physical response or failure terminal at or after the
deadline is reported as deadline rather than data or `Unavailable`.
Peer-identity mismatch already processed before logical deadline delivery is
not replaced; a later mismatched terminal remains visible in cancellation
drain. Structural work rechecks the same deadline before issuing a follow-up or
completed closure.

Explicit cancellation or dropping the acquisition immediately releases
quarantined candidates and their permits, and tombstones its in-flight request.
libp2p cannot cancel that physical request, so it retains one peer slot and one
permit until the terminal response or failure. That terminal is discarded,
cannot advance the acquisition, releases its resources, and is reported as
`ProofCancellationDrained` without exposing response bytes; a typed terminal
failure cause may remain visible. Cancellation does not close or redial the
shared connection.

A drain notification exists only when libp2p still owned the request after
logical expiry or cancellation. If the terminal was already physical, deadline
delivery itself releases the permit and no later drain follows. The 120-second
logical deadline does not bound drain time: a request issued just before expiry
may consume another ten-second negotiation plus 30-second exchange envelope
while the network remains polled, and a found body may be allocated before its
tombstone discards it.

## Journal-backed inbound serving

Strictly framed proof, block, and head requests may be answered from one borrowed
healthy `ProofChainJournal`. The serving adapter consumes one externally visible
network event per call:

| Event | Action |
| --- | --- |
| Inbound proof request | Serve the exact accepted proof or `Unavailable` |
| Inbound block request | Serve the exact committed block or `Unavailable` |
| Inbound head request | Serve the matching chain head or `Unavailable` |
| Every other event | Return the original event unchanged |

Exactly one service result is returned for each delivered supported request.
Serving failure does not stop the adapter, retry, substitute a response, or hide
the next event. It preserves the channel-free request description and complete
`RespondError`. Announcements are forwarded unchanged and never acknowledged by
the adapter.

For every supported request, the authoritative response-attempt order is:

1. require journal health and perform the proof/block lookup or head read and
   chain comparison;
2. preserve every journal error, including `Poisoned`, as `Journal`;
3. require the private response channel to remain open, otherwise
   `ChannelClosed`;
4. consume one token from the shared inbound application-request bucket,
   otherwise `RateLimited`;
5. only after the token, copy proof bytes, encode a block, or construct the
   typed fixed-size head response (the 32-byte head value may already have been
   materialized); and
6. submit the owned response through libp2p.

Thus externally visible precedence is
`Journal -> ChannelClosed -> RateLimited -> copy/encode -> send`. Journal and
pre-charge channel failure consume no token. A charged response attempt is not
refunded if final submission returns `ChannelClosed`. Rate exhaustion performs
no proof-sized copy or block encoding. No failure becomes `Unavailable`.

Proof lookup returns borrowed accepted canonical bytes or missing. Found serving
makes exactly one bounded proof-sized copy for asynchronous ownership. Block
lookup returns only a committed selected block; found serving encodes at most one
353-byte buffer, while an unknown ID or virtual genesis anchor is unavailable.
Head serving checks journal health, then compares the immutable requested chain
ID; mismatch is unavailable and match returns the exact head, including virtual
genesis for an empty journal. Head serving is fixed-size and allocation-free at
the transport-neutral boundary.

The shared bucket starts with eight response-attempt tokens and refills one per
elapsed monotonic second up to eight across proof, block, and head serving in
one network instance. From full, at most 68 response attempts can be admitted in
60 continuously driven seconds. It is not per-peer fairness, a bandwidth quota,
or a proof/checker-work quota; an authorized peer can consume the admitted
steady-state rate.

The journal borrow ends when the service call returns and is never retained by
the asynchronous write. Serving performs no proof checking, block application,
journal scan, state mutation, disk write, synchronization, retry, queueing, or
background work. A successful local channel submission does not prove remote
receipt or use.

## Failure, liveness, and trust boundaries

Transport framing, authentication, and protocol negotiation failures never
become object-level `Unavailable`. Outbound failures, authenticated-peer
mismatch, proof deadlines, and cancellation drains retain distinct typed causes.
Inbound request and stream failures are exposed when the pinned libp2p
behaviour reports them; not every pre-delivery negotiation or request-read
failure is promised as an application event. A dropped response channel is a
transport failure.

Listener progress, managed redial, negotiation, request reads, response writes,
timeouts, deadlines, and terminal delivery advance only while the caller polls
the network. Stopping polling removes every wall-time progress guarantee.
`ProofChainJournalError::Commit` and `Poisoned` are never translated into peer
responses and retain the journal's drop-and-reopen recovery boundary.

`Unavailable` means only that one authenticated serving boundary returned no
object for one exact request. It is not global absence, invalidity,
non-membership, freshness, or finality and creates no permanent negative cache.
Proof bytes remain unselected candidates; a matching block identity proves no
ancestry availability; and a reported or announced head may be stale, ahead,
misconfigured, on another history, or dishonest.

An authenticated head, announcement, or receipt must never become the trusted
expected head for `ProofChainJournal::open_verified` merely because Noise
identified its peer. Only explicit caller policy may turn an observation into a
separate block or ancestry retrieval target, and every import retains strict
journal validation. Static identity authorization is not Sybil/eclipse
resistance, discovery, dynamic proof authorization, key custody, peer scoring,
fork choice, consensus, finality, or economic identity.

The announcement contains no application signature beyond its live
authenticated session, and its receipt cannot be replayed as evidence that the
peer still observes, stores, or agrees with the same head.
