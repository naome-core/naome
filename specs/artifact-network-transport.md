# NAOME Artifact Network Transport

## Scope and authority

This document normatively defines transport-neutral artifact, artifact-block,
and artifact-chain-head exchanges; authenticated static-peer framing; head
announcements; resource bounds; and caller-routed journal,
candidate-block-store, or canonical-payload-archive serving. The
[Caller-Selected Orchestration](caller-selected-orchestration.md) contract owns
survey, broadcast, ancestry, import, and catch-up workflows.

`StaticArtifactNetwork` connects at most eight explicitly configured peers over
TCP, authenticates libp2p identities with Noise, and multiplexes application
protocols with Yamux. It advances only while its caller polls. It creates no
runtime, retry task, serving task, import task, or other NAOME-owned background
task.

Content, blocks, heads, announcements, and receipts remain untrusted
observations. No network exchange selects a block, supplies citation authority,
creates a checkpoint, or establishes consensus, finality, proposer, validator,
or economic authority.

## Static authenticated sessions

A configured peer binds one expected `PeerId` and dial `Multiaddr`. Local and
duplicate peer identities are rejected. Noise must authenticate the configured
identity before an application request can be delivered. The address is routing
data, not identity; learned peer records and dial candidates never authorize
artifact sessions.

For a configured pair, the endpoint with lexicographically lower raw
`PeerId::to_bytes()` is the sole dial owner. It maintains at most one connection
to the higher endpoint. Connection generations prevent stale terminal events
from changing a newer session. There is no role reversal, cross-dial race, or
request-triggered connection. A request without an established managed session
fails before consuming an application permit.

The exact application protocol identifiers are:

```text
/naome/artifact-exchange
/naome/artifact-block-exchange
/naome/artifact-chain-head-exchange
/naome/artifact-chain-head-announcement
```

Protocol-local request identifiers are namespaced and cannot alias across these
behaviours.

## Transport-neutral messages

The enclosing transport supplies one complete message boundary.

### Artifact

```text
request     = ArtifactId[32]
Unavailable = empty response
Found       = candidate tagged artifact bytes[1..=4,194,305]
```

Any 32-byte request is a syntactic address only. A found response is opaque at
this boundary: it may be a proof or definition, malformed, noncanonical,
invalid, unavailable in the required dependency context, or for the wrong
identity. Strict block admission must decode, check against selected prior
state, derive the typed `ArtifactId`, and compare the immutable request. Empty
is one peer's `Unavailable`; reset, timeout, truncation, or absence is transport
failure.

### Artifact block

```text
request     = ArtifactBlockId[32]
Unavailable = empty response
Found       = ArtifactBlock[128]
```

A nonempty response is rejected above 128 bytes, decoded as one complete fixed
block, hashed once, and exposed only when its `ArtifactBlockId` equals the
immutable request. Any other nonempty length is a block-decode failure. The
block carries no payload or chain ID.

### Artifact-chain head

```text
request     = ArtifactChainId[32]
Unavailable = empty response
Found       = ArtifactBlockId[32]
```

A found head is one responding peer's local observation, not an ancestry proof
or trusted rollback anchor. Every other nonempty response length is invalid.
The virtual genesis is a valid empty-journal head value but is not a retrievable
block.

### Head announcement

```text
request = ArtifactChainId[32] | ArtifactBlockId[32]
receipt = 01
```

The announcement is exactly 64 bytes. It contains no height, time, state root,
signature, or payload. The sole receipt is exactly byte `01`; it proves only
that the authenticated live peer returned that byte for this request generation.

## Stream framing

Each exchange occupies one request-response Yamux substream. Request and
response readers require the exact accepted body followed by end-of-stream.

| Protocol | Request frame | Response frame | Complete response bytes |
| --- | --- | --- | ---: |
| Artifact | `ArtifactId[32]` | `length u32be`, then `payload[length]` | 4..=4,194,309 |
| Artifact block | `ArtifactBlockId[32]` | `length u8`, then `block[length]` | 1 or 129 |
| Head pull | `ArtifactChainId[32]` | `length u8`, then `head[length]` | 1 or 33 |
| Head announcement | `chain[32]`, then `head[32]` | receipt `01` | 1 |

Artifact response length is `0..=4,194,305`. Zero is unavailable. The prefix is
framing and is not part of canonical artifact bytes.

Artifact-block response length is exactly `0` or `128`, which fits one `u8`.
The unavailable frame is exactly `00`; a found frame begins `80` and contains
the 128 block bytes, for 129 bytes total. This one-byte prefix is not part of
block identity.

For the block golden in [Proof Protocol](proof-protocol.md), the request is:

```text
2d5b1570acc98fd873426f4f5148f8aa4c625997324c69cf96a108cc1b2e076d
```

Its complete found frame is byte `80` followed directly by these four 32-byte
fields; line breaks are presentation only:

```text
9754a99788a5a44e8d4e2fd6e385970d3ce0120c624de04e3250a9e8d0f64c2e
2222222222222222222222222222222222222222222222222222222222222222
3333333333333333333333333333333333333333333333333333333333333333
4444444444444444444444444444444444444444444444444444444444444444
```

Head response length is exactly `0` or `32`. Its frames are `00` or `20`
followed by 32 head bytes. Announcement receipt is exactly `01`. Oversized or
impossible lengths are rejected before body allocation. All frames reject
truncated prefixes, truncated bodies, trailing bytes, and incomplete transport
terminals; none of those become `Unavailable` or acknowledgement.

## Shared resource envelope

One network instance enforces:

| Resource | Limit |
| --- | ---: |
| Configured peers | 8 |
| Pending inbound connection attempts | 8 |
| Pending outbound connection attempts | 8 |
| Established connections, total | 8 |
| Established connections per peer | 1 |
| Pending or caller-retained application permits | 8 |
| Pending outbound application requests per peer | 1 |
| Streams per artifact, block, or head exchange per connection | 2 |
| Head-announcement streams per connection | 1 |
| Aggregate application streams per connection | 7 |
| Negotiating inbound streams per connection | 2 |
| Yamux substreams per connection | 8 |
| TCP listen backlog | 16 |
| Connection establishment | 10 seconds |
| Negotiated request/response phase | 30 seconds |
| One exact artifact-block import | 120 seconds monotonic |
| Requests issued by one block import | at most 8 |
| Candidate bodies retained by one block import | at most 1 |
| Declared response bytes read by one block import | at most 33,554,440 |
| Blocks retained by one ancestry pull | 16 |
| Managed-session idle expiry | effectively disabled; at most 8 sessions |
| Pre-Noise inbound authentication burst/refill | 8 / 1 per second |
| Store- or journal-response attempt burst/refill | 8 / 1 per second |

Managed redial delays are `1, 2, 4, 8, 16, 32, 60` seconds and then remain at
60. A connection stable for 60 seconds resets backoff. Idle expiry is
effectively disabled; static peer and connection caps bound retained sessions.
Every timer requires continued caller polling.

The eight shared permits jointly bound pending requests, quarantined artifact
candidates, decoded blocks, heads, and receipts. At most eight maximum artifact
buffers can be retained: 33,554,440 payload bytes. One block import tries at
most eight configured peers for one immutable `ArtifactId`, so its maximum
declared artifact-response ingress is the same 33,554,440 bytes. These limits do
not include transient decoder, checker, or journal state.

Pending connection limits precede the global pre-Noise token bucket. The bucket
starts with eight and refills one per monotonic second to eight. The inbound
response bucket is shared across artifact, block, and head serving from a
journal, candidate block store, or canonical payload archive. It is not
per-source fairness, DDoS protection, or Sybil resistance.

## Outbound correlation and tickets

Starting a direct request checks: configured peer, no pending request for that
peer, connected managed session, then one shared permit. It then queues the
immutable request and records protocol, peer, generation, request, and network
instance.

Opaque non-cloneable tickets for blocks, heads, and announcements must match all
of those facts before transport or response content is interpreted. Peer and
ticket mismatch precede transport and object validation. Mismatch preserves the
values for correct routing. A successful event retains its permit until the
ticket consumes it or is dropped; terminal failure releases before delivery.

Dropping these direct tickets does not cancel libp2p work. Their peer slot and
permit remain until a terminal event. Unsupported remote protocol is a later
transport failure, not a start failure.

## Candidate-store retention and serving

A caller may consume one exact block ticket and its matching generation-bound
terminal into a caller-supplied chain-scoped `ArtifactBlockCandidateStore`.
Ticket mismatch is returned with both routable values before store access. A
matched transport failure or the authenticated peer's `Unavailable` response is
reported without insertion. A found response has already passed fixed 128-byte
canonical decoding and exact `ArtifactBlockId` comparison; success is returned
only after the store reports `Inserted` or the exact idempotent
`AlreadyPresent`. Capacity, corruption, and ambiguous durability remain typed
candidate-store failures.

The request carries no chain ID, so only the caller routes an inbound request to
the intended chain-scoped candidate store. Candidate-store response precedence
is:

1. store health and exact integrity-checked candidate read;
2. response-channel availability;
3. shared inbound response token;
4. fixed block encoding or `Unavailable` construction; and
5. libp2p response submission.

A store read failure never becomes `Unavailable` and may poison the store under
its own integrity contract. Serving does not insert, replace, refresh, promote,
or delete a candidate. The store retains no source or requester identity or
receipt time, and a submitted response does not prove remote receipt. This
composition defines no automatic relay, retry, peer or target selection,
payload availability, chain membership, fork choice, consensus, or finality.

## Canonical-payload-archive serving

A caller may route one exact statically authorized Noise-authenticated inbound
artifact request from one peer to one caller-supplied Foundation-scoped
`CanonicalArtifactPayloadStore`. The request contains only its exact
`ArtifactId`; it carries no artifact-chain, branch, selected-state, or archive
identity. Only the caller chooses the archive and whether to invoke this
responder for that request.

Archive response precedence is split so the response budget protects the
potential maximum-sized payload read:

1. require a healthy archive handle and look up the exact address in its
   in-memory index through `contains`;
2. require the response channel to remain open;
3. consume one shared inbound response token;
4. for an indexed address, integrity-read the exact owned payload through
   `get`; and
5. construct the exact found bytes or `Unavailable` response and submit it to
   libp2p.

Consequently, a closed channel or exhausted response bucket performs no
artifact-sized archive read or allocation. A later indexed-entry read or
integrity failure remains a typed payload-store error, may poison that archive
handle under its existing contract, and never becomes `Unavailable`. An
unindexed address yields the statically authorized Noise-authenticated peer's
`Unavailable` response only after the same channel and response-token checks.

A found response contains the archive's exact tagged canonical payload bytes.
The responder neither recreates the context in which those bytes were archived
nor validates them against any selected or candidate ancestry. The receiver
must still perform complete target-context validation. Serving does not insert,
replace, refresh, delete, import, promote, select, rank, or persist a branch;
retain source, requester, or receipt-time provenance; or establish validity,
continued availability, peer trust, chain membership, fork choice, consensus,
finality, or economic authority.

The archive retains no source provenance. Explicit caller routing may therefore
retransmit exact bytes that this node learned elsewhere, but the responder
chooses neither the original source nor the requesting recipient and defines no
automatic relay admission, eviction, recipient-selection policy, or relay task.

This is a standalone explicit response boundary. It does not inspect or fall
back to an `ArtifactChainJournal`, choose between selected and archived bytes,
serve candidate blocks, start a service loop, retry, or start an automatic
relay. Journal-backed artifact serving remains selected-only.

## Exact block import

After caller-selected direct-child preflight, import requests exactly the
block's immutable `ArtifactId`. It tries the authenticated block peer first,
then remaining configured peers in raw peer-ID order, once each, with one
request in flight. Disconnected or busy peers are skipped. Correlated transport
failure or `Unavailable` may rotate; a nonempty response is retained opaque and
handed immediately with the block to strict journal application.

Retrieval never decodes the artifact, distinguishes proof from definition,
normalizes, checks mathematics, inspects dependencies, or fetches a cited
`ProofId` or `DefinitionId`. Missing selected dependencies, malformed or
noncanonical bytes, invalid mathematics, or wrong identity are terminal
application failures and do not trigger fallback.

One 120-second deadline spans all peer attempts for the immutable address. It
begins after block preflight, includes negotiation and responses, and excludes
the synchronous journal application after a complete response. Expiry on
equality wins over a simultaneous physical response. Cancellation releases any
quarantined candidate and tombstones in-flight work; libp2p's eventual terminal
is drained without exposing bytes or advancing import. Physical drain can
outlive the logical deadline.

## Journal-backed serving

One service call consumes one delivered event. A supported artifact, block, or
head request is answered from a borrowed healthy
`ArtifactChainJournal`; every other event, including announcements, is returned
unchanged.

Response-attempt precedence is:

1. journal health and exact selected lookup or chain comparison;
2. response-channel availability;
3. shared inbound response token;
4. one bounded payload copy, fixed block encoding, or fixed head construction;
5. libp2p response submission.

Journal errors never become `Unavailable`. Rate exhaustion performs no
artifact-sized copy. An artifact lookup serves only the exact tagged bytes of a
selected accepted record; block lookup serves only a committed selected block;
head lookup returns the exact current head only for the matching chain. Unknown
objects and mismatched chains are unavailable. The journal borrow ends when the
service call returns, and serving performs no checking, import, mutation, disk
write, retry, archive lookup, or background work. In particular, the journal
service never falls back to a canonical payload archive.

Inbound announcements require explicit caller acknowledgement. The journal
adapter never acknowledges, compares, retrieves, or selects them automatically.

## Failure and trust boundaries

Framing, identity authentication, protocol negotiation, timeout, truncation,
and reset failures remain distinct from object-level unavailable. Listener,
redial, request, response, timeout, and terminal progress stop when polling
stops. A poisoned journal, candidate block store, or canonical payload archive
is never translated into network content.

`Unavailable` is one authenticated peer's response to one address. It is not
global absence, invalidity, authenticated-set non-membership, freshness, or
finality and creates no permanent negative cache. A fetched artifact remains
unselected; a matched block ID proves no ancestry; a head may be stale,
dishonest, or on another branch.

Noise authentication does not turn a head or receipt into a trusted expected
head for verified journal open. Only explicit caller policy may choose a
retrieval target, and every resulting block and artifact retains strict local
validation. Static peers do not provide discovery, Sybil/eclipse resistance,
fork choice, consensus, key custody, proposer identity, or economics.

This artifact protocol is a clean prerelease cutover. Proof-only protocol
identifiers and frames have no compatibility negotiation or legacy decoder.
