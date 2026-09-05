# Fixed-Validator Consensus Transport V0

## Scope and authority

`PROD-020-043` defines one explicit one-hop proposal or vote delivery through
`StaticArtifactNetwork` to a caller-selected configured Noise-authenticated
peer. The network advances only while its caller polls. The existing
[artifact transport](artifact-network-transport.md) owns managed static
connections and shared request permits; the existing
[node driver](fixed-validator-node-driver-v0.md) owns signing, publication
commands, strict input admission, and consensus transitions.

This component accepts owned raw bytes, not a signing scope, driver, command,
or verified proposal token. A caller may destructure `PublishProposal` and
supply its canonical proposal control and exact artifact payload, or destructure
`PublishVote` and supply the signed vote bytes. In the latter case the caller
must separately retain `released_proposal`, including `Some` from higher-round
pairing. A vote envelope carries no proposal. Delivery never consumes that
token or admits the sender's own publication.

The immediate Noise `PeerId` is an authenticated transport observation. It is
not a consensus signer, proposer, validator, proof of provenance, or basis for
message validity or selection. A configured peer may send opaque bytes signed
by another identity. The caller must separately choose a descriptive driver
event route; the driver's unchanged branch-relative decoding, signature,
context, round, role, quorum, and artifact checks remain authoritative.

The separate [bounded runtime](fixed-validator-runtime-v0.md) consumes driver
publications and composes these transport operations with explicit local timing
and ordinary strict admission. Those behaviors belong to that runtime, not to
this byte-delivery component.

This transport does not grant signing, consensus admission, branch selection,
finality, persistence, forwarding, or peer-trust authority. It does not settle
`NET-009` general gossip or `NET-021` reserved consensus capacity.

## Exact envelope

The request-response protocol is
`/naome/fixed-validator-consensus-push-v0`. Each exchange occupies one Yamux
substream. The enclosing stream requires exact EOF after both request and
response bodies.

| Variant | Request bytes | Body limits |
| --- | --- | --- |
| Proposal | `00`, `control_length u32be`, `payload_length u32be`, `control[control_length]`, `payload[payload_length]` | Control 481..=25,177; payload 1..=4,194,305 |
| Vote | `01`, `signed_vote[214]` | Exactly 214 signed-vote bytes |
| Receipt | Response `01` | Exactly one byte |

The tags and length fields are transport framing, not part of canonical
consensus or artifact bytes. Control limits derive from
`VerifiedFixedConsensusProposalV0::{MIN_BYTE_LENGTH, MAX_BYTE_LENGTH}`;
payload and vote limits derive from `ARTIFACT_PAYLOAD_MAX_BYTES` and
`VerifiedConsensusVoteV0::BYTE_LENGTH`. Inner encodings remain opaque: the
transport accepts lengths inside the control interval even when no valid
canonical proposal can have that particular length. It does not inspect proof
tags, signatures, message roles, heights, rounds, or artifact contents.

Unknown outer tags, invalid lengths, truncated prefixes or bodies, trailing
bytes, and any receipt other than exact `01` plus EOF fail transport decoding.
Both proposal lengths are validated before either body is allocated or read.
The decoder reserves one inbound event and the combined declared body bytes
before fallible exact-capacity allocation. A read, allocation, EOF, or cancelled
read-future failure releases partial buffers and that reservation.

## Ownership and limits

Outbound length validation precedes peer preflight. Peer preflight then keeps
the existing order: configured peer, no physically pending application request
for that peer across all protocols, connected managed and protocol session,
and one of eight shared outbound permits. A synchronous rejection returns the
exact owned `ConsensusPushMessage` through `ConsensusPushStartError`, including
both original allocations of a proposal. The private codec request cannot be
constructed through the public API to bypass this gate.

Successful queueing consumes the input. A `ConsensusPushTicket` identifies the
protocol-local request generation, expected peer, message kind and lengths,
and network instance. The physical pending request retains a shared permit.
An authenticated successful terminal event retains it until ticket completion
or event drop; a failed terminal releases it while retaining the network
identity needed for correlation. Mismatched completion returns both ticket
and terminal unchanged. Other protocols, another network with the same numeric
request ID, stale generations, different peers, or different message descriptors
cannot complete the ticket.

Dropping the ticket does not cancel a queued request. An asynchronous failure
carries no retry copy and cannot establish whether the receiver processed the
message before the response was lost. A caller needing retries must retain
its own input and explicitly initiate each attempt. There is no automatic
retry, forwarding, cancellation API, durable outbox, deduplication across
attempts, or exactly-once delivery.

Each network separately budgets consensus ingress at eight retained events
and 33,755,856 combined body bytes, exactly eight maximum proposal bodies of
4,219,482 bytes. Recovery-bundle ingress has its own unchanged budget. Both
use the same private checked-counter and ownership-permit implementation;
their budgets do not borrow capacity from one another.

After complete decoding the consensus permit binds to the authenticated
immediate peer. At most one inbound consensus event per peer may remain
retained, including across stream timeout, disconnect, and reconnect. A second
same-peer event is omitted without a receipt; dropping its unbound permit
cannot release the first event's peer binding. The peer check follows decoding,
so this is a retained-custody bound, not a byte-rate or DDoS policy. Global
capacity failure occurs after the fixed header and before any body read.

Dropping an inbound event releases its permit. Explicit
`acknowledge_consensus_push` queues only the stream receipt and transfers the
source and exact original allocations into `ReceivedConsensusPush`. A closed
response channel returns that same source and message in the typed error.
Once bytes transfer to application ownership, they no longer count against
transport retention; callers must bound their own retained copies and driver
inboxes separately. Acknowledgement does not prove that its response was
received, that bytes were persisted, or that consensus admission succeeded.

## Scheduling and failure boundary

The consensus request-response handler permits one concurrent stream per
connection shared between inbound and outbound directions. A held inbound
response channel occupies that worker until acknowledgement, drop, or timeout.
Simultaneous opposite-direction requests can fail; callers seeking an ordinary
request/receipt round trip complete one direction before starting the other.

Per-exchange limits now sum to nine, while the existing total Yamux ceiling
remains eight. Streams under negotiation or awaiting cleanup also consume
capacity. Limits provide no reserved consensus slot, fairness, queueing, or
progress guarantee. Exhaustion can fail a request or close the connection and
affect other exchanges; normal typed failure handling applies.

The existing 30-second timeout covers the negotiated request-response phase,
not a production consensus deadline or an absolute enqueue-to-delivery budget.
No timer policy, wall-clock interpretation, automatic driver polling,
application routing loop, node binary, general gossip, network completeness,
production runtime, or dynamic-validator policy is added.

## Verification evidence

Codec and transport unit tests cover exact variant framing and maximum widths,
pre-allocation rejection, event and combined byte limits, malformed receipts,
permit release, duplicate-peer custody, shared outbound preflight, dropped
tickets, terminal correlation, authenticated opaque delivery, and exact owned
message recovery after a closed response channel.

The Unix integration test uses two independently provisioned fixed-validator
drivers with distinct consensus keys and independently generated Noise keys.
Actual `PublishProposal` and `PublishVote` commands cross a real loopback
connection. Transport and acknowledgement leave both authority layouts and
unadmitted inboxes unchanged. Strict driver admission separately rejects bad
producer signatures, wrong context, and invalid payloads. Explicit admission
and stepping produce anchored votes, including higher-round checkpoint and
precommit with `Some` proposal custody. That token retains its exact bytes and
allocations across vote-delivery success, synchronous rejection, disconnect,
and asynchronous failure. Finality files remain unchanged.

This is local two-driver loopback evidence, not deployment, a multi-process
consensus run, production timing or liveness measurement, exhaustive allocation
or I/O fault injection, or non-Unix signer-runtime evidence.
