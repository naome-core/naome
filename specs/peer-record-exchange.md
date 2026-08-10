# NAOME Peer Record Exchange

## Status and scope

This document defines the prerelease V0 transport-neutral request and response
for pulling one bounded batch of peer-address records, plus its atomic
transition into the [peer-address store](peer-address-management.md). It is an
NAOME batch wrapper around standard interoperable libp2p signed peer records,
not a new peer-record format.

The exchange defines bytes and store admission only. It does not open sockets,
select a libp2p protocol identifier, authenticate a source, create discovery
sessions, or alter the authenticated proof transport. A caller may submit a
decoded response only with the exact configured source identity authenticated
by a separately defined transport.

## Request

The request is exactly zero bytes:

```text
end of stream
```

Any request byte is invalid. V0 has no filter, cursor, requested identity,
sequence watermark, pagination token, or correlation field. Transport-level
request correlation remains the responsibility of a future binding.

## Response

The response is:

```text
record_count       u8, 0..=32
records            record_count record entries
end of stream

record entry:
    envelope_length    u16 big endian, 1..=4096
    signed_envelope    envelope_length bytes
```

Every `signed_envelope` must be the normalized outer-protobuf encoding of one
valid standard interoperable libp2p `SignedEnvelope` containing a standard
peer record. Its signature, embedded subject `PeerId`, address count, address
grammar, and bounds must satisfy Peer Address Management. Re-encoding the
verified outer envelope through the standard libp2p encoder must reproduce the
received entry bytes exactly. Rust-libp2p's legacy routing-state envelope is
not accepted.

Entries are strictly ascending by the raw binary bytes returned for their
embedded subject `PeerId`. Equal or descending subjects are invalid, so one
response cannot contain duplicate subjects or multiple sequences for one
subject. Envelope order is the only batch order; it does not assert preference,
trust, reachability, or consensus order.

The maximum complete response is exactly `131137` bytes:

```text
1 + 32 * (2 + 4096)
```

The decoder reads the one-byte count before reserving entries. It validates
each two-byte length against `1..=4096` and the remaining response envelope
before allocating or reading that entry. A missing count, count above 32,
zero-length or oversized entry, truncated entry, invalid or non-normalized
envelope, non-ascending subject, trailing byte, or total response above
`131137` bytes rejects the complete response. It never returns a partial batch.

`record_count = 0` means only that this responder returned no records in this
exchange. Because V0 has no cursor or completeness commitment, any response of
zero to 32 records is non-authoritative about the responder's complete store
and proves no network-wide absence.

## Atomic store admission

One admission call supplies exactly:

- one healthy `PeerAddressStore`;
- one configured, separately authenticated source `PeerId`;
- one decoded, ordered batch containing `0..=32` signed records; and
- one local receipt time used for every inserted or replaced record.

The source is the bootstrap that supplied the batch, not the subject that
signed an individual record. A signature authenticates only its subject's
address claim. It does not authenticate the batch source or authorize the
subject for proof exchange.

Admission preflights the complete transition before snapshot I/O or in-memory
mutation:

1. require a healthy store and a source present in its immutable bootstrap
   configuration;
2. validate the single local receipt time;
3. reject any record whose subject is the local store identity;
4. compare every subject with its retained sequence watermark;
5. treat a lower sequence, or an equal sequence with identical normalized
   envelope bytes, as stale;
6. reject an equal sequence with different normalized envelope bytes as a
   sequence conflict;
7. stage every unknown subject as an insertion attributed to this source;
8. stage every strictly newer subject as a replacement while retaining the
   bootstrap source that first introduced that subject; and
9. validate the final staged state against the 256-record total, 32-record
   per-source, and eight-record per-IP-group limits.

This numbered order defines error precedence. The local-subject check covers
the complete batch before sequence classification; sequence classification
then follows canonical subject order. Capacity errors are reported in total,
source, then network-group order.

Capacity is evaluated over the complete final state: groups removed by a
replacement no longer count, groups introduced by that replacement do count,
and stale entries change nothing. The wire order cannot create a partial
success or make quota results depend on sequential mutation.

If the batch contains no insertion or replacement, admission succeeds as an
all-stale no-op and performs no snapshot commit. Otherwise the store encodes
and durably commits exactly one next snapshot for the whole batch. Only after
that commit succeeds does the complete staged state become visible. Every
inserted or replaced record receives the one supplied local receipt time;
stale records retain their prior receipt time and therefore cannot refresh
their seven-day TTL.

Unknown-source, local-subject, sequence-conflict, allocation, count, source
capacity, network-group capacity, or total-capacity errors expose no batch
mutation and perform no snapshot commit. Snapshot I/O follows the existing
store poisoning contract: a commit error returns no successful batch result,
poisons the live handle, and requires drop and reopen because durable state may
be ambiguous.

## Security boundary and exclusions

V0 guarantees bounded framing, strict standard-record verification, unique
ordered subjects, one authenticated-source input to admission, whole-batch
quota preflight, stale-replay TTL preservation, and at most one durable store
transition. These guarantees do not establish that an address is reachable or
that a source and subject represent independent operators.

This contract does not define or claim:

- a libp2p stream protocol, socket, listener, dial, timeout, retry, request
  correlation, or authenticated transport binding;
- push gossip, subscriptions, cursors, deltas, pagination, Rendezvous, DHT,
  DNS, mDNS, NAT traversal, relay, or hole punching;
- dynamic session ownership, learned-peer connection authorization, peer
  scoring, reputation, bans, Sybil resistance, or eclipse resistance;
- conversion of a learned record into `StaticPeer`, proof availability, proof
  authorization, consensus, mining, validator roles, finality, rewards, fees,
  or settlement; or
- a replacement for the standard libp2p signed peer-record payload, domain,
  signature, or sequence semantics.

The next slice may bind this exchange to explicitly authenticated bootstrap
sessions. Dynamic peer sessions and any proof-exchange authorization remain
separate designs.
