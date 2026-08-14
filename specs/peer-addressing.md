# NAOME Peer Addressing

## Authority model

This document defines bootstrap configuration, standard signed peer records,
their bounded durable store and local issuer, the canonical record-batch format,
and its authenticated pull and response bindings.

The following facts remain separate:

| Fact | What it establishes | What it does not establish |
| --- | --- | --- |
| `BootstrapPeer` | An operator chose one expected `PeerId` and initial address | General trust, artifact authorization, or availability |
| Standard signed peer record | The identity-key holder signed its own address claim | Honest operation, unique control, freshness, or reachability |
| Local receipt time | This store accepted this exact record recently enough for local policy | Signing time or network-wide freshness |
| Observed authenticated reachability | One exact endpoint was reachable at one instant | The protocol persists no such observation |
| `StaticPeer` | The operator authorized one identity for artifact transport | Sybil or eclipse resistance |

Source and subject are also distinct. The `source` is the configured bootstrap
whose authenticated connection supplied a batch. The `subject` is the identity
that signed one embedded record. Source is local diversity provenance, not an
endorsement. A learned subject never becomes a `StaticPeer` implicitly.

## Bootstrap configuration

One local identity may configure at most eight unique `BootstrapPeer` values.
Each contains one expected non-local `PeerId` and one binary `Multiaddr` of at
most 256 bytes, exactly:

```text
/ip4/<address>/tcp/<nonzero-port>
/ip6/<address>/tcp/<nonzero-port>
```

No suffix is permitted. Operator-controlled bootstrap addresses may be private,
loopback, or otherwise local. The outbound handshake must nevertheless
authenticate the configured `PeerId` at the configured address. This contract
supplies no default bootstrap list, DNS resolution, remote-list update,
learned-address substitution, or fallback address. Only a configured bootstrap
identity may be the source of a stored record.

## Standard signed peer records

### Canonical envelope admission

A record is a standard libp2p `SignedEnvelope` whose payload is the standard
peer-record protobuf. Admission applies this exact order:

1. require an envelope length in `1..=4096` bytes;
2. decode the outer protobuf with the standard libp2p signed-envelope decoder;
3. require payload-type bytes `03 01`, then verify the signature using the
   standard `libp2p-peer-record` domain separation;
4. decode the standard peer-record payload and its embedded `PeerId`, then
   require that identity to match the signing key;
5. decode every payload address as a binary `Multiaddr`;
6. require a canonical subject identity of at most 44 bytes and a normalized
   re-encoded envelope of at most 4096 bytes;
7. require `1..=4` addresses and, for each in order, require at most 256 bytes,
   the exact globally routable IP/TCP shape, then no duplicate of an earlier
   address;
8. apply retained-sequence policy for the subject; and
9. require the final total, source, and IP-group quotas.

After verification, the receiver re-encodes the outer envelope with the
standard libp2p encoder and stores that normalized protobuf. Normalization may
remove incidental outer-protobuf representation choices, but it must not alter
the signed payload, signature, subject, sequence, address order, or address
bytes, and the result must remain at most 4096 bytes. External bytes always
cross the full signature, embedded-identity, address, bound, and normalization
path.

The legacy `libp2p-routing-state` envelope is invalid. There is no fallback,
translation, or migration parser. The standard libp2p format is authoritative;
NAOME requires independent cross-decoding and does not define a second envelope
format for trusted local construction.

### Address policy and resource bounds

For learned and locally issued records, IPv4 is global exactly when it is
outside all of these ranges:

```text
0.0.0.0/8       10.0.0.0/8       100.64.0.0/10
127.0.0.0/8     169.254.0.0/16   172.16.0.0/12
192.0.0.0/24    192.0.2.0/24     192.168.0.0/16
198.18.0.0/15   198.51.100.0/24  203.0.113.0/24
224.0.0.0/4     240.0.0.0/4
```

IPv6 must be inside `2000::/3` and outside `2001:2::/48`, `2001:10::/28`,
`2001:20::/28`, and `2001:db8::/32`. This fixed predicate, rather than a
platform or changing registry classifier, is normative. DNS names, UDP, QUIC,
relay paths, appended peer components, and every other address shape are
invalid.

One store has these limits:

| Resource | Limit |
| --- | ---: |
| Bootstrap peers | 8 |
| Stored records | 256 |
| Addresses per record | 4 |
| Normalized signed-envelope bytes | 4096 |
| Binary bytes per address | 256 |
| Records attributed to one source | 32 |
| Records covering one IPv4 `/16` or IPv6 `/32` group | 8 |
| Selected candidates | 8 |
| Selected candidates attributed to one source | 2 |
| Local record lifetime | 604800 seconds |

An IP group is the first 16 address bits for IPv4 or the first 32 for IPv6. A
record counts once for each distinct group represented by its addresses.
Capacity failure rejects a record or complete batch; it never evicts a subject,
truncates an envelope, drops a signed address, or partially replaces state.

### Sequence and freshness

A signed sequence is subject-controlled ordering data, not a clock. For a
retained subject:

- a lower sequence is stale;
- an equal sequence with identical normalized envelope bytes is stale;
- an equal sequence with different normalized bytes is a conflict; and
- a greater sequence replaces the record and refreshes local receipt time while
  retaining the bootstrap source that first introduced the subject.

Stale records do not refresh receipt time. A record is eligible exactly while:

```text
receipt_time <= now < receipt_time + 604800
```

All arithmetic is checked. An earlier local time is not freshness. Expired
records remain stored, occupy capacity, and retain their sequence watermark, so
an equal or older replay cannot regain a fresh TTL. A newer sequence may replace
an expired record.

## Peer-address store

### Atomic batch admission

One canonical batch is admitted with one healthy store, one configured and
separately authenticated source, and one caller-supplied local receipt time for
all inserted or replaced records. The complete transition is preflighted before
snapshot I/O or memory mutation in this exact order:

1. require a healthy store and a source in its immutable bootstrap
   configuration;
2. validate the one local receipt time;
3. reject any batch subject equal to the local store identity;
4. compare subjects with retained watermarks in canonical subject order;
5. classify lower sequences and byte-identical equal sequences as stale;
6. reject an equal sequence with different normalized bytes as a conflict;
7. stage every unknown subject as an insertion attributed to this source;
8. stage every newer subject as a replacement retaining its original source;
9. validate the complete final state against total-record, per-source, then
   per-IP-group capacity, in that precedence.

The local-subject check covers the complete batch before sequence
classification. Replacements remove their old groups and add their new groups
for final-state quota calculation; stale entries change nothing. Wire order
cannot produce a partial result.

An empty or all-stale batch succeeds without a snapshot commit. A batch with at
least one insertion or replacement produces exactly one atomic snapshot. Only
after durable commit does the staged state become visible. Unknown source,
invalid receipt time, local subject, sequence conflict, allocation, or quota
failure writes nothing. A commit I/O error returns no successful admission,
poisons the handle, and may leave either the old or new complete snapshot
durable; strict reopen is the only recovery.

### Deterministic candidate selection

Store creation obtains one random 32-byte ordering salt from the operating
system and persists it. Selection considers only fresh records at UTC day
`floor(now / 86400)`. Every eligible address has this exact big-endian rank:

```text
SHA256(
    "naome:peer-address-rank\0"
    || ordering_salt[32]
    || utc_day_u64_be[8]
    || subject_peer_id_length_u8 || subject_peer_id
    || address_length_u16_be || address
    || source_peer_id_length_u8 || source_peer_id
)
```

Bytewise subject, address, then source order breaks equal scores. Scanning this
total order selects at most eight rows while preserving at most one address per
subject, two subjects per source, and one candidate per IPv4 `/16` or IPv6
`/32` group. A selected candidate conveys no reachability or artifact authority.

### Snapshot ownership, encoding, and recovery

One store holds an exclusive cooperative sidecar lock for the lifetime of its
snapshot directory handle. A mutation is fully constructed and validated,
written to a same-directory temporary, synchronized, and atomically renamed
over the snapshot. Unix implementations also synchronize the parent directory
before acknowledging success. The store makes no sudden-power-loss guarantee
for the renamed directory entry on platforms without a safe parent-directory
sync.

Any commit I/O error poisons all later reads, selection, and mutation. A
temporary file is never authoritative. Drop and strict reopen is the only
recovery from ambiguity.

Canonical bootstrap configuration sorts validated entries by raw `PeerId`
bytes and then raw address bytes and encodes:

```text
bootstrap_count_u8
each (
    peer_id_length_u8 || peer_id
    || address_length_u16_be || address
)
```

Its digest is exactly:

```text
SHA256(
    "naome:peer-address-bootstrap-config\0"
    || canonical_bootstrap_configuration
)
```

The snapshot uses unsigned big-endian integers, subject entries sorted by
raw `PeerId` bytes, and no padding:

```text
header                        "naome:peer-address-store\0"
local_peer_id_length          u8
local_peer_id                 local_peer_id_length bytes
bootstrap_configuration       bootstrap configuration digest [32]
ordering_salt                 32 bytes
entry_count                   u16
entries                       entry_count entries
snapshot_checksum             32 bytes

entry:
    source_peer_id_length     u8
    source_peer_id            source_peer_id_length bytes
    receipt_time              u64
    envelope_length           u16
    standard_signed_envelope  envelope_length bytes
```

Every peer-ID length is `1..=44` and must contain one canonical libp2p
`PeerId`. Variable lengths are validated against their bound and remaining
bytes with checked arithmetic before read or allocation. With 256 maximal
entries, the complete image is at most `1_062_824` bytes:

```text
25 + (1 + 44) + 32 + 32 + 2
   + 256 * ((1 + 44) + 8 + (2 + 4096))
   + 32
```

The checksum is exactly:

```text
SHA256(
    "naome:peer-address-store-checksum\0"
    || every snapshot byte before snapshot_checksum
)
```

Open rejects oversized metadata before allocating the complete image. It then
requires the exact header, expected local identity and bootstrap digest,
restored salt, checksum, sorted unique subjects, valid normalized records and
metadata, complete bytes, no trailing byte, and every live bound. It reconstructs
source counts, group counts, subjects, and sequence watermarks instead of
trusting derived data. It never skips, repairs, truncates, evicts, or
reinterprets an entry, and it has no legacy reader or migration path.

The checksum detects accidental corruption only. It does not authenticate
local source, receipt, bootstrap, salt, or ordering metadata and does not
prevent rollback or replacement by another valid snapshot.

## Local record issuer

### Identity and sequence authority

One `LocalPeerRecordIssuer` binds one persisted `PeerId`, one highest-issued
sequence watermark, and one exclusively locked authoritative directory. The
caller supplies the signing key on every issuance; its derived identity must
match. The private key is never retained or persisted.

Creation accepts an operator-asserted floor equal to the highest sequence ever
issued for that identity by any prior authoritative state. A never-used
identity starts at zero and first issues sequence one. `u64::MAX` is valid state
but cannot issue again. The issuer cannot infer or repair a lost floor from a
key, store, responder, or network; an unknown floor must not be guessed.

Only one directory may be authoritative for an identity. Its cooperative lock
cannot detect copies, restored backups, another directory, or a writer that
ignores the lock. The snapshot stores no prior envelope or addresses. A
committed sequence gap is valid if the process stops before returning the
record.

### Construction and exact precedence

One issuance polls at most five iterator items, bounding discovery of a fifth
address without exhausting an unbounded source. It requires `1..=4` distinct
addresses satisfying the same exact global-IP/TCP grammar. It preserves input
order and bytes; it neither sorts nor silently deduplicates them.

The payload fields are the signing key's exact `PeerId`, the next durable
sequence, and the exact validated address order. The standard envelope uses
domain `libp2p-peer-record` and payload type `03 01`. The issuer encodes the
payload and envelope once and constructs the trusted local record from those
validated values; it does not decode or verify its own new signature a second
time. Receiving that record still uses the full external decoder.

Issuance follows this exact order:

1. reject a poisoned handle;
2. require the supplied signing key to match the bound identity;
3. compute `last_issued_sequence.checked_add(1)`;
4. poll at most five address inputs while collecting at most four;
5. validate the count, then each address in input order by byte length, exact
   global-IP/TCP shape, and duplication against prior addresses;
6. encode the canonical standard peer-record payload;
7. sign and canonically encode the standard envelope once;
8. construct the record from the validated identity, sequence, ordered
   addresses, and new envelope;
9. encode the next issuer snapshot;
10. atomically commit the new watermark; and
11. only after commit succeeds, update the in-memory watermark and return the
    record.

Empty input or a fifth address is an address-count error. For each address,
length wins before shape and global-routing policy, which wins before duplicate
detection; after count succeeds, the first invalid address in iterator order
wins. Identity mismatch and sequence exhaustion occur before the iterator is
observed. Every pre-commit failure leaves the handle healthy and both
watermarks unchanged.

### Issuer snapshot and recovery

The issuer uses exactly:

- `local-peer-record-issuer.lock`, held exclusively for the handle lifetime;
- `local-peer-record-issuer.bin`, the authoritative snapshot; and
- `local-peer-record-issuer.tmp`, a non-authoritative same-directory temporary.

`create` refuses to replace an existing snapshot and commits the supplied floor
before returning. `open` requires a snapshot, reads at most one sentinel byte
beyond the maximum, and validates the complete image. The exact unsigned
big-endian, unpadded encoding is:

```text
header                       "naome:local-peer-record-issuer\0" [31]
peer_id_length               u8, 1..=44
peer_id                      peer_id_length bytes
last_issued_sequence         u64 big endian
snapshot_checksum            32 bytes
```

Its maximum is exactly 116 bytes: `31 + 1 + 44 + 8 + 32`. Its checksum is:

```text
SHA256(
    "naome:local-peer-record-issuer-checksum\0"
    || every snapshot byte before snapshot_checksum
)
```

Open validates file size, minimum length, checksum, exact header, canonical
bounded identity, expected identity, sequence, and EOF. It has no open-or-create,
legacy, repair, truncation, or migration path.

Every issuance writes and synchronizes the temporary, renames it atomically,
and on Unix synchronizes the parent before success. A commit error returns no
record and poisons the handle because either old or proposed watermark may be
durable; in-memory state does not advance. Later issuance and watermark
inspection both fail rather than expose a possibly stale value. Strict reopen
determines the installed watermark. A create-time commit error likewise
requires open as the only recovery probe. The issuer must commit the watermark
before returning the record, but the checksum and directory lock do not provide
rollback protection or prove that the floor is globally maximal.

## Canonical record batch

The transport-neutral request is exactly zero bytes followed by EOF. The
response has no outer length prefix:

```text
record_count       u8, 0..=32
records            record_count record entries
end of stream

record entry:
    envelope_length    u16 big endian, 1..=4096
    signed_envelope    envelope_length bytes
```

Every envelope is the exact normalized standard encoding defined above.
Entries are strictly ascending by raw embedded-subject `PeerId` bytes. Equal or
descending subjects are invalid, so a batch contains at most one record per
subject. Order conveys no preference or authority.

The maximum response is exactly `131137` bytes:

```text
1 + 32 * (2 + 4096)
```

The decoder reads the count before reserving entries. For each entry it reads
the two-byte length and rejects zero, more than 4096, or bytes outside the
remaining bounded frame before allocating or reading the body. It requires EOF
before signature and canonical-batch work. Missing or excessive count,
truncation, invalid or non-normalized records, non-ascending subjects, trailing
bytes, or an oversized response rejects the whole batch; no partial batch is
returned. A zero count means only that this responder published no records in
this exchange, not complete or network-wide absence.

## Authenticated outbound pull

### Direction, correlation, and ownership

One dedicated `PeerRecordBootstrapClient` has zero to eight configured sources
and supports only outbound `/naome/peer-record-exchange`. It has no listener,
inbound stream capacity, responder API, or artifact protocol. A cold request dials
the exact configured address and Noise identity; a different identity is a
terminal transport failure. A healthy authenticated connection may be reused.

Starting a pull checks unknown bootstrap identity before source already active
or retained. No separate global-limit error exists because eight immutable
source slots and one permit per source impose the global bound.

Each pull correlates its request identifier, expected source, and retained
source permit. A terminal checks request identity, then authenticated peer,
then response or transport failure. Unknown or stale identifiers are ignored;
peer mismatch is typed and never yields a batch. The permit remains held while
an authenticated batch awaits atomic store admission and releases after that
consuming admission or on drop, so the source cannot restart early. Network
failure never becomes an empty batch or store mutation, and polling performs no
disk I/O.

### Pull limits

| Resource | Limit |
| --- | ---: |
| Configured sources | 8 |
| Active or retained pulls per source / client | 1 / 8 |
| Pending / established outbound connections | 8 / 8 |
| Established connections per source | 1 |
| Concurrent record streams per connection | 1 |
| TCP/Noise/Yamux establishment | 10 seconds |
| Outbound protocol negotiation | 10 seconds |
| Negotiated request/response | 30 seconds |
| Fully idle authenticated connection | 10 seconds |
| Request / maximum response bytes | 0 / 131137 |

The establishment, negotiation, and exchange bounds are consecutive physical
phases, not a resettable application deadline. The client has no automatic
retry, fallback, refresh, managed redial, backoff, or keepalive. Progress and
timeout delivery require continued polling. The ten-second negotiation value is
the pinned libp2p default, not a NAOME-owned constant; dependency upgrades must
revalidate it.

## Authenticated inbound responder

### Immutable publication and direction

One dedicated responder consumes a verified canonical batch of `0..=32`
records, encodes it once, drops the decoded batch, and retains one shared
immutable response buffer for its lifetime. Every successful response uses
identical bytes; changing publication requires a new responder. It does not
read a store, issue records, apply TTL, preserve upstream provenance, or infer
freshness or completeness. An empty configured batch is valid, but no rejection
or failure is encoded as an empty response.

The responder supports only inbound `/naome/peer-record-exchange`, one
listener, and any successfully Noise-authenticated requester. It has no dial
API, outbound protocol, or artifact protocol. The responder's Noise `PeerId`
becomes the pull result's source; it is never substituted by a signed subject
or by an operator's upstream source.

A second listen attempt fails while the listener slot is occupied. A listener
error reports the error without silently releasing that slot; a listener-closed
terminal releases it so the caller may listen again.

### Gate and request precedence

Pending TCP connections cross the connection-limit gate before one global
pre-authentication bucket. A connection-limit rejection consumes no token. The
bucket starts at burst eight and lazily refills one token per monotonic second
up to eight; a permitted attempt consumes its token even if the later handshake
fails, with no refund.

After authentication and negotiation, the codec reads one byte to distinguish
EOF from a malformed nonempty request. A valid empty request then crosses a
separate global bucket with the same burst-eight, refill-one-per-second rule.
That token is consumed before queueing the fixed response and is never refunded.
Malformed, timed-out, or failed reads consume no valid-request token and close
their connection.

Terminal request failures distinguish valid-request rate exhaustion, nonempty
request, expiry of the nested request-read timeout, request-read I/O failure,
and later inbound transport failure. Every eager rejection closes the request's
connection and sends no response. Local rejection and later transport cleanup
are correlated into one terminal request event. No failure becomes an empty
response. `ResponseSent` means only that immutable bytes were flushed locally;
it does not prove remote receipt, decoding, admission, or retention.

### Responder limits and rate accounting

| Resource | Limit |
| --- | ---: |
| Active listener / TCP backlog | 1 / 16 |
| Pending / established inbound connections | 8 / 8 |
| Established connections per authenticated `PeerId` | 1 |
| Pending or established outbound connections | 0 |
| Negotiating streams / concurrent requests per connection | 1 / 1 |
| Pre-authentication attempts | Global burst 8, refill 1/second |
| Valid requests admitted | Global burst 8, refill 1/second |
| TCP/Noise/Yamux establishment | 10 seconds |
| Inbound protocol negotiation | 10 seconds |
| Empty request read | 10 seconds, nested in exchange timeout |
| Complete negotiated exchange | 30 seconds |
| Fully idle authenticated connection | 10 seconds |
| Request / immutable response bytes | 0 / `1..=131137` |

The ten-second negotiation value is again supplied by the pinned libp2p
version and must be revalidated on dependency upgrade.

Pending and established pools are separate, so eight handshakes may coexist
with eight established connections, while only established connections own at
most eight concurrent writes. From a full valid-request bucket, starts are at
most `8 + floor(t / 1 second)`. The first continuously driven 60 seconds admit
at most 68 response bodies, or `68 * 131137 = 8917316` publication bytes. An
arbitrary 60-second egress window may also begin with eight authorized writes
already in flight, for at most 76 bodies and `9966412` bytes. Sustained admitted
publication is at most `131137` bytes per second. Framing, handshake, kernel,
and transport overhead are outside these byte counts.

The pre-authentication bucket bounds handshake admissions, not raw TCP attempts
rejected earlier or unsuccessful protocol negotiations. Connection, stream,
backlog, and timeout slots can still be exhausted; the responder makes no
volumetric availability or fairness guarantee. Listener and timeout progress
require continued polling.

## Resulting trust boundary

This contract provides bounded canonical self-signed address claims,
authenticated bootstrap provenance, local receipt freshness, retained sequence
watermarks, atomic snapshot transitions, deterministic local candidate
diversification, commit-before-return local issuance, and bounded directional
exchange. It does not provide reachability, key custody, rollback protection,
live publication, automatic discovery, artifact authorization, operator
independence, reputation, Sybil or eclipse resistance, consensus, or finality.
