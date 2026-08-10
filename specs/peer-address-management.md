# NAOME Peer Address Management

## Status and scope

This document defines the prerelease V0 local address-management contract. It
stores a bounded set of standard libp2p signed peer records and derives a
small, deterministic, locally diversified set of dial candidates. The store is
a routing input for a later discovery transport; it does not alter the
[authenticated proof transport](authenticated-proof-transport.md).
The transport-neutral [peer-record exchange](peer-record-exchange.md) may
submit up to 32 ordered records through one atomic store transition without
making those records proof-authorized peers.

V0 deliberately separates five facts:

| Input | What it establishes | What it does not establish |
| --- | --- | --- |
| `BootstrapPeer` | An operator chose one expected `PeerId` and initial address | General peer trust, proof authorization, or availability |
| Standard signed peer record | The holder of one libp2p identity key signed its own address claim | Honest operation, unique control, or current reachability |
| Local receipt time | This store first accepted this exact record recently enough for local policy | The record's creation time or network-wide freshness |
| Observed reachability | A successful authenticated dial would establish that one endpoint was reachable at that instant | V0 records no such observation and never infers it from receipt or selection |
| `StaticPeer` | The operator explicitly authorized an identity for the current proof transport | Sybil or eclipse resistance |

None of these facts substitutes for another. In particular, an identity can
create and sign arbitrarily many peer records. A learned record must therefore
never be converted implicitly into a `StaticPeer`.

## Bootstrap boundary

The caller may configure at most eight `BootstrapPeer` values. Each contains
one expected `PeerId` and one dial `Multiaddr` of at most 256 binary bytes. The
address shape is exactly `/ip4/<address>/tcp/<nonzero-port>` or
`/ip6/<address>/tcp/<nonzero-port>` with no suffix. Unlike learned addresses,
operator-controlled bootstrap addresses may be private, loopback, or otherwise
local for development and private deployments. Duplicate peer identities and
the local identity are invalid. The expected identity must still be confirmed
by the authenticated libp2p handshake when a future bootstrap transport dials
the address.

Bootstrap peers are operator configuration, not signed-record storage. They
are initial rendezvous points from which a later protocol may receive signed
records. Only a configured bootstrap identity may be the source of a V0 store
entry. The source is diversity provenance, not endorsement of the record
subject. Bootstrap peers do not become proof peers, and a connection to one
does not authorize proof requests or responses.

This MR defines no bundled default list, DNS resolution, remote list update,
or authenticated bootstrap socket/session binding. The transport-neutral batch
bytes are defined separately in [Peer Record Exchange V0](peer-record-exchange.md).
Supplying and updating bootstrap configuration is an operator responsibility.

## Signed-record admission

The store accepts an envelope together with the authenticated `PeerId` of the
configured bootstrap that supplied it and a local receipt time. The bootstrap
is the record's `source`; the peer that signed the embedded address claim is
the record's `subject`. Source and subject may be equal. An unconfigured source
is rejected before mutation.

Admission is strict and all-or-nothing:

1. require an envelope in `1..=4096` bytes;
2. decode its outer protobuf with the standard libp2p signed-envelope decoder;
3. decode only the standard interoperable libp2p peer-record payload and its
   standard domain separation and payload type;
4. verify the envelope signature and require the embedded `PeerId` to match
   the signing key;
5. require `1..=4` distinct, structurally valid `Multiaddr` values, each
   consisting exactly of one globally routable IPv4 or IPv6 component followed
   by one nonzero TCP port;
6. require every binary address encoding to be in `1..=256` bytes;
7. apply the stale, conflict, insertion, or strictly newer replacement policy
   for the subject's retained sequence watermark; and
8. require all fixed total, source, and IP-group capacity limits to remain
   satisfied.

After verification, V0 re-encodes the outer `SignedEnvelope` through the
standard libp2p encoder and persists that normalized outer protobuf. It does
not preserve incidental outer-protobuf representation choices from the input.
The signed peer-record payload, signature, subject, sequence, and address order
remain unchanged, and the normalized envelope must still fit the 4096-byte
bound.

The Rust-libp2p legacy routing-state envelope is not accepted. V0 uses only
the standard interoperable signed peer-record envelope; there is no legacy
fallback, migration parser, translation, or best-effort salvage. Signed
address order and bytes remain the record owner's authenticated claim.

The record sequence is signer-controlled ordering data. It selects a newer
record for the same subject but is not trusted as a clock. Freshness is based
only on the persisted local receipt time. Replaying the same or an older
sequence cannot refresh that time. A strictly newer record refreshes the local
receipt time but retains the source that first introduced that subject; a
subject cannot improve its diversity placement by moving among bootstraps.

## Bounds and freshness

One store contains at most:

| Resource | Limit |
| --- | ---: |
| Operator bootstrap peers | 8 |
| Stored signed peer records | 256 |
| Signed addresses per record | 4 |
| Signed-envelope bytes | 4096 |
| Binary bytes per address | 256 |
| Records attributed to one source | 32 |
| Records covering one IPv4 `/16` or IPv6 `/32` group | 8 |
| Selected peer candidates | 8 |
| Selected candidates attributed to one source | 2 |
| Local record lifetime | 7 days (`604800` seconds) |

An IP group is the first 16 bits of an IPv4 address or the first 32 bits of an
IPv6 address. A record occupies each distinct group represented by its
addresses only once. For V0, learned IPv4 addresses are global exactly when
they are outside `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`,
`169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`,
`192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`,
`224.0.0.0/4`, and `240.0.0.0/4`. Learned IPv6 addresses must be in
`2000::/3` and outside `2001:2::/48`, `2001:10::/28`, `2001:20::/28`, and
`2001:db8::/32`. This fixed V0 predicate, rather than a platform or evolving
registry classifier, defines `global` for the store.

DNS names, every address rejected by that predicate, UDP, QUIC, relay paths,
appended peer components, and every other multiaddress shape are rejected.
Bounds are checked before mutation. Fixed capacity rejects the new record; it
never evicts an accepted subject, truncates an envelope, drops individual
signed addresses, or partially replaces an existing record.

A record is fresh exactly while:

```text
receipt_time <= now < receipt_time + 604800
```

All arithmetic is checked. A local time earlier than the persisted receipt
time does not make the record eligible. Expiry is local policy, not evidence
that the address is globally invalid. Expired entries remain persisted as
bounded sequence watermarks and continue to occupy capacity. This prevents a
replayed equal or older record from being reintroduced with a fresh local TTL.
A strictly newer signed sequence may replace an expired or unexpired record;
an equal or older sequence may not extend its lifetime.

## Atomic record batches

The store also admits the bounded batch defined by Peer Record Exchange. One
configured authenticated source and one local receipt time apply to the whole
batch. It preflights every subject decision and the complete final total,
source, and IP-group quotas before mutation. Stale records are ignored without
refreshing receipt time; a sequence conflict, local subject, unknown source, or
capacity failure rejects the complete batch without a snapshot write.

An all-stale or empty batch performs no commit. A batch with at least one
insertion or replacement produces exactly one atomic snapshot commit, never
one commit per record. Strictly newer replacements retain their originally
recorded bootstrap source. The detailed framing, ordering, error, and atomicity
rules are normative in [Peer Record Exchange](peer-record-exchange.md).

## Reachability boundary

V0 records no dial result or reachability score. Receiving, validating,
persisting, or selecting a record proves no address reachable. A later dynamic
session layer may observe an authenticated successful connection to the exact
subject and address, but that runtime fact must remain separate from signed
record authenticity, local receipt freshness, bootstrap provenance, and proof
authorization.

## Deterministic diversified selection

Creating a store generates one random 32-byte local ordering salt and persists
it in the snapshot. Random generation uses the operating system's secure
random source and creation fails if 32 bytes cannot be obtained. Selection
takes a Unix time, considers only fresh signed records, and produces at most
one `(subject, address, source)` candidate per subject. A candidate grants no
connection or proof capability.

The UTC day is `floor(now / 86400)`. Every eligible signed address is ranked by
this exact digest, where integers are big endian and lengths cover the field
that immediately follows:

```text
SHA256(
    "naome:peer-address-rank-v0\0"
    || ordering_salt[32]
    || utc_day_u64_be[8]
    || subject_peer_id_length_u8 || subject_peer_id
    || address_length_u16_be || address
    || source_peer_id_length_u8 || source_peer_id
)
```

Bytewise subject, address, and source order breaks the cryptographically
negligible case of equal scores. Selection scans that total order and accepts a
candidate only while preserving all of these constraints:

- at most eight candidates total;
- at most one candidate for one subject;
- at most two candidates attributed to one source; and
- at most one selected candidate from one IPv4 `/16` or one IPv6 `/32` group.

Persisting the salt keeps selection stable within one UTC day across process
restarts. Distinct store salts make a remote party unable to choose one
universal ordering across nodes; the day input limits permanent ordering bias.
The salt is local ranking state, not an authentication key. The scheme is
deterministic load spreading, not a proof of independent operators, autonomous
systems, or failure domains. The source and IP-group bounds reduce
concentration in this local cache but do not provide Sybil or eclipse
resistance.

## V0 snapshot and recovery

### Ownership and commit

One address store has exclusive cooperative ownership of its snapshot
directory through a sidecar lock held for the complete handle lifetime. A
second handle fails immediately rather than reading or writing concurrently.

Every accepted mutation is first constructed and validated as a complete
bounded next state. It is encoded to a temporary file in the same directory,
the temporary file is synchronized, and atomically renamed over the snapshot.
On Unix, the parent directory is also synchronized before success is
acknowledged. Rust's standard library exposes no safe portable
parent-directory synchronization contract on Windows and other non-Unix
targets, so V0 does not claim that the renamed directory entry survives a
sudden power loss there. A successful reopen still verifies the complete
installed snapshot on every platform.

Any commit I/O error conservatively poisons the live handle and permits no
further reads, selection, or mutation, even when the previous snapshot remains
authoritative because the failure preceded the rename. A failure at or after
the rename is durability-ambiguous. Drop and reopen is the only recovery path.
Temporary files are never treated as snapshots on open.

### Encoding

The store persists one bounded V0 snapshot. A canonical bootstrap
configuration first sorts validated entries by raw `PeerId` bytes and then raw
address bytes and encodes:

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
    "naome:peer-address-bootstrap-config-v0\0"
    || canonical_bootstrap_configuration
)
```

Local-identity, duplicate-identity, count, address-shape, and address-length
validation occurs before this digest is calculated.

The snapshot uses unsigned big-endian integers, byte strings length-prefixed as
shown, entries sorted by raw subject `PeerId` bytes, and no padding:

```text
header                        "naome:peer-address-store-v0\0"
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

The local identity prevents one node's local ranking store from being opened
as another node's store. The bootstrap digest binds the exact canonical
operator configuration because every persisted source must still be one of
those configured identities. The ordering salt is generated once on creation
and restored exactly on open. Envelope bytes identify the subject, sequence,
and addresses and are not redundantly persisted as trusted metadata.

Snapshot decoding applies the same normalized-envelope, identity, address,
count, source, group, and time bounds as live admission before exposing a
handle. It revalidates every standard signed envelope and reconstructs source
counts, group counts, subjects, and signed sequence watermarks rather than
trusting derived metadata.

Every peer-ID length must be in `1..=44` and contain one canonical libp2p
`PeerId`. Before reading or allocating a variable field, the decoder validates
its length against the corresponding bound and the remaining file bytes using
checked arithmetic. With 256 maximally sized entries, the complete snapshot is
at most `1_062_827` bytes:

```text
28 + (1 + 44) + 32 + 32 + 2
   + 256 * ((1 + 44) + 8 + (2 + 4096))
   + 32
```

File metadata larger than this maximum is rejected before reading an entry or
allocating the complete image.

The exact V0 header is mandatory. A wrong header, local identity, or bootstrap
digest, duplicate or non-sorted subjects, invalid records, impossible metadata,
missing bytes, trailing bytes, or any limit violation fails closed. The loader
does not skip, repair, truncate, evict, or reinterpret an entry. There is one
semantic prerelease format path: no separate version branch, legacy snapshot
reader, format probe, or migration branch exists. V0 data must be recreated if
this format changes.

The snapshot checksum is exactly:

```text
SHA256(
    "naome:peer-address-store-checksum-v0\0"
    || every snapshot byte before snapshot_checksum
)
```

It detects accidental corruption of the locally written image. It is not keyed
authentication and cannot detect replacement with a separately valid snapshot,
rollback to an older valid image, or modification by an attacker who recomputes
the checksum. Signed envelopes still authenticate only their subjects' address
claims; source, receipt, bootstrap digest, and ordering metadata remain local
and unauthenticated.

## Security boundary and exclusions

V0 provides bounded parsing and persistence, standard self-signed address
authenticity, local receipt freshness, retained sequence watermarks, and
deterministic source- and prefix-aware candidate selection. It does not define
or claim:

- a socket-bound discovery protocol, address gossip, dynamic proof sessions, or
  automatic mutation of `StaticProofNetwork`; the transport-neutral batch
  wrapper defines no socket or authenticated session;
- DHT, DNS bootstrap, mDNS, rendezvous, NAT traversal, relay, hole punching,
  or external-address verification;
- peer scoring, reputation, bans, operator identity, source independence,
  autonomous-system diversity, Sybil resistance, or eclipse resistance;
- liveness, proof availability, consensus, fork choice, finality, mining,
  validation roles, rewards, fees, or settlement; or
- authenticated snapshot metadata, rollback protection, remote backup,
  protection from non-cooperating writers or filesystem attackers, or an
  online key-management policy.

The next network slice must bind bounded record exchange to authenticated
bootstrap sessions and define how dynamic discovery sessions are owned,
expired, and rate-limited. Only a separately explicit authorization policy may
decide which identities participate in proof exchange.
