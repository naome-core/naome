# NAOME Local Peer Record Issuance

## Status and scope

This document defines the prerelease V0 durable local issuer that constructs
standard interoperable libp2p signed peer records one at a time. A
`LocalPeerRecordIssuer` binds one local `PeerId` to one exclusively locked
state directory, retains only the highest sequence that the operator declares
or this issuer successfully commits, and constructs a bounded canonical
[`SignedPeerRecord`](peer-address-management.md) with the next sequence.

The issuer closes the local construction boundary before an operator builds a
[`PeerRecordBatch`](peer-record-exchange.md) for the separate immutable
[bootstrap responder](authenticated-peer-record-responder.md). It is not a
listener, responder, address store, seed registry, key store, reachability
probe, or proof-session authority.

## Public boundary and authority

The public lifecycle is deliberately explicit:

```text
LocalPeerRecordIssuer::create(directory, identity, last_issued_sequence)
LocalPeerRecordIssuer::open(directory, identity)
issuer.peer_id()
issuer.last_issued_sequence()
issuer.issue(identity, addresses)
```

`identity` is a caller-owned libp2p keypair. Creation persists only its derived
`PeerId` and the caller-supplied `last_issued_sequence`; opening requires a
keypair with that same derived identity. The private key is neither retained by
the issuer nor written to disk. Every issuance call supplies the signing key
again and must match the persisted identity exactly.

The creation sequence is an operator assertion: it must equal the highest
sequence ever issued for this identity through any prior authoritative state.
For an identity that has never issued a record, the floor is zero and the first
record receives sequence one. A floor of `u64::MAX` is valid durable state but
cannot issue another record. The issuer cannot discover, prove, or repair a
lost floor from the network, an address store, a responder, or the keypair.
When the highest prior sequence is unknown, this contract provides no safe
recovery claim and the operator must not guess a lower value.

Exactly one state directory must be authoritative for an identity. The
directory lock prevents cooperating handles from using that same directory
concurrently, but it cannot detect a copied snapshot, a second directory, a
restored older backup, or another process that ignores the lock. Running two
authoritative issuers for one identity can create equal-sequence conflicts.

The snapshot stores no prior signed envelope or address list. Opening restores
the identity and watermark, not a previously returned record. Sequence gaps
are valid: a process may commit a watermark and terminate before the caller
can use the returned record. `last_issued_sequence()` reports the last
successfully committed in-memory watermark only while the handle is healthy;
it returns the poisoned-state error after commit ambiguity instead of exposing
a potentially stale value.

## Record construction

One issuance accepts an iterator of addresses and consumes at most five items:
the first item beyond the four-address limit terminates collection without
exhausting an unbounded source. The complete input must contain `1..=4`
distinct addresses. Each binary address is at most 256 bytes and has exactly
one of these forms, with a nonzero TCP port and no suffix:

```text
/ip4/<globally-routable-address>/tcp/<port>
/ip6/<globally-routable-address>/tcp/<port>
```

Private, loopback, link-local, documentation, multicast, unspecified,
non-global, DNS, UDP, QUIC, relay, circuit, and otherwise extended addresses
are rejected. Address order and bytes remain signer-controlled authenticated
content; the issuer neither sorts nor deduplicates them.

The next sequence is `last_issued_sequence.checked_add(1)`. It is ordering data
only. It is not derived from wall-clock time and establishes no creation time,
freshness, current reachability, availability, preference, trust, or proof
authorization.

The signed payload is the standard interoperable libp2p peer-record protobuf:

```text
peer_id     signing key's exact PeerId
sequence    next durable sequence
addresses   exact validated input order
```

It is wrapped in a standard libp2p `SignedEnvelope` with domain separation
`libp2p-peer-record` and payload-type bytes `03 01`. Rust-libp2p's legacy
`libp2p-routing-state` envelope is not produced. Before signing, the issuer
reuses the same bounded identity and complete ordered-address validator used by
received `SignedPeerRecord` values. It then canonically encodes the payload and
outer envelope exactly once and constructs the record from those already
validated inputs and the just-produced signature. It does not decode or
signature-verify its own trusted envelope a second time.

External envelope bytes remain untrusted and still cross the complete standard
signature, embedded-identity, address, bound, and normalization decoder. An
independent standard-libp2p cross-decode plus fixed encoding goldens must prove
that locally issued bytes satisfy that receiving path. Trusted local
construction is an allocation and cryptographic-work optimization, not a
second record format or weaker external admission path.

## Issuance order and errors

An issuance follows this exact precedence:

1. reject a poisoned handle;
2. require the supplied signing key's `PeerId` to equal the bound identity;
3. compute `last_issued_sequence + 1` with checked arithmetic;
4. boundedly allocate and collect at most five address inputs;
5. validate count, then every address in input order by byte length, exact
   globally routable IP/TCP shape, and duplication against prior addresses;
6. allocate and encode the canonical standard peer-record payload;
7. sign and canonically encode the standard envelope once;
8. construct the `SignedPeerRecord` from the validated identity, next sequence,
   exact ordered addresses, and newly encoded envelope;
9. allocate and encode the next issuer snapshot;
10. atomically commit the next watermark; and
11. only after commit success, update the in-memory watermark and return the
    signed record.

The public non-exhaustive issuer error preserves typed causes for directory,
lock, snapshot read, bounded allocation, identity, record validation,
sequence exhaustion, signing, commit, and poisoned-state failures. Empty or
fifth-address input is an address-count error. For each address, length wins
before shape/global routing, which wins before duplicate detection. After the
count passes, the first invalid address in iterator order wins.

A sequence-exhausted issuer rejects before allocating, polling, or otherwise
observing the address iterator. Identity mismatch has the same non-consumption
property. This makes durable state precedence independent of caller input
behavior.

Identity mismatch, invalid input, sequence exhaustion, allocation, encoding,
and signing failures occur before snapshot mutation. They return no record,
leave the handle healthy, and do not advance either the durable or in-memory
watermark. No error is converted into a partially built record.

## Durable state and recovery

The caller supplies the issuer directory. V0 uses exactly these files:

- `local-peer-record-issuer.lock`, an advisory exclusive sidecar lock held for
  the complete handle lifetime;
- `local-peer-record-issuer.bin`, the authoritative snapshot; and
- `local-peer-record-issuer.tmp`, a same-directory commit temporary that is
  never treated as authoritative during open.

`create` creates the directory when necessary, acquires the lock, refuses to
replace an existing snapshot, and commits the supplied floor before returning
a handle. `open` acquires the same lock, requires the snapshot, performs a
bounded read with at most one sentinel byte beyond the accepted maximum, and
verifies the complete image before exposing a handle. Neither operation is an
implicit open-or-create path.

The snapshot uses unsigned big-endian integers, no padding, and this exact
encoding:

```text
header                       "naome:local-peer-record-issuer-v0\0" [34]
peer_id_length               u8, 1..=44
peer_id                      peer_id_length bytes
last_issued_sequence         u64 big endian
snapshot_checksum            32 bytes
```

Its maximum length is exactly 119 bytes:

```text
34 + 1 + 44 + 8 + 32
```

The checksum is:

```text
SHA256(
    "naome:local-peer-record-issuer-checksum-v0\0"
    || every snapshot byte before snapshot_checksum
)
```

Open validates the metadata length cap before allocating the complete image,
then the minimum length, checksum, exact header, bounded canonical `PeerId`,
expected identity, sequence, and absence of trailing bytes. A wrong or partial
header, checksum mismatch, malformed or overlong identity, identity mismatch,
truncation, trailing byte, or oversized file fails closed. V0 has one
prerelease format path and no legacy reader, migration branch, truncation,
repair, or best-effort salvage.

Every issuance encodes the complete next snapshot into the temporary file,
synchronizes that file, and atomically renames it over the authoritative
snapshot. On Unix, it also synchronizes the parent directory before reporting
success. Rust exposes no safe portable parent-directory synchronization
contract on every non-Unix target, so V0 does not claim that a renamed
directory entry survives sudden power loss there. Successful open still
verifies the complete installed snapshot on every platform.

During `issue`, any commit I/O error returns no record and poisons the live
handle. The failure may have happened before or after rename, so durable state
may contain either the previous or proposed watermark even though in-memory
state is not advanced. The poisoned handle performs no later issuance; drop
and strict reopen is the only recovery path. Reopen resolves which complete
snapshot is installed and continues from that watermark.

During `create`, a commit error returns no handle but may already have installed
the supplied floor. Strict `open` is the only recovery probe; the operator must
not recreate state with a guessed floor. Temporary state is ignored in both
paths.

The checksum detects accidental corruption of locally written bytes. It is not
keyed authentication, rollback protection, secure backup, or proof that the
floor is globally maximal. Replacement with an independently valid older
snapshot can reintroduce a used sequence. Avoiding that requires external
authoritative state outside this contract.

## Responder integration

A successfully returned `SignedPeerRecord` may be placed explicitly into a
canonical `PeerRecordBatch` and supplied to a new
`PeerRecordBootstrapResponder`. The responder still encodes and serves only
the immutable constructor batch. Issuing a newer record does not update a
running responder, export an address store, select other records, or announce
anything to the network. Publishing the newer record requires explicit
operator batch construction and responder rebuild or restart.

The responder's authenticated Noise identity is the batch source observed by
a pull client; the issued record's signer is its subject. These identities may
be equal, but neither role grants proof authority and no upstream provenance is
added to the record.

## Security boundary and exclusions

V0 provides one identity-bound, cooperatively exclusive, bounded durable
sequence watermark; shared bounded prevalidation; canonical standard
interoperable self-signing; and commit-before-return monotonicity within one
unrolled-back authoritative directory. Independent compatibility tests bind
the optimized trusted-construction path to the strict external decoder. The
issuer prevents same-state concurrent sequence reuse and avoids wall-clock
collisions. It does not make one identity one independent operator or one
reachable node.

This contract does not define or claim:

- private-key persistence, encryption, hardware custody, backup, recovery,
  compromise handling, rotation, or revocation;
- discovery of local or external addresses, interface monitoring, AutoNAT,
  reachability probing, NAT traversal, relay, hole punching, or automatic
  record refresh;
- store export, publication selection, completeness, responder mutation, hot
  reload, push, gossip, subscription, or periodic publication;
- a bundled seed list, DNS bootstrap, remote bootstrap configuration, or a
  deployed public endpoint;
- dynamic learned-candidate sessions, conversion into `StaticPeer`, proof
  authorization, proof exchange, peer scoring, reputation, Sybil resistance,
  or eclipse resistance; or
- consensus, checkpoints, fork choice, finality, mining, validator roles,
  transactions, rewards, fees, balances, or settlement.

These remain separate later contracts.
