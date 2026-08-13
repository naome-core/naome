# NAOME Canonical Proof Payload Store

## Scope and trust boundary

This document defines the Foundation-scoped, append-only archive implemented by
`CanonicalProofPayloadStore`. The store durably associates one `ProofId` with
the exact canonical proof-certificate bytes taken from an
`AcceptedProofRecord`. It is independent of any deployment or selected proof
chain, so the same admitted payload may be retained once and later considered
for multiple proof contexts under the same compiled Foundation contract.

Canonical provenance comes only from the insertion gate: callers cannot insert
a raw address and byte slice. Under cooperative exclusive ownership, opening
and reading preserve that accepted association through framing and integrity
checks, but do not decode, normalize, mathematically check, resolve
dependencies, or derive `ProofId` from the stored payload. A loaded
`CanonicalProofPayload` is therefore an owned candidate, not a recreated
`AcceptedProofRecord`.

Before admitting loaded bytes to any target ledger, branch, or selected chain,
the consumer must perform that target's complete external admission sequence:

```text
strict decode
  -> exact canonical-normal-form comparison
  -> dependency resolution and mathematical checking
  -> expected ProofId comparison
  -> target-state registration
```

The archive grants no mathematical truth, dependency availability, block
inclusion, selected membership, checkpoint authority, finality, consensus, or
economic authority. The [Proof Protocol](proof-protocol.md) owns proof identity
and admission. The [Proof Chain Journal](proof-chain-journal.md) remains the sole
durable owner of selected proof-chain state.

## Public state and local limits

`ProofPayloadStoreLimits::new(max_entries, max_total_payload_bytes)` accepts only
positive limits. If both inputs are zero, `ZeroMaxEntries` takes precedence over
`ZeroMaxTotalPayloadBytes`. The fields are private and exposed through
`max_entries` and `max_total_payload_bytes`.

Limits are local resource policy, not format identity. They are neither
persisted nor hashed. Changing limits is not itself a format error; resource
checks accept the complete committed contents only when they fit the supplied
entry and aggregate-payload caps. `limits` returns the immutable policy of the
current handle and remains available after poisoning.

The store exposes these public operations:

- `insert(&AcceptedProofRecord)` appends or recognizes one immutable payload;
- `get(ProofId)` returns an owned `CanonicalProofPayload` or absence;
- `contains(ProofId)`, `len`, `is_empty`, and `total_payload_bytes` query the
  current in-memory index; and
- `create` and `open` establish an exclusively owned handle.

All operations above except `create`, `open`, and the immutable `limits` getter
first require a healthy handle. `total_payload_bytes` counts only the payload
bytes of unique committed entries; framing and digest bytes are excluded.

`CanonicalProofPayload::proof_id` returns the archived address,
`canonical_proof_bytes` borrows the exact owned bytes, and
`into_canonical_proof_bytes` consumes the wrapper. Its debug representation
exposes the address and byte count, not payload contents.

## Directory and exclusive ownership

The caller supplies an existing directory. The store uses exactly two fixed
files:

- `proof-payload-store.lock`, an advisory exclusive-writer sidecar lock; and
- `proof-payload-store.log`, the append log defined below.

The sidecar is opened read/write and locked non-blockingly before the log is
created or opened. A second cooperative process or handle fails rather than
observing or mutating the store. The lock remains held for the full handle
lifetime, including while the handle is poisoned.

`create` uses exclusive file creation and never replaces or reinitializes an
existing log. It writes and synchronizes the complete Foundation-scoped prefix
before returning. If creation, prefix writing, or synchronization fails, it may
leave a partial or durability-ambiguous final-path file; a later `create` does
not replace that file automatically. Portable durability of the parent
directory entry remains the caller's provisioning responsibility.

`open` requires an existing recognized log, strictly checks every complete
entry's framing, digest, address uniqueness, and resource bounds, recovers at
most one incomplete final append, synchronizes the resulting visible image,
and only then returns a handle.

## File prefix and Foundation context

Every log starts with exactly:

```text
magic[26]       = "naome:proof-payload-store\0"
foundation[9]   = "naome:zfc"
```

The prefix is 35 bytes. A missing prefix or different magic is
`InvalidHeader`; with a complete recognized magic, different Foundation bytes
are `FoundationIdMismatch`. Entry scanning and tail recovery begin only after
both checks succeed.

The prefix stores no proof-chain identifier, definition source, local limits,
entry count, aggregate byte count, head, or selected-state root. An
incompatible prerelease Foundation or format is recreated rather than opened
through a compatibility alias, legacy parser, or migration path.

## Entry encoding and digest

The prefix is followed by zero or more entries with no padding:

```text
payload_length     4-byte unsigned big-endian integer
proof_id           32 raw ProofId bytes
canonical_payload  payload_length bytes
entry_digest       32 SHA-256 bytes
```

`payload_length` is in `1..=CERTIFICATE_MAX_BYTES`, where
`CERTIFICATE_MAX_BYTES` is `4_194_304`. A structurally possible entry is
therefore `69..=4_194_372` bytes, including all framing and the digest. Length
and file-offset arithmetic is checked before an entry is indexed.

The exact digest is:

```text
entry_digest = SHA256(
    "naome:proof-payload-store-entry\0"
    || u32be(length(foundation))
    || foundation
    || payload_length
    || proof_id
    || canonical_payload
)

foundation = "naome:zfc"
```

The digest detects accidental corruption and completes the two-phase append. It
is not `ProofId` derivation, proof decoding, canonicality checking,
mathematical checking, a signature, a MAC, or protection against a party that
can rewrite the file and recompute SHA-256. The separate address is retained
because `ProofId` binds checked statement identity and canonical proof bytes;
it cannot be reconstructed from payload bytes without complete proof checking.

## Insertion and durable commit

Insertion executes in this order:

1. require a healthy handle;
2. obtain the exact `ProofId` and canonical byte slice from the supplied
   `AcceptedProofRecord`;
3. if the address is already indexed, reread and integrity-check its complete
   stored entry while comparing the payload bytes exactly;
4. return `AlreadyPresent` for equal bytes, or `PayloadConflict` for different
   bytes, without modifying the log;
5. for a new address, check the next entry count and then the resulting
   aggregate payload bytes against the local limits;
6. reserve one index slot before file mutation;
7. append the length, address, and payload, then synchronize that complete body;
8. append the digest, then synchronize it; and
9. install the reserved index entry, advance the committed boundary and totals,
   and return `Inserted`.

The existing-address comparison precedes both capacity checks. Exact replay is
therefore idempotent even when either limit is full. A different payload at the
same address is never replaced. `PayloadConflict`, capacity errors, allocation
failure before append, and offset overflow leave the handle healthy and perform
no log mutation.

Any seek, write, or synchronization error once the commit phase begins returns
`Commit` and poisons the handle because the durable result may be either the old
log or the new entry. No further health-sensitive operation is allowed.
Dropping and reopening is the only recovery probe.

The first synchronization barrier completes before the digest is written, and
the second completes before success is acknowledged. No aggregate snapshot or
aggregate entry buffer is constructed; insertion hashes and writes one bounded
accepted payload directly.

## Open, replay, and recovery

After locking, opening, and checking the prefix, replay scans from byte 35. For
each entry it performs the following exact sequence:

1. fewer than four remaining bytes are an incomplete tail;
2. otherwise read `payload_length`, reject zero or a value above
   `CERTIFICATE_MAX_BYTES` with `InvalidPayloadLength`, and check the computed
   entry end for `EntryOffsetOverflow`;
3. an in-range entry end beyond EOF is an incomplete tail;
4. read the address, stream the complete payload through a bounded scratch
   buffer, read the footer, and require the exact digest;
5. reject a repeated address with `DuplicateProofId`;
6. compute the next unique entry count and reject count overflow or the local
   entry limit;
7. compute the next aggregate payload bytes and reject byte-count overflow or
   the local byte limit; then
8. reserve and install the address-to-offset-and-length index entry.

Digest and duplicate-address validation precede local capacity classification,
so corrupt committed bytes are not reported as resource policy failures. An
incomplete tail is not an entry and consumes no capacity. If a complete
digest-valid prefix already exceeds the supplied limits, `open` fails without
recovering or modifying a later suffix.

Replay streams payload bytes only to the SHA-256 state and retains only
addresses, offsets, lengths, the unique count, and aggregate payload bytes. It
deliberately does not allocate a complete payload, decode a certificate, derive
normal form, resolve references, check mathematics, or verify that the stored
address follows from the payload. Those target-context operations remain
mandatory on consumption.

If EOF occurs before a complete in-range final entry, replay truncates the log
to the preceding committed boundary and synchronizes the truncation. A failure
to truncate or synchronize is `Recovery`. A complete entry with an invalid
length, digest, or duplicate address is corrupt and is never skipped,
truncated, or repaired. A completely replayed image is synchronized before the
handle is returned; failure is `Stabilize`.

## Reads, index queries, and poisoning

`get` first consults the in-memory index. An unknown address returns absence
without file I/O. For a known address it allocates exactly one bounded owned
payload, then rereads the indexed length, address, payload, and digest. The
length and address must still match the index and the digest must still match
the entry. Success returns those exact bytes without interpreting them.

`contains`, `len`, `is_empty`, and `total_payload_bytes` query the index without
rereading the log. They describe the image established by open and subsequent
successful inserts; they do not independently detect an out-of-contract file
mutation.

A post-open entry read error returns `Read`; a length or address mismatch, or a
payload or footer change that breaks the indexed entry digest, returns
`StoredEntryChanged`. Either poisons the handle because its index can no longer
be trusted. This applies to `get` and to the existing-entry comparison performed
by `insert`. `PayloadAllocation` occurs before the read and does not poison the
handle. After poisoning, every health-sensitive method returns `Poisoned`;
`limits` is the sole exception.

## Error precedence

`CanonicalProofPayloadStoreError` preserves the first authoritative boundary
that fails:

- `LockFile`, `Locked`, or `Lock` precedes every log-file operation;
- creation and opening use `Create` and `Open`; existing-file scan I/O uses
  `Read` with its field offset;
- `InvalidHeader` precedes `FoundationIdMismatch`, which precedes entry work;
- entry framing and endpoint checks precede digest, duplicate address, entry
  capacity, aggregate-byte capacity, and index allocation, in that order;
- a known-address insert reread and exact comparison precedes all capacity
  checks, while a new-address insert checks entry capacity before aggregate
  bytes and index allocation;
- a known-address `get` reports payload allocation before its entry reread;
  entry I/O or change then poisons the handle; and
- once the commit phase begins, every seek or append I/O failure is `Commit`
  and poisons the handle regardless of which durable prefix later appears.

Opening returns no partial handle after any failure. Ordinary limit, conflict,
allocation, or pre-append arithmetic errors on a live handle leave it usable.

## Resource contract

The store retains one hash-index record per unique address and no payloads in
memory. Opening is linear in visible log bytes, uses a fixed bounded streaming
buffer, and allocates only the index. Insertion is linear in one payload and
does not rewrite older entries. A known `get` is linear in and allocates exactly
one payload; an exact duplicate insert performs one streaming reread and exact
comparison without allocating that payload.

Each complete entry contributes 68 framing-and-digest bytes in addition to its
payload. The local limits bound unique index entries and aggregate payload bytes
but are not a physical-file-length header. Individual payload framing is still
bounded by `CERTIFICATE_MAX_BYTES`, and all count, total, and offset arithmetic
fails closed on overflow.

## Crash and corruption boundary

The two synchronization barriers and terminal digest let reopen distinguish a
complete intact append from an incomplete final append under the cooperative
exclusive-lock model. They do not provide malicious-filesystem integrity or
freshness:

- a party able to rewrite bytes can also recompute an unkeyed digest;
- truncation or rollback to an independently valid committed prefix is not
  detectable;
- an in-range damaged final length can make a suffix appear incomplete and may
  cause recovery to the preceding committed boundary;
- a missing or different Foundation-scoped prefix and any complete invalid
  entry fail closed, but do not identify the cause; and
- file mutation outside the advisory lock contract is unsupported; a later
  indexed read detects changes only when its framing or digest no longer
  matches.

A separately authenticated higher-level commitment is required where rollback
or adversarial storage is in scope. The payload store itself intentionally owns
no such authority.

## Conformance requirements

Implementations and tests must cover, at minimum:

- both zero-limit errors and reopening one store under fitting and non-fitting
  local policies;
- exclusive locking, create-without-replacement, exact prefix checks, and a
  Foundation mismatch;
- insertion, owned retrieval, absence, metrics, reopen persistence, exact
  idempotence at full capacity, conflict rejection, and entry-before-byte limit
  precedence;
- every incomplete tail position across the entry body and digest, plus
  rejection of invalid lengths, wrong digests, duplicate addresses, and
  complete over-limit entries;
- every append write and synchronization cut, poisoned-handle behavior, and
  old-or-new recovery after reopen;
- a post-open integrity change and a truncation or read failure observed by
  `get` or duplicate insertion; and
- streaming replay without per-payload retention or aggregate snapshot rewrite.

## Non-goals

The payload store defines no:

- raw or network-originated insertion path;
- reusable accepted-record cache, dependency graph, closure proof, statement or
  derivation metadata, or independent proof admission;
- selected-chain deduplication, journal refactor, automatic journal integration,
  block storage, candidate history, branch execution, fork choice, or reorg;
- network discovery, fetching, serving, authorization, or peer policy;
- overwrite, deletion, garbage collection, reference counting, pruning,
  compaction, snapshotting, or migration;
- consensus, checkpointing, finality, validator policy, rewards, fees, staking,
  slashing, token issuance, or other economic state; or
- Foundation authoring syntax, definition-source tooling, or compatibility
  commitment.
