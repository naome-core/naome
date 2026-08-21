# NAOME Canonical Artifact Payload Store

This document normatively defines a Foundation-scoped append-only archive of
exact tagged proof and definition payloads. It preserves bytes admitted from
accepted records or strictly validated as exact children of selected or
candidate-branch state and may supply exact owned bytes to an explicitly
caller-routed network response, but does not preserve or confer selected-state
authority.

## Scope and write gate

The ordinary `CanonicalArtifactPayloadStore::insert` entry point accepts only
an `AcceptedArtifactRecord` produced by strict ledger admission. It stores the
record's exact `ArtifactId` and complete canonical artifact bytes, including tag
`00` for proof or `01` for definition.

The separate public
`CanonicalArtifactPayloadStore::validate_and_insert_candidate_payload` entry
point accepts one caller-supplied `ArtifactChainJournal`, one `ArtifactBlock`,
and owned canonical artifact bytes. It first requires a healthy archive handle,
so a poisoned archive error precedes candidate validation. It then requires the
block to be an exact direct child of that journal's current selected head and
performs the same complete parent, artifact-set-root, decode, canonicality,
content-identity, dependency, mathematical, and novelty validation as strict
block application. Validation is read-only and every validation error precedes
archive mutation. Only after that complete check succeeds may the store
privately insert or idempotently confirm the exact validated payload; the method
exposes no `AcceptedArtifactRecord` or reusable validation token. An archive
error leaves the journal unchanged and retains the archive's existing typed
poison-and-reopen boundary.

The separate public
`CanonicalArtifactPayloadStore::validate_and_insert_branch_payload` write gate
accepts one caller-supplied `ArtifactChainBranchSnapshot`, one exact-child
`ArtifactBlock`, and owned canonical artifact bytes. Archive health precedes
branch validation. The gate uses
`ArtifactChainBranchSnapshot::validate_child` to repeat the complete
context-specific checks against that exact predecessor, then privately inserts
or idempotently confirms the validated payload. It returns a
`CandidateBranchPayloadArchiveOutcome` containing the immutable successor only
after the archive acknowledges that write. Validation failure leaves both
predecessor and archive unchanged. A `CandidateBranchPayloadArchiveError`
returns no successor, leaves the predecessor unchanged, and retains the
archive's existing typed poison-and-reopen boundary; an ambiguous write may be
recovered only by dropping and reopening the archive.

For caller-supplied bytes missing from the archive, an incremental
candidate-branch reconstruction cursor may consume these successors in exact
forward ancestry order. An awaiting cursor exclusively borrows the exact
archive supplied at start and cannot redirect continuation to another archive.
Each successor becomes available only after the corresponding archive
acknowledgement, so an ordinary later failure can leave a durable validated
payload prefix without exposing a partially reconstructed branch. A fresh
reconstruction must integrity-read and fully revalidate every such archive hit
against its newly chosen branch snapshot; the earlier acknowledgement is
neither a reusable validation token nor proof that the target remains a
candidate after selected-state advancement.

The branch gate advances only the caller-held memory snapshot. It does not
write a candidate branch, selected journal, block store, branch marker, or
checked-record cache, and it does not expose an `AcceptedArtifactRecord` or a
reusable validation token. A later reconstruction integrity-reads archived
bytes and repeats the complete target-ancestry validation rather than trusting
the earlier archive acknowledgement.

Loading those bytes does not recreate the original checked context. Before use
in another branch or chain state, a consumer must decode the typed payload,
require canonical bytes, resolve every proof dependency and function-obligation
statement from that target's selected state, repeat mathematical checking,
derive the typed `ArtifactId`, compare it with the archive address, and register
only through normal block admission.

The archive cannot resolve citations and is not searched implicitly by the
checker, authoring compiler, journal, or network importer.

## Files, Foundation context, and limits

One caller-provisioned directory contains:

```text
artifact-payload-store.lock
artifact-payload-store.log
```

Creation uses create-new semantics and synchronizes the prefix. Every handle
holds a nonblocking exclusive lock. Portable parent-directory-entry durability
remains the caller's responsibility.

The exact prefix is:

```text
"naome:artifact-payload-store:v1\0"[32]
"naome:zfc"[9]
```

The archive is Foundation-scoped, not chain-scoped. Payloads from different
deployments may coexist because their cryptographic identities already bind the
Foundation contract; the archive retains no selected ancestry or deployment
claim.

Each handle has positive `max_entries` and `max_total_payload_bytes` limits.
They are local policy rather than persisted identity. Reopen under different
positive limits succeeds only if all committed unique entries fit both.

## Entry and integrity digest

Each entry is:

```text
payload_length   u32 big-endian
artifact_id      ArtifactId[32]
artifact         tagged canonical payload[payload_length]
digest           SHA256[32]
```

`payload_length` is in `1..=4,194,305`. The digest is:

```text
SHA256(
  "naome:artifact-payload-store-entry:v1\0"
  || u32be(length("naome:zfc")) || "naome:zfc"
  || payload_length_u32_bytes
  || ArtifactId[32]
  || artifact[payload_length]
)
```

It binds Foundation context, exact length bytes, address, artifact tag, and
complete typed payload. Entries contain no proof, definition, dependency,
statement, derivation, block, chain, selection, consensus, or finality metadata.

## Insert, replay, and recovery

Insertion first requires a healthy handle. Repeating an exact identity and
exact bytes is idempotent and returns `AlreadyPresent` even at capacity. The
same identity with different bytes is a collision and fails without
replacement. New entries are checked against count and aggregate-byte limits
before file mutation.

The store reserves index capacity, appends and synchronizes length, address,
and payload, then appends and synchronizes the digest. Only then does it publish
the offset and aggregate byte count in memory.

Open validates the prefix and Foundation bytes, then streams entries with an
8-KiB replay buffer. It bounds length before processing payload bytes, computes
the digest incrementally, rejects a wrong digest or duplicate address, applies
the configured limits, and retains only an address/offset index plus the total
payload byte count.

At most one final framing-incomplete entry with an otherwise valid declared
length is recoverable. It is truncated to the preceding committed boundary and
synchronized. A zero or oversized length, wrong complete digest, duplicate,
prefix mismatch, Foundation mismatch, or resource-limit failure is complete
corruption and fails closed.

## Reads, poisoning, and authority

`get` rereads the indexed length, address, payload, and digest; it rechecks all
entry integrity before returning an owned `CanonicalArtifactPayload`. It does
not decode or mathematically check that payload and does not return an
`AcceptedArtifactRecord`. `contains`, `len`, `is_empty`, and
`total_payload_bytes` describe only the local archive.

An append I/O failure poisons the handle because the commit outcome is
ambiguous. Any post-open read or integrity failure poisons it because offsets
can no longer be trusted. Subsequent operations fail until drop and reopen.
Ordinary idempotent insertion, collision, and capacity failures do not poison.

Archive presence proves only that one local store retained bytes under an
integrity digest. It does not prove data availability elsewhere, continued
mathematical validity under another context, selected ancestry, network
acceptance, consensus, or finality.

Full-preflight offline candidate import integrity-reads each exact payload once,
privately retains the complete byte-bounded path, and validates it against the
current selected-head snapshot before the first journal write. Ordinary journal
application then repeats complete target-context validation from those retained
bytes. The archive is not mutated, and neither archive presence nor successful
preflight is a reusable admission or selected-state token.

## Caller-routed network serving

`StaticArtifactNetwork::respond_artifact_from_payload_store` consumes one exact
statically authorized Noise-authenticated inbound `ArtifactRequest` only when
its caller explicitly routes that request and one mutable archive handle to
this responder. The request contains an `ArtifactId` but no chain, branch,
selected-state, or archive identity. The archive is Foundation-scoped, and the
responder does not infer or select an artifact-chain context.

Serving first calls `contains` to require archive health and look up the exact
address in the in-memory index. It then requires an open response channel and
consumes one shared inbound response token. Only for an indexed address does it
call `get`, which performs the complete existing entry integrity read and
returns owned bytes. This order ensures a closed channel or rate-limited
request performs no artifact-sized archive read or allocation. A `get` failure
remains typed, may poison the handle, and produces no network response; it is
never translated to `Unavailable`. An unindexed address is served as
`Unavailable` after the same channel and token checks.

A found response is the exact archived tagged canonical payload. Loading and
serving it still does not recreate the original checked context or expose an
`AcceptedArtifactRecord`. The responder does not decode, recheck, register, or
refresh the bytes; every receiver must repeat complete validation against its
own exact target ancestry. Serving is read-only except for the existing poison
transition on an integrity failure and retains no requester, source, or receipt
metadata.

Because the archive retains no source provenance, explicit caller routing may
retransmit exact bytes that the node learned elsewhere. The responder chooses
neither the original source nor the requesting recipient and defines no
automatic relay admission, eviction, recipient-selection policy, or relay task.

The response call performs no selected-journal lookup or fallback, candidate
block lookup, automatic publication, service loop, retry, import, promotion,
branch selection, validity assertion, peer trust, global-availability claim,
consensus, finality, or economic action. One statically authorized
Noise-authenticated peer's `Unavailable` response proves no wider absence.

## Compatibility and non-goals

This `v1` tagged-artifact archive is a clean prerelease cutover. Earlier payload
archives have no legacy reader or migration and must be removed and recreated.

The store alone does not select blocks, persist candidate execution state,
cache reusable checked records, resolve dependencies, fetch content, compact or
prune, synchronize peers, choose forks, or establish proposer authority,
consensus, or economics. Its candidate-payload write gates delegate all
context-specific checking to the caller-supplied journal or branch snapshot and
record no result other than the same non-authoritative Foundation-scoped
payload bytes.
