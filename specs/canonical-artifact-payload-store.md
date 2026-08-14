# NAOME Canonical Artifact Payload Store

This document normatively defines a Foundation-scoped append-only archive of
exact tagged proof and definition payloads. It preserves bytes admitted from
accepted records but does not preserve or confer selected-state authority.

## Scope and write gate

`CanonicalArtifactPayloadStore` accepts only an `AcceptedArtifactRecord`
produced by strict ledger admission. It stores the record's exact `ArtifactId`
and complete canonical artifact bytes, including tag `00` for proof or `01` for
definition.

Loading those bytes does not recreate the original checked context. Before use
in another branch or chain state, a consumer must decode the typed payload,
require canonical bytes, resolve every proof and definition dependency from
that target's selected state, repeat mathematical checking, derive the typed
`ArtifactId`, compare it with the archive address, and register only through
normal block admission.

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
"naome:artifact-payload-store:v0\0"[32]
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
  "naome:artifact-payload-store-entry:v0\0"
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

## Compatibility and non-goals

This `v0` tagged-artifact archive is a clean prerelease cutover. The proof-only
payload archive has no legacy reader or migration and must be removed and
recreated.

The store does not select or execute blocks, cache reusable checked records,
resolve dependencies, fetch content, compact or prune, synchronize peers,
choose forks, or establish proposer authority, consensus, or economics.
