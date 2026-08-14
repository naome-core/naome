# NAOME Artifact Block Candidate Store

This document normatively defines a chain-scoped append-only store for
structural `ArtifactBlock` candidates. It preserves observed block bytes for
later caller evaluation and deliberately confers no selected-state authority.

## Trust boundary

`ArtifactBlockCandidateStore` accepts any canonically shaped 128-byte
`ArtifactBlock`, including a sibling, an orphan, a block with unavailable
payload, or a block invalid against current selected state. Insertion performs
no parent lookup, ancestry execution, root projection, artifact retrieval,
proof or definition checking, fork choice, consensus, or finality decision.

A returned candidate must still be evaluated in an explicit target chain
context and supplied with its exact tagged artifact payload. The store cannot
resolve a `ProofId` or `DefinitionId`, and its contents are never part of
`ArtifactState`.

## Files, context, and limits

One caller-provisioned directory contains:

```text
artifact-block-candidate-store.lock
artifact-block-candidate-store.log
```

Creation uses create-new semantics, never replaces an existing store, and
synchronizes its prefix. Every handle holds a nonblocking exclusive lock.

The prefix is:

```text
"naome:artifact-block-candidate-store:v0\0"
ArtifactChainId[32]
```

The chain ID is derived from the expected complete `ArtifactChainDefinition`.
It prevents accidental mixing across deployment and Foundation contexts but
does not imply that a retained block belongs to a valid ancestry.

Each handle has a positive `max_entries` limit. Limits are caller policy, not
persisted identity. Reopening with another positive limit is allowed only when
all committed unique entries fit it.

## Entry encoding

Every entry is exactly 160 bytes:

```text
block          ArtifactBlock[128]
commit_footer  ArtifactBlockId[32]
```

The footer is derived from the complete block under
`"naome:artifact-block:v0\0"`. The store retains no artifact payload, chain
height, receipt time, peer identity, score, validity bit, or selection flag.

## Insert and replay

Insertion first requires a healthy handle and derives the block identity. An
exact already retained identity is idempotent and returns `AlreadyPresent` even
at capacity. A new identity is rejected at capacity before file mutation.
Otherwise the store reserves its index entry, appends and synchronizes the
128-byte block, appends and synchronizes the 32-byte footer, then publishes the
offset in memory.

Open validates the header and expected chain ID, then streams fixed-size entries.
For each complete entry it decodes the block, derives its identity, compares the
footer, rejects a duplicate identity, enforces capacity, and records only the
block offset. Complete corruption fails closed.

One final entry shorter than 160 bytes is an incomplete tail. Open truncates it
to the preceding committed boundary and synchronizes the file. No complete
entry, wrong footer, duplicate, header mismatch, chain mismatch, or limit
failure is recoverable by truncation.

## Reads, poisoning, and resources

`get` seeks to the indexed offset, rereads the exact entry, redecodes the block,
and rechecks the derived identity and footer before returning an owned block.
`contains`, `len`, `is_empty`, `chain_id`, and `limits` expose only the local
structural index.

An append I/O failure poisons the handle because the durable outcome is
ambiguous. A post-open read or integrity failure also poisons it because indexed
offsets can no longer be trusted. All subsequent operations fail until drop and
reopen. Ordinary duplicate and capacity results do not poison.

The in-memory index stores one block ID and file offset per unique candidate;
block bodies remain on disk until read. Every limit is checked before growth.
Portable durability of the parent directory entry remains the caller's
responsibility.

## Compatibility and non-goals

This `v0` artifact format is a clean prerelease cutover. A proof-block candidate
store has no compatibility alias or migration and must be removed and recreated.

The store does not retain payloads, validate artifacts, choose or execute an
ancestry, mutate the selected journal, supply citation resolution, reorganize a
chain, discover peers, or establish consensus or finality.
