# NAOME Artifact Chain Journal

This document normatively defines local crash-consistent persistence for one
selected linear artifact chain. The [Proof and Artifact Protocol](proof-protocol.md)
owns block and artifact admission. The journal neither weakens those checks nor
defines fork choice, consensus, or finality.

## Ownership and authority

`ArtifactChainJournal` privately owns one `ArtifactChainState`: exact head,
checked proof and definition resolver state, authenticated artifact DAG, and an
index of committed blocks. It is the sole durable selected-state owner.

The journal accepts exactly one `ArtifactBlock` and its exact tagged proof or
definition payload per append. Replay invokes the same strict block application
used in memory. Persisted metadata never recreates an accepted record directly
and never bypasses canonical decoding, dependency resolution, proof checking,
definition checking, expected-`ArtifactId` comparison, or root validation.

Read-only validation is current-state-relative and non-authoritative. Every
later append repeats the complete checks. Candidate stores, payload archives,
network responses, and local authoring cannot mutate or resolve through the
journal except by successful block application.

## Files and exclusive access

One caller-provisioned directory contains:

```text
artifact-chain.lock
artifact-chain.journal
```

The directory must already exist. Creation uses create-new semantics and never
replaces a journal. Every open handle acquires the nonblocking exclusive lock;
a second concurrent handle fails. The journal and lock are not process-wide
global files, and a caller must not place unrelated chain journals in one
directory.

Creation synchronizes the complete prefix before success. Portable durability
of the parent directory entry remains the caller's provisioning responsibility.

## Prefix and chain context

The exact prefix is:

```text
"naome:artifact-chain-journal:v1\0"[32]
ArtifactChainId[32]
```

It is exactly 64 bytes. `ArtifactChainId` is derived from the complete expected
`ArtifactChainDefinition`; opening does not accept a raw address as trusted
chain semantics. Replay requires the exact header and expected chain ID before
examining entries.

## Entry encoding

Each committed entry is:

```text
body_length     u32 big-endian
block           ArtifactBlock[128]
artifact        tagged canonical payload[1..=4,194,305]
commit_footer   ArtifactBlockId[32]
```

`body_length` covers only `block || artifact`. It is in
`129..=4,194,433`. A complete entry therefore occupies
`165..=4,194,469` bytes including its four-byte length and 32-byte footer.
The payload's first byte is the artifact tag: `00` proof or `01` definition.

The footer is exactly:

```text
ArtifactBlockId = SHA256("naome:artifact-block:v0\0" || block[128])
```

It is a commit marker and block-integrity check, not a checksum over the
payload. Strict replay binds payload to `block.artifact_id` by deriving the
checked typed identity. No entry contains height, chain ID, payload checksum,
dependency list, statement identity, or authenticated-set nodes.

## Durable append

An append proceeds:

1. require a healthy handle;
2. reject a stale parent before cloning or validating payload bytes;
3. encode the fixed block and reserve the block-index entry;
4. apply the block once in memory, performing complete preflight, typed
   canonical decode, mathematical checking, dependency resolution, expected-ID
   comparison, and registration;
5. read the accepted record's exact tagged payload;
6. append `body_length || block || payload` and synchronize it;
7. append the block-ID footer and synchronize it; and
8. publish the block in the in-memory committed index.

Ordinary validation failures perform no file write and preserve a healthy
handle. A caller may have performed read-only validation earlier, but append
never consumes that result as authority and repeats the complete checks against
its then-current state. The payload is mathematically checked once per append,
not once before and once during in-memory application.
No fallible selected-state operation follows the in-memory block application.
An I/O error after that point leaves memory potentially ahead of disk and
poisons the handle. Every public read, validation, preparation, or append then
fails until the handle is dropped and the file is reopened and replayed.

The two synchronization points define the footer as the durable commit boundary.
The journal does not promise atomic filesystem writes larger than the platform
provides.

## Replay and recovery

Open reconstructs an empty `ArtifactChainState` from the expected definition,
then processes entries in file order:

1. validate the prefix and chain ID;
2. read and bound `body_length` before allocating payload storage;
3. require the complete declared entry;
4. decode the fixed block and derive its `ArtifactBlockId`;
5. require the footer to equal that identity;
6. strictly apply the block and exact tagged payload; and
7. index the committed block only after application succeeds.

Replay naturally handles mixed proof and definition entries and reconstructs
the same selected dependency resolver. A complete entry with a wrong footer,
invalid artifact, missing earlier dependency, stale parent, wrong root,
duplicate identity, or any other semantic failure is corruption and fails
closed. It is never skipped or normalized.

At most one framing-incomplete final entry is recoverable. A tail shorter than
the four-byte length, or shorter than its valid declared complete entry, is
truncated to the preceding committed boundary and synchronized. An invalid
declared length is complete corruption, not an incomplete tail.

`open_recovering_unverified` permits that tail recovery after strict replay of
the committed prefix. `open_verified` additionally requires the reconstructed
head to equal a separately trusted expected `ArtifactBlockId`; when a tail is
present, the head comparison occurs before truncation. A mismatch preserves the
file unchanged.

## Selected snapshots and memory-only candidate branches

Creation retains one immutable structurally shared selected-artifact snapshot
at the virtual genesis position. Each successful durable selected append retains
the resulting snapshot with that selected block, and strict replay rebuilds the
same snapshot sequence from the existing journal entries. The journal therefore
has one selected snapshot for virtual genesis and one for every retained
selected `ArtifactBlock`. No snapshot bytes, branch marker, or new framing field
are added to the journal format.

`ArtifactChainJournal::branch_snapshot_at` first requires a healthy journal and
only then looks up the caller-supplied `ArtifactBlockId`. The identifier must be
the journal's exact virtual genesis or one of its retained selected blocks. An
unselected, unknown, candidate-only, or other-chain block identity fails as a
fork point. Success returns an owned `ArtifactChainBranchSnapshot` rooted in the
exact replay-checked state at that selected position.

The returned snapshot uses the proof protocol's persistent path-copy boundary.
Successful and failed child validation cannot change the journal's selected
head, resolver, accepted records, authenticated root, selected-block index, or
durable bytes. Independent clones may evaluate siblings, and a later selected
journal append does not change an already returned snapshot. Reference-count
bookkeeping is representation metadata rather than selected-state mutation.

Candidate snapshots exist only in caller-held memory. They are not inserted
into the selected-position index, written to the journal, restored on open, or
recovered after a restart. Replay rebuilds selected snapshots only. Recreating a
discarded candidate branch therefore requires the caller to supply its blocks
and canonical payloads again from a selected fork point.

## Read interface

A healthy journal exposes the derived chain ID, exact head (virtual genesis
when empty), committed block lookup by `ArtifactBlockId`, accepted artifact
lookup by `ArtifactId`, immutable `ArtifactState`, count, emptiness,
`ArtifactSetRoot`, and set witnesses. These are views of replay-checked selected
state only.

An absent lookup is not evidence of global absence. A returned record or witness
does not establish network finality. The immutable `ArtifactState` may resolve
authoring citations only while borrowed from a healthy journal; it contains no
candidates, archived payloads, or fetched but unselected artifacts.

## Resource and failure contract

Entries are length-bounded before payload allocation. Replay retains accepted
records, selected resolver indexes, authenticated-set topology, and one
selected-block index whose entries also reference the immutable structurally
shared state at that selected position, plus the virtual-genesis snapshot. New
snapshots path-copy only changed identity-map and authenticated-set paths; they
do not retain duplicate payload buffers or Merkle-node serialization.
Framed-payload and selected-block-index reservation failures are explicit.
Ordinary reference-counted node allocation is not represented as a protocol
error and follows the Rust allocator's process-level failure behavior.

Opening or reading can fail on lock, I/O, invalid header, chain mismatch,
invalid entry length, offset overflow, allocation, footer mismatch, replay
admission, trusted-head mismatch, or tail-recovery failure. Complete corruption
never produces a partial healthy handle. Post-open ambiguity poisons the handle;
reopen is the only recovery path.

## Compatibility and non-goals

The `v1` header and `canonical-definition-v1` chain identity are a clean
prerelease cutover. Earlier journals have no legacy reader or migration; remove
and recreate local data.

The journal does not define durable candidate-branch storage, rollback,
reorganization, pruning, candidate-snapshot retention or eviction policy,
compaction, discovery, networking, consensus, finality, proposer authority,
economics, or backup policy.
