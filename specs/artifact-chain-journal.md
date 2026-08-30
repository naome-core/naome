# NAOME Artifact Chain Journal

This document normatively defines local crash-consistent persistence for one
selected linear artifact chain. The [Proof and Artifact Protocol](proof-protocol.md)
owns block and artifact admission. The journal neither weakens those checks nor
defines fork choice, consensus, or finality.

## Ownership and authority

`ArtifactChainJournal` privately owns one `ArtifactChainState`: exact head,
checked proof and definition resolver state, authenticated artifact DAG, and an
index of committed blocks. It is the sole durable owner for this artifact-only
journal workflow.

When fixed-validator artifact-consensus V0 is enabled, this artifact-only
journal is not an independent consensus-selected-head or finality authority.
`FixedValidatorFinalityJournalV0` instead stores the exact verified consensus
envelope and artifact payload together and reconstructs their coupled state
from one history. Implementations must not compose two independently committed
artifact and consensus journals and call the result atomic. The artifact-only
journal remains available only in a separately provisioned directory for the
explicitly caller-selected recovery, candidate-validation, and offline-transfer
workflows defined below; those workflows continue to grant no consensus or
finality authority. Because both formats use the same file and exclusive-lock
names, they are mutually exclusive within one directory.

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

The caller may use that exact retained position as a historical structural
recovery anchor. The journal does not replace it with the current head, choose
it from candidate observations, or infer that it is a preferred fork point. A
network workflow using the snapshot must still require its candidate path to
reach that exact address and treat any different selected position as divergent
for that operation.

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

## Local candidate-branch reconstruction

`ArtifactChainJournal::reconstruct_candidate_branch` accepts one healthy
selected journal, one caller-routed `ArtifactBlockCandidateStore` for the same
`ArtifactChainId`, one healthy Foundation-scoped
`CanonicalArtifactPayloadStore`, one exact caller-selected target
`ArtifactBlockId`, and one `CandidateBranchReconstructionLimits` containing a
positive `max_blocks`. The target chooses only which locally retained
observations to evaluate. It does not choose a consensus branch.

Journal and candidate-store chain IDs are compared before health or disk reads.
The boundary then walks parent addresses backward from the target through exact
integrity-checked candidate-store reads. It stops at the first parent that is
the journal's virtual genesis or a retained selected block, which is the nearest
selected artifact ancestor on that retained path. The walk rejects a selected
target, a missing or corrupt candidate, a repeated identity, a broken parent or
artifact-set-root link, or a path requiring more than `max_blocks` candidate
blocks. `max_blocks` bounds this one local operation only; it is not a
consensus branch-depth, retention, or verification-work rule.

After discovering the complete path, reconstruction obtains the replay-built
snapshot at that selected ancestor and evaluates retained candidates in forward
order. For each block it integrity-reads the exact archived payload addressed
by the block's `ArtifactId` and calls the ordinary immutable snapshot child
validation. Missing or corrupt archive content and every canonical, identity,
dependency, mathematical, novelty, parent, or root failure are typed errors.
Success returns one `ReconstructedCandidateBranch`, including an owned
memory-only snapshot, only after the exact target has validated. A
`CandidateBranchReconstructionError` returns no partial snapshot.

Reconstruction performs no insert, replacement, refresh, promotion, deletion,
or durable-byte mutation in the journal, candidate store, or payload archive.
Successful and ordinary failed evaluation leave selected snapshots and state
unchanged. A corrupt candidate or archive integrity read retains that store's
typed poison-and-reopen behavior; poisoning a handle is not candidate or
selected-state mutation. In particular, an archive hit is revalidated rather
than promoted or refreshed. Missing local content is not fetched and proves no
global absence. The caller may separately use the payload archive's
branch-candidate write gate to validate and durably retain one exact child
before attempting reconstruction again.

### Incremental payload recovery cursor

`ArtifactChainJournal::start_candidate_branch_reconstruction` exposes the same
structural walk and forward validation as an opaque consuming progress cursor.
It accepts the same exact target, matching candidate store, payload archive,
and positive caller-local `CandidateBranchReconstructionLimits`. The complete
candidate path is integrity-read and shape-checked back to its nearest selected
ancestor before the cursor can report a missing payload or change the archive.
The cursor then owns that ancestor's immutable replay-built snapshot and the
forward candidate path, and its lifetime exclusively binds the exact payload
archive supplied at start so continuation cannot be redirected to another
archive; a later selected-journal append cannot change the captured state.

For each child in forward order, an exact archive hit is integrity-read and
fully revalidated read-only through
`ArtifactChainBranchSnapshot::validate_child`. On the first archive miss,
`CandidateBranchReconstructionProgress::AwaitingPayload` returns an opaque
`CandidateBranchReconstructionCursor` that exposes only the overall target,
pending block, and exact pending `ArtifactId`. The consuming
`validate_and_archive_pending_payload` operation accepts owned payload bytes,
delegates to `CanonicalArtifactPayloadStore::validate_and_insert_branch_payload`
for complete branch-context validation, and advances only after the archive
durably inserts or idempotently confirms those exact bytes. It then continues
across read-only validated archive hits until the next miss or until
`CandidateBranchReconstructionProgress::Complete` returns the fully validated
`ReconstructedCandidateBranch`.

No progress value exposes a partial branch snapshot. A validation or archive
error consumes the active cursor and returns no successor; every earlier
acknowledged archive entry remains durable, and a fresh explicit start
integrity-reads and revalidates that prefix before resuming at a later miss.
The existing all-local `reconstruct_candidate_branch` delegates to this state
machine but preserves its all-or-nothing interface and typed missing-payload
failure. Neither entry point fetches content, mutates the journal or candidate
store, persists a branch snapshot, or assigns selection, consensus, finality,
availability, or peer-trust authority. Continuing a cursor after the selected
head advances evaluates only its captured historical artifact state and makes
no claim that the target remains an unselected candidate.

## Full-preflight offline candidate import

`ArtifactChainJournal::import_candidate_branch_from_archive` accepts one
mutable selected journal, one exact caller-selected target `ArtifactBlockId`,
one caller-routed `ArtifactBlockCandidateStore` for the same `ArtifactChainId`,
one Foundation-scoped `CanonicalArtifactPayloadStore`, and positive
caller-local `CandidateBranchArchiveImportLimits` containing `max_blocks` and
`max_buffered_payload_bytes`. Invoking this method is the caller's explicit
authorization to advance that local artifact journal toward the exact target.
It is not consensus branch selection, fork choice, or finality authority.

Journal and candidate-store chain IDs are compared before health or disk reads.
The method then captures the journal's current exact head and replay-built
immutable snapshot and rejects a target already present anywhere in selected
history. Starting at the target, it integrity-reads retained candidates
backward, rejects repetition and broken parent or artifact-set-root continuity,
and applies `max_blocks` before inspecting another address. The first selected
position reached must be the captured current head, including virtual genesis
only when virtual genesis is that head. Encountering any other retained
selected position is divergent ancestry and fails before payload access or
journal mutation.

After retaining the complete block path in forward order, preflight
integrity-reads each block's exact archived payload and checks cumulative owned
payload bytes against `max_buffered_payload_bytes` before retaining another
payload. It privately retains those exact owned bytes and applies complete
immutable snapshot child validation from the captured head through the target.
Missing or corrupt archive content, allocation or byte-limit exhaustion, and
every canonical, identity, dependency, mathematical, novelty, parent, or root
failure are typed preflight errors. No preflight failure writes the journal,
candidate store, or payload archive; an integrity failure may still poison the
affected read handle under its existing poison-and-reopen contract. Complete
preflight exposes no accepted record, branch snapshot, or reusable validation
token.

Only after the entire path and its payload bytes pass preflight does the method
begin selected-journal application. In forward order it moves each privately
retained exact payload into ordinary `ArtifactChainJournal::apply_block`. That
call repeats complete target-state validation and the existing synchronized
single-entry journal commit; preflight cannot bypass admission. A block enters
the import's acknowledged count and becomes its last-acknowledged head only
after `apply_block` returns success. `CandidateBranchArchiveImportOutcome`
reports the captured anchor, exact target, acknowledged block count, and total
buffered payload bytes. Success leaves the exact target as the local selected
artifact-journal head.

A later validation or journal error never rolls back an earlier acknowledged
block. `CandidateBranchArchiveImportError::Commit` reports only the exact
acknowledged prefix. If the current journal commit has an ambiguous I/O outcome,
that block is excluded from the acknowledged count and head, the journal
retains its existing poisoned state, and the caller must drop and reopen it
under the ordinary journal recovery contract to determine the durable prefix
before retrying. The complete ancestry is not one transaction; the existing
single-entry recovery boundary applies independently to each attempted block.

Both positive limits bound only this caller-local operation. They are not
consensus branch-depth, payload-size, validation-work, retention, or admission
rules. Retaining the bounded payload bytes is private implementation state for
this one call and creates no reusable certificate. Candidate-store and payload-
archive durable bytes remain read-only except that an integrity failure may
poison the affected handle.

The operation does not discover or choose a target, inspect peers, fetch
missing data, archive payloads, mutate candidate retention, import from a
historical selected anchor, reorganize or roll back selected history, choose or
rank competing branches, define retention or pruning, map consensus ancestry,
or establish consensus canonicality, finality, peer trust, global availability,
or economic authority.

## Candidate-branch recovery bundles

The [Candidate-Branch Recovery Bundle V0](candidate-branch-recovery-bundle.md)
defines one caller-owned canonical offline transfer artifact. The existing
`export_candidate_branch_recovery_bundle_v0` mode binds one exact unselected
candidate target to this journal's captured current head and root. The separate
`export_genesis_anchored_candidate_branch_recovery_bundle_v0` mode also accepts
only an exact unselected candidate target, but emits the existing V0 format
anchored at this journal's virtual-genesis position and replay-built
virtual-genesis root.
Virtual genesis and every selected target are rejected; this is not a
selected-journal backup mode.

Genesis-anchored export integrity-walks the retained candidate suffix to its
nearest retained selected ancestor, prepends the exact selected prefix from
virtual genesis through that ancestor, and forward-validates the complete path
from the immutable virtual-genesis snapshot. Exact selected-prefix payloads
come from the corresponding replay-accepted journal records; the caller-routed
payload archive supplies only the candidate-suffix payloads. The selected bytes
are ordinary validation input and confer no reusable validation, provenance,
selection, or finality claim.

The positive caller-local bundle limits apply to the whole combined block
count, aggregate payload bytes, and final canonical encoding. Export publishes
nothing until the complete bounded path validates and performs no journal,
candidate-store, or payload-archive write.

`import_candidate_branch_recovery_bundle_v0` is unchanged. It re-decodes and
fully preflights the whole bundle under the destination limits, accepts only a
destination head equal to the encoded anchor or one exact contiguous encoded
prefix, and then applies only the remaining suffix through ordinary sequential
journal admission. Each acknowledged block is durable independently; an
ambiguous current append requires reopen, and a retry succeeds only from the
exact reopened bundle prefix. A divergent or longer head fails before a new
append.

Neither export mode chooses a target or branch, mutates selected state, or
creates a durable competing-branch representation. The format and these methods
define no rollback, reorganization, networking, authentication, availability,
peer trust, consensus, finality, or economic authority.

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

The fixed-validator joint-finality V0 header is a separate clean prerelease
replacement in the same file and lock namespace. An artifact-only journal is
not migrated, reinterpreted, or opened beside it in one directory; the caller
must provision a fresh directory or explicitly recreate the local data under
the selected format.

The journal does not define durable candidate-branch storage, rollback,
reorganization, pruning, candidate-snapshot retention or eviction policy,
compaction, discovery, networking, consensus, finality, proposer authority,
economics, or backup policy.
