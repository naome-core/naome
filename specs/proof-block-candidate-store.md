# NAOME Proof Block Candidate Store

## Scope and trust boundary

This document defines the chain-scoped append-only store implemented by
`ProofBlockCandidateStore`. It durably retains typed canonical `ProofBlock`
values under their internally derived `ProofBlockId`, allowing siblings and
orphans to coexist without changing the selected chain.

The store is a structural quarantine, not a candidate history. Typed insertion
and strict replay establish canonical block structure and exact content
identity only. They do not establish that a parent exists, ancestry reaches the
chain's virtual genesis, the proof payload is available, the single-proof block
is executable in its parent state, or a block is selected, preferred, or
finalized.
The [Proof Protocol](proof-protocol.md) owns block encoding, identity, and
execution. The [Proof Chain Journal](proof-chain-journal.md) remains the sole
durable owner of selected proof-chain state.

## Public state and local limits

`ProofBlockCandidateStoreLimits::new(max_entries)` accepts only a positive
entry limit. The field is private and exposed by `max_entries`.

Limits are local resource policy, not format identity. They are neither stored
nor hashed. Reopening with different positive limits is allowed only when all
complete committed entries fit the supplied limit.

The store exposes:

- `create` and `open`, which establish one exclusively owned handle;
- `insert(&ProofBlock)`, which appends or recognizes one immutable block;
- `get(ProofBlockId)`, which returns an owned `ProofBlock` or absence;
- `contains`, `len`, and `is_empty`, which query the current in-memory index; and
- `chain_id` and `limits`, which expose immutable handle context.

All operations except the immutable `chain_id` and `limits` getters require a
healthy handle.

The returned block's exact verified address remains derivable through
`ProofBlock::id`; no storage-specific wrapper or duplicate identity is exposed.

## Directory and exclusive ownership

The caller supplies an existing directory. The store uses two fixed files:

- `proof-block-candidate-store.lock`, an advisory exclusive-writer sidecar;
  and
- `proof-block-candidate-store.log`, the append log.

The sidecar is opened read/write and locked non-blockingly before the log is
created or opened. A second cooperative process or handle fails rather than
observing or mutating the store. The lock remains held for the complete handle
lifetime, including while the handle is poisoned.

`create` uses exclusive file creation and never replaces an existing log. It
writes and synchronizes the complete chain-scoped prefix before returning. A
creation or prefix-synchronization failure may leave a partial or durability-
ambiguous final-path file; a later `create` does not replace it automatically.
Portable durability of the parent directory entry remains the caller's
provisioning responsibility.

`open` requires an existing recognized log. It checks the complete prefix and
every committed entry, enforces the supplied limits, recovers at most one
framing-incomplete final append, synchronizes the resulting visible image, and
only then returns a handle.

## File prefix and chain context

Every log starts with exactly:

```text
magic[34]       = "naome:proof-block-candidate-store\0"
proof_chain_id  = 32 definition-derived bytes
```

The fixed prefix is 66 bytes. Creation derives the identifier from the supplied
`ProofChainDefinition`. Opening derives the expected identifier from its
supplied definition and compares all 32 stored bytes before entry scanning or
tail recovery. Missing or different magic bytes are `InvalidHeader`; a complete
recognized prefix with a different chain identifier is `ChainIdMismatch`.

The definition itself is not stored. The identifier binds local deployment,
Foundation, and virtual-genesis context under the Proof Protocol's identity
assumptions, but does not make standalone blocks self-labeling. In particular,
the prefix does not prove that any retained parent belongs to this chain.

The format has no compatibility alias, legacy parser, or migration. The
`single-proof-v0` chain identity and fixed block width deliberately reject the
earlier prerelease multi-proof store; it must be recreated.

## Entry encoding and commit footer

The prefix is followed by zero or more entries without padding:

```text
proof_block   128 canonical ProofBlock bytes
block_id      32 raw ProofBlockId bytes
```

Every entry is exactly 160 bytes. File-offset arithmetic is checked before
reading its fixed block and footer.

The footer must equal the `ProofBlockId` derived from the fixed-width canonical
block exactly as defined by the [Proof Protocol](proof-protocol.md).
It reuses that protocol identity as both exact lookup address and two-phase
commit marker, defining no second digest or hash domain. A mismatch is
`BlockIdMismatch`; a repeated valid address in the log is `DuplicateBlockId`.

The footer detects accidental changes to canonical block bytes under the hash
assumptions. It is not a signature, MAC, ancestry proof, proof-execution result,
or protection against a party that can rewrite the log and recompute SHA-256.

## Insertion and durable commit

Insertion executes in this order:

1. require a healthy handle;
2. derive `ProofBlockId` from the typed block;
3. if the ID is indexed, reread and structurally verify the complete entry;
4. return `AlreadyPresent` for the same block or, defensively, `BlockConflict`
   if different canonical bytes derive the same ID, without modifying the log;
5. for a new ID, check the next entry count and encode the fixed canonical block;
6. reserve one exact-ID index slot and check append-offset arithmetic before
   file mutation;
7. require the visible file length to equal the indexed committed boundary;
   mismatch is `StoreLengthChanged`, poisons the handle, and writes nothing;
8. append the canonical block, then synchronize that body;
9. append the derived block ID, then synchronize the footer; and
10. install the reserved index entry, update the committed boundary, and return
    `Inserted`.

Known-ID comparison precedes capacity checks, making exact replay idempotent at
full capacity. The typed gate accepts no caller-supplied raw bytes or claimed
ID. It does not inspect the parent, locate the payload, or execute the block.

Any seek, write, or synchronization error after commit begins returns `Commit`
and poisons the handle because the durable result may be either the old log or
the new entry. No index state becomes visible before both barriers succeed.
Dropping and reopening is the only recovery probe.

## Open, replay, and recovery

After locking and validating the prefix, replay scans from byte 66. For each
entry it:

1. treats fewer than 160 remaining bytes as an incomplete final append;
2. checks the fixed entry endpoint for overflow;
3. reads exactly one block into a fixed 128-byte buffer and interprets its four
   raw 32-byte fields;
4. derives its `ProofBlockId` and compares the complete footer;
5. rejects a duplicate derived ID;
6. checks unique-entry count against the supplied limit; and
7. reserves and installs one ID-to-entry-offset index record.

A framing-incomplete final append is truncated to the preceding committed
boundary and synchronized. Every exact 128-byte block body is structurally
decodable; a wrong footer, duplicate ID, or over-limit entry fails closed and is
never skipped, truncated, or repaired. A complete valid image is synchronized
before the handle is returned.

Replay never checks parent availability, constructs parent or child indexes,
sorts blocks, executes proofs, loads payloads, or infers a preferred branch.
Insertion order has no protocol meaning.

## Reads, queries, and poisoning

`get` first consults the in-memory index. An unknown ID returns absence without
file I/O. For a known ID it rereads the fixed canonical block and footer;
interprets the block's four fields; and requires both derived and stored IDs to
equal the lookup ID. Success returns the owned decoded candidate.

`contains`, `len`, and `is_empty` use only the index image established by open
and successful inserts. They do not independently detect out-of-contract file
mutation.

A post-open entry read failure returns `Read`; a derived identity or footer that
no longer equals the indexed ID returns `StoredEntryChanged`. Either poisons the
handle because the offset index can no longer be trusted. Once poisoned, every
health-sensitive method returns `Poisoned`; `chain_id` and `limits` remain
available.

Before appending a new ID, insertion also verifies that the visible file length
still equals the committed boundary captured by the index. External truncation
or extension returns `StoreLengthChanged`, poisons the handle, and performs no
write.

## Error precedence

`ProofBlockCandidateStoreError` preserves the first authoritative boundary:

- `LockFile`, `Locked`, or `Lock` precedes all log-file work;
- creation and opening use `Create` and `Open`; existing-file scan I/O uses
  `Read` with the field offset;
- `InvalidHeader` precedes `ChainIdMismatch`, which precedes entry work;
- fixed-entry endpoint checks precede `BlockIdMismatch`, then
  `DuplicateBlockId`, entry capacity, and index allocation;
- a known-ID insertion reread and exact comparison precedes capacity checks;
- a new-ID insertion checks entry capacity before index allocation, then
  verifies the visible committed boundary before writing;
- external length drift returns `StoreLengthChanged` and poisons without a
  write; and
- after commit begins, every seek, append, or synchronization failure is
  `Commit` and poisons the handle.

Opening returns no partial handle. Ordinary limit, conflict, arithmetic, and
pre-append errors leave a live handle usable.

## Resource and integrity contract

The store retains one hash-index record containing an entry offset per unique
block ID and no blocks in memory. Opening is linear in committed entries and
reuses one fixed 128-byte stack buffer. Exact-ID
lookup uses the same fixed buffer to reread one entry and returns its owned
decoded block. Insertion hashes and encodes one fixed block without
rewriting older entries. No operation scans all retained blocks to answer a
lookup or builds a parent/child adjacency index.

Each committed entry adds only the 32-byte commit footer to its 128 canonical
block bytes. The local entry limit therefore bounds index memory, canonical
block bytes, and physical file growth together. All count and offset arithmetic
fails closed on overflow.

The two synchronization barriers and terminal block ID let reopen distinguish
a complete intact append from an incomplete final append under cooperative
exclusive ownership. They do not detect rollback to an independently valid
prefix or malicious rewriting with recomputed identities. External mutation
outside the advisory-lock contract is unsupported; a later indexed read detects
it only when framing, strict decoding, or identity no longer matches.

## Conformance requirements

Implementations and tests must cover, at minimum:

- the zero entry limit and reopening under fitting and non-fitting policies;
- exclusive locking, create-without-replacement, exact prefix checks, and chain
  mismatch;
- insertion, retrieval, absence, metrics, persistence, sibling and orphan
  coexistence, exact idempotence at capacity, and immutable no-replacement
  behavior; `BlockConflict` is a defensive hash-collision path and does not
  require an artificial collision fixture;
- the exact format, fixed-field block interpretation, wrong footers, duplicate
  IDs, fixed-entry boundaries, and limit precedence;
- every incomplete-tail position and rejection of complete invalid entries;
- every append write and synchronization cut, old-or-new recovery, and poisoned
  handle behavior;
- post-open change, truncation, and read failure; and
- proof that candidate retention neither mutates nor authorizes selected state.

## Non-goals

The candidate store defines no:

- proof payload storage, dependency acquisition, mathematical checking,
  proof execution, or reusable accepted record;
- parent availability, ancestry completion, height, branch execution, branch
  validity, parent/child index, or candidate scoring;
- selected-journal integration, admission, rollback, reorganization, fork
  choice, checkpointing, consensus, or finality;
- network discovery, ingestion, fetching, serving, peer authorization, or
  propagation policy;
- overwrite, deletion, garbage collection, pruning, compaction, snapshots,
  migration, or retention policy; or
- validator identities, signatures, proposals, votes, rewards, fees, staking,
  slashing, token issuance, or other economic state; or
- definition artifacts, generalized block payloads, or any rule for admitting
  definitions.
