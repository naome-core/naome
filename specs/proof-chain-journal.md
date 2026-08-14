# NAOME Proof Chain Journal

## Scope, ownership, and compatibility

This document defines the crash-consistent append journal for one selected
linear proof chain. `ProofChainJournal` is the sole durable owner of that state:
each entry contains one complete canonical `ProofBlock` and the exact canonical
payload for its one `ProofId`. Strict replay reconstructs
the exact head, proof DAG, authenticated proof set, and private committed-block
lookup without bypassing parentage, root binding, canonicality, mathematical
checking, or address correlation.

The format has no compatibility alias, legacy parser, or migration. An
incompatible prerelease directory must be recreated. Unverified open may recover
only an incomplete append tail; verified open additionally requires a
separately trusted exact head. Block preparation is read-only and block
application is the sole durable mutation.

The `single-proof-v0` chain-definition identity domain changes the stored
identifier and virtual genesis relative to the earlier prerelease multi-proof
block format. Those journals and candidate stores must be recreated; open never
rewrites the prefix, translates entries, or accepts the old chain namespace.

Every selected-state operation requires a healthy handle. The immutable
`chain_id` getter alone remains available after poisoning; it performs no disk
I/O and the ID is not repeated in block or entry bytes. Private chain, proof,
and block-index state is exposed only through health-sensitive queries.

The health-sensitive `proof_state` query returns an immutable borrow of the
checker state already owned by the selected proof DAG. It performs no replay,
disk I/O, reconstruction, cloning, registration, or state mutation. Only proofs
selected by strict block application or replay can resolve through this borrow.
Structural candidates, archived payloads, fetched bytes, and checked proofs
outside the journal are not consulted or merged.

The borrow is tied to the journal handle, preventing mutable block application
through that handle until the reader finishes. The selected authoring adapter
uses this query before parsing source, so `Poisoned` takes precedence over
authoring failures. Successful compilation does
not change journal bytes, head, authenticated root, proof count, or records.

The journal is local recovery state. A valid file is not evidence of network
selection, checkpoint authority, finality, or consensus. It defines no
competing-history store, reorganization, snapshot, pruning, or network policy.

## Directory and exclusive ownership

The caller supplies an existing directory. The journal uses exactly two fixed
files:

- `proof-chain.lock`, an advisory exclusive-writer sidecar lock; and
- `proof-chain.journal`, the append journal defined below.

The sidecar is opened read/write and locked before the journal is created or
opened. Lock acquisition is non-blocking. A second cooperative process or
handle fails rather than observing or mutating selected state. The lock remains
held for the complete handle lifetime, including while the handle is poisoned.

`create` uses exclusive file creation and never replaces or reinitializes an
existing journal. `open_recovering_unverified` and `open_verified` require an
existing recognized journal. The caller supplies the complete supported
`ProofChainDefinition` to all three operations; they derive its `ProofChainId`
once before header work. If initial header writing or synchronization fails,
`create` may leave a partial or durability-ambiguous final-path file and returns
no handle. A later `create` will not replace it; prerelease recovery requires
explicit operator inspection and recreation. The implementation must not delete
the file automatically after an ambiguous synchronization failure.

## File prefix and chain context

Every journal starts with the following exact bytes:

```text
magic[26]       = "naome:proof-chain-journal\0"
proof_chain_id  = 32 definition-derived bytes
```

The magic in hexadecimal is:

```text
6e616f6d653a70726f6f662d636861696e2d6a6f75726e616c00
```

The complete fixed prefix is therefore 58 bytes. Any missing or different
magic byte is an unsupported or corrupt journal. Opening reads the complete
stored chain identifier and compares it with the identifier derived from the
caller-supplied definition before entry scanning or tail recovery. A mismatch
returns no journal handle and does not modify the file.

Persisting the chain identifier binds the local replay context and virtual
genesis parent while retaining the 58-byte prefix and avoiding redundant
Foundation and root bytes in the journal. It does not put the identifier into
canonical block bytes, authenticate an operator, select a network, authorize a
block, or establish consensus. The definition itself is not persisted; the
[Proof Protocol](proof-protocol.md) owns its canonical representation and
identity.

## Entry encoding

The fixed prefix is followed by zero or more entries with no padding:

```text
entry_body_length  4-byte unsigned big-endian integer
entry_body         entry_body_length bytes
commit_block_id    32 raw ProofBlockId bytes

entry body:
    proof_block     128 canonical ProofBlock bytes
    canonical_proof remaining entry-body bytes
```

`entry_body_length` is in `129..=4_194_432`: exactly 128 fixed block bytes plus
one payload in `1..=CERTIFICATE_MAX_BYTES`, where `CERTIFICATE_MAX_BYTES` is
`4_194_304`. The outer body length determines the proof length without a
redundant block length, proof length, or proof count. Checked length and offset
arithmetic precedes payload allocation or reading.

Including the four-byte outer length and 32-byte footer, a structurally
possible entry is `165..=4_194_468` bytes. Strict proof decoding makes the
smallest valid entry 170 bytes because a canonical nonempty proof certificate
requires at least six bytes. A prefix followed by one maximum entry is
`4_194_526` bytes.

The fixed block width and proof length derived from the outer frame are local
framing rules; they are not part of `ProofBlockId`. The entry stores no separate
proof identity, state roots, or payload count. The block already commits those
values. Replay couples the remaining payload bytes to the block's sole
`proof_id`.

## Block-ID commit footer

`commit_block_id` must equal the `ProofBlockId` computed from the fixed-width
canonical block in that entry. It is the entry's two-phase commit
marker and reuses the identity already required by linear block execution; the
journal defines no additional hash domain or digest chain.

The block ID binds the exact canonical block, including its parent, state roots,
and sole `ProofId`. Strict replay then decodes and checks the canonical payload
and requires its derived `ProofId` to equal that identity. Exact body
consumption binds the local framing. Consequently, committed payload bytes
remain checked without a second journal-specific SHA-256 pass over as much as
4 MiB.

A wrong footer fails with `ProofChainJournalError::BlockIdMismatch`, whose
`expected` value is the ID derived from the decoded block and whose `actual`
value is the stored footer. Exact block parentage rejects omission,
duplication, or reordering of complete entries during strict replay. The
footer is not a signature or keyed authenticator and does not defend against a
malicious filesystem or rollback to an independently valid prefix. A payload-
only corruption that preserves framing and the block footer instead fails at
strict block replay, such as proof decoding or expected-identity correlation;
it is not misclassified as a footer mismatch.

## Read-only block validation

`validate_block` accepts one already supplied block and its one addressed proof
candidate. It first requires a healthy journal handle, then delegates exact-
parent and complete single-proof validation to
`ProofChainState::validate_block`. It performs no journal write, block-index
reservation, selected-state mutation, proof retention, or head advance.

An ordinary validation failure is reported as `BlockAdmission` with the exact
block and single-proof error precedence. Success returns no record, durable
receipt, or transferable validation object. It establishes only that this
direct child and exact payload were executable against the journal's selected
state during the call; it grants no selection, proposal, vote, certificate, or
finality authority.

Validation does not reserve the parent or candidate. Multiple siblings may
validate against one unchanged head, and durable application of one makes the
others stale. Every application repeats full block and proof validation against
the then-current selected state.

## Block application and durable commit

Block preparation is read-only: it does not check payloads, mutate state, write
an entry, or choose among competing blocks. Durable application accepts an
already supplied block and its one owned canonical proof payload.

Application executes in this order:

1. require a healthy journal handle;
2. require the supplied parent to equal the exact current head before block
   retention, index reservation, or candidate work;
3. retain the block's fixed canonical bytes and decoded value, then reserve
   one private lookup slot before state mutation;
4. invoke `ProofChainState::apply_block` exactly once, preserving its own parent-
   first single-proof error precedence;
5. after successful in-memory application, use the advanced exact head as the
   block ID and locate the retained proof record through the block's exact
   `ProofId`;
6. append the outer length, canonical block, and retained proof slice directly;
7. synchronize the complete length and body;
8. append the block ID as the commit footer;
9. synchronize the footer;
10. install the already reserved block lookup entry; and
11. only then acknowledge success and expose the retained record.

An ordinary block or proof error occurs before file mutation and leaves the
handle healthy. Parent mismatch precedes current-root, already-selected,
projected-root, and payload work. Single-proof block
application remains responsible for strict decoding, canonicality, mathematical
checking, dependency resolution against earlier selected blocks, and expected-
identity comparison. The journal does not duplicate or weaken those checks.

The journal streams the block and retained proof slice without an aggregate
entry buffer. Replay holds exactly one bounded candidate before block
application.

## Commit failure and poisoning

Any seek, write, or synchronization error after successful in-memory block
application makes durability ambiguous. The call returns no record, the handle
becomes poisoned, and every subsequent selected-state read, preparation, or
application fails. The immutable `chain_id` context remains readable; dropping
and reopening the journal is the only selected-state recovery path.

The first synchronization barrier completes before the footer is written, so
a complete footer cannot be issued before its body has been synchronized. The
second barrier is required before success is acknowledged. `sync_all` provides
Rust's portable file-content-and-metadata synchronization contract; it does not
by itself guarantee that the parent directory entry survives power loss.
Directory provisioning durability remains the caller's responsibility.

## Open and deterministic replay

After acquiring the lock and validating the complete prefix against the chain
identity derived once from the supplied definition, opening initializes an
empty `ProofChainState` with that identity and scans entries. For each
structurally complete entry it:

1. validates the outer length and complete entry boundary;
2. reads the first 128 body bytes and interprets the four raw 32-byte block
   fields;
3. derives the sole proof length from the remaining body bytes, allocates that
   bounded payload, and reads it exactly;
4. compares the stored footer with the decoded block's `ProofBlockId`;
5. uses the block's sole `ProofId` as that payload's expected address;
6. submits the block and payload exactly once to the fresh
   `ProofChainState`; then
7. reserves and installs the decoded block in the private exact-ID lookup.

Framing validation precedes footer comparison because framing is needed to
locate bounded fields. Canonical block decoding and payload allocation precede
footer comparison; footer comparison precedes block application. Replay never
trusts redundant identities, preloads later dependencies, bypasses the exact
parent, skips invalid entries, or commits a partial block.

The first complete framing, block-ID, or block-application error fails closed
and returns no handle. A complete invalid entry is never skipped, truncated, or
repaired. Before exposing a completely replayed visible image,
`open_recovering_unverified` calls `sync_all`; failure to stabilize returns no
handle.

## Error and validation precedence

`ProofChainJournalError` preserves the first authoritative boundary that
failed. Lock acquisition yields `LockFile`, `Locked`, or `Lock` before any
journal file operation. Creation and opening I/O use `Create` and `Open`, while
I/O during an existing-file scan uses `Read`. A complete prefix is required
before `ChainIdMismatch` can be reported; missing or wrong prefix bytes are
`InvalidHeader`.

For each visible entry, deterministic semantic precedence is:

1. fewer than four remaining bytes are an incomplete tail; otherwise read the
   outer length, reject its range with `InvalidEntryLength`, check its endpoint
   with `EntryOffsetOverflow`, and treat a valid endpoint beyond EOF as an
   incomplete tail;
2. read and interpret the four fixed 32-byte block fields;
3. reserve exactly the body remainder as the one bounded payload and read it;
4. read the footer and return `BlockIdMismatch { expected, actual, .. }`, where
   `expected` is the decoded block's ID and `actual` is the stored footer, on
   inequality; and
5. return `Replay` wrapping the first `ProofBlockApplyError` from strict
   application; and
6. after successful replay application, return `BlockIndexAllocation { entry }`
   if the private selected-block lookup cannot reserve its entry.

Any field read failure is `Read` at that field's offset. A failed payload-buffer
reservation is `Allocation` at the point above; it does not reorder the
surrounding structural checks.

Verified opening reports `HeadBlockIdMismatch` after strict prefix replay but
before either `Recovery` of an incomplete tail or `Stabilize` of a complete
image. Unverified recovery performs the applicable `Recovery` or `Stabilize`
directly.

Every health-sensitive selected-state handle method checks `Poisoned` before
its own work; the immutable `chain_id` getter is the explicit exception.
Read-only block preparation wraps its single-proof preparation error as
`Preparation`.
Read-only validation and application wrap an ordinary block failure as
`BlockAdmission`. Validation performs no lookup reservation or file I/O.
For application, parent mismatch precedes block retention and lookup reservation;
after a matching parent,
`BlockIndexAllocation` precedes root, candidate, and proof work so no lookup
allocation remains after state mutation. Any append, seek, or synchronization
failure after in-memory success is `Commit { block_id, source }` and poisons the
handle. These variants do not replace the block and ledger precedence defined
by their source contracts.

## Verified open

`open_verified` accepts the same `ProofChainDefinition` plus one
caller-supplied expected `ProofBlockId`. It completes lock acquisition, prefix
and chain-context validation, entry framing, block-ID footer checks, and strict
replay before comparing the reconstructed exact head with the expected head. A
mismatch returns no journal handle and, in particular, does not truncate an
otherwise recoverable incomplete tail. Only after a matching head does verified
opening recover such a tail or stabilize an already complete visible image.

The expected head must come from a separately trusted source. Under the block
hash assumptions, it recursively commits the complete admitted ancestry and
every block's before-and-after `ProofSetRoot`. Strict replay verifies that
the retained proof state realizes those commitments, so a second expected
proof-set root would be redundant.

Before the first admitted block, the expected head is the supplied definition's
derived virtual genesis parent. That anchor is not a stored or admitted block.

## Committed block lookup

The journal retains one decoded lookup entry for every strictly replayed or
successfully committed block. Exact-ID lookup first requires health, returns
only blocks on this selected line, and treats an unknown ID or virtual genesis
anchor as absent.

Replay installs a lookup entry only after framing, fixed-field interpretation,
footer identity, and strict block application; reservation failure aborts opening
without a partial handle. Live application reserves capacity and retains the
bounded block before chain mutation, but exposes it only after body and footer
synchronization. Commit failure poisons all selected-state lookups, and reopen
reconstructs whichever old or new committed prefix became durable.

The lookup changes no bytes, trusts no disk index, is rebuilt on every open, and
does not scan the file or proof state per query. Each block adds exactly one
proof, so retained block count equals selected proof count. The
[Proof Network Transport](proof-network-transport.md) may borrow an exact block
or read the chain-scoped head, but it cannot retain the borrow across an
asynchronous write or turn the result into checkpoint or selection authority.

## Incomplete-tail recovery

If EOF occurs after the last committed entry but before a complete next entry
footer, the suffix is an uncommitted append tail.
`open_recovering_unverified` truncates the file to
the preceding committed boundary, synchronizes the truncation, and only then
returns the recovered prefix. A truncation or synchronization error fails
recovery.

This rule applies only when the declared outer entry boundary cannot be
complete in the visible file. A structurally complete entry with a wrong
block-ID footer or failed strict block application is corrupt and is not
discarded.

## Crash and corruption boundary

Without a separately durable trusted head, no self-contained append file can
distinguish every damaged final outer length or exact rollback to an earlier
valid entry boundary from a crash that left precisely that prefix. Accordingly:

- an incomplete final entry is discarded as uncommitted;
- a complete invalid entry fails closed;
- an in-range damaged outer length can make a suffix appear incomplete and may
  cause truncation to the preceding committed boundary; and
- `open_recovering_unverified` cannot detect replacement or truncation to an
  independently valid prefix, while `open_verified` detects it only when
  supplied the expected head from a separately trusted source.

The journal provides deterministic local recovery under this crash and
torn-append model. Neither a valid file nor a matching expected head proves
that a network selected or finalized the chain.

## Network boundary

Network serving may read healthy exact proofs, committed blocks, and the
chain-scoped head. It never converts a journal error to `Unavailable`, bypasses
block application, or establishes a trusted checkpoint. Response ownership,
correlation, authentication, and permits belong to the
[Proof Network Transport](proof-network-transport.md).

This proof-only journal defines no definition artifact, generalized
proof/definition block union, validator set, fork choice, consensus, or
finality rule.
