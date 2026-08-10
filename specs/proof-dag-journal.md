# NAOME Proof DAG Journal

## Status and scope

This document defines the crash-consistent local append journal for one
selected NAOME `ProofDag`. It is a prerelease storage contract and may change
before the first stable protocol release.

The journal stores bounded proof transactions. Each transaction contains one
dependency-first, root-closed sequence of canonical proof-certificate payloads.
Opening the journal reconstructs every identity, conclusion, dependency edge,
and authenticated-set node through strict proof replay. Persisted bytes never
bypass proof checking.

Journal transaction order and transaction boundaries are local recovery data.
They are not consensus order, block structure, finality evidence, or economic
transactions. The journal defines no networking, snapshots, compaction,
pruning, garbage collection, fork choice, rewards, fees, or settlement.

## Directory and exclusive ownership

The caller supplies an existing directory. Journal uses exactly two fixed
files:

- `proof-dag.lock`, an advisory exclusive-writer sidecar lock; and
- `proof-dag.journal`, the append journal defined below.

The sidecar is opened read/write and locked before the journal is created or
opened. Lock acquisition is non-blocking. A second cooperative process or
handle fails rather than observing or mutating the selected state. The lock is
held for the complete handle lifetime, including while the handle is poisoned.

`create` uses exclusive file creation and never replaces or reinitializes an
existing journal. `open` requires an existing journal and never initializes an
empty, partial, or unrecognized file.

## File header

Every journal begins with these exact 36 ASCII bytes, including the final NUL:

```text
naome:proof-dag-transaction-journal\0
```

Hexadecimal:

```text
6e616f6d653a70726f6f662d6461672d7472616e73616374696f6e2d6a6f75726e616c00
```

Any missing or different header byte is an unsupported or corrupt journal.
Only the transaction encoding in this document is recognized.

## Transaction encoding

The header is followed by zero or more transactions with no padding:

```text
transaction_body_length  4-byte unsigned big-endian integer
proof_count              1-byte unsigned integer
proofs                   proof_count proof entries
transaction_digest       32 bytes

proof entry:
    proof_length          4-byte unsigned big-endian integer
    canonical_proof       proof_length bytes
```

`proof_count` is in `1..=8`. Every `proof_length` is in
`1..=CERTIFICATE_MAX_BYTES`, where `CERTIFICATE_MAX_BYTES` is `4_194_304`.
The inner lengths must consume the transaction body exactly; missing or
trailing body bytes are invalid.

`transaction_body_length` covers `proof_count`, every inner proof length, and
every proof payload. It is in `6..=33_554_465`. The upper bound is exactly:

```text
1 + 8 * (4 + 4_194_304)
```

The framing permits at most `33_554_432` proof-payload bytes. Length and offset
arithmetic is checked before body allocation or reading. A proof length larger
than the remaining transaction body is invalid even when it is within the
single-certificate bound.

Expected request identities are not stored. They are admission context, not
intrinsic proof content. Strict replay reconstructs each actual `ProofId`; the
last proof is the transaction root.

## Chained transaction digest

The initial previous digest is:

```text
SHA256("naome:proof-dag-transaction-journal-genesis\0")
```

For every transaction in physical order:

```text
transaction_digest = SHA256(
    "naome:proof-dag-transaction\0"
    || previous_transaction_digest[32]
    || transaction_body_length_be[4]
    || proof_count[1]
    || each (proof_length_be[4] || canonical_proof[proof_length])
)
```

The stored digest is both the chained integrity value and the transaction
commit footer. It binds transaction boundaries, proof boundaries, order, and
every proof byte. Each transaction therefore adds 37 bytes beyond its inner
proof entries: four outer-length bytes, one count byte, and the 32-byte footer.

For boundaries located from an intact outer length, the digest chain detects
byte corruption and deletion, duplication, reordering, or regrouping unless
the file is replaced by an independently valid prefix or the digest chain is
recomputed. The journal is not a keyed authentication mechanism.

## Admission and atomic state transition

The single-proof APIs use the same transaction encoding with `proof_count = 1`.
The addressed rooted-batch API accepts one immutable `requested_root` and one
dependency-first sequence of `AddressedProofCandidate` values. Ledger State
performs the complete in-memory transition defined by
[Ledger State](ledger-state.md) before journal I/O begins.

For a rooted addressed transaction:

1. require a healthy journal handle;
2. preflight the candidate count, unique expected identities, and final-root
   binding;
3. strictly decode, canonicality-check, mathematically check, address-check,
   and stage every candidate against the selected base plus earlier staged
   candidates;
4. require every staged candidate to be transitively reachable by exact
   `ProofId` from the final requested root;
5. atomically register all records in Ledger State and the authenticated proof
   set;
6. append one complete transaction body;
7. synchronize the body;
8. append its chained digest footer;
9. synchronize the footer; and
10. only then acknowledge success and expose the retained root record.

An admission error occurs before file mutation and leaves the handle healthy.
No partial candidate subset becomes visible. A valid but unrelated proof
cannot be smuggled into selected state through a failing or successful rooted
transaction.

The journal writes retained canonical proof slices directly and hashes the
same slices incrementally. It does not concatenate the complete transaction
into another proof-sized buffer. Replay allocates each individually bounded
proof payload and holds at most eight candidates before rooted admission.

## Commit failure and poisoning

Any seek, write, or synchronization error after successful in-memory
admission makes durability ambiguous. The call returns no record, the handle
becomes poisoned, and all subsequent reads and admissions fail. Dropping and
reopening the journal is the only recovery path.

The first synchronization barrier completes before the footer is written, so
a complete footer cannot be issued before its body has been synchronized. The
second barrier is required before success is acknowledged. `sync_all` provides
Rust's portable file-content-and-metadata synchronization contract; it does
not by itself guarantee that the parent directory entry survives power loss.
Directory provisioning durability remains the caller's responsibility.

## Open and deterministic replay

After acquiring the exclusive lock, `open` validates the exact header and
scans transactions from the first byte after it. For each complete transaction
it:

1. validates the outer length and complete transaction boundary;
2. validates `proof_count`, every inner proof length, and exact body
   consumption while incrementally hashing the body;
3. compares the stored and reconstructed chained digests; and
4. submits the ordered payloads to a fresh `ProofDag` through strict
   unaddressed rooted-batch admission.

Replay derives every actual identity exactly once. The final actual `ProofId`
is the replay root, every earlier proof must be transitively reachable from it,
and every dependency must be in the already replayed state or earlier in the
same transaction. Replay never trusts stored identities, sorts candidates,
preloads later dependencies, skips invalid candidates, or commits a partial
transaction.

The first complete framing, digest, or proof-admission error fails closed and
returns no journal handle. A complete invalid transaction is never skipped,
truncated, or repaired. Before a completely replayed visible image is exposed,
`open` calls `sync_all`; failure to stabilize returns no handle.

`open_verified` completes lock acquisition, format validation, digest checks,
strict replay, tail recovery, and stabilization before comparing the resulting
`ProofSetRoot` with one caller-supplied expected root. A mismatch returns no
handle. The expected root must come from a separately trusted source and binds
the exact complete replayed set, not an arbitrary prefix or subset.

## Incomplete-tail recovery

If EOF occurs after the last committed transaction but before a complete next
transaction footer, the suffix is an uncommitted append tail. `open` truncates
the file to the preceding committed boundary, synchronizes the truncation, and
only then returns the recovered prefix. A truncation or synchronization error
fails recovery.

This recovery rule applies only when the outer transaction boundary cannot be
complete in the visible file. A structurally complete transaction with invalid
inner framing, a wrong digest, or failed strict rooted replay is corrupt and is
not discarded.

## Crash and corruption boundary

Without a separately durable trusted head, no self-contained append file can
distinguish every damaged final outer length or exact rollback to an earlier
valid transaction boundary from a crash that left precisely that prefix.
Accordingly:

- an incomplete final transaction is discarded as uncommitted;
- a complete invalid transaction fails closed;
- an in-range damaged outer length can make a suffix appear incomplete and may
  cause truncation to the preceding committed boundary; and
- `open` cannot detect replacement or truncation to an independently valid
  prefix, while `open_verified` detects it only when supplied the expected
  complete-state root from a separately trusted checkpoint or finalized
  source.

The journal provides deterministic local recovery under this crash and
torn-append model. It does not authenticate a malicious filesystem.

## Golden vectors

The genesis digest is:

```text
7127edbfaed6d7b39d6a9ef69b3e3412a5ade11c0c13b2622b0ca33f11523764
```

The canonical one-step Pairing proof payload is six bytes:

```text
000000011001
```

Its count-one transaction body is 11 bytes:

```text
0100000006000000011001
```

The transaction digest is:

```text
a7ac477d54ca4421cfbeb77a1bace81be2b98588af20d2f5abeae8ffc6a84b4f
```

The complete 47-byte transaction is:

```text
0000000b0100000006000000011001a7ac477d54ca4421cfbeb77a1bace81be2b98588af20d2f5abeae8ffc6a84b4f
```

The complete 83-byte one-transaction journal is:

```text
6e616f6d653a70726f6f662d6461672d7472616e73616374696f6e2d6a6f75726e616c000000000b0100000006000000011001a7ac477d54ca4421cfbeb77a1bace81be2b98588af20d2f5abeae8ffc6a84b4f
```

## Explicit exclusions

This contract defines no storage-format migration, alternate parser, dynamic
batch limit, automatic sorting, partial success, generic rollback, snapshots,
compaction, pruning, reorganization, multi-writer coordination beyond the
exclusive lock, peer provenance, request history, networking, block format,
consensus, finality, rewards, fees, or settlement.
