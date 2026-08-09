# NAOME Proof DAG Journal

## Status and scope

This document defines a crash-consistent local append journal for one selected
NAOME `ProofDag`. It is a prerelease storage contract and may change before
the first stable protocol release.

The journal persists only canonical proof-certificate payloads in their local
dependency-first admission order. Opening it reconstructs the selected proof
DAG by strict replay. Persisted identities, conclusions, or dependency indexes
are never trusted because the format does not store them.

Journal order is local recovery order. It is not proof consensus order,
finality evidence, a block format, or economic settlement history. The journal defines
no snapshots, compaction, pruning, garbage collection, state commitment,
authenticated rollback detection, fork choice, rewards, fees, or networking.

## Directory and exclusive ownership

The caller supplies an existing journal directory. Journal uses exactly two
fixed files in it:

- `proof-dag.lock`, an advisory exclusive-writer sidecar lock; and
- `proof-dag.journal`, the append journal defined below.

The sidecar is opened read/write and locked before the journal is created or
opened. Lock acquisition is non-blocking. A second cooperative process or
handle fails rather than observing or mutating the selected state. The lock is
held for the complete handle lifetime, including while the handle is poisoned.

`create` uses exclusive file creation and never replaces an existing journal.
`open` requires an existing journal and never initializes an empty, partial, or
unrecognized file.

## File header

Every journal begins with these exact 24 ASCII bytes, including the final NUL:

```text
naome:proof-dag-journal\0
```

Hexadecimal:

```text
6e616f6d653a70726f6f662d6461672d6a6f75726e616c00
```

Any missing or different header byte is an unsupported or corrupt journal.

## Chained frame encoding

The header is followed by zero or more frames with no padding:

```text
payload_length     4-byte unsigned big-endian integer
canonical_payload  payload_length bytes
entry_digest       32 bytes
```

`payload_length` must be in `1..=CERTIFICATE_MAX_BYTES`. Impossible lengths
are rejected before payload allocation or reading. Checked offset arithmetic
precedes every frame read.

The initial previous digest is:

```text
SHA256("naome:proof-dag-journal-genesis\0")
```

For every frame, in physical order:

```text
entry_digest = SHA256(
    "naome:proof-dag-journal-entry\0"
    || previous_entry_digest[32]
    || payload_length_be[4]
    || canonical_payload[payload_length]
)
```

The stored `entry_digest` is both the chained integrity value and the commit
footer. A frame therefore adds exactly 36 bytes beyond its proof payload. For
frames whose boundary is located from an intact length field, the digest chain
detects byte corruption and deletion, duplication, or reordering inside a
journal unless the file is replaced by an independently valid older prefix as
described under limitations.

## Durable append

One public append processes exactly one caller-owned proof payload:

1. strictly admit the bytes through `ProofDag`, including decode,
   canonicality, mathematical checking, dependency resolution, and state
   registration;
2. write `payload_length || canonical_payload` at the current committed end;
3. call `sync_all` for that frame body;
4. write the chained `entry_digest` commit footer;
5. call `sync_all` again; and
6. only then acknowledge success and expose the retained record.

An admission error occurs before file mutation and leaves the handle healthy.
Any seek, write, or synchronization error after in-memory admission makes
durability ambiguous. The call returns no record, the handle becomes poisoned,
and every subsequent read or append fails. Dropping and reopening is the only
way to reconcile whether that frame reached durable storage.

The first synchronization barrier ensures that a complete footer can become
durable only after the corresponding body was synchronized. The second barrier
is required before success is acknowledged. `sync_all` expresses the portable
Rust file-content-and-metadata synchronization contract; it does not by itself
provide a portable guarantee that the parent directory entry survived power
loss. Directory provisioning durability is outside Journal.

## Open and deterministic recovery

After acquiring the lock, `open` validates the header and scans physical frames
from the first byte after it. For every complete frame it:

1. preflights the length and complete frame boundary;
2. recomputes and compares the chained digest; and
3. submits the payload to a fresh `ProofDag` through strict canonical-byte
   admission.

Replay never sorts, skips, repairs, or preloads later dependencies. The first
complete digest mismatch or proof-admission error fails closed and returns no
journal handle. Before a completely replayed visible image is exposed, `open`
calls `sync_all`. This stabilizes a complete footer that may still have been
visible only in the operating-system page cache after an earlier ambiguous
commit error. Failure to stabilize returns no handle.

If EOF occurs after the last committed frame but before a complete next commit
footer, the remaining bytes are one uncommitted append tail. `open` truncates
the file to the preceding committed boundary, synchronizes that truncation,
and only then returns the recovered prefix. A truncation or synchronization
error fails recovery.

## Crash and corruption boundary

Journal distinguishes a complete chained frame from an incomplete final
append. Without a separately durable trusted head, no self-contained append
file can also distinguish every damaged last-frame length or exact rollback to
an older valid frame boundary from a crash that left precisely that prefix.

Accordingly:

- an incomplete final frame is discarded as uncommitted;
- a structurally complete frame with a wrong digest or failed strict replay is
  corrupt and never discarded silently;
- an in-range damaged length at any frame boundary can make the entire
  remaining suffix indistinguishable from one incomplete append and may be
  truncated to the preceding committed boundary; and
- replacement or truncation to an independently valid older prefix is not
  authenticated until a future external state commitment or finalized
  checkpoint exists.

The journal protects deterministic local recovery under its crash/torn-append
model. It is not a malicious-filesystem authentication mechanism.

## Golden vectors

The genesis digest is:

```text
e1712a2358d91e869a2c3d865deccd7fc4f3557a8c7327febc470becd78684ab
```

The canonical one-step Pairing proof payload is six bytes:

```text
000000011001
```

Its first-frame digest is:

```text
31d98be3372c21576e6ff70b6796e965924ec358746f1efdd22c2dad1345c73a
```

The complete 42-byte first frame is:

```text
0000000600000001100131d98be3372c21576e6ff70b6796e965924ec358746f1efdd22c2dad1345c73a
```

The complete 66-byte one-entry journal is:

```text
6e616f6d653a70726f6f662d6461672d6a6f75726e616c000000000600000001100131d98be3372c21576e6ff70b6796e965924ec358746f1efdd22c2dad1345c73a
```
