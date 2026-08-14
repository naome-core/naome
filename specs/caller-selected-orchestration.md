# NAOME Caller-Selected Orchestration

## Authority and scope

This document defines bounded workflows built from the exact exchanges in
[Artifact Network Transport](artifact-network-transport.md). Every workflow
requires an explicit caller-selected peer set, chain context, or target block.
None groups matching observations into a quorum, ranks branches, chooses a
target, performs discovery, or establishes consensus or finality.

Workflows advance only when the caller routes an exact correlated
`NetworkEvent`. `accepts_event` is the non-consuming routing predicate.
Mismatches never inspect, reinterpret, or discard another workflow's event.
Cancellation is logical: retained values are released, while an already queued
libp2p request drains its peer slot and shared permit through the network event
loop.

## Head survey

A head survey sends one immutable `ArtifactChainHeadRequest` to one to eight
caller-selected peers and returns one source-bound outcome per peer in original
caller order.

Start is all-or-none. Before the first request it requires a nonempty peer list,
at most eight unique peers, every peer statically authorized, no peer request
already pending, every head exchange connected, and enough shared permits for
the complete set. Any failure queues nothing and consumes no permit.

Each matching terminal records exactly one of:

```text
peer -> Found(ArtifactBlockId)
peer -> Unavailable
peer -> TransportFailure
```

Failure of one peer neither cancels nor retries another. Completion preserves
the shared request and ordered rows. The workflow does not deduplicate equal
heads, prefer a majority, compare local ancestry, retrieve a block, or create a
negative cache. Dropping or cancelling leaves physical pending requests to
drain normally.

## Head broadcast

A head broadcast snapshots one healthy `ArtifactChainJournal` and sends the
same `ArtifactChainId || ArtifactBlockId` announcement to one to eight
caller-selected peers. It returns one source-bound receipt or failure per peer,
again in caller order, with no aggregate acceptance result.

Start validates the nonempty unique peer set, then reads the journal head. A
journal error, including poison, precedes peer and capacity checks. It next
preflights every peer and atomically acquires all required permits before
queueing. The immutable snapshot does not change if the journal advances later;
an empty journal announces virtual genesis.

Only the exact correlated `01` response is a receipt. A peer failure is retained
as that row's result and does not affect other rows. Receipt count is not a
quorum, freshness proof, availability proof, or consensus vote.

## Direct-child block import

One `ArtifactBlockImport` targets one exact `ArtifactBlockId` from one statically
authorized peer. It is the smallest network workflow permitted to mutate the
selected journal.

### Start and block phase

Start first reads the healthy journal head and chain context and checks the
committed block index. It rejects a target already equal to the current head,
virtual genesis, or another committed block. It then starts exactly one
addressed block request. The current root is read only after a matched block is
retrieved; no artifact request begins before that preflight succeeds.

The block terminal must match network instance, authenticated peer, protocol,
request generation, and target ID. Unavailable or transport failure is terminal.
The transport exposes a found block only after exact 128-byte decode and
`ArtifactBlockId` comparison.

Before any artifact traffic, import performs journal read-only validation of the
block's parent and roots without payload bytes:

1. target identity already matched during block exchange;
2. parent must equal the current journal head;
3. previous root must equal the current `ArtifactSetRoot`;
4. the block's `ArtifactId` must not already be selected; and
5. projected insertion must equal the resulting root.

Failure is terminal and sends no artifact request.

### Artifact phase and commit

After preflight, import requests only the block's one `ArtifactId`. It tries the
block peer first and then other configured peers in deterministic raw-peer-ID
order, at most once each, one request at a time. Disconnected or busy peers are
skipped. Correlated transport failure or unavailable may rotate while the
single 120-second absolute deadline remains unchanged.

A found response remains opaque. The workflow passes the exact bytes and
retained block directly to `ArtifactChainJournal::apply_block`. That operation
repeats complete block preflight, decodes the proof-or-definition tag, requires
canonical typed bytes, checks mathematics and all selected-prior dependencies,
derives and compares `ArtifactId`, registers, and durably appends. Success is
reported only after the journal acknowledges its commit.

Malformed bytes, noncanonical proof, invalid definition, missing proof or
definition dependency, wrong identity, stale state, or journal failure is
terminal and never causes peer fallback. The importer does not inspect or fetch
dependencies. An ordinary failure for the current block performs no mutation;
an ambiguous commit follows the journal's poison and reopen boundary.

Expiry or explicit cancellation releases any quarantined payload and tombstones
the in-flight attempt. The eventual physical terminal drains without exposing
bytes or advancing import. Dropping the workflow has the same logical
cancellation behavior.

## Bounded ancestry pull

An `ArtifactBlockAncestryPull` retrieves a structural path from one exact
caller-selected target back to the selected journal head snapshotted at start.
It uses one authenticated peer, requests one exact block at a time, retains at
most 16 blocks, acquires no artifact payload, and never mutates selected state.

Start reads the healthy head and root, rejects a target already in selected
context, snapshots the virtual genesis, and requests the target. Each matched
found block has already passed block-ID correlation. Before requesting its
parent, the pull:

- requires the journal head still to equal the anchor snapshot;
- requires the received block's resulting root to equal its retained child's
  previous root, when a child exists;
- completes only when the parent equals the anchor and the first block's
  previous root equals the anchor root;
- rejects a repeated target or parent identity;
- rejects encountering virtual genesis or an already selected block other than
  the exact anchor as divergent ancestry; and
- rejects the need for a seventeenth retained block.

On completion, blocks are returned in forward application order from the
anchor's direct child through the target. The result proves only content-address
and structural parent/root continuity from one authenticated source. It proves
no payload availability, artifact validity, selected ancestry, or finality.
Any failure releases retained blocks and changes no journal state.

## Sequential ancestry import

`ArtifactBlockAncestryImport` consumes one completed unselected ancestry so the
same retained vector cannot be reused concurrently. It does not re-request
blocks. It preflights the first retained block against the then-current journal,
then uses the direct import artifact phase for each block in forward order.

Exactly one artifact request is active. A block must commit durably before the
next retained block starts. After each acknowledged commit the workflow records:

```text
committed_block_count
last_acknowledged_head_block_id
```

Later failure does not roll back the acknowledged prefix. The returned error
identifies the overall target, failed block, prior acknowledged count and head,
and exact direct-import source. An ambiguous journal commit is deliberately not
counted as acknowledged; recovery requires journal reopen. Cancellation drops
unprocessed blocks and never rolls back the committed prefix.

## Composed catch-up

`ArtifactBlockCatchUp` composes exactly one ancestry pull followed by exactly
one ancestry import for the same caller-selected peer and target. Pull failure
occurs before any catch-up commit. Once pull completes, the workflow consumes
its result and starts sequential import; it performs no new selection or target
ranking between phases.

Progress exposes the active phase, pending block, pending peer, acknowledged
block count, and last acknowledged head. During artifact fallback the pending
peer may differ from the ancestry source. Completion means the exact target was
durably acknowledged by the journal. A catch-up error preserves whether it came
from retrieval or import and, for import, the exact committed-prefix metadata.

The 16-block bound makes catch-up intentionally partial. A caller may choose a
new explicit target or another bounded workflow afterward, but no workflow
automatically continues, reorganizes, or selects a competing history.

## Trust boundary

Authenticated sources prevent peer-ID substitution; exact tickets prevent
cross-request substitution; block hashes bind returned bytes; root continuity
detects structural discontinuity; strict journal application enforces the
mathematical and selected-dependency contract. None of these mechanisms decides
which peer or branch should be trusted.

A candidate store may retain retrieved blocks but cannot promote them. A payload
archive may retain accepted bytes but cannot resolve them. A head, receipt,
continuous ancestry, successful read-only validation, or downloaded artifact
does not become selected until the caller explicitly drives strict journal
application. These workflows define no discovery, quorum, fork choice,
reorganization, rollback, consensus, finality, incentives, or economics.
