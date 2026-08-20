# NAOME Caller-Selected Orchestration

## Authority and scope

This document defines bounded workflows built from the exact exchanges in
[Artifact Network Transport](artifact-network-transport.md). Every workflow
requires an explicit caller-selected peer set, chain context, or target block.
None groups matching observations into a quorum, ranks branches, chooses a
target, performs discovery, or establishes consensus or finality.

Workflows advance only when the caller routes an exact correlated
`NetworkEvent`. `accepts_event` is the non-consuming routing predicate.
The caller retains an event when that predicate is false and must not pass it
to the consuming `on_event`; doing so is a caller routing error that may end the
workflow. Lower-level mismatch APIs that accept both routable values return
both unchanged.
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

## Durable candidate-store ancestry fill

`StaticArtifactNetwork::start_artifact_block_candidate_ancestry_fill` accepts
one exact target, one caller-routed chain-scoped
`ArtifactBlockCandidateStore`, the selected journal, and one caller-supplied
peer identity used only if an exact candidate address is missing. The returned
`ArtifactBlockCandidateAncestryFill` exclusively borrows that exact store for
its lifetime, so one fill cannot silently assemble a completion claim across
substituted same-chain stores.

Start compares the store and journal `ArtifactChainId` values before any health
or disk read. It then reads the selected head, rejects a target already equal to
the head, virtual genesis, or another committed block, and snapshots the
selected artifact-set root. Beginning at the target, it integrity-reads each
already retained exact candidate and applies the shared ancestry checks in
order: child/root continuity; anchor/root completion; repeated parent;
divergent virtual-genesis or other selected history, including a typed
selected-state read failure; and the need for a seventeenth block. Retained
blocks are never requested again. The first missing exact address starts one
request to the caller-supplied peer; only that request start applies the
existing configured-peer and Noise-authenticated transport checks. A fully
retained path completes without opening a request or inspecting that peer.

`ArtifactBlockCandidateAncestryFill::on_event` accepts only the exact correlated
terminal from the network instance that owns the active request. A transport
failure or `Unavailable` response inserts nothing. For a found identity-matched
block, the workflow first requires the selected head still to equal its captured
anchor, then applies the shared ancestry checks, durably inserts the block, and
only after the store acknowledges that insertion scans or requests its parent.
It continues with at most one active request until another error or completion.
If that subsequent retained scan or parent-request start fails, the already
acknowledged insertion remains durable.

`ArtifactBlockCandidateAncestryFillProgress` is an allocation-free `Option`
alias. `Some(fill)` retains the store borrow and exactly one active
missing-block request. `None` is the sole completion observation and exposes no
anchor, target, or retained-count fields. It means only that every block in the
bounded continuous path for the caller's exact target was integrity-read from
or durably acknowledged by the same store. It does not mean that any committed
artifact payload is available or valid.

An ordinary later failure or explicit cancellation preserves every earlier
acknowledged insertion. A new explicit caller start may therefore skip that
retained target-side prefix and, while the retained continuation remains
readable and shape-valid, resume at the first missing address, possibly with
another caller-selected configured peer. This is durable partial progress, not
automatic retry or scheduling. Candidate read failures and ambiguous insert
failures retain the store's typed poison-and-reopen boundary. The fill never
requests an artifact payload, mutates the journal, imports or promotes a
candidate, records peer provenance, chooses a target, peer, chain, store,
journal, or branch, relays or gossips, or establishes artifact validity,
payload availability, rollback, reorganization, consensus, or finality.

### Caller-ordered fallback fill

`StaticArtifactNetwork::start_artifact_block_candidate_ancestry_fill_with_peer_fallback`
is a separate opt-in mode. It accepts the same exact target, candidate store,
and selected journal plus one caller-ordered peer-identity slice. The direct
single-peer start above keeps its no-retry behavior unchanged.

Retained candidates are read and shape-checked before the fallback slice is
inspected. A fully retained path therefore completes without validating or
using any fallback peer. Only at the first missing exact address does the mode
reject an empty slice or one longer than `MAX_STATIC_PEERS`, then the lowest raw
duplicate `PeerId`, then the lowest raw `PeerId` absent from the network's
static configuration. A valid slice keeps the caller's exact order; it is not
sorted for execution.

For each missing address, the mode tries every listed peer at most once and
keeps at most one block request active. An `AlreadyPending` or
`PeerDisconnected` start is skipped. Any other request-start error is
terminal. Each started attempt retains the existing 30-second transport
request timeout; there is no new aggregate fallback deadline. A matched
transport failure, `InvalidResponse`, or authenticated `Unavailable` response
may advance to the next caller-ordered peer. `PeerMismatch`, an unmatched
event, or an event from another network instance is terminal and never rotates.
If every listed peer is skipped as busy or disconnected before any request
starts, the mode reports no requestable listed peer. If a matched retryable
terminal has already occurred and every later peer is skipped, that last
terminal remains the exact error.

A found identity-matched block ends fallback for that address. The captured
selected head is rechecked, the shared ancestry shape checks run, and the store
must durably acknowledge the block before the full caller-ordered attempt set
is reset for a missing parent. Head, shape, candidate-read, and candidate-insert
errors are terminal. An error after an acknowledged insertion preserves that
insertion exactly as in the direct fill. The fallback records no peer
provenance, requests no artifact payload, mutates no journal, promotes no
candidate, and establishes no peer trust, reachability, target or branch
selection, background retry schedule, network-wide availability, consensus,
finality, or economic authority.

### Direct candidate-payload validation and archive

`StaticArtifactNetwork::start_artifact_block_candidate_payload_fill` is a
separate caller-driven direct-peer workflow. The caller supplies one exact
target, one chain-scoped `ArtifactBlockCandidateStore`, one matching selected
journal, one Foundation-scoped `CanonicalArtifactPayloadStore`, and one peer
identity used only if the exact committed payload is absent from that archive.
The workflow does not choose any of those inputs.

Start rejects unequal candidate-store and journal `ArtifactChainId` values
before any health or disk read, then captures the selected head and rejects a
target equal to that head, virtual genesis, or another selected block. It next
integrity-reads the exact retained target block and requires its direct-parent,
previous-root, and resulting-root shape to match the captured selected state.
Only after those selected-context and candidate-shape checks does it
integrity-read the archive. An exact archive hit is fully revalidated against
that current journal through
`CanonicalArtifactPayloadStore::validate_and_insert_candidate_payload`; it
completes without inspecting peer configuration or opening a request. Archive
presence alone is never treated as current validity.

Only an archive miss validates the caller-supplied peer as statically
configured and connected and starts one request for the block's exact committed
`ArtifactId`. The request uses the existing Noise-authenticated session,
generation correlation, global pending-request bound, and absolute artifact
request deadline. It tries that peer once: there is no peer fallback, retry,
rotation, or aggregate workflow deadline.

The active fill accepts only its exact terminal from the network instance that
started it. Transport failure, deadline, `Unavailable`, invalid payload, peer
mismatch, or an unrelated event is typed and archives nothing. A found response
first requires the selected head still to equal the captured head and then
passes the owned bytes and retained block to
`CanonicalArtifactPayloadStore::validate_and_insert_candidate_payload`.
Completion occurs only after strict validation and a durable inserted or
idempotently confirmed archive outcome.

The candidate store is read-only apart from its existing integrity-read poison
semantics, and the selected journal is never mutated. Previously acknowledged
archive entries survive later ordinary failure; an ambiguous archive write
retains the archive's poison-and-reopen boundary. The workflow requests no
block, exposes no accepted-record or reusable-validation token, does not import,
promote, select, rank, replace, refresh, or delete a candidate, records no peer
provenance, starts no background task, and establishes no continued artifact
validity, chain membership, network-wide availability, consensus, finality, or
economic authority.

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

### Candidate-store start

`StaticArtifactNetwork::start_artifact_block_candidate_ancestry_import`
accepts one exact target, one caller-routed `ArtifactBlockCandidateStore`, the
selected journal, and one caller-preferred configured artifact-payload peer. It
compares the store and journal `ArtifactChainId` values before any health or disk
read. It then reads the selected head, rejects a target already equal to the
head, virtual genesis, or another committed block, and snapshots the selected
artifact-set root.

Starting at the target, the method integrity-reads one exact candidate address
at a time. A store error or missing address precedes shape checks for that
block. The shared bounded ancestry checks then apply in order: child/root
continuity; anchor/root completion; repeated parent; divergent virtual-genesis
or other selected history, including a typed selected-state read failure; and
the need for a seventeenth block. Completion reverses the retained path into
forward order and issues no block request.

The complete path enters the same strict sequential import with the
caller-preferred peer, existing deterministic configured-peer fallback, and a
fresh absolute deadline for each block's committed artifact request. Candidate
reads and successful imports never insert, replace, refresh, mark, or delete an
entry; an integrity failure retains the store's existing poison-and-reopen
contract. The preferred or fallback payload peer is not candidate provenance.
Only this explicit caller start can lead to journal application, with the
existing acknowledged-prefix and ambiguous-commit semantics.

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
