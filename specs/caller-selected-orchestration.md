# NAOME Caller-Selected Orchestration

## Authority and scope

This document defines bounded workflows built from the exact exchanges in
[Artifact Network Transport](artifact-network-transport.md). Every workflow
requires an explicit caller-selected peer set, chain context, or target block.
None groups matching observations into a quorum, ranks branches, chooses a
target, performs discovery, or establishes consensus or finality.

The durable candidate ancestry-fill and candidate-branch payload-fill
workflows accept the sealed read-only `SelectedArtifactHistory` capability. The
storage crate supplies it only for `ArtifactChainJournal` and
`FixedValidatorFinalityJournalV0`; peer or candidate state cannot implement it.
Its immutable `ArtifactChainId` permits mismatch rejection before an operable
selected-state read, while head, root, and exact-position snapshot access remain
subject to the source's health rules. For a finality journal, every such
position is one local fixed-validator V0 finalized artifact snapshot. A reopened
source is operable only after exact replay equals the caller's separately
trusted journal-state ID; neither a live created handle nor a verified reopen is
a global-finality or peer-truth statement.

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
`ArtifactBlockCandidateStore`, one selected-artifact history source, and one
caller-supplied peer identity used only if an exact candidate address is
missing. The returned
`ArtifactBlockCandidateAncestryFill` exclusively borrows that exact store for
its lifetime, so one fill cannot silently assemble a completion claim across
substituted same-chain stores.

Start compares the store and source's immutable `ArtifactChainId` values before
an operable selected-state health check or candidate-store disk read. It then
reads the selected head, rejects a target already equal to the head, virtual
genesis, or another selected block, and snapshots the selected artifact-set
root. A poisoned or terminally halted finality history therefore fails before
candidate reads or peer inspection. Beginning at the target, the workflow integrity-reads each
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
requests an artifact payload, mutates the selected-history owner, imports or
promotes a candidate, records peer provenance, chooses a target, peer, chain,
store, history source, or branch, relays or gossips, or establishes artifact
validity, payload availability, rollback, reorganization, consensus, or
finality.

### Caller-ordered fallback fill

`StaticArtifactNetwork::start_artifact_block_candidate_ancestry_fill_with_peer_fallback`
is a separate opt-in mode. It accepts the same exact target, candidate store,
and selected-artifact history source plus one caller-ordered peer-identity
slice. The direct single-peer start above keeps its no-retry behavior unchanged.

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
provenance, requests no artifact payload, mutates no selected-history owner,
promotes no candidate, and establishes no peer trust, reachability, target or
branch selection, background retry schedule, network-wide availability,
consensus, finality, or economic authority.

### Explicit historical selected-anchor fill

`StaticArtifactNetwork::start_artifact_block_candidate_ancestry_fill_from_selected_anchor`
is a separate direct-peer mode for recovering a candidate path to one exact
caller-selected historical position in selected-artifact history. The caller
supplies the exact candidate target, exact selected anchor, matching
chain-scoped candidate store and history source, and one peer identity used only
when an exact candidate address is absent. The anchor may be virtual genesis or
any retained selected block; it need not be the current selected head. With a
joint journal it is a caller-chosen local finalized artifact position, not a
consensus fork-choice or global-finality decision.

Start compares candidate-store and immutable history-source chain IDs before
operable history health or candidate-store disk reads, then obtains the anchor's
immutable replay-built snapshot through
`SelectedArtifactHistory::selected_branch_snapshot_at`. An unknown,
candidate-only, other-chain, or otherwise unretained anchor is terminal. The
snapshot supplies the exact anchor `ArtifactSetRoot`; the mode never substitutes
the current head or another selected position. A later selected-head advance
does not invalidate or retarget this historical anchor.

Beginning at the target, the mode applies the ordinary candidate ancestry
integrity and shape checks while walking backward toward that exact anchor. It
rejects a selected target, a repeated address, broken child/root continuity,
encountering virtual genesis or any retained selected block other than the
exact anchor, and a path requiring more than the existing fixed maximum of 16
candidate blocks. Already retained candidates are never requested again. The
direct peer remains uninspected until the first missing exact block address, so
a fully retained path completes without validating or using that peer.

At a miss, the mode starts at most one generation-bound request to the supplied
statically configured Noise-authenticated peer. A found identity-matching block
must pass the captured anchor and retained-child shape checks and be durably
inserted before the mode scans or requests its parent. A transport failure,
`Unavailable`, request-start failure, mismatched event, shape error,
candidate-store error, or newly encountered different selected position is
terminal. Every earlier acknowledged insertion remains durable, permitting a
fresh explicit restart to skip that retained prefix. Completion exposes only
that one continuous structural path to the exact anchor is integrity-readable
from the same candidate store; it proves no payload availability or artifact
validity.

`StaticArtifactNetwork::start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback`
is the corresponding opt-in caller-ordered fallback. It preserves the direct
mode unchanged and reuses the ordinary fallback fill's lazy peer-slice
validation, exact caller order, per-address attempt reset, one-active-request
bound, retryable-terminal classification, and durable insertion boundary. The
block-peer slice is inspected only at the first store miss. It is independent
of any payload-peer identity or order the caller may later supply.

After block completion, the caller may explicitly start the existing
candidate-branch payload fill against the target, stores, selected-artifact
history source, and a separately chosen direct payload peer or caller-ordered
payload-peer slice. That second start repeats its own complete selected-context,
retained-path, archive, and strict artifact-validation checks. There is no
combined coordinator, automatic phase transition, shared peer provenance, or
atomic claim spanning the two workflows. In particular, block-fill completion
cannot be reused as a payload-validation token and does not freeze the selected
context for a later payload start.

Both explicit-anchor modes leave the selected-history owner read-only and never
request an artifact payload, import, promote, select, rank, persist an executed
branch, reorganize, roll back, define retention or trust policy, or establish
consensus, global finality, or economic authority. A finality journal advances
only through its separate `commit_verified` boundary.

### Explicit canonical-payload-archive serving

`StaticArtifactNetwork::respond_artifact_from_payload_store` is a standalone
caller-routed response call. The caller supplies one exact statically authorized
Noise-authenticated inbound artifact request from one peer and one
Foundation-scoped `CanonicalArtifactPayloadStore`. The request contains only
its `ArtifactId` and does not identify a chain, branch, selected journal,
candidate block, or archive. Invoking the method is the caller's explicit
choice of that archive for that one request.

The responder first uses `contains` to require a healthy archive and determine
whether the exact address is indexed without reading payload bytes. It then
requires the response channel to remain open and consumes one token from the
same bounded inbound response bucket used by journal and candidate-block
serving. Only an indexed hit proceeds to `get` for a complete integrity read
and owned payload. A hit submits those exact tagged canonical bytes; a miss
submits `Unavailable`. A closed channel or exhausted bucket therefore performs
no artifact-sized archive read or allocation. A later `get` error remains a
typed payload-store failure, may poison the handle, and submits no response.

Serving is not candidate validation. The archive records no branch context,
and the returned bytes remain opaque until the receiver strictly validates
them against its own exact target ancestry. Because the archive retains no
source provenance, explicit caller routing may retransmit exact bytes that this
node learned elsewhere; the responder chooses neither their original source nor
the requesting recipient and defines no automatic relay admission, eviction,
recipient-selection policy, or relay task. It does not inspect or fall back to
the selected journal, choose between selected and archived bytes, serve a
candidate block, start a service loop, retry, import, promote, select, rank, or
establish validity, peer trust, global availability, consensus, finality, or
economic authority. The existing journal responder remains selected-only.

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

### Restartable candidate-branch payload recovery

`StaticArtifactNetwork::start_artifact_block_candidate_branch_payload_fill`
extends the direct archive workflow to one fully retained candidate ancestry.
The caller supplies one exact target, one caller-routed chain-scoped
`ArtifactBlockCandidateStore`, one matching selected-artifact history source,
one Foundation-scoped `CanonicalArtifactPayloadStore`, one peer identity used
only at an archive miss, and positive caller-local
`CandidateBranchReconstructionLimits`. The workflow chooses none of them. The
limit bounds this one reconstruction attempt only; it does not create a
protocol branch-depth, retention, or verification-work rule.

Start first delegates to the storage reconstruction cursor. Candidate-store and
immutable selected-history chain context are compared before operable history
health or store disk reads, and the complete retained block path is
integrity-read and structurally checked back to its nearest selected ancestor
before any payload request or archive write. A poisoned or terminally halted
finality history and an exceeded reconstruction limit therefore fail before
payload-peer inspection or archive mutation. A missing block is terminal and is
never requested by this workflow. The caller may first run the separate
candidate-ancestry fill and then explicitly restart.

The reconstruction cursor advances forward from its owned immutable snapshot.
Every exact archive hit is integrity-read and fully revalidated read-only
without inspecting peer configuration or opening a request. Only an archive
miss validates and uses the caller's exact peer identity to request the pending
block's committed `ArtifactId`, under the existing configured-peer,
Noise-authenticated generation-correlation, global-permit, and absolute
artifact-request-deadline checks. At most one request is active. Each missing
address tries that peer once: there is no fallback, retry, rotation, or
aggregate workflow deadline.

The active fill consumes only its exact correlated terminal from the network
instance that started it. Transport failure, deadline, `Unavailable`, invalid
payload, peer mismatch, and unrelated events remain typed. A found owned
payload is passed directly to the reconstruction cursor's strict branch
validation-and-archive gate. The archive must durably insert or idempotently
confirm the exact bytes before the cursor may validate archive hits or request
the next missing address.

The cursor retains its captured historical snapshot, so selected-head
advancement while a request is active neither aborts nor retargets the
workflow. Completion still means only that the caller's original target and
entire retained ancestry validated against that captured selected ancestor; it
does not claim that the target remains unselected or currently preferred.
Completion returns the full `ReconstructedCandidateBranch` only after every
child validates. No failure exposes a partial snapshot.

Every acknowledged archive entry remains durable after a later ordinary
failure or request-start error. A fresh explicit start integrity-reads and
revalidates those hits and can resume at the next archive miss if the target is
still reconstructable in the new selected context. An ambiguous archive write
retains the archive's poison-and-reopen boundary. The workflow never requests
an absent block, mutates the candidate store or selected-history owner,
persists a branch snapshot, imports, promotes, selects, ranks, reorganizes, or
rolls back a branch, records peer provenance, chooses a target or peer, starts
background work, or establishes global availability, peer trust, consensus
ancestry, consensus, global finality, economics, or protocol-wide resource
authority. A finality journal remains read-only and advances only through its
separate `commit_verified` boundary; acknowledged payload-archive writes are
not one cross-store transaction with that journal or the candidate store.

### Caller-ordered candidate-branch payload fallback

`StaticArtifactNetwork::start_artifact_block_candidate_branch_payload_fill_with_peer_fallback`
is a separate opt-in mode. It accepts the same exact target, caller-routed
stores and selected-artifact history source, and positive local reconstruction
limit as the direct mode, plus one caller-ordered payload-peer slice. The direct
single-peer API and its no-fallback behavior remain unchanged.

The complete candidate-block path is integrity-read and structurally checked
before payload traffic exactly as in the direct mode. The reconstruction cursor
then integrity-reads and fully revalidates every archive hit before inspecting
the fallback slice. A fully archived branch therefore completes without
validating or using any fallback peer. Only at the first archive miss does the
mode reject an empty slice or one longer than `MAX_STATIC_PEERS`, then the
lowest raw duplicate `PeerId`, then the lowest raw `PeerId` absent from the
network's static configuration. A valid slice retains the caller's exact order;
it is not sorted for execution.

For each missing `ArtifactId`, the mode creates one fresh 120-second absolute
deadline shared by every attempt for that address, tries each listed peer at
most once, and keeps at most one request active. An `AlreadyPending` or
`PeerDisconnected` start is skipped. Any other request-start error is terminal.
A matched transport failure, including a framing or codec failure, or an
authenticated `Unavailable` response may advance to the next caller-ordered
peer. Deadline expiry, `PeerMismatch`, an unmatched event, or an event from
another network instance is terminal and never rotates. If every listed peer
is skipped before an attempt starts, the mode reports that no listed peer could
request the address. If a matched retryable terminal has already occurred and
all later peers are skipped, that last terminal remains the exact error.

A found response ends fallback for that address. Its owned opaque bytes pass
immediately to the same strict branch validation-and-archive gate as the direct
mode. Malformed or noncanonical bytes, identity, mathematical, dependency, or
novelty failure, and every reconstruction or archive error are terminal and do
not try another peer. Only a successful durable insertion or exact idempotent
confirmation permits the cursor to advance. The complete caller-ordered peer
set and a new per-address deadline are then reset for the next archive miss;
there is no aggregate branch deadline.

Every acknowledged archive entry survives a later ordinary failure. A fresh
explicit caller start revalidates that durable prefix and can resume at the next
miss. The fallback records no peer provenance and defines no automatic retry,
resume, scheduling, or background task. It does not fetch an absent candidate
block, mutate the candidate store or selected-history owner, persist, import,
promote, select, rank, reorganize, or roll back a branch, choose the target or
peer order, or establish peer trust, reachability, global availability,
consensus ancestry, consensus, finality, economics, or protocol-wide resource
authority.

### Explicit fixed-validator acquisition-to-vote composition

One optional caller-owned fixed-validator V0 composition may use the anchored
finality journal exposed read-only by a live node signing scope as the
`SelectedArtifactHistory` input to the existing candidate-ancestry and
candidate-branch payload fills. The caller supplies one exact unselected target,
complete proposal-control bytes, matching chain-scoped candidate and
Foundation-scoped payload stores, positive reconstruction limits, and one exact
statically configured Noise-authenticated peer for each direct fill. The caller
owns the Tokio runtime, drives both network event loops, routes only exact
correlated terminals, and explicitly starts each phase. The composition defines
no background task, daemon, automatic phase transition, retry, delivery
acknowledgement, peer selection, or target selection.

The ancestry fill must complete before the payload fill starts. Its durable
candidate insertion establishes only an unselected structural path and is not a
payload-validation token. The payload fill therefore repeats its own selected-
history, candidate-path, archive, and strict artifact validation and completes
only after every required payload is durably inserted or idempotently confirmed.
Neither fill mutates the selected-finality owner. A peer session and a successful
response authenticate only the immediate transport endpoint and exact correlated
exchange; they establish no provenance, truth, validity, selection, availability,
consensus, or finality authority.

Voting follows the [exact input admission](fixed-validator-node-voting-v0.md#exact-round-and-input-admission)
and [ordered execution](fixed-validator-node-voting-v0.md#ordered-vote-execution)
contracts. Candidate-unavailable and payload-unavailable remain typed rejections
with the unchanged signing scope; invalid proposal control releases no signature.
Even after both fills, each vote operation integrity-reads its exact sources and
repeats complete proposal, producer, artifact, lock-effect, and applicable
caller-routed prevote-batch verification before any signer write. Store presence
supplies no cached validity.

The Unix reference vector uses a one-validator fixed set, passes the exact
anchored prevote it just received as the complete precommit batch, and proves
that successful voting changes only the signer journal-and-anchor pair. Both
caller-routed source stores and the finality journal-and-anchor pair remain
byte-identical during voting, the acquired stores reopen with the exact target
and payload, and strict node restart recovers the completed Precommit state.
This is local two-peer transport evidence for one explicit library composition,
not production liveness or a two-validator consensus claim.

This composition does not acquire or route proposal-control or vote messages,
observe its own returned vote automatically, select a consensus event or branch,
advance or roll back finality, import or promote the candidate, provide
cross-store atomicity, define operation-bearing blocks, integrate dynamic
validators, or choose timeout, scheduling, custody, key-loading, retry, or
production-runtime policy. Those remain separate component and product
boundaries.

### Driver-held selected-history composition

The composition uses the driver's sealed read-only `selected_artifact_history`
projection under the [driver lifecycle contract](fixed-validator-node-driver-v0.md#construction-and-process-local-lifecycle),
retaining that shared borrow across both direct fills and releasing it before
consuming the driver. The projection exposes no raw scope, branch, signing
session, concrete journal, or mutable handle; lower-level progress values retain
no history borrow and acquire no driver-lifecycle authority. The driver starts
no network work, chooses no target or peer, and mutates neither source store.

After both fills, the caller integrity-reads the exact target and archived
payload and submits raw `CurrentRoundProposal` inputs with separately supplied
complete control bytes. [Event admission](fixed-validator-node-driver-v0.md#consuming-event-admission-and-bounded-retention)
and [step execution](fixed-validator-node-driver-v0.md#deterministic-step-selection)
fully reverify them; tampering returns a rejected event without a signer write.
The ordinary anchored prevote publication and separately pending arm must both
transfer before the caller explicitly re-admits that exact vote as
`CurrentRoundProposalPrevote` for the unchanged strict-supermajority precommit
path. Store membership and network arrival supply no admission token, and
publication performs no self-observation.

The Unix reference vector proves one caller-owned two-peer Noise session can
complete both fills while the driver retains signing ownership, that selected
finality and all source stores remain byte-identical throughout voting, and that
strict restart recovers only the completed Precommit signer state. It is not an
automatic acquisition loop, production runtime, multi-validator consensus, or
non-Unix claim. It adds no proposal or vote transport, self-delivery, scheduling,
retry, acknowledgement, peer or target selection, operation-bearing block, or
dynamic-validator policy.

### Driver-held historical-conflict acquisition composition

One separate explicit caller-owned composition may use the same live driver's
sealed `selected_artifact_history` borrow to acquire one exact sibling at an
already selected positive height. The caller chooses the exact retained
historical parent anchor, sibling target, configured block peer, configured
payload peer, candidate and Foundation payload stores, positive reconstruction
limit, complete proposal-control bytes, exact signed-precommit batch, evidence
round, and invocation time. The historical-anchor ancestry fill first obtains
only the exact structurally continuous candidate path to that replay-retained
anchor. The separately started branch-payload fill then captures the applicable
selected artifact snapshot and completely validates and archives every required
payload. Neither successful phase supplies a proposal, vote, validity, or
finality token to the next phase.

The shared selected-history borrow ends before driver consumption. After any
pending arm or vote-publication command transfers, the [driver terminal bridge](fixed-validator-node-driver-v0.md#explicit-candidate-backed-terminal-bridge)
applies the [candidate-backed finalized-sibling exact-batch contract](fixed-validator-node-finality-v0.md#candidate-backed-finalized-sibling-exact-batch-admission).
It integrity-reads the acquired target and payload and independently verifies
the complete proposal, producer, artifact transition, positioned fixed set, and
strict-supermajority batch against the replay-retained parent before either
anchored stop. Success returns only their exact paired terminal evidence, with
no driver, signing scope, selected branch, or winner.

Candidate acquisition may durably add exact entries only to the caller-routed
candidate store, and payload reconstruction may durably add exact validated
entries only to the caller-routed archive. The later terminal attempt changes
neither completed source image. A malformed or insufficient terminal batch
after successful acquisition grants no finality or signer effect, consumes the
driver under its existing terminal-call contract, and leaves strict anchored
restart as the only continuation classifier. The two fills are not one atomic
operation with each other or with either authority pair.

The authenticated immediate peer, correlated response, caller-selected target
and anchor, network completion, and store presence establish no provenance,
truth, availability, cached validity, preference, selection, rollback, or
finality authority. This composition adds no automatic target, anchor, peer,
proposal, or vote acquisition; fallback or retry policy; consensus-message
transport; inbox or durable acquisition intent; background scheduling,
acknowledgement, daemon, or production runtime; dynamic validators; repair; or
cross-store atomicity. Its Unix two-peer reference vector is local library
runtime evidence only, not production liveness, multi-validator consensus, or a
non-Unix guarantee.

### Driver-held direct-child finality acquisition composition

One explicit caller-owned composition may borrow the live driver's sealed
selected-artifact history to fill one exact caller-selected direct-child
candidate against the current selected head, then separately acquire and
validate its payload. The caller chooses the target, configured peer, stores,
positive reconstruction limit, complete proposal-control bytes, exact
signed-precommit batch, evidence round, and invocation time. Candidate and
payload acquisition may add only the corresponding source entries and cannot
advance either anchored authority pair.

After both fills and the shared history borrow end, separately supplied
consensus evidence enters the [direct-child driver bridge](fixed-validator-node-driver-v0.md#explicit-candidate-backed-direct-child-bridge).
Pending outward commands transfer first; every non-fallthrough exact-current
finality classification returns the unchanged driver for `step`; only then do
generation preflight and complete independent live-branch verification begin.
Source entries may already be durable when a later gate declines.

The bridge preserves the unchanged driver on typed pre-effect rejection and
consumes fatal outcomes under strict reopen. Only a verified direct child
advances both anchored authority pairs, returns the aligned child driver with
volatile inbox custody, and queues its child round-zero Proposal arm. A changed
selected head invalidates reuse of the earlier acquisition snapshot. Success
and rejection leave source entries unchanged, apart from existing live-handle
poisoning on integrity failure.

This composition adds no automatic acquisition, retry, target or peer choice,
proposal or vote transport, evidence preference, cached validity, branch
selection, rollback, repair, cross-store atomicity, daemon scheduling, dynamic
validators, or production-runtime policy. Its Unix two-peer reference vectors
are local library integration and strict-reopen evidence, not production
liveness, multi-validator consensus, or non-Unix guarantees.

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

## Recovery-bundle unselected staging

An inbound recovery-bundle push remains opaque until its caller explicitly
acknowledges the stream. The source-aware acknowledgement preserves the exact
owned bytes and authenticated immediate source while sending only the existing
stream-acceptance receipt. The caller separately selects the expected source,
one exact retained selected anchor, one exact unselected target, a sealed
read-only selected history, matching candidate store, Foundation-scoped payload
archive, and destination-local bundle limits.

Staging rejects a source mismatch before bundle or store access. Otherwise it
strictly re-decodes and completely validates the caller-selected bundle against
the retained selected anchor and any exact selected prefix, then preflights
both destination stores before writing. It retains only the non-selected suffix,
first as structural candidate blocks and then as strictly validated canonical
payloads. Candidate and payload stores have separate acknowledged prefixes;
there is no cross-store transaction, rollback, or implicit resume. A fresh
explicit retry after reopen repeats the entire preflight and idempotently
accepts only exact durable entries.

Neither acknowledgement nor staging chooses the source, anchor, target, stores,
limits, candidate, or branch. The transport source is not durable provenance,
the stream receipt does not attest decoding or storage, and no step mutates
selected history, promotes a candidate, persists caller intent, schedules a
retry, or starts background work.

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
