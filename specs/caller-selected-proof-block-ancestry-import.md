# NAOME Caller-Selected Proof Block Ancestry Import

## Status and scope

This document defines one bounded, caller-driven forward import of a completed
[`UnselectedProofBlockAncestry`](caller-selected-proof-block-ancestry-pull.md)
into the current selected [`ProofChainJournal`](proof-chain-journal.md). It is a
prerelease orchestration contract and may change before the first stable
protocol release.

The caller first chooses an exact target and obtains a structurally continuous
path through the separate caller-selected ancestry pull. This import consumes
that opaque result without fetching any block again. It processes the retained
blocks in forward order, from the captured anchor's direct child through the
exact caller-selected target. For each block it reuses the existing bounded
proof-dependency acquisition and the journal's sole strict block-application
path.

This is a bounded, explicit import, not synchronization or consensus. A peer
cannot choose the ancestry target, start the import, change the block order, or
select a replacement after failure. Authentication identifies the peer that
supplied the retained path and the peers serving proof payloads; it does not
establish mathematical validity, network selection, consensus, or finality.

The import defines no new wire message, protocol identifier, libp2p behaviour,
connection, peer authorization, storage format, dependency, or migration. It
adds no ancestry-wide rollback mechanism or transaction.

## Public surface

The public Rust surface is equivalent to:

```text
StaticProofNetwork::start_proof_block_ancestry_import(
    &mut self,
    selected: &ProofChainJournal,
    ancestry: UnselectedProofBlockAncestry,
) -> Result<ProofBlockAncestryImport, ProofBlockAncestryImportError>

ProofBlockAncestryImport::anchor_block_id(&self) -> ProofBlockId
ProofBlockAncestryImport::target_block_id(&self) -> ProofBlockId
ProofBlockAncestryImport::committed_block_count(&self) -> usize
ProofBlockAncestryImport::last_acknowledged_head_block_id(&self) -> ProofBlockId
ProofBlockAncestryImport::pending_block_id(&self) -> ProofBlockId
ProofBlockAncestryImport::pending_peer_id(&self) -> PeerId
ProofBlockAncestryImport::accepts_event(&self, event: &NetworkEvent) -> bool
ProofBlockAncestryImport::cancel(self)
ProofBlockAncestryImport::on_event(
    self,
    network: &mut StaticProofNetwork,
    selected: &mut ProofChainJournal,
    event: NetworkEvent,
) -> Result<ProofBlockAncestryImportProgress, ProofBlockAncestryImportError>

type ProofBlockAncestryImportProgress = Option<ProofBlockAncestryImport>

ProofBlockAncestryImportError::committed_block_count(&self) -> usize
ProofBlockAncestryImportError::target_block_id(&self) -> ProofBlockId
ProofBlockAncestryImportError::last_acknowledged_head_block_id(&self) -> ProofBlockId
ProofBlockAncestryImportError::failed_block_id(&self) -> ProofBlockId
ProofBlockAncestryImportError::block_import_error(&self) -> &ProofBlockImportError
```

`ProofBlockAncestryImport` is non-cloneable and privately owns:

- the immutable anchor and target block identities from the consumed ancestry;
- the authenticated ancestry-source peer;
- zero or more not-yet-started retained blocks in exact forward order;
- the exact block currently undergoing proof acquisition;
- one existing direct-child proof-block import continuation; and
- the count and exact head of the durably acknowledged prefix.

The workflow exposes no retained block vector, block bytes, proof bytes,
addressed candidates, request identifier, permit, or replacement target.
`pending_block_id` is the exact retained block currently being imported.
`pending_peer_id` is the peer serving the current dependency request and may
change only under the existing bounded proof-peer fallback policy.

`accepts_event` accepts only the exact generation-safe `OutboundProof` terminal
awaited by the current proof acquisition. An ancestry import never accepts an
`OutboundBlock` event because every block was already retrieved and matched by
the consumed ancestry. `on_event` consumes both the continuation and its exact
event. `Some(import)` is the only continuation; `None` means the original
caller-selected target has been durably acknowledged as the journal head.

## Starting an import

Starting consumes the complete `UnselectedProofBlockAncestry` and performs
these checks and actions in order:

1. retain its immutable anchor, target, source peer, and forward-ordered block
   vector without cloning block contents;
2. select the first retained block, which the ancestry contract already binds
   as that anchor's direct child;
3. delegate to the existing direct-child context preflight, whose current-head
   comparison therefore requires the healthy journal head to equal the retained
   anchor; and
4. start the existing bounded proof-dependency acquisition for that block's
   root proof, preferring the authenticated ancestry-source peer.

The consumed ancestry always contains between one and sixteen blocks. Its
target is the last retained block, so the implementation does not need an
empty-success state. The ancestry type is the authority for its construction
invariants; the importer does not duplicate canonical block decoding, identity
checking, reverse-to-forward ordering, repeated-parent detection, or adjacent
root-continuity checks. It nevertheless rechecks the first block against the
current journal because selected state may have advanced after retrieval.

The direct-child preflight requires current parent, previous proof-set root,
local transition preparation, and resulting proof-set root in the precedence
defined by the existing
[Caller-Selected Proof Block Import](caller-selected-proof-block-import.md).
Starting performs no block request, journal write, state mutation, retry, dial,
head request, or target substitution.

Any start failure reports a committed count of zero, the retained anchor as the
last acknowledged head, the first block as the failed block, and the exact
nested direct-child import error. No continuation or proof candidate remains.

## Forward import and durable acknowledgement

The workflow delegates every accepted proof terminal to the current existing
direct-child import continuation. That continuation retains exact event,
network-instance, peer, request-generation, selected-parent, proof-acquisition,
strict application, and commit error precedence.

While one block's proof closure is incomplete, this workflow performs no
selected-state mutation; an independent caller may advance the journal, which
the active direct-child import rejects on its next correlated event. The
ancestry importer retains no proof-sized copy outside the underlying
acquisition. When the closure completes, it is consumed immediately through
`UnselectedProofClosure::apply_block`. The journal's normal strict application
remains the sole mutation and its successful return is the only durable
acknowledgement.

After one successful acknowledgement the importer:

1. increments the committed prefix count;
2. records the committed block ID as the exact last acknowledged head;
3. discards the completed block and proof-acquisition state;
4. if that block is the caller-selected target, returns `None` without starting
   more work; otherwise
5. takes the next retained block in forward order, preflights it against the
   now-advanced journal, and starts its proof acquisition.

There is never more than one block's proof closure in memory. Starting block
`n + 1` occurs only after block `n` returned from the journal's durable commit.
No later block is preflighted or applied, and no proof payload for it is
requested or decoded, while an earlier block remains unacknowledged. The
retained blocks themselves were already decoded by the completed ancestry pull.

The completed path's parent and transition-root continuity makes each retained
successor structurally suitable for the preceding fetched block. It does not
replace the per-block current-state preflight or final strict application.
Mathematical proof checking and exact payload correlation therefore still occur
for every block against the state produced by the complete acknowledged
prefix.

## Committed-prefix semantics

The workflow deliberately provides forward-only committed-prefix semantics,
not ancestry-wide atomicity. The journal offers one atomic append at a time and
has no rollback, fork store, or multi-entry transaction. Pretending that up to
sixteen separate synchronization barriers form one transaction would make the
API's failure semantics false.

If block `n` fails after `n - 1` successful acknowledgements:

- blocks `1..n - 1` remain selected and durable;
- the error reports `n - 1` as its committed block count;
- the error reports block `n - 1`, or the original anchor when `n == 1`, as its
  last acknowledged head;
- the error reports block `n` as the exact failed block; and
- the nested direct-child error preserves the concrete context, request,
  proof-acquisition, validation, or journal failure.

The importer never automatically pulls a replacement ancestry or resumes the
old path. Retrying requires the caller to observe the acknowledged journal
head, explicitly choose a target again, and perform a fresh ancestry pull
anchored to that new head. This makes the new caller decision and new network
evidence explicit.

An ambiguous journal commit error is terminal even though the error's prefix
metadata contains only previously acknowledged blocks. The failing block may
or may not be durable, the journal handle is poisoned, and the importer must
not guess, continue, retry, or start the next block. Dropping and reopening the
journal is the existing recovery boundary; replay then determines the exact
old-or-new durable head.

## Error ownership and precedence

`ProofBlockAncestryImportError` is an owned fail-closed wrapper struct around
one `ProofBlockImportError`. It always carries:

```text
committed_block_count
last_acknowledged_head_block_id
target_block_id
failed_block_id
block_import_error
```

For the first block, the committed count is zero and the acknowledged head is
the ancestry anchor. For any later block, those fields describe exactly the
prefix already acknowledged before that block began. The wrapper does not
classify an ambiguous failing commit as acknowledged.

At start and after each acknowledged block, current-parent preflight precedes
previous-root checking, local preparation, resulting-root checking, and proof
request start. During proof acquisition, exact event and driver correlation
precede selected-head drift; authenticated peer mismatch likewise precedes
state drift. The existing dependency acquisition then preserves its deadline,
response, canonicality, identity, candidate-bound, cycle, and fallback
precedence. Strict block application and journal commit preserve all existing
nested transition and storage precedence.

Every ordinary failure performs no selection of the current block and no
rollback of the workflow's acknowledged prefix; independent callers may have
changed selected state. Prefix metadata is evidence about this workflow's
durable acknowledgements, not necessarily the journal's current head. Only the
existing ambiguous journal commit may poison the handle after in-memory
admission.

## Cancellation and event ownership

`cancel` consumes the ancestry import and drops the current direct-child proof
acquisition. Its existing cancellation guard immediately releases quarantined
candidate buffers and marks the one in-flight request for drain. The physical
terminal still owns its peer slot and shared permit until the transport emits
`ProofCancellationDrained`.

Cancellation performs no further mutation or rollback; blocks already
acknowledged by this workflow remain committed. Independent journal changes are
outside its control. Cancellation never rolls back an acknowledged block,
applies the current partial closure, starts the next block, or re-fetches
ancestry.

Passing an event without first checking `accepts_event` consumes both values
and returns an error with the current prefix metadata and nested
`UnexpectedEvent`. It does not inspect or reroute the unrelated event.

## Resource boundary

The ancestry import adds no independent network or persistence budget. It
composes at most sixteen existing direct-child proof acquisitions strictly
sequentially:

| Resource | Bound |
| --- | ---: |
| Retained caller-selected blocks | 1..=16 |
| Block requests issued during import | 0 |
| Active block proof acquisitions | 1 |
| Proof candidates retained at once | at most 8 |
| Proof requests per block | at most 15 |
| Proof requests per complete ancestry | at most 240 |
| Canonical proof payload bytes retained at once | at most 33,554,432 bytes |
| Shared pending or retained network permits | 8 across the network |
| Pending proof request per peer | 1 |
| Durable journal entries per successful ancestry | 1..=16 |
| Journal synchronization barriers per committed block | 2 |
| Journal synchronization barriers per complete ancestry | 2..=32 |

The importer moves the ancestry's existing bounded block vector and consumes
it once. It does not clone the vector, refetch canonical block bytes, retain
multiple proof closures, concatenate proof payloads across blocks, or allocate
an ancestry-sized result. Completed prefixes are represented by a count and
one exact block identity.

The existing non-resetting 120-second dependency-acquisition deadline applies
independently to each block because the next acquisition begins only after the
preceding durable acknowledgement. There is no ancestry-wide wall-time
guarantee if the caller stops driving `StaticProofNetwork::next_event`.

## Security boundary

The consumed opaque ancestry binds the caller's exact target, the captured
anchor, the authenticated path source, exact block identities, parent links,
and structural transition-root continuity. Consuming rather than reconstructing
that result prevents a caller from passing an arbitrary vector under the
ancestry-import API and prevents block payload substitution between retrieval
and import.

Every proof request remains exact-addressed and generation-safe. Proof fallback
may obtain payloads from different statically authorized peers, but canonical
decoding, mathematical checking, dependency resolution, exact transition order,
and the journal—not peer identity—decide admission. One dishonest block or
proof source can terminate the current import but cannot bypass a check or
change the already acknowledged prefix.

Successful local import proves deterministic validity and local durable
selection only. It establishes no global availability, unique chain, fork
choice, consensus, finality, or economic value.

## Explicit exclusions

This contract defines no automatic target selection, automatic composition
with head pull, background synchronization, polling, announcement,
subscription, gossip, DHT, height, range request, block refetch, block retry,
block-peer fallback, hedged request, ancestry-wide transaction, rollback,
orphan pool, competing-branch store, reorganization, fork choice, checkpoint
trust, proposer, signature, proof of work, proof of stake, validator set,
voting, quorum, consensus, finality, dynamic learned-peer authorization, peer
scoring, reputation, new proof-bundle format, storage migration, compatibility
parser, snapshot, pruning, compression, erasure coding, data-availability
sampling, reward, fee, balance, novelty policy, issuance, or settlement.
