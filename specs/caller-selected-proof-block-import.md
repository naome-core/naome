# NAOME Caller-Selected Proof Block Import

## Status and scope

This document defines one bounded, caller-driven import of one exact
[`ProofBlock`](proof-block.md) that must directly extend the current selected
head. It is a prerelease orchestration contract and may change before the first
stable protocol release.

The caller supplies both the target `ProofBlockId` and the initially preferred
statically authorized peer. The import composes the existing
[Authenticated Proof Block Transport](authenticated-proof-block-transport.md),
bounded proof-dependency acquisition from the
[Authenticated Proof Transport](authenticated-proof-transport.md), and the
sole atomic mutation boundary of the
[`ProofChainJournal`](proof-chain-journal.md). It defines no new wire message,
protocol identifier, libp2p behaviour, connection, storage format, or proof
validation path.

This contract is deliberately one direct-child import, not head discovery or
chain synchronization. No peer chooses the target. Fetching a block or its
proof payloads gives those peers no authority to select, order, finalize, or
reward it. The caller's exact target remains immutable throughout the import,
and only the journal's normal strict block application may change selected
state.

## Public surface

The public Rust surface is equivalent to:

```text
StaticProofNetwork::start_proof_block_import(
    &mut self,
    selected: &ProofChainJournal,
    peer_id: PeerId,
    target_block_id: ProofBlockId,
) -> Result<ProofBlockImport, ProofBlockImportError>

ProofBlockImport::target_block_id(&self) -> ProofBlockId
ProofBlockImport::pending_peer_id(&self) -> PeerId
ProofBlockImport::accepts_event(&self, event: &NetworkEvent) -> bool
ProofBlockImport::cancel(self)
ProofBlockImport::on_event(
    self,
    network: &mut StaticProofNetwork,
    selected: &mut ProofChainJournal,
    event: NetworkEvent,
) -> Result<ProofBlockImportProgress, ProofBlockImportError>

type ProofBlockImportProgress = Option<ProofBlockImport>
```

`ProofBlockImport` is non-cloneable and privately owns exactly one phase:

- one generation-safe `BlockRequestTicket` while the target block is pending;
  or
- the exact decoded target block and one existing
  `ProofDependencyAcquisition` while proof payloads are pending.

It exposes no block bytes, proof bytes, addressed candidates, raw libp2p
request identifier, response outcome, or alternative target. `pending_peer_id`
returns the block peer during block retrieval and the peer currently serving
the sequential dependency request during proof acquisition. The latter may
change under the existing bounded proof-peer fallback rules without changing
the target block.

`accepts_event` is the routing guard. It returns true only for the exact
generation-safe `OutboundBlock` event in the block phase or the exact
`OutboundProof` event awaited by the underlying dependency acquisition in the
proof phase. Every other `NetworkEvent`, including another import's otherwise
equal public request, is rejected. Callers driving multiple workflows must
route an event only after this predicate succeeds.

`on_event` consumes the import and its accepted event. `Some(import)` returns
the only continuation after another proof request has been started. `None` is
returned only after the exact target block and all committed proof payloads
have passed the existing strict application and the journal has acknowledged
its durable commit. The alias keeps this progress result allocation-free and
avoids storing the import beside a redundant completion variant.

## Starting an import

`start_proof_block_import` performs these checks in order:

1. read the healthy journal's current head;
2. reject the target as `TargetAlreadySelected` when it equals that current
   head;
3. otherwise query the healthy journal's committed exact-ID block index and
   reject the target as `TargetAlreadySelected` when it already belongs to the
   selected ancestry; and
4. call the existing `request_block` with the caller's peer and exact target,
   preserving its `UnknownPeer`, `AlreadyPending`, `PeerDisconnected`, and
   `GlobalLimit` precedence inside `RequestStart`.

Journal poisoning or another journal query error is `SelectedState` and
precedes network work. The already-selected check performs no journal scan and
does not mutate memory or disk. A target absent from the local index is not
thereby valid, available, a direct child, or selected by any network.

The block request uses the existing `/naome/proof-block-exchange` framing,
authenticated peer binding, private request generation, shared per-peer slot,
and shared eight-permit budget. Starting an import never dials, retries another
peer for the block, announces the target, or creates an import-wide background
task.

## Block phase

Only the exact block terminal accepted by the retained ticket may advance this
phase. Processing preserves this order:

1. reject a different phase, request generation, authenticated peer, request,
   or network instance as `UnexpectedEvent` before extracting any outcome;
2. complete the existing block ticket, preserving a correlated terminal
   failure as `BlockRequestFailed`;
3. convert a successfully framed peer-local `Unavailable` response to
   `BlockUnavailable`;
4. retain the found block that the existing transport already strictly decoded
   and whose computed `ProofBlockId` already matched the immutable caller
   target;
5. require the block parent to equal the journal's current exact head;
6. require the block transition's previous `ProofSetRoot` to equal the
   journal's current authenticated proof-set root;
7. call `ProofChainJournal::prepare_block` with the fetched transition's exact
   ordered `ProofId` values;
8. require the fetched transition's resulting `ProofSetRoot` to equal the
   locally projected resulting root from that prepared block; and
9. start the existing dependency acquisition for the transition's final,
   root-proof identity, preferring the authenticated block peer.

Steps 5 through 8 are read-only context preflights. Parent mismatch precedes
all transition preparation and proof traffic. Previous-root mismatch precedes
preparation. Preparation reuses the journal's existing proof-ID count,
duplicate, already-selected, and bounded authenticated-set projection rules;
its error remains `SelectedState`. Resulting-root mismatch follows successful
preparation. No block field is repaired, normalized, reordered, or replaced by
the locally prepared value.

The local preparation is not selection. It checks that the target could
describe one direct transition from the current selected context before the
implementation requests as many as eight independently bounded proof
payloads. The fetched block remains the sole block later submitted to
authoritative application.

`BlockUnavailable` is only one authenticated peer's response for one exact
address. It proves neither global absence nor invalidity. The import creates no
negative cache and does not rotate the block request to another peer.

## Proof phase

The proof phase delegates response decoding, canonical-normal-form checking,
reference discovery, exact address retention, cycle detection, retry policy,
request count, deadline, and cancellation to the existing
`ProofDependencyAcquisition` unchanged.

Before handing each accepted proof terminal to that acquisition, the import
first preserves network-instance and authenticated-peer correlation. It then
reads the healthy journal head and requires it to equal the fetched block's
parent before interpreting any other proof outcome. If the current head no
longer equals that parent while proof traffic is in flight,
`ParentBlockIdMismatch` terminates the import. Dropping the consumed
acquisition then releases quarantined payloads and retains no path to
admission.

An existing acquisition error is wrapped as `ProofAcquisition` together with
the immutable target block ID. `AwaitingResponse` becomes `Some(import)` with
the same target block and the updated underlying acquisition. Its current peer
may change only according to the existing per-address proof fallback policy.
Block identity, block contents, requested root, discovered addresses,
acquisition deadline, and request budget do not reset.

When the dependency acquisition completes, the import immediately consumes
the resulting opaque `UnselectedProofClosure` through:

```text
UnselectedProofClosure::apply_block(
    self,
    selected: &mut ProofChainJournal,
    block: &ProofBlock,
) -> Result<&AcceptedProofRecord, ProofChainJournalError>
```

This is the sole mutation. It rechecks journal health and current parent,
correlates the opaque candidates into the fetched block's exact transition
order, and delegates to the journal's existing atomic block application. The
transition then rechecks previous root, candidate count and exact ordered
identities, projected resulting root, strict canonical proof decoding,
mathematical validity, requested identities, dependency order, root closure,
and selected-state registration before the journal writes anything.

Only successful journal acknowledgement produces `None`; the committed block
identity is exactly the caller's original target, which is observable through
`target_block_id` before consuming each continuation. The import never
constructs a replacement block from the current journal, silently follows a
new head, or exposes a closure for another block.

## Error family and precedence

`ProofBlockImportError` has these public classes:

```text
SelectedState { source: Box<ProofChainJournalError> }
TargetAlreadySelected { block_id: ProofBlockId }
RequestStart { block_id: ProofBlockId, source: RequestStartError }
UnexpectedEvent
BlockRequestFailed {
    peer_id: PeerId,
    block_id: ProofBlockId,
    source: Box<OutboundProofBlockFailure>,
}
BlockUnavailable { peer_id: PeerId, block_id: ProofBlockId }
ParentBlockIdMismatch { expected: ProofBlockId, actual: ProofBlockId }
PreviousProofSetRootMismatch { expected: ProofSetRoot, actual: ProofSetRoot }
ResultingProofSetRootMismatch { expected: ProofSetRoot, actual: ProofSetRoot }
ProofAcquisition {
    block_id: ProofBlockId,
    source: Box<DependencyAcquisitionError>,
}
```

At start, selected-state health and the existing-ancestry check precede block
request preflights. In the block phase, generation correlation precedes the
terminal outcome; correlated failure precedes unavailable; unavailable
precedes journal context work; current parent precedes previous root;
previous root precedes local preparation; and preparation precedes resulting
root. No proof request starts after any block-phase error.

In the proof phase, exact event and network-instance correlation precede the
current-parent recheck. An authenticated `PeerMismatch` terminal is likewise
reported before selected-state drift can mask that correlation failure. The
parent recheck precedes every other proof outcome and payload interpretation.
The underlying dependency acquisition then preserves its own request,
deadline, response, canonicality, candidate-bound, and dependency-cycle
precedence. On completion, `UnselectedProofClosure::apply_block` and
`ProofChainJournal` retain their existing strict block, transition, batch,
ledger, and commit precedence inside `SelectedState`.

Every ordinary error performs no selected-state mutation and no journal write.
Only an existing ambiguous journal I/O failure after successful in-memory
application may return `SelectedState` containing `Commit` and poison the
journal. Reopening remains the only recovery path and reconstructs whichever
old or new complete commit became durable.

## Cancellation and event ownership

`cancel` consumes the logical import and performs no new physical cancellation
operation.

During block retrieval, dropping the existing `BlockRequestTicket` is
non-cancelling. The physical libp2p request retains its peer slot and shared
permit until its terminal is emitted; that later `OutboundBlock` event no
longer belongs to an import and must be handled or dropped by the caller.

During proof acquisition, consuming the import drops the existing acquisition.
Its cancellation guard immediately releases all quarantined candidate buffers
and marks the one in-flight proof request for drain. The physical terminal
still releases the remaining peer slot and permit through the existing
`ProofCancellationDrained` path. Cancellation never commits a partial closure
or block.

Passing an event without first checking `accepts_event` consumes both values
and returns `UnexpectedEvent`; it does not reroute or inspect the unrelated
event. Correct multi-workflow drivers therefore route by the predicate before
calling `on_event`.

## Resource boundary

The import adds no independent network or persistence budget. It composes these
existing bounds sequentially:

| Resource | Bound |
| --- | ---: |
| Caller-selected block targets per import | 1 |
| Block requests issued per import | 1 |
| Block request body | 32 bytes |
| Complete found block response frame | at most 355 bytes |
| Retained decoded block | at most 353 canonical bytes and 8 proof IDs |
| Proof candidates retained | at most 8 |
| Proof requests issued by dependency acquisition | at most 15 |
| Block plus proof requests issued per import | at most 16 |
| Canonical proof payload bytes retained | at most 33,554,432 bytes |
| Shared pending or retained network permits | 8 across the network |
| Pending proof or block request per peer | 1 |
| Durable journal entries committed per successful import | 1 |
| Complete durable journal entry | at most 33,554,855 bytes |
| Journal synchronization barriers per successful import | 2 |

The block phase uses the existing request-response timeout and has no retry or
additional import deadline. The proof phase creates the existing non-resetting
120-second dependency-acquisition deadline only after block preflight succeeds.
There is no wall-time guarantee if the caller stops driving
`StaticProofNetwork::next_event`.

The importer retains one decoded bounded block in addition to the existing
dependency-acquisition state. It introduces no proof-sized copy, combined
block-and-proof wire bundle, ancestry vector, orphan cache, worker queue,
background task, or second journal entry. Successful application keeps the
existing single journal-entry maximum and synchronization barriers.

## Security boundary

The immutable caller target, private block request generation, authenticated
peer, and exact block content identity prevent a response for another block or
request generation from changing the import target. Direct-parent and root
preflights reject stale or different-state blocks before proof traffic. Final
strict application repeats every authoritative condition so state changes
between preflight and commit cannot bypass validation.

Proof fallback may obtain different payloads from different statically
authorized peers. Exact request addresses, canonical checking, mathematical
checking, dependency validation, and the fetched block's committed order—not
peer identity—decide whether those bytes can be admitted. Authentication
establishes the source of each transport response, not the truth, selection,
or finality of the block.

The caller's target choice is an API fact, not a consensus decision. A caller
can choose a valid sibling, stale child, or maliciously advertised address; the
import will either fail against current local context or commit only if the
complete block and proof closure pass the existing deterministic checks. A
successful local import establishes neither global agreement nor economic
value.

## Explicit exclusions

This contract defines no target or head discovery, announcement, subscription,
gossip, DHT, polling scheduler, height, range, parent query, child query,
ancestry walk, multi-block synchronization, block retry, block peer fallback,
hedged request, orphan pool, competing-branch store, replacement-block
construction, implicit target substitution, peer-selected block, fork choice,
rollback, reorganization, checkpoint trust, proposer, signature, proof of work,
proof of stake, validator set, voting, quorum, consensus, finality, dynamic
learned-peer authorization, peer scoring, reputation, proof bundle wire format,
storage migration, compatibility parser, snapshot, pruning, compression,
erasure coding, data-availability sampling, reward, fee, balance, novelty
policy, issuance, or settlement.
