# Fixed-Validator Node Round Progression V0

## Authority and scope

This document defines the synchronous explicit-event and quorum-driven
round-progression boundary for one closure-scoped fixed-validator V0 node
signer. It composes the exact branch and anchored signer already owned by
`FixedValidatorNodeSigningScopeV0` with three existing lock-state transitions
and two exact signed-vote-batch adapters:

- one caller-routed Precommit close, bound to the exact context and source
  position, advances only to the same-height sequential `R + 1` Proposal phase;
- one exact current-round precommit/nil quorum, supplied either as a canonical
  certificate or a complete signed-precommit batch, advances only to the
  same-height sequential `R + 1` Proposal phase; and
- one exact higher-round prevote or precommit quorum, supplied either as a
  canonical certificate or as a complete vote batch with an explicit route,
  advances only to its authenticated round and role-corresponding Prevote or
  Precommit phase.

All are consuming node-scope operations. Mere submission, routing, storage,
network receipt, or peer provenance grants no certificate validity or
progression authority. The explicit close requires exact event identity and
Precommit phase but does not prove why the caller classified the phase as
closed. A batch route names only an expected round, role, target, and local work
ceiling; it is unauthenticated metadata and grants no authority independently
of its votes. Only complete verification against the branch-derived fixed-set
snapshot authorizes a quorum transition. No path observes or accumulates votes,
creates a vote, finalizes a value, selects a branch, or advances height.

## Exact round and bounded admission

Except for reading the caller ceiling required to bound preflight, before
inspecting certificate bytes, a batch route's evidence identity, or batch
bytes, the coordinator requires the signer session to be operational and free
of pending vote, height, or higher-round work. It derives round zero from the
node-owned branch, requires the branch next height to equal the signer height,
enforces the persisted node-finality ceiling and caller-local inclusive ceiling
on the current signer round, and reconstructs that exact round sequentially.
The caller supplies no cursor and the coordinator does not clone the branch.

The destination, not only the current round, must also fit both ceilings. For a
current-round nil quorum the coordinator preflights `R + 1`. For higher-round
evidence it first requires that this first successor is locally admissible,
before inspecting certificate framing, and then passes the lower verifier the
minimum of the caller and persisted finality ceilings. This early capacity
check reports finality when `R + 1` exceeds finality and otherwise caller
capacity; in particular, a zero caller ceiling may reject without inspecting an
embedded target. Once successor capacity permits strict target inspection, an
embedded target that exceeds both ceilings reports the persisted finality limit
first. Every destination-ceiling failure is a no-effect rejection that returns
the same scope. A signer already above the persisted finality ceiling is instead
a node-coherence failure and returns no scope.

For an explicit Precommit close, the caller supplies the event's consensus
context and source position. After readiness, coherence, current-round ceiling,
and exact-round reconstruction, both must equal the node-derived round and the
live phase must be Precommit. Context, position, or phase mismatch returns the
unchanged scope. Only then does the coordinator require `R + 1` to fit the
persisted finality ceiling and caller-local ceiling, derive that sole successor
internally, and apply it. No caller cursor is accepted, so a delayed close for
round `R` cannot close a later Precommit phase.

The current-round quorum path verifies the exact canonical certificate at `R`
and requires precommit role with nil target. Its batch sibling applies the
unchanged all-or-nothing exact-batch constructor at that same derived round,
requires every supplied vote to authenticate precommit/nil, and passes only the
resulting canonical certificate into the same transition.

The higher-round certificate path uses strict framing only to bound routing
work, requires the same height and a strictly higher round within both ceilings,
derives every intervening branch round, and then fully verifies the same
canonical bytes at the target snapshot. Its batch sibling checks the routed
round is strictly higher, reports the persisted finality ceiling before the
caller ceiling when both reject that round, derives the exact bounded branch
round, and applies the unchanged exact-batch constructor with the route's
required role and target. Only its canonical certificate enters the existing
checkpoint path, where it is independently framed and fully reverified. An
unauthenticated embedded position or caller route therefore grants neither
validity nor state change.

## Ordered progression and durability

Explicit-close and current-round nil-quorum success, whether the quorum arrived
as a certificate or exact batch, change only the live signer state to `R + 1`
Proposal. They preserve the exact lock and complete valid-value proof and write
neither journal nor anchor. A later proposal or vote at that round must still
pass through its existing durable signer boundary. Absent a later durable node
or signer action, a crash therefore restores the prior durable signer state,
not this volatile observation. Otherwise strict restart follows that later
durable ready, pending, or terminal state; incomplete preparation remains
fail-closed.

Higher-round success is durable before continuation returns:

1. Fully verify and seal the source-bound higher-round transition.
2. Append and synchronize its complete checkpoint to the signer journal.
3. Advance the independent signer anchor to that exact checkpoint state.
4. Consume the private prepared capability in the same live signer session.
5. Recheck session provenance and unchanged source state, then publish only the
   authenticated target position and phase.
6. Drop every branch-borrowed cursor and capability before returning the
   replacement node scope plus copied position and phase diagnostics.

External callers cannot access the raw cursor-supplied sequential transition,
the quorum-specific raw nil transition, or split higher-round prepare and
acknowledgement stages. The exact-event-bound consuming coordinator is the sole
public ordinary sequential path. It accepts no timestamp, deadline, timer
generation, or proof of expiry and grants no timeout-expiry or scheduling
authority.

## Outcomes, failures, and restart

A stale or foreign close identity, wrong close phase, malformed,
context-invalid, wrong-position, wrong-role, wrong-target, duplicate, inactive,
invalid-signature, insufficient, wrong-height, non-higher, or otherwise
mutation-free quorum or batch rejection returns the unchanged scope. Caller or
persisted destination-capacity rejection also returns the unchanged scope, with
finality precedence when both limits reject the same target. Session and
first-successor preflight precede certificate framing, batch bytes, and every
route field except the caller ceiling used by that preflight. No signer or
finality bytes change on those paths.

A branch/signer mismatch, current-round derivation failure, current signer
above the persisted finality ceiling, non-operational session, internal
transition invariant failure, checkpoint append or anchor failure, or live
acknowledgement failure consumes the scope. Once durable preparation begins,
the live caller cannot distinguish every possible durable prefix; strict reopen
against the independent signer anchor is the only classifier. No failure path
performs repair, rollback, or automatic retry.

## Exclusions

This coordinator does not define or perform:

- timeout measurement, timeout expiry, timer generation or cancellation, phase
  scheduling, backoff, event-loop ordering, node-owned or shared buffering,
  retry, or daemon ownership;
- vote observation, collection, accumulation, delivery-completeness inference,
  filtering, grouping, competing-evidence choice, proposal selection, or
  proposal authoring beyond all-or-nothing construction from one exact
  caller-supplied batch;
- network transport, peer discovery, provenance trust, or peer-selected
  admission;
- finality, height advancement, branch or sibling selection, rollback,
  reorganization, candidate promotion, or store mutation;
- dynamic validator sets, multi-key coordination, key loading, rotation,
  remote signing, or production custody; or
- cross-file atomicity, automatic crash-gap repair, hardware monotonicity, or
  non-Unix file-anchor runtime guarantees.

These remain required product capabilities where the consensus ledger says so;
this boundary only applies an exact caller-classified Precommit close or fully
verified certificate derived from one prebuilt certificate or one complete
caller-supplied batch to the already-decided local round and phase progression.
A separately retained proposal token cannot by itself invoke or replace this
progression authority. The separate exact pairing coordinator must independently
verify both the proposal and matching certificate before it can reuse the
specialized durable higher-round transition.
