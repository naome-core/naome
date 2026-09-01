# Fixed-Validator Node Round Progression V0

## Authority and scope

This document defines the synchronous quorum-driven round-progression boundary
for one closure-scoped fixed-validator V0 node signer. It composes the exact
branch and anchored signer already owned by `FixedValidatorNodeSigningScopeV0`
with two existing lock-state transitions:

- one exact current-round precommit/nil quorum advances only to the same-height
  sequential `R + 1` Proposal phase; and
- one exact higher-round prevote or precommit quorum advances only to its
  authenticated round and role-corresponding Prevote or Precommit phase.

Both are consuming node-scope operations. Mere submission, routing, storage,
network receipt, or peer provenance grants no certificate validity or
progression authority. Only complete verification against the branch-derived
fixed-set snapshot authorizes the corresponding local transition. Neither path
creates a vote, finalizes a value, selects a branch, or advances height.

## Exact round and bounded admission

Before inspecting certificate bytes or reporting a work-limit rejection, the
coordinator requires the signer session to be operational and free of pending
vote, height, or higher-round work. It derives round zero from the node-owned
branch, requires the branch next height to equal the signer height, enforces the
persisted node-finality ceiling and caller-local inclusive ceiling on the
current signer round, and reconstructs that exact round sequentially. The
caller supplies no cursor and the coordinator does not clone the branch.

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

The current-round path verifies the exact canonical certificate at `R` and
requires precommit role with nil target. The higher-round path uses strict
framing only to bound routing work, requires the same height and a strictly
higher round within both ceilings, derives every intervening branch round, and
then fully verifies the same canonical bytes at the target snapshot. An
unauthenticated embedded position therefore grants neither validity nor state
change.

## Ordered progression and durability

Current-round nil-quorum success changes only the live signer state to `R + 1`
Proposal. It preserves the exact lock and complete valid-value proof and writes
neither journal nor anchor. A later vote at that round must still pass through
the existing durable vote-execution boundary. A crash before such a vote
therefore restores the last durable signer state, not this volatile observation.

Higher-round success is durable before continuation returns:

1. Fully verify and seal the source-bound higher-round transition.
2. Append and synchronize its complete checkpoint to the signer journal.
3. Advance the independent signer anchor to that exact checkpoint state.
4. Consume the private prepared capability in the same live signer session.
5. Recheck session provenance and unchanged source state, then publish only the
   authenticated target position and phase.
6. Drop every branch-borrowed cursor and capability before returning the
   replacement node scope plus copied position and phase diagnostics.

External callers cannot access the quorum-specific raw nil transition or split
higher-round prepare and acknowledgement stages. The ordinary one-step
`advance_round` facade remains separate for later timeout-driven coordination;
this component grants it no timeout-expiry or scheduling authority.

## Outcomes, failures, and restart

A malformed, context-invalid, wrong-role, wrong-target, wrong-height,
non-higher, or otherwise mutation-free quorum rejection returns the unchanged
scope. Caller or persisted destination-capacity rejection also returns the
unchanged scope, with finality precedence when both limits reject the same
target. No signer or finality bytes change on those paths.

A branch/signer mismatch, current-round derivation failure, current signer
above the persisted finality ceiling, non-operational session, internal
transition invariant failure, checkpoint append or anchor failure, or live
acknowledgement failure consumes the scope. Once durable preparation begins,
the live caller cannot distinguish every possible durable prefix; strict reopen
against the independent signer anchor is the only classifier. No failure path
performs repair, rollback, or automatic retry.

## Exclusions

This coordinator does not define or perform:

- timeout measurement, timeout expiry, phase scheduling, backoff, event-loop
  ordering, buffering, retry, or daemon ownership;
- quorum construction, vote collection, competing-evidence choice, proposal
  selection, or proposal authoring;
- network transport, peer discovery, provenance trust, or peer-selected
  admission;
- finality, height advancement, branch or sibling selection, rollback,
  reorganization, candidate promotion, or store mutation;
- dynamic validator sets, multi-key coordination, key loading, rotation,
  remote signing, or production custody; or
- cross-file atomicity, automatic crash-gap repair, hardware monotonicity, or
  non-Unix file-anchor runtime guarantees.

These remain required product capabilities where the consensus ledger says so;
this boundary only assigns the already-decided quorum evidence its exact local
round and phase authority.
