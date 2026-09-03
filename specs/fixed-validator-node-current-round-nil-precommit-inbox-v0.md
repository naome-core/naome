# Fixed-Validator Node Current-Round Nil-Precommit Inbox V0

## Authority and scope

This document defines one bounded, process-local nil-precommit evidence inbox
owned only by `FixedValidatorNodeDriverV0`. It retains complete canonical
`Precommit/Nil` votes already authenticated against the driver's exact live
fixed-validator V0 round so one driver step can recognize a current-round nil
quorum and invoke the existing same-height round-progression coordinator.

The inbox owns only:

- complete canonical current-round `Precommit/Nil` votes;
- the exact parent coordinate, position, and authenticated active signer
  derived during admission;
- checked logical canonical-input accounting and one immutable saturation
  reason; and
- deterministic, non-authoritative construction of one exact vote batch from
  a retained current-position quorum.

The inbox has no signing scope, key, timer, proposal or artifact payload,
finality or selected-state handle, journal or anchor handle, peer identity, or
network route. Retention and local quorum construction are not provenance,
validity, branch-selection, finality, or round-transition authority. Only the
owning driver's fixed step policy may supply one retained batch to
`advance_round_for_nil_precommit_vote_batch`. That existing consuming
coordinator repeats complete verification and remains the sole same-height
round-progression authority.

## Independent caller-local limits

`FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0` contains one positive
entry limit and one positive logical canonical-input-byte limit. Every retained
vote consumes one entry and its fixed complete 214-byte canonical vote length.
The limits bound retained input count and logical canonical input bytes, not
allocator overhead, event rate, protocol-wide evidence, or total resident
memory.

These limits are independent of the higher-round, current-voting, and current-
proposal-finality inbox limits. Capacity cannot be borrowed or charged across
the four resource classes. Exhausting nil-precommit capacity therefore cannot
consume the capacity reserved for proposal finality or authenticated higher-
round escape.

## Driver-owned admission

`CurrentRoundNilPrecommit` carries one complete canonical signed vote and no
caller-supplied context, position, role, target, round, or signer. The existing
pending-command custody gate runs first and returns the complete event without
inspection. Otherwise, the driver reconstructs its exact live branch round and
uses the narrow active-nil-precommit verifier before offering the authenticated
input to this inbox.

The vote must strictly authenticate:

1. the driver's exact consensus context;
2. the exact current height and round selected only by the node-derived typed
   round;
3. the `Precommit` role and `Nil` target;
4. one canonical strict Ed25519 signature; and
5. membership of that signer in the round's immutable active fixed-validator
   snapshot.

Only after those checks succeed does the inbox associate the vote with the
typed round's exact parent coordinate. That coordinate is local branch binding,
not a caller field or a separately authenticated vote field.

A stale or future position, foreign context, proposal target, prevote role,
inactive signer, malformed bytes, or invalid signature is returned losslessly
without retention. Admission is available in Proposal, Prevote, or Precommit
phase and does not consult the phase-local due fence. Current-, higher-, or
finality-inbox saturation and ambiguity do not block it. A successful position
advance does not relabel retained evidence from the former position.

Admission performs no signing, lock, valid-value, timer, finality, branch,
journal, anchor, candidate-store, payload-store, or selected-state mutation.
Every rejected event returns its original owned canonical vote bytes.

## Retention, duplicates, and saturation

Exact parent-bound canonical vote replay is no-growth. Every other fully
admitted vote consumes one entry and its exact logical input bytes. While
healthy, the inbox retains every byte-distinct same-semantic signature variant
and every signer input without eviction or arrival-order preference.

Before insertion, the inbox checks entry addition, canonical-input-byte
addition, and both declared limits. The first nonduplicate checked-accounting
overflow or declared-capacity failure preserves the complete retained prefix
and exact rejected event and latches one immutable nil-precommit-class
saturation reason. Later nil-precommit events are returned losslessly until an
explicit nil-precommit-only drain-and-reset. Collection reservation failure
instead returns the event and source without changing entries, counters, or
saturation.

Saturation denies later insertions, but it does not invalidate a strict
supermajority already present in the retained prefix. Every admissible input in
this inbox has the same exact `Precommit/Nil` role and target, so omitted later
inputs cannot introduce a competing actionable target. A retained quorum may
therefore remain actionable after saturation. If the retained prefix is not
quorate, saturation falls through to lower-priority driver work; it cannot
create a quorum, block proposal finality, block higher-round escape, or force
the due transition.

This class-local rule does not claim that a saturated prefix is a complete
network view or that its chosen signature representations are globally
canonical. Per-semantic-key caps, peer rate control, durable retention, and
protocol-wide total-memory limits remain separate resource and networking
policy.

## Exact-current quorum construction

The absence of a retained vote matching the exact live parent coordinate and
position is resolved before sequential round reconstruction. Only a matching
preclassification result proceeds to full typed-round derivation and quorum
construction. This is a local work bound, not a quorum, validity, or transition
decision.

The classifier is crate-private and considers only retained votes whose exact
parent coordinate and position match the driver's unchanged live round. Votes
are ordered by authenticated signer and complete canonical bytes. For each
active signer, every variant remains retained while the lexicographically
smallest complete 214-byte canonical vote becomes that signer's sole
representative for this local construction. The signer contributes its exact
active weight once, and all offline active weight remains in the unchanged
denominator.

The selected representatives enter the existing exact-batch constructor with
the required `Precommit/Nil` role and target. Empty evidence, insufficient
weight, and exact two-thirds equality are not quorate. Only weight strictly
greater than two thirds yields one actionable retained batch. Because this
inbox admits a single target class, it has no target-choice or multiple-root
classification and no ambiguity latch.

The batch is merely an operation-local representation of the retained evidence.
It is not exposed as a public certificate or command and does not advance a
round by itself. A fallible classifier scratch-reservation failure or typed
constructor rejection changes no retained input, driver authority, or durable
state and cannot fall back to a partial batch. This does not claim exhaustive
process-allocation-failure recovery inside reused infallible encoders.

## Driver execution and priority

`FixedValidatorNodeDriverV0::step` applies this order:

1. transfer any pending command;
2. apply exact-current proposal-finality policy;
3. apply higher-round policy, executing its unique action or honoring its block;
4. execute an exact-current retained nil-precommit quorum;
5. apply ordinary current proposal or prevote-quorum voting policy; and
6. execute only the exact live due path or remain idle.

The established proposal-finality path therefore remains first when matching
non-nil and nil precommit quorums are simultaneously retained for the exact
current position. A finality quorum missing its proposal or multiple quorate
proposal roots keeps its established no-winner block. Finality-class saturation
and no proposal quorum fall through; higher-round escape then precedes nil-
precommit work. This ordering reuses the existing policy and introduces no new
choice between finality and round progression.

An actionable nil quorum precedes ordinary current voting and due work. The
driver first preflights the next timer generation, then supplies references to
the selected complete vote bytes to
`advance_round_for_nil_precommit_vote_batch` with its existing work ceiling.
That coordinator reconstructs the exact current round, rechecks successor
capacity, and completely reverifies context, position, role, target,
membership, signatures, distinct signers, and strict threshold before applying
the existing transition. Retained evidence is therefore never cached validity
or round-transition authority.

A pre-effect coordinator rejection restores the returned unchanged scope into
the same driver, preserves all four inboxes, timers, due observation, pending
command, lock, valid evidence, and durable files, and returns its existing typed
round-advance rejection without lower-priority fallthrough. A fatal derivation
or session error returns no driver or scope; strict anchored restart remains the
only recovery classifier.

Success moves only the same branch and height from round `R` to round `R + 1`
Proposal. It preserves the exact lock and complete valid value, valid round,
and proof; writes no signer or finality journal or anchor bytes; finalizes no
value; invalidates the old timer and due observation; and queues exactly one
successor Proposal-phase timeout-arm command. It emits no signed-vote command.

All four volatile inboxes, their exact inputs, counters, saturation reasons,
and existing ambiguity latches remain unchanged after success. Their evidence
for the former position is stale but still charged until its independent
class-specific drain. A later authority-bearing operation must evaluate and
verify evidence against the new live position rather than relabeling or pruning
the retained bytes.

## Drain and restart

`drain_current_nil_precommit_inbox_and_reset` returns one
`FixedValidatorNodeDriverCurrentNilPrecommitDrainV0`. Its `into_parts` separates
the continuing driver from
`FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0`, whose exact-size
iterator items are the raw fixed-width `[u8; 214]` canonical nil precommits. It
clears only this inbox's entries, accounting, and saturation. It does not change
the other three inboxes, their latches, the live signing scope, lock or valid
value, timer, due observation, pending command, journal, anchor, branch, or
retained source store, and it grants no reinsertion order or evidence
preference.

The inbox, accounting, and classifier are volatile. Driver or process loss
drops them. Strict restart reconstructs only existing journal- and anchor-
authorized signer and finality state; a fresh driver starts with an empty nil-
precommit inbox. Every redelivered vote must pass complete admission against the
fresh exact current position. A locally signed nil precommit is never
self-counted; it requires the same explicit event admission as any other
independently obtained canonical vote.

## Determinism and exclusions

For the same exact live branch state, limits, and retained vote set, every
insertion-order permutation yields the same quorum result, per-signer
representatives, and exact selected batch. This is a process-local retained-set
claim only. It does not establish equal evidence views across nodes, delivery
completeness, fairness across drain and reinsertion, or independence from when
an external runtime submits an event or requests a step.

This inbox and its driver integration do not define or perform:

- proposal, branch, sibling, or finality selection; finality installation;
  rollback; reorganization; candidate promotion; or conflict punishment;
- lower- or candidate-backed finality routing, higher-round vote-only catch-up,
  proposal authoring, self-observation, or automatic event acquisition;
- timeout duration, elapsed-time proof, scheduling, asynchronous event-loop
  ownership, command acknowledgement, or retry;
- networking, peer authentication, provenance trust, relay, gossip, peer rate
  control, or evidence-completeness inference;
- artifact fetch, payload persistence, availability certification, or
  candidate- or payload-store mutation;
- equivocation verdicts, slashing, economics, dynamic-validator behavior, key
  rotation, remote signing, or production custody; or
- canonical or durable protocol-wide evidence storage, signer-subset or
  signature-representation preference, or total resident-memory bounds.

These exclusions state that this component grants none of those authorities;
they do not make those capabilities optional for the broader product.
