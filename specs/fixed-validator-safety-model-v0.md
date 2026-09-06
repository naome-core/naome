# Bounded fixed-validator V0 safety model

## Contract and status

`TEST-005-001` supplies finite, independent model checking and selected real
coordinator trace replay for the existing artifact-only fixed-validator V0
rules. It grants no new production authority and changes no protocol behavior.
`TEST-005` remains `IN_PROGRESS`; the general `SEC-007` safety requirement remains
`NOT_IMPLEMENTED`.

The independent oracle requires that no reachable state make complete,
proposal-backed strict-supermajority precommit proofs available for both of two
different semantic values at the same height, even across different rounds.
This is stronger than requiring two honest recipients not to finalize different
values: any accepted finality in the modeled protocol needs one such proof.
The model checks potential proofs, without adding recipient finalization events
or selecting a preferred proof. Proof availability is append-only, so a later
stop cannot erase an earlier conflict.

The model and oracle in
`crates/naome-node/src/fixed_validator/tests/safety_model/model.rs` use only the
standard library. They do not call production locking, proposer, quorum,
signature, proposal admission, or finality helpers. The separate adapter in
`crates/naome-node/src/fixed_validator/tests/safety_model.rs` uses production
coordinators to check explorer-produced witnesses against actual execution.

## Finite bounds

Each exhaustive run has these bounds:

- One fixed context, one parent, and its next height; the real replay uses H1.
- Two distinct, always-valid semantic values, A and B, sharing that parent.
  Round-specific producer authorization and proof variants do not create new
  semantic values. The replay checks complete `ConsensusValueV0` equality.
- Four distinct validators of unit agreement weight, starting from zero
  proposer priorities. The first three proposers are keys 0, 1, and 2 in sorted
  key order. Each of the four possible placements of one Byzantine validator
  is explored separately. Its weight is 1/4, strictly below one third.
- Honest actions in rounds 0, 1, and 2. Advancing out of round 2 reaches a
  terminal exploration cursor at round 3; it creates no round-3 proposal or
  vote. This boundary is not protocol finalization or a durable stop.
- A hard ceiling of 2,000,000 visited reduced state classes **per placement**.
  Exceeding it fails the test as incomplete. There is no successful partial
  search, random sample, elapsed-time cutoff, or additional depth truncation.

Every action advances an honest cursor except proposal authoring, which occurs
at most once per eligible proposer round. There are at most 27 cursor advances
and three honest authoring events on a path. The exploration terminates over
the full reachable graph within the round bounds.

These bounds do not cover unequal weights, larger or changing validator sets,
other initial priority vectors or proposer windows, additional semantic values,
multiple heights, malformed input, or cryptographic failure. They do not
establish the general safety requirement for arbitrary executions.

## Decision-event abstraction

The state retains each honest node's round, next phase, lock value/round, and
valid value/round; each honest proposer emission; and every honest prevote and
precommit in the bounded execution. Each honest key may emit at most one target
at each round/role. A skipped slot remains absent, distinct from nil. Advancing
one node never deletes its previously emitted messages.

The Byzantine key may sign every target at every bounded position. These
signatures are implicitly available from the start. A quorum exists precisely
when the available distinct signers satisfy the independently computed integer
inequality `3 * signed_weight > 2 * total_weight`. Votes for a proposal root can
form a prevote quorum even without a matching proposal in that round; locked
nodes can emit that root after proposal-phase close.

An honest proposer in its Proposal phase authors one fresh A/B value when it
has no valid value, or its exact retained valid value otherwise. The Byzantine
proposer can authorize both values. Because producer authorization does not
bind the optional proof wrapper, every authorized root can be delivered with
no proof or with any available earlier-round prevote proof for that value.
This includes stripping and attaching proofs on honest authored roots.

At each state, every enabled honest decision is explored:

- Admit an available proposal or explicitly close Proposal; apply the existing
  lock and valid-value comparison, then emit the derived prevote.
- Deliver a current prevote quorum and, for a non-nil target, a matching
  proposal; or explicitly close Prevote. The proposal may arrive after that
  node's own nil or different-root prevote. Emit the resulting precommit.
- Explicitly close Precommit and advance one round, preserving lock and valid
  state; or use a current nil-precommit quorum to advance from any phase.
- Use a strictly higher-round prevote or precommit quorum to enter its
  role-corresponding phase, preserving lock/valid state and emitting no vote.

Proposal proof of the same round but a different retained valid value rejects
without a successor. Repeated delivery of identical semantic messages, partial
delivery without a complete decision input, and elapsed waiting are stutters.
Choosing another event or ending at a prefix represents withholding and loss.
Explicit close does not imply measured timer expiry.

This complete-bundle abstraction conservatively permits delivery choices that
particular driver inbox priorities might prevent. It is a safety
overapproximation of the modeled decision rules, not an exact message-queue,
network, driver, or timeout-scheduler simulation. It makes no liveness or
eventual-delivery claim. Honest nodes may continue modeled same-height actions
after a proof becomes available; omitting finalization-induced stops only adds
possible actions and cannot conceal a conflicting proof.

## State equivalences

Depth-first search retains an actual path and uses these equivalences only for
the visited-state key:

1. A global exchange of A and B preserves all rules and the conflict oracle.
   The exchange applies to locks, valid values, authored roots, vote targets,
   and stored quorum facts. Honest identities are never permuted.
2. The proof wrapper originally emitted by an honest proposer does not affect
   later possibilities: every supported wrapper for that authorized root is
   already available under the abstraction. The key retains the root.
3. Once **every** honest cursor has passed a round, no honest vote or authoring
   event there can change. Future actions need only that round's quorum facts
   for every role/target and its authored roots. Those facts replace individual
   historical vote slots in the key; the actual replay path retains the votes.
4. A node beyond the round bound cannot act again, so its lock and valid state
   do not affect future behavior. Its old emitted messages remain available.
5. Higher-round checkpoint targets have the same successor for a given role
   and destination round. The explorer retains one available target as a
   concrete witness; it does not separately measure every role/target family.

The packed key uses 112 bits. Counts report reduced state classes and generated
successful transitions, including edges to already visited classes. They are
not counts of concrete network schedules. Witnesses and counterexamples are
deterministic first-found paths, not claimed shortest or minimized paths.

## Required evidence and replay

For every Byzantine placement the test requires actual witnesses for both A
and B finality certificates, conflicting-proposal lock retention, a newer valid
proof, nil-quorum lock clearing, close preserving a lock, precommit differing
from the node's own prevote including an actual nil prevote, each higher-round
role, nil-precommit preemption,
and proof-authorized unlocking. With the stated three-round bound, unlocking
necessarily demonstrates `L = 0 < P = 1 < R = 2`.

Every retained witness is replayed through three independently provisioned,
anchored honest node signers in nested `run_with_signing_session` callbacks.
Each honest scope evolves for the entire trace; messages from separately
reopened executions of the same key are never combined. Honest proposal and
vote bytes must be outputs of the actual consuming coordinators. Only the
designated Byzantine key is used for raw signing. The adapter verifies the
independently assumed sorted-key proposer schedule against the real branch.

After each action, the adapter compares round, phase, lock value/round, valid
value/round, and every emitted vote's position, role, and target. Actual vote
batches include only matching messages emitted in this execution plus the
Byzantine signature. Real proposal proof construction and finality sealing
stay outside the independent model.

At the end of each witness, every available complete finality proof is verified
against the original exact parent and committed at all three honest nodes.
The append-only observation list must agree on complete semantic value and
ancestry across recipients and proof rounds. The replacement signers must
reach H2/R0/Proposal. Already-selected evidence variants retain the same value.
Witnesses without a finality proof must produce no finality observation.

Two deliberately weakened models must produce reproducible conflicting-proof
counterexamples: accepting half the total weight as quorum, and losing the
lock at ordinary round close. Each counterexample is replayed through its own
model's enabled actions and rechecked by the oracle. These are test-only
negative controls, not reported production vulnerabilities.

Run the checks with `cargo test -p naome-node safety_model -- --nocapture`.
The replay uses Unix anchored journals and ordinary local I/O. It supplies
selected local coordinator and durable-finality integration evidence, not
exhaustive implementation equivalence, process networking, crash/restart or
I/O-fault coverage, live multi-process agreement, or deployment evidence.
General simulation, resilience, and live-network claims remain unfinished.
