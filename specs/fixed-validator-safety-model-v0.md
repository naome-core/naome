# Bounded fixed-validator V0 safety model

## Contract and status

`TEST-005-001` and `TEST-005-002` supply finite, independent model checking and selected real
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
`crates/naome-node/src/fixed_validator/tests/safety_model/model.rs` and
`crates/naome-node/src/fixed_validator/tests/safety_model/profiles.rs` use only the
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
- Four distinct validators, starting from zero proposer priorities. The unit
  suite retains all four placements of one Byzantine key among four unit
  weights; the first three proposers are sorted keys 0, 1, and 2.
- The weighted suite enumerates all 6,561 key-ordered vectors with each weight
  in `1..=9`, retaining every placement of one Byzantine key whose weight is
  strictly below one third of the fixed total. All 19,164 eligible vector/fault
  pairs map to 19 behavioral configuration classes, described below. Each class
  is explored completely. The four unit runs are reused within this suite.
- Honest actions in rounds 0, 1, and 2. Advancing out of round 2 reaches a
  terminal exploration cursor at round 3; it creates no round-3 proposal or
  vote. This boundary is not protocol finalization or a durable stop.
- A hard ceiling of 2,000,000 visited reduced state classes per unit placement,
  and 5,000,000 per additional weighted configuration. Exceeding the applicable
  ceiling fails the test as incomplete. There is no successful partial
  search, random sample, elapsed-time cutoff, or additional depth truncation.

Every action advances an honest cursor except proposal authoring, which occurs
at most once per eligible proposer round. There are at most 27 cursor advances
and three honest authoring events on a path. The exploration terminates over
the full reachable graph within the round bounds.

These bounds do not cover arbitrary weight ratios, larger or changing validator
sets, other initial priority vectors or proposer windows, additional semantic
values, multiple heights, malformed input, or cryptographic failure. Separate
full-width arithmetic replays below do not expand the exhaustive graph domain.
These bounds do not establish safety for arbitrary executions.

## Weighted configuration equivalence

For each concrete vector, an independent signed-integer reference computes the
three proposers from zero priorities: rescale only when the spread exceeds
`2 * total`, using the ceiling divisor and truncation toward zero; subtract the
floor average; add each weight; choose the maximum with the lowest sorted key
breaking a tie; subtract the total from the winner. Within this domain and
three-round window, the test additionally checks that each pre-step
normalization is the identity. No production proposer helper is used.

A configuration signature contains the quorum answer for **every** subset of
the three honest validators together with the available Byzantine signature
(eight answers), and the complete three-round proposer sequence. For comparison
only, the fault maps to abstract actor 3 and all six permutations of the honest
actors are considered. Every eligible vector/fault pair is checked against its
representative under an explicit bijection, including the complete truth table
and schedule. Numeric weights affect this model only through those answers and
that schedule, so configurations with the same signature have isomorphic
transition systems and the same conflict oracle.

Each search uses its representative's original sorted-key weights, fault index,
and proposer sequence and a separate visited set. The canonical permutation is
never used to assign weights to new raw keys. Honest identities are not
permuted within a search. A repeated proposer retains its own local lock/valid
state and has a separate authoring slot in every round. The grid includes
ordinary distinct proposers, two-round repetitions, and `[9,1,1,1]` with fault 1,
where honest key 0 proposes in all three rounds.

The eight cooperative answers are sufficient because the model always permits
the Byzantine signature. They do not assert that the other eight exact signer
subsets have identical answers across a class. Actual all-subset arithmetic
verification is limited to the concrete profiles replayed below. Mutation
controls retain their separate unit-weight runs and are outside this quotient.

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

For every unit-weight Byzantine placement the test requires actual witnesses for both A
and B finality certificates, conflicting-proposal lock retention, a newer valid
proof, nil-quorum lock clearing, close preserving a lock, precommit differing
from the node's own prevote including an actual nil prevote, each higher-round
role, nil-precommit preemption,
and proof-authorized unlocking. With the stated three-round bound, unlocking
necessarily demonstrates `L = 0 < P = 1 < R = 2`.

Every weighted class must also produce both A and B finality witnesses. Across
unequal-weight classes the replay corpus additionally requires every transition
category above, honest proposal authoring by the same key in more than one
round, and authoring by the same key in all three rounds. Individual weighted
geometries need not support every category. The tests replay all 48 retained unit
witnesses and 50 selected weighted witnesses: both finality paths per class,
plus each additional category once from an unequal-weight execution. Exploration
continues after collecting witnesses; the safety oracle still checks every new
reduced state class.

Each selected witness is replayed through three independently provisioned,
anchored honest node signers in nested `run_with_signing_session` callbacks.
Each honest scope evolves for the entire trace; messages from separately
reopened executions of the same key are never combined. Honest proposal and
vote bytes must be outputs of the actual consuming coordinators. Only the
designated Byzantine key is used for raw signing. The adapter verifies the
independently computed key-ordered proposer schedule against the real branch.

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

## Full-width arithmetic and exact-subset replay

The arithmetic matrix uses each of the 19 concrete representatives and its
common positive scaling by `floor(u128::MAX / total)`, plus one mixed-scale
boundary profile. This is 39 concrete profiles. Scaling preserves the quorum
ratios and, because all three small-profile normalizations are identity, the
selected schedule. The adapter checks every actual three-round production
schedule, including each scaled case.

For the mixed profile, let `M = u128::MAX = 3k`; its key-ordered weights are
`[2k-1, 1, 1, k-1]`, with fault 1 and expected proposers `[0,3,0]`. The total is
exactly `M`. Subsets `{0}`, `{0,1}`, and `{0,1,2}` have signed weights `2k-1`,
`2k`, and `2k+1`, so they respectively reject, reject at equality, and accept.
An independent wide oracle multiplies by repeated `overflowing_add`, retaining
an explicit carry limb and comparing `(carry, low)` pairs. Checked carry
vectors cover these three boundary sums. It does not use production threshold
helpers or signed `i128` for full-width priorities.

For each profile, the actual round-zero proposer authors a valid value (using
the consuming coordinator when honest), and the three same-execution anchored
honest scopes emit prevotes and then precommits. Only the faulty signature is
fabricated. For each role, all 16 exact distinct-signer subsets, including those
without the fault, are compared with the independent oracle. Empty-batch and
insufficient-weight rejections are checked explicitly, including their exact
signed and total weights. This yields 1,248 role/subset certificate checks and
624 precommit-subset finality-sealing checks. Required nonvacuity includes a
one-signer quorum, a two-signer quorum, a rejected three-signer batch, and exact
two-thirds rejection.

Every accepted precommit subset is sealed against the original parent and
committed at all three honest recipients. Later same-value subsets may return
`AlreadyFinalized`; the append-only observations must preserve complete value
and ancestry, with each signer at H2/R0/Proposal. The matrix verifies these exact
representatives and full-width arithmetic boundaries, not every numeric weight
vector or every execution at full width.

Run the checks with `cargo test -p naome-node safety_model -- --nocapture`.
The replay uses Unix anchored journals and ordinary local I/O. It supplies
selected local coordinator and durable-finality integration evidence, not
exhaustive implementation equivalence, process networking, crash/restart or
I/O-fault coverage, live multi-process agreement, or deployment evidence.
General simulation, resilience, and live-network claims remain unfinished.
