# Fixed-Validator Node Finality V0

## Authority and scope

This document defines the synchronous live-finality coordination boundary for
one closure-scoped fixed-validator V0 node signer. It composes the existing
sealed consensus transition, exact-current-round proposal-sealing boundary, or
candidate-backed verification boundary with the anchored finality journal and
anchored per-key vote-safety session. It creates no way to select or rank a
transition.

The sealed-transition ingress accepts one
`OwnedVerifiedFixedConsensusTransitionV0`. Its private fields prove that
complete typed branch verification already bound the exact parent coordinate,
consensus position, value, canonical envelope, canonical artifact payload, and
immutable child branch.

The supplemental exact-current-round ingress instead accepts separate complete
canonical proposal-control bytes, one owned complete canonical artifact
payload, one exact canonical non-nil precommit certificate, and an inclusive
caller-local round ceiling. It derives the signer's exact current round from the
node-owned branch and signer position, fully admits the proposal against that
round, seals it only with a matching certificate, and converts the result to the
same private-field owned transition before finality begins. The caller supplies
no round cursor, snapshot, parent, proposer, proposal root, or transition.

This direct ingress is supplemental rather than the node's sole finality
policy. It handles only evidence for the signer's exact current branch round.
The existing sealed-transition and candidate-backed ingresses remain separate;
this path does not define how late evidence for a lower round is routed, replay
an already selected value, or admit a selected-height sibling conflict.

The candidate-backed direct-child ingress instead requires one exact
caller-selected unselected direct-child `ArtifactBlockId`, caller-routed
matching-chain candidate and Foundation payload stores, one complete canonical
finality envelope, and an inclusive caller-local round ceiling. The existing
candidate-backed finality boundary integrity-reads the exact retained block and
payload, fully verifies the envelope against the current selected head under
both round ceilings, and only then commits the internally sealed transition.

The separate candidate-backed conflict ingress accepts the same explicit input
shape only for a height already retained by finality. It rejects an
evidence-free value equal to the selected value before source reads, fully
verifies a preliminarily distinct value against that height's exact retained
selected parent, and admits only the existing terminal sibling-conflict result.
The stores supply availability bytes only and receive no durable mutation;
source-integrity failures retain each store's existing poison-and-reopen
boundary.

For every ingress the caller explicitly chooses the one transition, exact input
set, or target to submit. That choice does not grant peer evidence, candidate
availability, or this coordinator any truth, preference, fork-choice, or
finality authority beyond complete typed verification and the finality
journal's existing rules. Neither candidate-backed form discovers a target or
promotes a suffix, and only the deny-only conflict form admits a fully verified
selected-height sibling without selecting either value.

The operation consumes `FixedValidatorNodeSigningScopeV0`. The scope retains a
mutable finality borrow internally, but exposes only read-only finality
diagnostics to callers. Its public `FixedValidatorNodeVotingSessionV0` facade
exposes read-only diagnostics and explicit bounded round control, but withholds
current-round decision, vote-preparation, acknowledgement, key-use, finality
height-transition, and conflict-stop methods. The consuming node-voting
coordinator owns the complete current-round durable sequence. The
node-owned finality journal is therefore the exclusive source of height and
stop authority for this scope. Only `commit_verified_finality`,
`commit_current_round_finality`, and `commit_candidate_backed_finality` may
couple its height capability into the signer. `commit_verified_finality` and
the separate `commit_candidate_backed_finality_conflict` may couple only an
exact anchored sibling-conflict capability into the signer. There is no public
mutable-journal or raw signing-session escape hatch. A continuation scope is
returned only by a complete nonterminal outcome; the candidate conflict method
has no continuation return type.

## Exact-current-round admission

The exact-current-round ingress performs a bounded pre-effect stage before it
consumes the scope into the existing finality commit:

1. Read the node-owned finality journal's persisted round ceiling and the
   signer's current position, derive round zero from the node-owned branch, and
   require the branch's next height to equal the signer height.
2. Require the signer round not to exceed the persisted finality ceiling, then
   compare it separately with the caller's inclusive ceiling and reconstruct
   that exact round sequentially.
3. Fully verify the separate proposal-control and owned artifact bytes against
   that branch-derived round, including context, height, ancestry, fixed set,
   scheduled proposer, state commitment, artifact transition, payload, producer
   authorization, and any earlier valid-round proof.
4. Fully verify and seal the admitted proposal with the supplied certificate,
   requiring non-nil precommit role and the exact same context, height, current
   round, proposal signing root, and positioned fixed-set snapshot.
5. Convert the sealed branch-relative proof to one
   `OwnedVerifiedFixedConsensusTransitionV0`; only then consume the scope into
   the ordinary finality commit and signer-height handoff.

This pre-effect derivation deliberately does not require the vote-safety session
to report current-vote readiness. A pending signer operation cannot suppress
otherwise valid finality: finality may become durable first and the subsequent
signer-height handoff may then fail under the existing consume-and-restart
contract. The path still treats a branch/signer height mismatch, round
reconstruction failure, or signer position above the persisted finality ceiling
as a node-coherence failure rather than caller input rejection.

A caller-ceiling violation, proposal rejection, or certificate rejection occurs
before a transition or finality effect exists and returns the same unchanged
signing scope with a typed rejection. None of those paths changes volatile
signer state or either journal or anchor. Submission, successful framing, or
caller classification alone grants no proposal, certificate, or finality
authority.

## Ordered transitions

`commit_verified_finality` applies exactly one sealed transition in this order:

1. Consume the transition through the anchored finality journal. A new record
   is published only after its journal footer and independent finality anchor
   synchronize under the existing journal contract.
2. If one new direct child finalized, issue the exact retained
   finality-to-signer height capability for that finalized height.
3. Consume that capability through the sole live signing session. The vote
   journal preflights the current lineage and pending state, appends the exact
   sequential child lineage, and advances the independent signer anchor before
   returning its prepared-height capability.
4. Acknowledge that exact anchored capability to move signer memory to the
   sealed child's round zero.
5. Only then return a replacement signing scope containing that child branch,
   the advanced node-scoped voter, and read-only diagnostics for the same
   selected finality head.

The transition is not a cross-file transaction. A later failure never removes,
replaces, rolls back, or reinterprets an earlier durable journal or anchor
step.

`commit_current_round_finality` first completes every exact-current-round
admission step above without changing node state. It then delegates only the
resulting owned transition to `commit_verified_finality` and enters the complete
five-step anchored finality and signer handoff. Once that commit begins, every
rejection or ambiguous durability result consumes the scope, and strict restart
remains the only durable-prefix classifier. The exact-current branch-relative
construction names one unselected direct child, so this ingress claims neither
the sealed ingress's already-selected replay result nor either sibling-conflict
path.

`commit_candidate_backed_finality` first applies the complete read-only source
and envelope verification described above. It then commits exactly one new
direct child through the same anchored finality pair and enters steps 2 through
5 of the shared signer handoff. One explicit call advances at most one height.
The candidate and payload stores are not participants in either anchored pair
and receive no durable insert, replacement, mark, refresh, or deletion from
this call.

`commit_candidate_backed_finality_conflict` consumes the scope and applies the
deny-only selected-height preflight and complete retained-parent verification
described above. A same-selected-value or unselected-height input returns an
error and no scope before source access. A distinct value can reach finality
only after complete authentication; its anchored terminal halt then enters the
same stop-capability and signer-stop sequence as the sealed-transition path.
The method returns only the paired terminal evidence after both anchors advance.

## Nonterminal outcomes

A newly selected direct child returns `Finalized` metadata naming its exact
authenticated position, ancestry identity, complete-envelope identity, and
anchored finality state identity. Continued signing authority appears only
beside this metadata after the ordered signer handoff completes.

An exact-current caller-cap, proposal, or certificate rejection returns a typed
reason together with the unchanged signing scope. It is a pre-effect outcome,
not a finality-commit error, and therefore carries no finality selection
metadata. Exact-current success uses the ordinary `Finalized` result; it does
not introduce another finality identity or authority source.

A candidate-backed child returns `CandidateBackedFinalized` metadata naming
the exact caller-selected target plus the same authenticated position,
ancestry, complete-envelope, and finality-state identities. It returns beside
continued signing authority only after the same complete signer handoff. The
candidate-backed direct-child boundary has no replay or conflict result; stale,
deep, already-selected, or sibling input is rejected instead.

If the generic sealed-transition ingress's exact value is already selected at
its retained height, the finality journal returns `AlreadyFinalized`. This
classification is based on the selected value, not on byte identity of its
evidence variant: a later round may carry a different valid envelope for the
unchanged value. The retained first envelope identity remains authoritative,
neither journal or anchor writes, and the already aligned branch and signer are
returned unchanged. The replay does not replace finality evidence or move the
signer. The exact-current ingress does not claim this replay classification.

An unselected parent, unsupported future gap, excessive authenticated round,
terminal journal, poisoned handle, or other finality rejection returns no
continuation scope even when the rejection itself wrote no byte. This strict
consume-on-error rule prevents callers from treating error categories as a
second signing-authority protocol.

## Conflict outcome

When the generic sealed-transition or candidate-backed conflict ingress makes
the finality journal durably admit a distinct verified sibling of an already
selected value, it appends and anchors its existing terminal conflict record.
The coordinator then obtains only that halt's opaque signer-stop capability and
consumes it through the current signing session. The stop preempts pending vote,
height, or higher-round work under the existing signer contract. The
candidate-backed ingress cannot reach this step from store presence, peer
provenance, a merely decoded value, or a selected-value replay; complete
branch-relative verification is mandatory. The exact-current direct-child
ingress is not a sibling-conflict path and makes no such outcome claim.

Only after the signer-stop record and independent vote anchor synchronize does
the coordinator return `FinalityStopped`, pairing the exact finality halt with
the matching per-key stop. It never returns a branch or signing scope from this
path. The conflict records evidence and stops; it does not choose a winning
sibling, roll back the retained selected value, or revoke bytes that a caller
already received before the stop.

## Failure and restart

Every error after an owned transition enters finality consumes the scope and
returns no signing authority. Exact-current caller-ceiling, proposal, and
certificate failures are earlier typed rejection outcomes that return the
unchanged scope. Error stages distinguish:

- finality commit rejection or ambiguous finality durability;
- exact-current node-coherence failure before finality admission;
- candidate source or envelope rejection, or ambiguous candidate-backed
  finality durability;
- failure to issue height authority after known finality success;
- signer child-lineage prepare or live acknowledgement failure after known
  finality success;
- failure to issue stop authority after a known finality halt; and
- signer-stop persistence failure after a known finality halt.

Errors after a known finality result retain that `Finalized` or
`CandidateBackedFinalized` metadata or exact halt. This is diagnostic evidence
of ordering, not rollback or repair authority. A pending vote can therefore
leave a newly finalized child durable while the signer remains pending at its
prior lineage; the call returns no scope. Strict create-or-restart handling is
the only classifier for the actual anchored prefixes. Exact matching pairs may
resume through the existing recovery and selected-suffix catch-up rules. A
complete journal suffix ahead of its independent anchor remains an explicit
anchor-behind failure requiring separate operator recovery policy.

## Exclusions

This coordinator does not define or perform:

- proposal authoring or producer signing;
- consensus event routing, phase scheduling, timeouts, or asynchronous daemon
  ownership;
- proposal, vote, quorum-certificate, or competing-evidence buffering,
  collection, construction, or preference;
- network transport, peer discovery, provenance trust, or peer-selected
  admission;
- late or lower-round finality-event routing, any claim that exact-current input
  is the node's sole finality policy, or automatic finality retry;
- candidate discovery, branch discovery, sibling ranking or winner selection,
  rollback, source mutation, or multi-height promotion;
- cross-journal atomicity, automatic repair, or operator crash-gap recovery;
- dynamic validator sets, multi-key stop fanout, key loading, rotation, remote
  signing, or production custody; or
- non-Unix file-anchor runtime guarantees or coordinated-device rollback
  detection.

The exclusive node-owned source rule is a node integration boundary only. It
does not change the lower-level storage contract, where independently opened,
content-equivalent histories may still produce semantically equivalent opaque
capabilities for storage-layer recovery tests. Those capabilities cannot enter
this node's public voting facade.

These are separate required product capabilities, not unnecessary work. The
candidate-backed integration intentionally stops at the already decided
caller-selected one-target direct-child or deny-only conflict boundary. Any
automatic selection, peer-driven promotion, or conflict-triggering policy
requires a separate explicit authority and policy decision. The exact-current
integration intentionally stops at separate complete caller-supplied bytes for
the signer's current branch round; it neither replaces the other finality
ingresses nor infers that no other finality evidence exists.
