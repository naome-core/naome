# Fixed-Validator Node Current-Round Finality Inbox V0

## Authority and scope

This document defines one bounded, process-local proposal-finality evidence
inbox owned only by `FixedValidatorNodeDriverV0`. It retains complete proposals
and individually authenticated proposal precommits for the driver's exact live
fixed-validator V0 round so the driver can compose either one uniquely ready
proposal/certificate pair or the first two complete conflicting pairs for the
node-owned current-round finality coordinators.

The inbox itself remains evidence custody rather than finality authority. It
owns only:

- fully admitted proposal inputs containing their exact canonical
  proposal-control and artifact-payload bytes;
- complete canonical `Precommit/Proposal(root)` votes already authenticated
  against the exact node-derived current round;
- checked logical canonical-input accounting and one class-local saturation
  reason; and
- deterministic, non-authoritative classification of one complete healthy
  retained snapshot or an already retained structurally complete conflict pair
  after saturation.

It has no signing scope, private key, timer, finality handle, selected-state
handle, candidate or payload store, peer identity, or network route. Retention,
quorum classification, and a selected local evidence representation do not
establish proposal availability beyond the retained payload, branch selection,
finality, or a height transition. Only the owning driver's fixed step policy may
copy a uniquely ready pair into `commit_current_round_finality` or two complete
conflicting pairs into `commit_current_round_preselection_conflict`; each
consuming coordinator repeats complete verification and alone holds its
respective ordinary-finality or terminal-halt authority. The driver never calls
the vote-batch sibling from retained evidence.

## Separate caller-local limits

`FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0` contains one positive
combined entry limit and one positive combined logical canonical-input-byte
limit. A proposal is charged one entry and the checked sum of its exact
proposal-control and artifact-payload lengths. Every proposal precommit is
charged one entry and its fixed complete 214-byte canonical vote length.

These limits are independent of both
`FixedValidatorNodeCurrentRoundInboxLimitsV0` and
`FixedValidatorNodeHigherRoundInboxLimitsV0`. Capacity cannot be borrowed or
charged across those three resource classes. The limits bound retained input
count and logical canonical input bytes, not allocator overhead, aggregate
event rate, protocol-wide evidence, or total resident memory.

## Driver-owned event admission

The driver accepts two distinct event forms for this inbox:

- `CurrentRoundFinalityProposal` carries complete canonical proposal-control
  bytes and the owned complete canonical artifact payload; and
- `CurrentRoundProposalPrecommit` carries one complete canonical signed vote.

Neither event carries a caller-supplied round, target, role, root, or signer.
`CurrentRoundFinalityProposal` is never automatically fanned out from or into
`CurrentRoundProposal`; each event has one explicit destination, reservation,
accounting result, and lossless rejection path. The finality inbox's later local
representative rule does not change the current voting inbox's fail-closed
treatment of byte-distinct same-root proposals before a prevote is chosen.
The existing pending-command custody gate runs first and returns the complete
event without inspection. Otherwise, finality admission is
independent of current- or higher-inbox saturation and ambiguity and does not
consult the phase-local due fence. Proposal, Prevote, and Precommit phases may
all admit evidence for the unchanged exact live position, whether or not that
phase's timer has been marked due. A successful position-advancing driver
transition changes the live position; it does not relabel retained evidence
from the former position.

For a finality proposal, the driver reconstructs its exact live branch round,
applies the existing bounded payload and proposal-control framing preflights,
makes the fallible bounded copy needed to preserve event ownership on
rejection, and completely verifies the proposal control, producer
authorization, parent, state commitment, artifact transition, and payload
against that round. Only the resulting private proposal token enters the
finality inbox.

For a proposal precommit, the driver reconstructs the same typed round and
uses its narrow active-proposal-precommit verifier. The complete vote must
strictly authenticate the branch context, exact position, `Precommit` role,
non-nil proposal root, signature, and membership of the signer in that round's
immutable active fixed-validator snapshot. `Precommit/Nil`, a stale or future
position, another context, an inactive signer, malformed bytes, or an invalid
signature is returned without retention. Nil-precommit collection and round
progression are a later scope.

Admission performs no signing, lock, valid-value, timer, finality, branch,
candidate-store, payload-store, or selected-state mutation. Every rejected
event returns its original owned byte boxes.

## Retention, duplicates, and class-local saturation

Exact proposal-control-plus-payload replay and exact parent-bound canonical
precommit replay are no-growth. Every other fully admitted input consumes one
entry and its exact logical input bytes. While healthy, the inbox retains every
byte-distinct same-root proposal representation, competing-root proposal,
same-semantic signature variant, competing proposal target, and signer input
without eviction or arrival-order preference.

Before insertion, the inbox checks entry addition, canonical-input-byte
addition, and both declared limits. The first nonduplicate checked-accounting
overflow or declared-capacity failure preserves the complete retained prefix
and exact rejected event and latches one immutable finality-class saturation
reason. Later finality events are returned losslessly until explicit
finality-only drain-and-reset. Collection reservation failure instead returns
the event and source without changing entries, counters, or saturation.

Saturation makes the retained prefix ineligible for unique-finality or
missing-proposal classification because a valid input was denied. One monotonic
exception applies: if the retained prefix already contains two distinct roots
that each have a matching retained proposal and enough retained precommits to
form a strict-supermajority certificate, that complete pair remains eligible for
terminal safety handling. The denied input never participates. The pair cannot
become incomplete merely because a later input was rejected.

Before deriving a typed round under saturation, the driver performs only a
bounded structural precheck that the exact live parent and position retain at
least one proposal and precommit for each of two distinct roots. If not, the
class remains nonclassifiable and falls through without round reconstruction.
If the full classifier does not prove two complete proposal-backed quorums, the
saturated prefix likewise falls through. Saturation does not block admission or
action in the separately budgeted higher or current voting inboxes. This keeps
an incomplete signature-variant flood from obtaining whole-driver denial-of-
service authority while preventing later saturation from erasing already
retained complete safety evidence. Per-semantic-key caps, peer rate control, and
protocol-wide retained-variant limits remain separate unresolved resource and
networking policy.

## Complete-snapshot classification

The classifier is part of the ordinary implementation but remains
crate-private and returns no public command, runtime observation, raw signing
scope, or caller-invokable finality path. Its inbox-internal result may borrow
the chosen proposal bytes and own the constructed certificate bytes so the
private driver execution path can fallibly copy the complete pair before
releasing any inbox borrow or consuming the signing scope. The crate-private
diagnostic adapter deliberately discards those bytes and retains only a
position-and-root descriptor for its ready or missing-proposal cases.
Classification uses the driver's exact unchanged live parent coordinate and
position. It evaluates matching roots in ascending order. A healthy zero- or
one-quorum result exhausts the set. Once multiple roots are quorate, the
classifier continues past roots without a retained proposal until it finds the
first two proposal-backed quorums or exhausts the retained set. Under saturation
it may return only that complete pair; every other result remains saturated and
nonclassifiable.

Proposal precommits are grouped by authenticated proposal root and then by
active signer. For each `(proposal root, signer)` pair, every variant remains
retained while the lexicographically smallest complete 214-byte canonical vote
is used solely for this local construction. That signer contributes its exact
active weight once to that root. The same signer may contribute once to another
root, which assigns no equivocation, fault, or punishment meaning. Offline
active weight remains in the unchanged denominator.

The selected variants for each evaluated root enter the existing exact-batch
constructor with the required `Precommit/Proposal(root)` role and target. Empty evidence,
insufficient weight, and exact two-thirds equality are not quorate. A strict
greater-than-two-thirds result authenticates only one canonical certificate for
that retained root; it does not finalize or select a proposal.

Every byte-distinct proposal representation remains retained. For a quorate
root with at least one matching fully admitted proposal, classification chooses
the lexicographically smallest
`(canonical_proposal_control_bytes, canonical_artifact_bytes)` tuple solely as
the stable local representative. This operation-local classifier treats
same-root variants as representations of one opaque target and makes no
conflict or equivocation verdict about them. Optional valid-round proof bytes do
not enter the established final envelope, but choosing the tuple can still
choose one producer-authorization and envelope-evidence representation. This
local choice does not define a globally canonical proposal representation,
producer authorization, envelope identity, certificate, signer subset, or
evidence preference.

The complete classification distinguishes:

1. no quorate proposal root;
2. exactly one quorate root with no retained matching proposal;
3. exactly one quorate root with at least one retained matching proposal and
   therefore one execution-ready local proposal/certificate pair; and
4. two or more quorate roots with fewer than two proposal-backed quorums; and
5. the first two proposal-backed quorate roots in ascending root order.

The fourth case chooses no root, proposal, certificate, branch, or winner and
remains a process-local blocking classification while healthy. The fifth case
retains both selected proposal tuples and independently constructed canonical
certificates only as inputs for complete re-verification. Its ascending order is
canonical witness order, never winner order, and it remains actionable after a
later saturation latch. Neither case is itself a durable finality conflict,
equivocation verdict, or proof that every node observed the same set. An
explicit classifier scratch-reservation failure or a typed certificate-
construction rejection changes no retained input or driver authority state and
cannot fall back to a partial prefix. This does not claim exhaustive process-
allocation-failure recovery inside reused infallible encoders.

## Driver finality execution and priority

`FixedValidatorNodeDriverV0::step` first transfers any pending command. With no
pending command, it classifies the exact-current finality inbox before any
higher-round, nil-precommit, current-voting, or due work, including before
voting-class block states. The healthy classifications, paired safety result,
and saturation have distinct effects:

A latched saturation without the structural possibility of a complete retained
pair, or the absence of an exact branch-coordinate/current-position precommit,
is resolved before sequential proposer-round reconstruction. This is a local
work bound only; it neither classifies a quorum nor grants validity or finality
authority.

1. no quorate root falls through to the existing higher, current, and due
   sequence;
2. while the inbox remains healthy, one quorate root without its matching
   proposal blocks that lower-priority work until a matching proposal is
   admitted or the finality inbox is explicitly drained;
3. one uniquely proposal-backed quorum is execution-ready and runs before all
   lower-priority work; and
4. while the inbox remains healthy, multiple quorate roots with fewer than two
   matching proposals choose no winner and block lower-priority work until more
   proposal evidence arrives or explicit finality drain; and
5. two proposal-backed quorate roots are terminally actionable before every
   lower-priority class, including after later finality saturation.

Finality-class saturation alone is not actionable. Absent a complete retained
pair, it remains class-local and falls through to higher, nil-precommit,
current, and due work so a valid same-semantic signature-variant flood cannot
obtain whole-driver stop authority. If a later denied distinct finality event
latches saturation over a formerly healthy missing-proposal or incomplete
conflicting-root prefix, saturation supersedes that derived block and restores
the same lower-priority fallthrough until explicit finality drain resets the
class. It does not supersede a complete retained proposal-backed pair.
Missing-proposal and conflicting-root blocks are derived from the exact live
position rather than latched across heights. Finality admission remains
available while either derived block is present, so the missing proposal may
complete the pair; no block grants discovery, acquisition, eviction, or durable
conflict-recovery authority.

For one uniquely ready pair, the driver first fallibly owns the selected
proposal-control and artifact bytes and retains the classifier-built canonical
precommit certificate. It preflights the next timer generation before consuming
the sole signing scope, then calls only `commit_current_round_finality`. The
coordinator reconstructs the exact current round, completely reverifies the
proposal, payload, producer authorization, snapshot, and certificate, seals the
transition, and alone performs the anchored finality-to-signer height handoff.
The classifier is therefore never cached validity or finality authority.

For a ready conflict pair, the driver fallibly owns both proposal-control,
artifact, and certificate triples without preflighting a successor timer that
will never exist. The node-owned coordinator derives the exact current round
once, independently re-verifies and seals both triples against the same parent,
and only then lets the anchored finality journal append its one neutral tag-`03`
halt. The resulting exact-anchor capability is routed into the signer as tag
`0b`. Success returns only the paired terminal diagnostics: neither transition
becomes selected, no driver or signing scope survives, the active timer is not
replaced, and no command or vote is emitted.

A pre-effect coordinator rejection restores the returned unchanged scope into
the same driver and preserves every inbox, timer, due observation, and latch.
A successful new finality returns the existing typed selection, installs the
returned child-height round-zero Proposal scope, invalidates the old timer and
due observation, and queues one child-phase arm command for a later step. The
defensive already-finalized continuation returns its typed selection without
claiming a height change or replacing the existing timer. A durable finality
stop returns only its existing paired stop evidence; any fatal coordinator
error returns no driver or scope, and strict anchored restart remains the only
recovery classifier.

## Drain, advancement, and restart

`drain_current_finality_inbox_and_reset` returns the continuing driver
plus every exact retained proposal input and canonical proposal precommit. It
clears only finality-inbox entries, accounting, and saturation. It does not
change either existing voting inbox or its ambiguity state, the live signing
scope, lock or valid value, timer, due observation, pending command, finality
journal, signer journal, anchors, or any retained source store, and it grants no
reinsertion order or evidence preference.

A higher, current, due, or successful finality action may advance the live
position. Evidence retained for the former position remains byte-charged but
nonmatching until its class-specific lossless drain; the driver does not
silently prune, relabel, or route it as lower-round evidence. In particular, a
successful finality transition preserves every higher, current-voting, and
current-finality inbox byte, counter, saturation state, and ambiguity latch.
Those stale volatile owners can block later work under their existing policies
until explicitly drained. Only the old timer and due observation are replaced
by the child-height timer sequence.

The finality inbox, its accounting, and every classification are volatile.
Driver or process loss drops them. Strict restart reconstructs only the
existing journal- and anchor-authorized signer and finality state; a fresh
driver starts with an empty finality inbox. Proposal and precommit inputs must
be explicitly redelivered and fully reverified against the fresh current
position. Locally signed precommits are never self-counted; they require the
same explicit event admission as any independently obtained canonical vote.
After a successful paired halt, strict restart obtains the terminal finality
and signer evidence solely from their two anchored journals; it never depends
on reconstructing the volatile inbox or either embedded proposal as a selected
branch.

## Determinism and exclusions

For the same exact live branch state, finality limits, and retained set, every
insertion-order permutation yields the same classification, proposal
representatives, per-signer precommit representatives, and canonical
certificate bytes. This includes the same retained complete conflict pair under
a later saturation latch; denied inputs remain outside the compared set. This
is a process-local frozen-snapshot claim only. It does not establish equal
evidence views across nodes, delivery completeness, fairness across drain and
reinsertion, or independence from when an external runtime submits an event or
requests classification.

This inbox and its driver integration do not define or perform:

- caller-, peer-, or arrival-order-selected finality; lower- or candidate-backed
  finality routing; rollback; reorganization; candidate promotion; sibling-
  winner choice; or any durable conflict beyond the exact two-complete-root
  neutral halt delegated to the node-owned coordinator;
- nil-precommit collection, nil-quorum round progression, higher- or
  lower-round finality routing, proposal authoring, or self-observation;
- proposal discovery, artifact fetch, payload persistence, availability
  certification, or candidate- or payload-store mutation;
- timeout duration, elapsed-time proof, scheduling, asynchronous event-loop
  ownership, command acknowledgement, or retry;
- networking, peer authentication, provenance trust, relay, gossip, peer rate
  control, or evidence-completeness inference;
- equivocation verdicts, punishment, slashing, economics, or dynamic-validator
  behavior; or
- canonical or durable protocol-wide evidence storage, signer-subset or
  representation preference, per-semantic signature-variant caps, or total
  resident-memory bounds.

These exclusions state that this component grants none of those authorities;
they do not make those capabilities optional for the broader product.
