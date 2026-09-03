# Fixed-Validator Node Current-Round Finality Inbox V0

## Authority and scope

This document defines one bounded, process-local proposal-finality evidence
inbox owned only by `FixedValidatorNodeDriverV0`. It retains complete proposals
and individually authenticated proposal precommits for the driver's exact live
fixed-validator V0 round so a later driver slice can compose them with the
existing current-round finality coordinator.

This is a finality foundation, not a finality transition. The inbox owns only:

- fully admitted proposal inputs containing their exact canonical
  proposal-control and artifact-payload bytes;
- complete canonical `Precommit/Proposal(root)` votes already authenticated
  against the exact node-derived current round;
- checked logical canonical-input accounting and one class-local saturation
  reason; and
- deterministic, non-authoritative classification of one complete healthy
  retained snapshot.

It has no signing scope, private key, timer, finality handle, selected-state
handle, candidate or payload store, peer identity, or network route. Retention,
quorum classification, and a selected local evidence representation do not
establish proposal availability beyond the retained payload, branch selection,
finality, or a height transition. This slice never calls
`commit_current_round_finality`,
`commit_current_round_finality_vote_batch`, or any other finality operation.

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
event without inspection. Otherwise, finality-foundation admission is
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
reason. Later finality-foundation events are returned losslessly until explicit
finality-only drain-and-reset. Collection reservation failure instead returns
the event and source without changing entries, counters, or saturation.

Saturation makes the retained prefix ineligible for finality classification
because a valid input was denied. It does not block admission or action in the
separately budgeted higher or current voting inboxes and does not block the
existing driver `step`. This class-local rule is deliberate: before the driver
has an executing finality path, one active signer must not obtain whole-driver
denial-of-service authority merely by supplying many valid signature variants.
Per-semantic-key caps, peer rate control, and protocol-wide retained-variant
limits remain separate unresolved resource and networking policy.

## Complete-snapshot classification

The classifier is part of the ordinary implementation but remains
crate-private and returns no public command, runtime observation, raw signing
scope, or caller-invokable finality path. Its inbox-internal result may borrow
the chosen proposal bytes and own the constructed certificate bytes so the
private driver adapter can classify the complete pair. The driver-level result
then deliberately discards those bytes and retains only a position-and-root
descriptor for its ready or missing-proposal cases. Classification is available
only for one healthy unsaturated retained snapshot and the driver's exact
unchanged live parent coordinate and position. It first derives the complete
matching root set and evaluates roots in ascending order. A zero- or one-quorum
result exhausts that set; a multiple-quorum result may return after the first
two quorate roots because no later root can restore uniqueness.

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

The complete healthy classification distinguishes:

1. no quorate proposal root;
2. exactly one quorate root with no retained matching proposal;
3. exactly one quorate root with at least one retained matching proposal and
   therefore one foundation-ready local proposal/certificate pair; and
4. two or more quorate roots.

The last case chooses no root, proposal, certificate, branch, or winner. It is
process-local conflicting-evidence classification only, not a durable finality
conflict record, terminal halt, equivocation verdict, or proof that every node
observed the same set. An explicit classifier scratch-reservation failure or a
typed certificate-construction rejection changes no retained input or driver
authority state and cannot fall back to a partial prefix. This does not claim
exhaustive process-allocation-failure recovery inside reused infallible
encoders.

## No driver-step effect

This foundation does not participate in `FixedValidatorNodeDriverV0::step`.
Foundation readiness, missing-proposal classification, multiple quorate roots,
and finality-class saturation neither produce a driver command nor block,
reorder, or replace the existing pending-command, higher-round, current-round,
or due sequence. The step performs no hidden finality inspection or finality
effect.

This deliberate boundary avoids adding a volatile attacker-influenceable
whole-driver block before the same driver can actually complete finality. A
later finality-execution slice must specify its own exact ordering, repeat all
proposal and certificate verification through the existing consuming finality
coordinator, and define how ready, incomplete, saturated, and conflicting
evidence affect progress. This specification grants none of that later
authority.

## Drain, advancement, and restart

`drain_current_finality_inbox_and_reset` returns the continuing driver
plus every exact retained proposal input and canonical proposal precommit. It
clears only finality-inbox entries, accounting, and saturation. It does not
change either existing voting inbox or its ambiguity state, the live signing
scope, lock or valid value, timer, due observation, pending command, finality
journal, signer journal, anchors, or any retained source store, and it grants no
reinsertion order or evidence preference.

A higher, current, or due driver action may advance the live position because
this foundation has no step effect. Evidence retained for the former position
then remains byte-charged but nonmatching until finality-only drain; the driver
does not silently prune, relabel, or route it as lower-round evidence.

The finality inbox, its accounting, and every classification are volatile.
Driver or process loss drops them. Strict restart reconstructs only the
existing journal- and anchor-authorized signer and finality state; a fresh
driver starts with an empty finality inbox. Proposal and precommit inputs must
be explicitly redelivered and fully reverified against the fresh current
position. Locally signed precommits are never self-counted; they require the
same explicit event admission as any independently obtained canonical vote.

## Determinism and exclusions

For the same exact live branch state, finality limits, and complete healthy
retained set, every insertion-order permutation yields the same classification,
proposal representative, per-signer precommit representatives, and canonical
certificate bytes. This is a process-local frozen-snapshot claim only. It does
not establish equal evidence views across nodes, delivery completeness,
fairness across drain and reinsertion, or independence from when an external
runtime submits an event or requests classification.

This inbox does not define or perform:

- finality commit, height transition, branch or sibling selection, rollback,
  reorganization, candidate promotion, conflict halt, or selected-state
  mutation;
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
