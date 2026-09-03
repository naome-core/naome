# Fixed-Validator Node Current-Round Inbox V0

## Authority and scope

This document defines the bounded, process-local current-round proposal and
proposal-prevote custody used only by `FixedValidatorNodeDriverV0`. It is a
separate resource class from the driver's higher-round recovery inbox so
untrusted current-round traffic cannot consume the capacity reserved for
authenticated higher-round escape.

The inbox owns only:

- fully admitted current-round proposal tokens containing their exact canonical
  proposal-control and artifact-payload inputs;
- complete canonical current-round `Prevote/Proposal(root)` votes already
  authenticated against the exact node-derived fixed-set round;
- checked logical canonical-input accounting; and
- an optional deny-only saturation reason.

The inbox has no signing scope, key, timer, peer identity, network route,
selected-state handle, finality handle, or durable encoding. Retention is not
validity, availability, selection, finality, or provenance authority. Every
proposal and certificate is fully reverified by the existing consuming voting
coordinator before an authority-bearing effect.

## Separate caller-local limits

`FixedValidatorNodeCurrentRoundInboxLimitsV0` contains one positive combined
entry limit and one positive combined logical canonical-input-byte limit.
Proposal accounting is the checked sum of its exact proposal-control and
artifact-payload lengths. One retained prevote is charged the fixed complete
canonical vote length. These limits bound retained input count and logical input
bytes, not allocator overhead or total resident memory, and are local resource
policy rather than consensus-validity limits.

The limits are independent of `FixedValidatorNodeHigherRoundInboxLimitsV0`.
Capacity in one inbox cannot be borrowed from or charged to the other.

## Driver-owned admission

The inbox is not a public raw-input verifier. The driver derives the exact live
round from its private branch and signing session before admitting either
current evidence form.

For `CurrentRoundProposal`, the driver:

1. requires Proposal or Prevote phase and no due observation for that exact
   active phase;
2. applies the canonical payload limit and proposal-control framing preflight;
3. makes the bounded fallible payload copy needed to preserve the original
   owned event on rejection;
4. fully verifies the proposal and payload against the node-derived current
   round; and
5. offers only the resulting private proposal token to the inbox.

For `CurrentRoundProposalPrevote`, the driver likewise requires Proposal or
Prevote phase and no due observation for that exact active phase, then uses the
typed current round to authenticate the complete vote, exact context and
position, active signer, `Prevote` role, and non-nil proposal target before
retention. The event carries no separate caller-supplied position, role, root,
or signer.

The due fence is phase-local. An event admitted before the exact active phase's
due observation may act ahead of that due path. Later current evidence is
returned losslessly until a successful transition invalidates that timer or a
fresh driver is opened. A newly armed Prevote phase may therefore admit the
proposal and votes again, including after strict restart. Precommit rejects
these event forms as stale.

Admission itself performs no signer, lock, finality, candidate-store, or
payload-store mutation. A rejected event returns its original owned byte boxes.

## Retention, duplicates, and saturation

Exact proposal-control-plus-payload replay and exact parent-bound canonical
vote replay are no-growth. Every other fully admitted input consumes one entry
and its exact logical input bytes. The healthy inbox retains byte-distinct
proposal variants, including variants with the same proposal signing root,
competing proposal roots, per-signer signature variants, and competing vote
targets without eviction or arrival-order preference.

Before insertion, the inbox checks entry addition, canonical-input-byte
addition, and both declared limits. A nonduplicate accounting overflow or
declared-capacity failure preserves the retained prefix and exact rejected
event and latches one immutable saturation reason. Collection reservation
failure instead returns the event and error without changing entries, counters,
or saturation.

Once saturation is latched, current evidence admission, current proposal or
quorum action, and current due action remain blocked until explicit current-only
drain-and-reset. This remains true after higher-round advancement because the
retained bytes still consume the separate budget and the driver could not
fairly treat a later current snapshot as complete after denying valid input.
Saturation does not block higher-round evidence admission or action; the driver
always evaluates that independently budgeted escape class first.

## Current proposal classification

For the driver's exact live parent coordinate and position, zero retained
proposals yields no current proposal action and exactly one yields that
proposal's exact inputs for repeated verification. Two or more byte-distinct
fully admitted proposals are ambiguous, including when their proposal signing
roots are equal because optional valid-round proof bytes are outside the
proposal root and may change the lock-directed prevote outcome.

Ambiguity performs no transition, produces no vote, and does not fall through
to due action. While it is live, it denies later current proposal and prevote
admission with exact event return and blocks current action and current due at
that position while preserving every input. It does not block independently
authenticated higher-round admission or action. After such an action advances
the live position, old-position ambiguity is nonactionable, but its bytes remain
charged until explicit drain; no input is pruned or selected by advancement.

The roots returned with an ambiguity reason are diagnostics only. Equal roots
remain ambiguous, and lexicographic order is used only to make those diagnostics
stable, never to prefer or execute one proposal.

## Current proposal-prevote quorum classification

In Prevote phase, and only after exactly one live proposal representation has
been established, the inbox considers retained votes with the exact live parent
coordinate, position, and proposal root. It orders candidates by active signer
and complete canonical bytes, retains the lexicographically smallest canonical
variant per signer for this one local construction, and invokes the existing
typed-round quorum constructor for `Prevote/Proposal(root)`.

An empty or insufficient batch is not actionable. A strict-greater-than-two-
thirds result yields only its canonical certificate bytes for the existing
proposal-quorum voting coordinator. Every other constructor failure is an
internal fail-closed rejection because admission and filtering should already
have established the required identities. Unchosen variants remain retained.

The driver does not silently insert or count the newly returned prevote.
Counting that returned instance requires publication-command custody transfer
followed by ordinary explicit admission. Independently obtained strict-valid
bytes signed by the local key are otherwise ordinary admitted evidence, because
the inbox does not infer transport provenance; exact runtime loopback remains
governed by ordinary duplicate rules.

## Action ordering and custody

With no pending command or higher-round global block, one driver step applies
this order:

1. execute exactly one actionable higher-round pair, if present;
2. enforce current-inbox saturation and live-position proposal ambiguity;
3. in Proposal, reverify the unique current proposal and invoke the existing
   anchored proposal-prevote path;
4. in Prevote, construct a unique matching quorum, then reverify the proposal
   and certificate and invoke the existing anchored proposal-precommit path;
5. otherwise execute only the exact live due path; or
6. remain idle.

A successful current vote queues the existing one-at-a-time
`PublishVote { released_proposal: None }` command, followed by a separately
emitted successor timeout-arm command. The current proposal and all current
prevotes stay in the inbox after both anchored votes until explicit drain or
owner loss; that retention grants no finality authority. Publication, relay,
peer receipt, and durable evidence custody remain runtime responsibilities.

## Drain and restart

`drain_current_inbox_and_reset` returns the continuing driver plus every exact
retained proposal input and canonical prevote. It clears current entries,
accounting, and saturation only. It does not change the higher-round inbox, the
live signing state, due observation, active timer, or pending command, and it
does not tell the caller what to reinsert.

The inbox, ambiguity derived from it, and all retained evidence are volatile.
Driver or process loss drops them. Strict restart reconstructs only existing
journal- and anchor-authorized signer and finality state; a fresh driver starts
with an empty current inbox. Re-admission repeats complete current-round
verification and remains subject to the fresh phase's due fence and configured
limits.

## Exclusions

This inbox does not define or perform:

- proposal authoring, candidate discovery or ranking, artifact fetch, payload
  persistence, or availability certification;
- timeout duration, elapsed-time proof, scheduling, event-loop ownership,
  command acknowledgement, or retry;
- networking, peer authentication, provenance trust, relay, gossip, or evidence
  completeness inference;
- finality, height transition, branch selection, rollback, reorganization,
  candidate promotion, or selected-state mutation;
- nil-quorum collection, higher-round quorum policy, equivocation verdicts,
  punishment, slashing, economics, or dynamic-validator behavior; or
- canonical or durable protocol-wide evidence storage or preference.

These exclusions state that this component grants none of those authorities;
they do not make those capabilities optional for the broader product.
