# Fixed-Validator Node Driver V0

## Authority and scope

This document defines one synchronous, closure-scoped, partial fixed-validator
V0 driver. The driver is the first node-owned control boundary above the
existing exact-event coordinators. For its lifetime it privately owns:

- the sole live `FixedValidatorNodeSigningScopeV0`;
- one existing bounded process-local higher-round proposal/prevote inbox;
- one separately bounded process-local current-round proposal/proposal-or-nil-
  prevote inbox;
- one independently bounded process-local current-round proposal-finality
  proposal/precommit inbox;
- one current phase-timer lineage and its checked generation;
- at most one timeout-due observation for that exact lineage; and
- at most one next outward command.

The driver accepts complete current- or higher-round proposals that it fully
admits into the existing private token boundary, complete canonical current-
round proposal or nil prevotes and higher-round proposal prevotes that it
independently admits against the exact node-derived fixed-set round, distinct
complete finality-proposal inputs and individual current-round proposal
precommits for its dedicated finality foundation, and opaque timeout tickets
that the same driver issued. One explicit step derives the live node identity,
classifies the complete healthy voting-inbox state, and invokes at most one
existing consuming node coordinator. It emits at most one timeout-arm or
signed-vote command. It does not expose the owned signing scope as an
alternative caller-controlled path.

This remains a partial driver boundary. Its input surface now covers current-
and higher-round proposal/prevote evidence, current-round nil prevotes,
current-round finality proposals and proposal precommits, and exact
driver-issued timeout-due tickets. It drives a current proposal through an
anchored prevote and one sole matching current proposal or nil prevote quorum
through an anchored precommit. The separately retained proposal-finality class
only classifies a healthy exact-current snapshot; it has no step effect and
performs no finality or height transition. Current-round finality execution,
lower- or candidate-backed finality routing, proposal authoring, networking,
and artifact-payload persistence remain outside this driver.

This ownership moves event choice out of a caller that could otherwise select
an inbox position or invoke a phase close directly. It does not make retained
evidence, a timeout ticket, a peer, or the driver itself a new source of
consensus validity. Every authority-bearing transition remains the existing
fully verifying, journal- and anchor-gated node operation.

## Construction and process-local lifecycle

Construction takes one live signing scope, separate positive current-voting,
higher-round, and current-finality inbox limits, and the existing inclusive
caller-local round-work ceiling. The driver owns every
subsequent replacement scope returned by a successful consuming operation. It
is not cloneable and provides no accessor that returns or borrows the raw scope
for mutation. Read-only diagnostics may expose the live context, position,
phase, separate inbox accounting, timer identity, and pending-command state
without granting transition authority. Finality-foundation classification
remains crate-private and produces no runtime-facing diagnostic.

Construction is consuming. If construction fails, it returns neither a driver
nor the supplied signing scope. The caller must strictly reopen the anchored
signer state before retrying; no construction error grants a reusable scope.

The driver, its inboxes, timer lineage, due observation, and pending command have
no canonical or durable encoding. Process or runtime-owner loss, including a
fatal coordinator outcome that returns no driver or scope, drops all of them.
Strict restart independently reconstructs only the journal-anchored node and
signer state under their existing contracts; this applies equally when a fatal
error consumes the driver before a coordinator begins. A fresh driver then
starts with all three inboxes empty, no inherited due observation, no inherited
pending command, and a new process-local timer lineage. A ticket issued by the
lost driver cannot authorize the fresh driver. Current proposal, prevote, and
proposal-precommit inputs may be explicitly re-admitted against that recovered
state; they are never
reconstructed as cached validity.

Dropping a driver neither rolls back a completed journal prefix nor proves that
a returned command was delivered. It can lose volatile inbox evidence, an
unreleased command, and a selected proposal token still held with that command.
The durable signer and finality stores keep their existing strict-reopen
classifications; closing this command-custody crash gap belongs to the later
runtime boundary.

## Consuming event admission and bounded retention

`FixedValidatorNodeDriverV0::admit_event` consumes the driver so a fatal
underlying session failure cannot return an alternative signing scope. Any
already pending arm or publication command first causes a lossless
`CommandPending` rejection of the complete event, forcing command custody to
transfer before input inspection or another potentially fatal admission. Its

`CurrentRoundProposal` carries complete canonical proposal-control bytes and
the owned complete canonical artifact payload, but no caller round or target.
The driver first applies its cheap private phase and due fence: Precommit is
stale and Proposal or Prevote already marked due is late, without round
derivation or input inspection. Otherwise it reconstructs the exact live round
from its private branch and signing session before applying payload and framing
preflights, bounded fallible copy, and complete proposal verification and
retaining only the private token. `CurrentRoundProposalPrevote` likewise carries
no caller position, role, target, or signer; after the same cheap fence, the
reconstructed typed round must verify the complete canonical vote as an exact-
position active-member `Prevote/Proposal(root)`. `CurrentRoundNilPrevote`
follows the same route but requires exactly `Prevote/Nil`. These event forms
share the current inbox's count and logical canonical-input-byte limits; neither
admission grants quorum, transition, or signing authority.

The current due fence is phase-local. Evidence admitted before the exact active
phase is marked due may act ahead of that due path; evidence submitted later is
returned losslessly. A successful transition invalidates the old timer, so the
newly armed Prevote phase may admit proposal and vote inputs again, including
after strict restart. The driver never silently inserts the newly returned
prevote: counting that returned instance requires the runtime to take the
publication command and explicitly loop its canonical vote back through
ordinary admission. Independently obtained strict-valid bytes signed by the
local key remain ordinary evidence because the driver infers no provenance.

`CurrentRoundFinalityProposal` is a distinct event carrying complete canonical
proposal-control bytes and the owned complete canonical artifact payload for
the dedicated proposal-finality resource class. It does not reuse
`CurrentRoundProposal`, so insertion into either inbox cannot partially charge
or implicitly validate the other. After the pending-command gate, the driver
derives the exact live branch round, applies the bounded proposal and payload
preflights, and fully verifies both inputs before retaining a private proposal
token under the finality limits.

`CurrentRoundProposalPrecommit` likewise carries one complete canonical signed
vote and no caller position, role, target, root, or signer. The driver derives
the exact live round and requires complete context, position, signature,
active-fixed-set membership, `Precommit` role, and a non-nil proposal target
before retention. `Precommit/Nil` is rejected because nil-precommit round
progression is a later scope. Both finality-foundation event forms are admitted
in Proposal, Prevote, or Precommit phase and do not consult the phase-local due
fence. Current- or higher-inbox saturation and ambiguity do not block them;
finality saturation blocks only later finality-foundation admission and
classification. A stale or future vote or proposal still returns losslessly,
and no retained former-position evidence is relabeled after a transition.

Its `FixedValidatorNodeDriverEventV0::HigherRoundProposal` variant carries one
descriptive `proposal_round`, complete canonical proposal-control bytes, and
the owned complete canonical artifact payload. The driver first uses the shared
live session, branch, successor-capacity, and persisted-before-local route
preflight without inspecting proposal bytes. Only after that succeeds does it
reject an artifact payload above the canonical byte limit, proposal-control
bytes outside the global length bounds, an unknown proof tag, or trailing bytes
after a no-proof tag before making one bounded fallible payload copy. Embedded
valid-round certificate framing and authentication remain part of complete
proposal admission after artifact validation. That admission reuses the same
derived target round rather than reconstructing it. It requires the proposal's
authenticated position to equal the descriptive route and retains only the
resulting private-field `FixedValidatorNodeDeferredProposalV0` token. The route
alone grants no position or proposal authority.

Successful proposal insertion delegates to the existing combined inbox and
preserves its exact duplicate, checked count and canonical-input-byte
accounting, fallible reservation, and lossless error contracts. The token is
still retained evidence while the driver survives rather than cached validity;
the selected proposal is fully reverified immediately before any durable
effect.

The `HigherRoundProposalPrevote` event accepts one complete canonical signed
vote and no separate position, role, or target. The driver first authenticates
the canonical context, signature, and position, requires a round strictly above
the live signer and within the work ceiling, sequentially derives that exact
fixed-set round, and then requires active membership and
`Prevote/Proposal(root)` before retention. No caller-supplied position, peer, or
arrival index can replace the authenticated vote fields or the node-derived
round. A vote-only quorum proves neither proposal availability nor an
actionable driver transition.

The `TimeoutDue` event accepts only an opaque ticket previously emitted by this
driver. It records no proposal, vote, or peer data and is governed by the exact
timer-lineage rules below.

The separately limited current-round inbox follows
`fixed-validator-node-current-round-inbox-v0.md`. Its exact duplicates are
no-growth; it retains all other fully admitted proposal and proposal-or-nil-
prevote variants under checked combined count and logical canonical-input-byte
limits. A first nonduplicate capacity or accounting rejection preserves the retained prefix and
exact event and latches current-class saturation. That saturation blocks later
current evidence admission, current action, and the due transition until explicit current-only
lossless drain, even after position advancement, but does not block the
independently budgeted higher-round escape class.

At one live position, any two byte-distinct fully admitted current proposals
are ambiguous, including variants with one proposal signing root, because an
optional valid-round proof can change lock-directed voting without changing
that root. While live, this ambiguity denies later current proposal and either
prevote admission with exact event return and blocks current action and the due transition at
that position. It retains every input and does not block higher-round admission
or action. Once higher evidence advances the signer, old-position ambiguity is
nonactionable, but its bytes remain charged until current-only drain.

`drain_current_inbox_and_reset` returns every exact current proposal input and
typed canonical proposal or nil prevote and clears only that inbox's entries,
accounting, saturation, and any latched current dual-quorum ambiguity. It
changes neither the higher-round inbox nor the signing state, active due
observation, timer, or pending command, and grants no reinsertion or selection
policy.

The third inbox follows
`fixed-validator-node-current-round-finality-inbox-v0.md`. It has a separate
positive combined entry and logical canonical-input-byte budget for fully
admitted finality proposals and proposal precommits. Exact duplicates are
no-growth; every other same-root or competing-root proposal representation and
signature variant remains retained while healthy. The first nonduplicate
declared-capacity or checked-accounting failure preserves the complete retained
prefix and exact rejected event and latches finality-class saturation;
collection reservation failure is no-state and does not latch saturation.

One crate-private finality-foundation classifier considers only the healthy
complete exact-live-position snapshot. For each evaluated proposal root it
uses the lexicographically smallest complete canonical precommit per active
signer, counts that signer once without renormalizing offline weight, and
applies the existing exact-batch constructor. A quorate root with one or more
matching fully admitted proposals uses the lexicographically smallest complete
proposal tuple solely as its stable local representative while preserving
every variant. The inbox-internal result may contain that proposal tuple and
the constructed certificate, but the driver-level classification deliberately
maps it to a crate-private descriptor containing only the position and proposal
root. It distinguishes no quorum, one quorum without a proposal, one
proposal-backed quorum, and multiple quorate roots. It chooses no winner
between roots and grants no finality or conflict-halt authority. Neither raw
proposal nor certificate bytes, a public command, nor a runtime-facing
observation is exposed by the driver classifier.

Neither that classification nor finality saturation changes `step`; the
existing pending-command, higher-round, current-round, and due ordering remains
unchanged. `drain_current_finality_inbox_and_reset` losslessly returns
every exact finality proposal and proposal precommit and resets only finality
entries, accounting, and saturation. It changes neither voting inbox, signing
state, due observation, timer, pending command, nor any durable authority file,
and grants no reinsertion or evidence-routing policy.

While the driver survives, the higher-round combined inbox retains distinct same-root
proposal variants, distinct canonical signature variants, and competing targets
without eviction or preference while healthy. Exact duplicates are no-growth.
The first nonduplicate declared-capacity or checked-accounting overflow
preserves the pre-attempt higher-round set and enters the higher-round deny-only
saturation state. Higher-round saturation blocks later event admission and any
new action selection or transition so an arrival-dependent retained prefix
cannot become actionable after another valid input was denied. Pending-command
admission rejection prevents higher-round saturation and command custody from
coexisting.

While the driver survives, the only higher-round saturation or ambiguity
recovery is an explicit full lossless higher-round inbox drain-and-reset. It
returns every owned proposal token and every retained canonical prevote,
restores the higher-round inbox to healthy empty, and does not choose which
evidence a caller should reinsert. Neither a successful timeout nor a round
change silently prunes, evicts, or resets retained higher-round evidence. A
fatal no-scope outcome instead destroys the volatile owner and therefore cannot
return or retain that process-local inbox.

## Opaque phase-timeout lineage

Only the driver can construct the ticket carried by an
`ArmPhaseTimeout(ticket)` command. A ticket is a copyable opaque private-field,
process-local value bound to the driver's identity, exact consensus context,
live source position, live phase, and checked timer generation. Construction
records the initial arm command as pending, so the first step emits that command
and performs no transition. A no-vote transition immediately prepares the next
arm command. A signed transition instead invalidates the source timer and keeps
only its checked successor generation with the pending publication; emitting
that publication prepares the successor arm command for one still later step.
Generation overflow fails closed before either transition begins.

Returning one exact current ticket records only that the external runtime has
classified this issued timer as due. A foreign-driver, stale-generation,
wrong-context, wrong-position, wrong-phase, duplicate-consumed, or otherwise
noncurrent ticket cannot close a phase. A ticket contains no timestamp,
deadline, duration, monotonic-clock reading, backoff value, or proof that real
time elapsed. The driver therefore prevents stale timeout reuse but deliberately
does not decide or verify when a timeout should become due.

The due observation remains subordinate first to complete actionable
higher-round evidence and then to current evidence already admitted before that
exact active phase was marked due. A unique current proposal therefore beats
Proposal due, and a sole matching current proposal- or nil-prevote quorum beats
Prevote due. Simultaneously actionable proposal and nil quorums instead block
current action and the due transition. Current evidence submitted after that phase-local due
observation is returned as late and cannot change the frozen choice. Within
either admitted evidence class, peer identity and arrival order grant no
preference.

## Deterministic step selection

A consuming `FixedValidatorNodeDriverV0::step` first emits any already pending
command and does not also perform a transition. Event admission is denied while
that command is pending, so later saturation or a potentially fatal admission
cannot overtake its transfer. With no pending command, higher-inbox saturation
globally blocks driver work, while current-inbox saturation blocks current
action and the due transition but still permits independently budgeted higher-round escape. A
fatal coordinator failure consumes the driver and its sole signing scope and
returns no driver on which another step could act; it also drops all three
process-local inboxes and their retained evidence with that volatile owner.
Otherwise, the step derives the exact current branch position and phase from the
privately owned scope and evaluates the two complete voting-inbox retained sets
in the order defined below.

The current-round finality inbox is deliberately absent from this ordering.
Its healthy readiness, missing-proposal, and multiple-quorum classifications,
and its saturated state are crate-private diagnostics with no step effect. They
cannot suppress a pending command, higher-round escape, current vote, or due
transition and cannot produce a command, signature, finality call, or height
change in this foundation slice.

For that snapshot, the driver applies the existing higher-round inbox rules at
every retained position still strictly above the live signer round and within
the work ceiling:

1. group exact typed proposal prevotes by authenticated position and proposal
   root;
2. count each active signer at most once per root, using the lexicographically
   smallest complete canonical vote variant for that signer and root;
3. require strict greater-than-two-thirds weight at that position plus at least
   one matching fully admitted proposal token; and
4. use the lexicographically smallest matching proposal-control and artifact
   tuple only after exactly one actionable position-and-root pair exists.

If two or more distinct position-and-root pairs are actionable, or the existing
per-position classifier finds multiple actionable roots, the step returns a
typed nonterminal ambiguity. While the driver survives, it retains every
proposal and vote, performs no phase or round transition, emits no command, does
not fall through to a due timeout, and exposes no alternative signing scope.
The driver does not choose the lowest round, highest round, smallest root, first
arrival, first peer, or first collection entry. Recovery requires the explicit
full lossless drain-and-reset described above.

Exactly one actionable higher-round pair has priority over an exact current due
timeout. The driver supplies that evidence-derived position to the unchanged
`try_pair_higher_round_inbox_at` coordinator. That coordinator repeats complete
proposal and certificate verification, durably checkpoints the higher-round
state, applies the proposal quorum, and completes the matching anchored
precommit before the driver records one pending
`FixedValidatorNodeDriverCommandV0::PublishVote`. That single command transfers
both the signed vote and `Some(exact selected proposal token)` losslessly to the
runtime. Only the selected proposal is removed on completed success; while the
driver survives, all votes and all other proposal variants remain retained. The
returned token remains unverified availability data and grants no replay,
selection, or finality authority. While pending it is outside the inbox
counters, but event admission is blocked, so the one-command state cannot be
used to grow another inbox entry before custody transfers.

If no higher-round pair is actionable, current saturation or a latched current
dual-quorum ambiguity blocks every current evidence admission, action, and due transition
until current-only drain. Otherwise, live-position byte-distinct proposal
ambiguity denies later current proposal and either prevote admission and blocks
current action and the due transition for that position while higher-round escape remains
available.

With a healthy unambiguous current inbox, Proposal phase selects only one exact
fully admitted proposal representation, copies its inputs fallibly, and invokes
the unchanged `sign_prevote_for_proposal` coordinator. That coordinator fully
reverifies the proposal and applies the existing lock-directed target rule
before the complete anchored vote-safety sequence may return a signed prevote.
Success queues `PublishVote { released_proposal: None }` and retains the
proposal in current-inbox custody.

In Prevote phase, the driver independently classifies proposal and nil votes for
the exact live parent and position. For each target it chooses the
lexicographically smallest canonical variant per signer and uses the unchanged
typed-round constructor to require strict greater-than-two-thirds weight. Empty
or insufficient evidence is not actionable. A proposal quorum is considered
only for exactly one retained proposal representation and the matching root.
One sole proposal certificate enters the unchanged
`sign_precommit_for_proposal_quorum` coordinator, which fully reverifies both
proposal and certificate, updates lock and valid state under the existing rule,
and completes the anchored proposal precommit. One sole nil certificate enters
the unchanged `sign_precommit_for_nil_quorum` coordinator, which fully
reverifies that certificate, clears the lock while preserving complete valid
evidence, and completes the anchored nil precommit. Either success queues
`PublishVote { released_proposal: None }`, retains every current input, and
performs no finality action.

If both proposal and nil certificates are actionable in one complete retained
snapshot, the driver chooses neither, signs nothing, does not fall through to
due, and latches one typed current-class ambiguity. That latch continues to
block current evidence admission, action, and the due transition until explicit current-only drain,
even if an independently prioritized higher-round action changes the live
position. Higher-round admission and action remain available because their
resource and authority class is evaluated independently first. The ambiguity
does not accuse a signer, discard evidence, or grant punishment authority.

Only if no higher or current evidence action is available may an exact current
due observation invoke the coordinator corresponding to the node-derived live
phase:

- Proposal close uses the existing exact-context-and-position path and may
  produce one anchored `PublishVote` prevote command with `None` for the
  released proposal;
- Prevote close uses the existing exact-context-and-position path and may
  produce one anchored `PublishVote` nil-precommit command with `None` for the
  released proposal; and
- Precommit close uses the existing exact-context-and-position path and may
  perform only the volatile same-height `R + 1` Proposal transition, with no
  signed command and no finality.

If no evidence action is available and the exact live phase has an armed timer
that is not due, the step is idle and changes nothing. One step never chains a
higher-round catch-up into a current action, chains either current vote into the
next phase, consumes more than one due observation, invokes more than one
consuming coordinator, or emits more than one command. A signed transition
records only its pending `PublishVote` plus an optional losslessly released
proposal token; only higher-round pairing supplies that token as `Some`, while
current and due votes supply `None`. A separate later step transfers that
command and prepares the successor phase's `ArmPhaseTimeout`, and another step
emits that arm command. A transition without a vote prepares only the successor
phase's arm command. Receiving either command does not acknowledge network
delivery, peer receipt, relay, payload persistence, inclusion, real-time
scheduling, or finality.

## Determinism boundary

For the same live scope state, limits, work ceiling, exact due state, and the
same complete healthy retained voting sets, every permutation of insertion
order yields the same step classification and selected canonical
representatives. Separately, the same exact live position and complete healthy
finality set yields the same crate-private finality classification and local
representatives. These are frozen-snapshot permutation claims only. They do not
claim a complete network view, simultaneous observation, deterministic results
across unequal retained sets, fairness across repeated drains and reinsertion,
operating-system event ordering, or independence from when an external runtime
invokes `step` or classification.

Peer identity and arrival order are absent from representative and quorum
classification within one fully admitted pre-due retained set. They cannot
grant validity, break ambiguity, or select a proposal or round. The explicit
phase-local due-admission fence, rather than peer identity, distinguishes
evidence accepted before due from evidence losslessly rejected afterward.

## Failures, command custody, and restart

Proposal, vote, ticket, ceiling, exact-identity, phase, or no-action admission
rejection causes no signer, consensus, or durable effect and preserves the live
scope and relevant retained prefix. The first nonduplicate declared-capacity or
checked-accounting rejection may additionally latch saturation while returning
the exact rejected event. Higher-round saturation or actionable ambiguity blocks
all later admission and work until full higher-inbox drain-and-reset. Current
saturation or latched dual-quorum ambiguity blocks current evidence admission,
current action, and the due transition until current-only drain but permits higher admission and
action. Current proposal ambiguity is derived from the retained live-position
set, denies later current proposal and either prevote admission, blocks current
action and the due transition, and becomes nonactionable after authenticated advancement; it
is never resolved by choosing a variant. Pending
commands deny every event admission until they transfer; no rejection creates a
signed command.

Finality-class saturation preserves the rejected finality event and retained
finality prefix, blocks only later finality admission and classification until
finality-only drain, and leaves `step` and both voting classes unchanged.
Finality-class multiple-quorum classification likewise has no step effect or
durable conflict meaning. An explicit classifier scratch-reservation failure or
typed certificate-construction rejection changes no retained bytes, saturation,
signing state, or durable state; this is not exhaustive process-allocation-
failure recovery.

Fatal errors are outside that surviving-owner contract even when they occur
before a consuming coordinator begins. Authenticated prevote-round derivation,
frozen-selection round derivation, checked timer-generation exhaustion, and any
later fatal coordinator path return neither driver nor signing scope and drop
the process-local inboxes. The durable stores remain bounded by their last
completed anchored prefix, and continuation requires strict anchored reopen into
a fresh driver.

Once an existing consuming coordinator begins a durable checkpoint or vote
operation, all of its current append, anchor, acknowledgement, completion, and
terminal-stop semantics remain unchanged. Any path on which that coordinator
returns no replacement scope consumes both the driver and its sole signing
scope, returns no driver, and emits no command, even if strict reopen may later
find a complete durable prefix. The driver neither reconstructs a missing
command from journal bytes nor retries an ambiguous effect. Strict anchored
restart remains the sole durable-prefix classifier. Because a fatal outcome has
no surviving signing scope or driver, destruction of that process-local owner
also drops its inboxes and retained evidence; the lower coordinator may have
restored a leased token internally, but this driver exposes no reusable
evidence from a fatal authority state.

At most one command is pending and at most one command is emitted from a step.
A step with a pending command returns exactly that command and performs no
transition. Only higher-round pairing transfers the exact selected token as
`Some` inside its publication; current-evidence and timeout-driven publications
carry `None`.
Emitting a pending `PublishVote` prepares only the resulting phase's arm command
for a later step, so no hidden multi-command queue can overwrite or reorder
either action. Once a command is returned, the driver does not know whether the
vote was queued, scheduled, sent, delivered, accepted, or lost, nor whether the
token was retained or archived; command, proposal, delivery, and replay custody
belong to the later runtime and transport boundary.

## Exclusions

This driver does not define or perform:

- timeout durations, the approximately-ten-second product target, increasing
  timeout backoff, wall-clock or monotonic-clock measurement, deadline
  scheduling, sleep, wakeup, or proof of expiry;
- an asynchronous event loop, daemon lifecycle, production node binary,
  operator configuration, process supervision, task scheduling, or command
  retry and acknowledgement;
- network transport, listener or dialer behavior, peer discovery,
  authentication, provenance trust, relay, gossip, delivery-completeness
  inference, or peer-selected admission;
- a complete or protocol-wide evidence view, durable inbox or timer encoding,
  restart reconstruction, cross-process exactly-once delivery, canonical
  evidence preference, automatic eviction, or protocol-wide resource limits;
- proposal authoring, higher-round nil-quorum collection, current-round
  finality execution, lower- or candidate-backed finality routing, finality or
  height transition, candidate
  discovery or ranking, branch or sibling choice, rollback, reorganization,
  candidate promotion, checkpoint synchronization, or store repair;
- artifact-payload persistence or candidate- or payload-store mutation;
- dynamic validator sets, multi-key coordination, key loading, rotation, remote
  signing, hardware monotonicity, slashing, economics, or production custody;
  or
- cross-file atomicity, exhaustive I/O-fault coverage, non-Unix anchor-runtime
  guarantees, or multi-process/devnet runtime evidence.

These exclusions are authority boundaries for this first node-owned driver,
not claims that the broader product can omit the corresponding capabilities.
In particular, later scheduler, transport, binary, finality-routing, and
multi-node work may compose this driver, but may not turn timer receipt, peer
identity, network arrival order, retained-set order, or caller-selected
positions into consensus validity or selection authority.
