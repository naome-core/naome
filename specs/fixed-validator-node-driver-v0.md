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
- one independently bounded process-local current-round nil-precommit inbox;
- one current phase-timer lineage and its checked generation;
- at most one timeout-due observation for that exact lineage; and
- at most one next outward command.

The driver accepts complete current- or higher-round proposals that it fully
admits into the existing private token boundary, complete canonical current-
round proposal or nil prevotes and higher-round proposal prevotes that it
independently admits against the exact node-derived fixed-set round, distinct
complete finality-proposal inputs and individual current-round proposal
precommits for its dedicated finality path, complete canonical current-round
nil precommits for its dedicated round-progression path, and opaque timeout
tickets that the same driver issued. One explicit step derives the live node
identity, classifies the exact-current finality, higher-round, nil-precommit,
and ordinary current-voting inbox state in its fixed order, and invokes at most
one existing consuming node coordinator. It emits at most one timeout-arm or
signed-vote or signed-proposal command. It does not expose the owned signing scope as an
alternative caller-controlled path.

The caller-selected action exceptions are the candidate-backed and direct
strictly lower-round single-proof finality bridges, strictly lower-round
paired-conflict bridge, explicit higher-round quorum catch-up methods, and
explicit current-round proposal authoring outside ordinary `step` selection.
All are available only after any pending outward command has transferred,
retain no evidence, use the driver's existing inclusive round-work ceiling,
and delegate every applicable proposal, source, positioned-fixed-set, batch,
finality, and signer check to existing consuming coordinators. The deny-only
historical selected-sibling bridge cannot return a driver after proof processing
begins. The positive direct-child bridges additionally preserve every
non-fallthrough current-finality classification ahead of caller choice, and
return a driver after proof processing only for a typed pre-effect
rejection or a completed child-height handoff. The lower-round paired bridge
instead submits two complete proofs for a
terminal neutral halt regardless of current-round inbox state, restoring the
driver only on typed pre-effect rejection. Explicit higher-round catch-up
preserves command, current-finality, and retained higher-proposal priority before
checkpointing a fully authenticated round and replacing the timer.

This remains a partial driver boundary. Its input surface now covers current-
and higher-round proposal/prevote evidence, current-round nil prevotes,
current-round finality proposals, proposal precommits, exact-current nil
precommits, and exact driver-issued timeout-due tickets. It drives a current
proposal through an anchored prevote, one sole matching current proposal or nil
prevote quorum through an anchored precommit, and one exact-current retained
nil-precommit quorum through the existing no-write same-height `R + 1`
transition. One uniquely proposal-backed current-round precommit quorum runs
through the existing fully verifying, anchored finality coordinator and may
return the child-height driver with the existing typed finality selection. Two
complete proposal-backed roots instead run through the neutral paired halt and
return no driver or selected branch. An explicit caller may separately submit
one exact candidate-backed direct-child proposal and precommit batch after
command custody and only when current-finality classification would otherwise
fall through. An explicit lower-round paired-conflict submission may instead
enter the fully verifying neutral halt after command custody, without waiting
for current-round finality classification. An explicit canonical higher-round
certificate or exact routed vote batch may separately advance to the evidence's
authenticated phase under the priority and lifecycle contract below. Explicit
proposal authoring may sign fresh or retained-valid input only after existing
step work is resolved and queues one proposal with its exact payload for
publication, without changing the phase, timer, or local voting inbox.
An explicit direct lower-round certificate or exact precommit batch may also
finalize under the same command and current-finality priority as the
candidate-backed direct-child bridge. Automatic lower-round or candidate-backed
evidence routing, broader or incomplete preselection conflict handling,
automatic proposal source selection, networking, and artifact-payload persistence
remain outside this driver.

This ownership moves event choice out of a caller that could otherwise select
an inbox position or invoke a phase close directly. It does not make retained
evidence, a timeout ticket, a peer, or the driver itself a new source of
consensus validity. Every authority-bearing transition remains the existing
fully verifying, journal- and anchor-gated node operation.

## Construction and process-local lifecycle

Construction takes one live signing scope, separate positive current-voting,
higher-round, current-finality, and current-nil-precommit inbox limits, and the
existing inclusive caller-local round-work ceiling. The driver owns every
subsequent replacement scope returned by a successful consuming operation. It
is not cloneable and provides no accessor that returns or borrows the raw scope
for mutation. Read-only diagnostics may expose the live context, position,
phase, separate inbox accounting, timer identity, and pending-command state
without granting transition authority. The standalone read-only finality
classifier remains crate-private. The public `step` surface exposes only the
typed operational block, finality, rejection, and stop outcomes described
below. The separate historical-conflict bridge is not an alternative step or a
way to recover the owned scope.

`FixedValidatorNodeDriverV0::selected_artifact_history` is the sole public
non-diagnostic projection from the privately owned scope. It returns only the
sealed read-only `SelectedArtifactHistory` trait implemented by the anchored
finality owner; it cannot expose the branch, signing session, raw scope, or any
mutable finality operation. The reference composition retains this shared
borrow while driving its explicit candidate-ancestry and candidate-branch
payload fills. Rust borrowing then prevents that composition from consuming the
same driver through event admission or a step until its retained acquisition
borrow ends. The lower-level progress values do not themselves retain or widen
this capability. The caller still chooses the exact target, peer, stores,
limits, and event routing, and the later driver event must pass the ordinary
complete proposal verification. The projection establishes no availability,
provenance, validity, vote-target, branch-selection, rollback, consensus, or
finality authority.

Construction is consuming. If construction fails, it returns neither a driver
nor the supplied signing scope. The caller must strictly reopen the anchored
signer state before retrying; no construction error grants a reusable scope.

The driver, its inboxes, timer lineage, due observation, and pending command have
no canonical or durable encoding. Process or runtime-owner loss, including a
fatal coordinator outcome that returns no driver or scope, drops all of them.
Strict restart independently reconstructs only the journal-anchored node and
signer state under their existing contracts; this applies equally when a fatal
error consumes the driver before a coordinator begins. A fresh driver then
starts with all four inboxes empty, no inherited due observation, no inherited
pending command, and a new process-local timer lineage. A ticket issued by the
lost driver cannot authorize the fresh driver. Current proposal, prevote,
proposal-precommit, and nil-precommit inputs may be explicitly re-admitted
against that recovered state; they are never reconstructed as cached validity.

Dropping a driver neither rolls back a completed journal prefix nor proves that
a returned command was delivered. It can lose volatile inbox evidence, an
unreleased command, and a selected proposal token still held with that command.
The durable signer and finality stores keep their existing strict-reopen
classifications; closing this command-custody crash gap belongs to the later
runtime boundary.

## Explicit current-round proposal authoring

The driver exposes three consuming source-specific methods, all using its
construction-time inclusive round-work ceiling:

- `author_proposal` takes one explicit fresh artifact and canonical payload, or
  the canonical payload for the private retained valid value.
- `author_candidate_backed_fresh_proposal` takes one exact caller-selected block
  target and its caller-routed candidate and payload stores.
- `author_payload_store_backed_retained_proposal` takes only the payload store;
  the private retained valid value supplies its sole artifact address.

Pending outward command custody takes priority and returns `CommandPending`
before source inspection. Otherwise the driver runs a read-only version of the
ordinary `step` priority prefix: non-fallthrough exact-current finality,
higher-round saturation or ambiguity and complete higher-proposal selection,
current nil-precommit selection, current-voting blocking and selection, then
the due observation. Any actionable result, blocker, selection rejection, or
reservation failure returns `StepWorkPending` with the unchanged driver before
source resolution. Finality `None` or non-pair `Saturated`, empty selections,
and incomplete evidence that would leave `step` idle do not themselves prevent
authoring. Newly detected ambiguity does not latch here. Ordinary `step` or the
corresponding lossless drain resolves the existing work; authoring never runs a
hidden step or chooses a proposal ahead of that work.

The existing proposal-authoring coordinator then derives the exact live
branch, height, round, phase, and scheduled proposer. Its session and ceiling
checks remain authoritative. Proposal phase, scheduled-proposer authority, and
the fresh-versus-retained source-kind checks precede any availability-store
read. The direct input follows the same source-kind contract. Store membership
supplies availability only; source selection grants no branch, validity,
finality, or vote authority.

After resolving one exact owned source, the driver path checks the canonical
payload length against `ARTIFACT_PAYLOAD_MAX_BYTES` and fallibly reserves and
copies publication custody before entering durable proposal preparation. The
unchanged consensus path fully verifies that same resolved artifact, payload,
and, when present, exact retained valid value and earlier-round prevote proof.
Anchored intent preparation, acknowledgement, signing, self-verification,
completion, and completion anchoring must all succeed before `Authored` returns.
The copied payload is moved directly into one pending `PublishProposal` with
the completed signed proposal. No source is read again after signing and no
payload copy or resize is required at that point. Existing public signing-scope
authoring methods keep their control-only outcome and do not request this
additional publication copy.

`Authored` preserves the position, Proposal phase, exact active timer ticket,
generation, all four inboxes, accounting, latches, lock and complete valid-value
evidence, and finality journal-anchor pair. It reserves no successor timer
generation. A separate `step` transfers exactly
`PublishProposal { proposal, canonical_artifact_bytes }`, then leaves no pending
arm command. It neither admits the proposal nor signs a local vote. The caller
must explicitly re-admit the published control and payload through the
ordinary current-proposal event before local voting; the existing admission
closure after a due observation still applies. Publication does not extend the
Proposal deadline or acknowledge delivery, retention, or payload persistence.

Typed source, input, payload-bound, or publication-reservation rejection restores
the unchanged driver with no signer effect. Exact completed replay queues the
same proposal and payload without another durable write, including at the
existing proposal replay ceiling. A fully valid different same-slot intent
instead returns only the existing terminal proposal-safety halt. Every fatal
round, session, preparation, acknowledgement, signing, or anchor error returns
no driver and no outward bytes; strict anchored reopen is the only continuation
classifier. A completed durable proposal may survive loss of pending volatile
publication, but restart creates no outbox or publication command. The caller
may explicitly supply the exact source again for the existing no-write replay.

## Explicit higher-round quorum catch-up

`FixedValidatorNodeDriverV0::advance_to_higher_round_quorum` consumes the driver
and borrows one complete canonical certificate.
`FixedValidatorNodeDriverV0::advance_to_higher_round_vote_batch` instead borrows
one exact canonical signed-vote batch and accepts its expected evidence round,
prevote-or-precommit role, and nil-or-proposal target. Both use the driver's
construction-time inclusive round-work ceiling; the persisted finality ceiling
remains independently authoritative. The batch route is unauthenticated
metadata, and neither method retains the submitted input.

The recoverable gates precede supplied-input inspection in this exact order:

1. A pending outward command returns `CommandPending`.
2. Only `None` or non-pair `Saturated` exact-current finality classification
   falls through. Ready finality, a complete paired conflict, a quorum missing
   its proposal, conflicting roots, and classification reservation or invariant
   rejection return `CurrentFinalityUnresolved`.
3. Existing higher-round saturation or latched ambiguity, or any result other
   than `None` from the complete retained higher-proposal selection, returns
   `HigherEvidenceUnresolved`. This includes a unique actionable proposal quorum,
   newly detected ambiguity, and reservation or invariant rejection.

These outcomes return the unchanged driver: no input is retained, no timer or
counter changes, and newly detected ambiguity does not create a latch. Ordinary
`step` or the appropriate lossless drain resolves the retained work. A retained
proposal quorum therefore runs its existing checkpoint, lock, and precommit
behavior before an explicit catch-up may proceed, even when the submitted
certificate names a later round. Current-voting and current-nil-precommit
inboxes, their blockers, and due observations introduce no additional gate.

After these gates, checked successor timer-generation reservation precedes the
existing consuming node round-progression coordinator. It requires same-height
strictly higher evidence within both ceilings and fully verifies the exact
positioned fixed set, strict-supermajority weight, and every signature. The
batch path applies its existing all-or-nothing role/target/position contract.
Either prevote target reaches only the higher-round Prevote phase; either
precommit target reaches only the higher-round Precommit phase. Lock and
byte-identical complete valid-value evidence are preserved. The existing
checkpoint, independent anchor, and live-session acknowledgement must complete
before `Advanced` returns the driver.

Success retains all four inboxes, charged accounting, saturation reasons, and
ambiguity latches. It invalidates the old timer and due observation, increments
the generation once, and queues exactly one arm for the destination phase.
There is no `PublishVote`, proposal-token release, proposal admission, lock or
valid-value update, finality write, selected-branch change, or lower-round
signing permission. The new round/phase and preserved lock/valid evidence are
recovered from the anchored checkpoint after owner loss; volatile inboxes and
commands are not reconstructed.

A typed coordinator rejection restores the unchanged driver, timer, due state,
and all retained evidence for explicit retry. Fatal round derivation, timer
generation, session, checkpoint, anchor, or acknowledgement failure uses the
existing consuming driver error and returns no driver or scope, even if it
occurs before durable work. Strict anchored reopen is the only continuation
path, including the existing `AnchorBehind` outcome after a completed checkpoint
journal append followed by anchor failure. The methods add no automatic general
quorum observation, collection, arbitration, transport, timing, or branch-choice
policy and do not change ordinary `step` selection.

## Explicit candidate-backed terminal bridge

`FixedValidatorNodeDriverV0::commit_candidate_backed_finality_conflict_vote_batch`
consumes the driver and accepts one caller-selected historical target, complete
canonical proposal-control bytes, one exact signed-precommit batch, one
evidence round, and borrowed candidate and Foundation payload stores. The
caller supplies no separate work ceiling: the method routes the driver's
construction-time inclusive ceiling unchanged alongside the evidence round.
The downstream persisted finality ceiling remains independently authoritative.

An already pending arm or vote-publication command is the first and only
recoverable gate. `CommandPending` returns the exact unchanged driver before
route, input, or source inspection, so the caller must transfer that existing
command before retrying. Due state, phase, retained inbox state, saturation, or
ambiguity creates no second driver-returning gate for this explicit terminal
attempt.

After command custody is clear, the method transfers the sole signing scope
exactly once to the existing candidate-backed finalized-sibling batch
coordinator. That coordinator reconstructs the replay-retained selected parent,
integrity-reads the caller-borrowed stores, and completely verifies the target,
proposal, producer, artifact transition, positioned fixed set, and every
precommit before the existing anchored halt and signer stop. Success returns
only `FinalityStopped`; every pre-append rejection, source failure, or durable
failure returns the existing consuming finality error. No such outcome returns
the driver, scope, timer, command, inbox custody, branch, or selected value, and
strict anchored reopen is the only subsequent signer-state classifier.

This bridge observes, discovers, acquires, buffers, groups, ranks, retries, or
routes no event. Caller target and round choice, store membership, peer
identity, provenance, or invocation timing grants no truth, preference,
winner, branch-selection, rollback, repair, finality, or signing authority.

## Explicit candidate-backed direct-child bridge

`FixedValidatorNodeDriverV0::commit_candidate_backed_finality_vote_batch`
consumes the driver and accepts one caller-selected direct-child target,
complete canonical proposal-control bytes, one exact signed-precommit batch,
one evidence round, and borrowed candidate and Foundation payload stores. The
caller supplies no separate work ceiling: the method routes the driver's
construction-time inclusive ceiling unchanged alongside the evidence round,
while the downstream persisted finality ceiling remains independently
authoritative.

The bridge first preserves outward-command custody exactly as the terminal
bridge does. `CommandPending` returns the exact unchanged driver before
current-finality classification, timer-generation, route, input, or source
inspection. With no pending command, the driver applies the same current-
finality classification that begins `step`. Only `None` or finality-class
`Saturated` may fall through to candidate processing. `Ready`,
`PreselectionConflict`, `MissingProposal`, `ConflictingRoots`, classifier
rejection, or classifier reservation returns `CurrentFinalityUnresolved` with
the unchanged driver before candidate input or source work; the caller must use
`step` to obtain the existing precise finality, block, rejection, or neutral
no-winner halt result. Fatal round reconstruction returns no driver and requires
strict reopen. Thus caller ordering cannot supersede retained exact-current
finality or choose one root from known conflicting evidence.

After current-finality fallthrough, the driver reserves the next checked timer
generation before transferring its sole signing scope to the existing
candidate-backed exact-batch coordinator. A typed caller-ceiling, route, source,
proposal, or batch rejection precedes node effect and returns that unchanged
scope to the same driver, preserving every inbox, counter, saturation and
ambiguity latch, timer, and due observation. Candidate and payload stores
receive no entry or byte mutation from the finality attempt; an integrity
failure may poison only its owning live source handle under the existing reopen
contract.

Only a fully verified new direct child may enter the existing anchored finality
and signer-height handoff. Success restores the returned child scope, preserves
all four volatile inboxes and their accounting as stale process-local custody,
invalidates the old timer and due observation, and queues exactly one arm
command for child-height round-zero Proposal using the reserved generation. The
returned typed selection names only the result authenticated by that existing
coordinator. A defensive terminal conflict returns only the existing paired
finality and signer-stop evidence. Checked generation exhaustion or any
coordinator error that returns no scope returns no driver, command, timer, or
inbox custody; strict anchored reopen is the sole continuation classifier and
finalized history is never rolled back.

This bridge observes, discovers, acquires, buffers, groups, ranks, retries, or
routes no event. Caller target, round, invocation time, store membership, peer
identity, or provenance grants no validity, preference, branch-selection,
rollback, repair, finality, or signing authority. It does not alter ordinary
`step` priority or make the direct method the node's sole finality policy.

## Explicit direct strictly lower-round finality

`FixedValidatorNodeDriverV0::commit_lower_round_finality` consumes the driver and
accepts complete canonical proposal-control bytes, an owned canonical artifact
payload, and one complete precommit certificate.
`FixedValidatorNodeDriverV0::commit_lower_round_finality_vote_batch` accepts the
same proposal and payload, one exact signed-precommit batch, and one explicit
evidence round. Both use the driver's construction-time inclusive work ceiling;
the existing persisted finality ceiling remains independently authoritative.
The certificate supplies only unauthenticated routing metadata until complete
verification. The batch's caller-supplied round likewise grants no authority.
Both existing coordinators require evidence strictly below the signer round
at the branch's next height before fully verifying the proposal, payload,
producer, positioned fixed set, and complete proof.

The two forms share one driver lifecycle and the existing positive-finality
priority. A pending outward command returns `CommandPending` with the unchanged
driver before classification or input inspection. Otherwise the exact-current
finality selector runs first: only `None` or saturation without a retained
complete conflict pair falls through. Ready finality, missing proposal,
conflicting roots, a complete paired conflict, classifier rejection, or
reservation failure returns `CurrentFinalityUnresolved` with the unchanged
driver. Ordinary `step` or the existing lossless finality drain resolves that
work. No additional gate is imposed by higher-round, current-voting, or
nil-precommit evidence, saturation, ambiguity, phase, or due state. This does
not change ordinary step ordering or the command-only terminal-pair exception.

After these gates, checked successor timer generation precedes transferring the
sole scope to the existing consuming lower-round coordinator. Any typed
pre-effect evidence rejection restores the unchanged scope to the same driver,
preserving every inbox byte, counter, saturation and ambiguity latch, timer,
generation, due state, and authority file. The owned payload argument is
consumed even when the driver is returned. Neither form retains caller inputs,
reads availability stores, filters a batch, or chooses evidence automatically.

A completed child-height handoff restores the returned scope and exact
`Finalized` selection. All four inboxes remain stale charged custody until
independent lossless drains. A changed position invalidates the old timer and
due observation, advances generation once, and queues exactly one child-height
round-zero Proposal arm; it emits no signed-vote or signed-proposal command.
Existing defensive unchanged-position or terminal finality outcomes are
forwarded without expanding the coordinator's accepted historical evidence.
Fatal classification, generation, coordinator, or handoff failure returns no
driver, scope, command, or volatile inbox custody. Known finality metadata in
an error remains diagnostic evidence of a completed prefix, not rollback
authority. Strict anchored reopen alone classifies the surviving durable
prefixes, including an independently lagging finality or signer anchor.

These explicit methods add no evidence observation, acquisition, buffering,
automatic routing, retry, competing-proof arbitration, cross-round conflict
interpretation, source preference, networking, multi-height promotion, repair,
or production runtime. They are separate complete-input ingresses and do not
assert that no other finality evidence exists.

## Explicit strictly lower-round paired-conflict bridge

`FixedValidatorNodeDriverV0::commit_lower_round_preselection_conflict_vote_batches`
consumes the driver and accepts two complete proposal-control, owned artifact-
payload, and exact signed-precommit-batch triples plus one shared evidence
round. It supplies the driver's construction-time inclusive work ceiling to
the existing lower-round paired coordinator. That coordinator independently
enforces node coherence, the persisted ceiling, a strictly earlier evidence
round, the caller work bound, and complete verification of both proposals,
payloads, producers, positioned fixed set, and strict-supermajority batches.

A pending outward command is the sole driver gate. `CommandPending` returns the
unchanged driver before route or proof inspection. Once command custody is
clear, this explicit terminal attempt proceeds regardless of phase, due state,
any current-round ready proposal, missing proposal, conflicting roots, complete
pair, saturation, or other retained inbox state. It does not classify current
finality, reserve a successor timer generation, or run ordinary `step` work.
The caller chooses the submission time, but only two fully verified distinct
same-position proofs may reach the existing canonically ordered neutral halt;
neither the caller nor this bridge chooses a winner.

Typed route, first-proof, or second-proof pre-effect rejection restores the
same scope to the unchanged driver, including every inbox, byte count, latch,
timer, and due observation. Owned payload arguments are consumed by the call,
including driver-returning outcomes; unlike event admission, this explicit
method promises no lossless return of caller inputs. It retains no submission
for retry. Success returns only the matching anchored finality halt and signer
stop. A coordinator error, including a same-value journal rejection or a
durability failure, returns no driver, scope, command, timer, or inbox custody;
strict anchored reopen remains the sole later durable-state classifier.

This bridge adds no automatic observation, collection, pairing, acquisition,
routing, or retry; cross-round pairing; peer authority; branch selection;
rollback; repair; atomicity across journals; daemon scheduling; or dynamic-
validator policy. Ordinary `step` ordering and the two candidate-backed bridges
retain their existing contracts.

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
progression uses the distinct `CurrentRoundNilPrecommit` event and resource
class below. Both finality event forms are admitted in Proposal, Prevote, or
Precommit phase and do not consult the phase-local due fence. Current- or higher-
inbox saturation and ambiguity do not block them; finality saturation blocks
later finality admission and every classification except an already retained
structurally complete proposal-backed conflict pair. A stale or future vote or
proposal still returns losslessly, and no retained former-position evidence is
relabeled after a transition.

`CurrentRoundNilPrecommit` carries one complete canonical signed vote and no
caller position, role, target, round, or signer. After the pending-command gate,
the driver derives its exact live branch round and authenticates the complete
vote's context, exact position, strict signature, active fixed-set membership,
`Precommit` role, and `Nil` target before associating it with that typed round's
node-derived parent coordinate and retaining it. A proposal target, prevote
role, stale or future position, foreign context, inactive signer, malformed
bytes, or invalid signature is returned losslessly.

Nil-precommit admission is available in Proposal, Prevote, or Precommit phase
and does not consult the phase-local due fence. Saturation or ambiguity in the
other three inboxes does not block it, and its own saturation blocks only later
nil-precommit insertion. Admission grants no quorum, timeout, transition,
finality, branch, provenance, peer-trust, or network authority. Retained former-
position votes are never relabeled after advancement.

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
limits. A first nonduplicate capacity or accounting rejection preserves the
retained prefix and exact event and latches current-class saturation. That
saturation blocks later current evidence admission, current action, and the due
transition until explicit current-only lossless drain, even after position
advancement, but does not block independently budgeted higher-round or nil-
precommit admission and action.

At one live position, any two byte-distinct fully admitted current proposals
are ambiguous, including variants with one proposal signing root, because an
optional valid-round proof can change lock-directed voting without changing
that root. While live, this ambiguity denies later current proposal and either
prevote admission with exact event return and blocks current action and the due
transition at that position. It retains every input and does not block higher-
round or nil-precommit admission and action. Once either evidence class
advances the signer, old-position ambiguity is nonactionable, but its bytes
remain charged until current-only drain.

`drain_current_inbox_and_reset` returns every exact current proposal input and
typed canonical proposal or nil prevote and clears only that inbox's entries,
accounting, saturation, and any latched current dual-quorum ambiguity. It
changes none of the higher-round, finality, or nil-precommit inboxes, signing
state, active due observation, timer, or pending command and grants no
reinsertion or selection policy.

The third inbox follows
`fixed-validator-node-current-round-finality-inbox-v0.md`. It has a separate
positive combined entry and logical canonical-input-byte budget for fully
admitted finality proposals and proposal precommits. Exact duplicates are
no-growth; every other same-root or competing-root proposal representation and
signature variant remains retained while healthy. The first nonduplicate
declared-capacity or checked-accounting failure preserves the complete retained
prefix and exact rejected event and latches finality-class saturation;
collection reservation failure is no-state and does not latch saturation.

One crate-private finality classifier considers the complete exact-live-position
snapshot while healthy and, after saturation, only when a structural precheck
shows that the retained prefix can already contain a complete proposal-backed
conflict pair. For each evaluated proposal root it uses the lexicographically
smallest complete canonical precommit per active signer, counts that signer once
without renormalizing offline weight, and applies the existing exact-batch
constructor. A quorate root with one or more matching fully admitted proposals
uses the lexicographically smallest complete proposal tuple solely as its stable
local representative while preserving every variant. The inbox-internal result
may borrow that tuple and own the constructed certificate. The execution path
fallibly copies either one or both proposal inputs before consuming the signing
scope, while the separate crate-private diagnostic maps ready and missing-
proposal cases to position-and-root descriptors.

The classifier distinguishes no quorum, one quorum without a proposal, one
proposal-backed quorum, multiple quorate roots with fewer than two matching
proposals, and the first two complete proposal-backed quorums in ascending root
order. It chooses no winner between roots and by itself grants no finality or
conflict-halt authority. With no pending command, the step treats a uniquely
proposal-backed quorum as ordinary finality, treats a complete pair as terminal
safety evidence, treats the remaining missing-proposal and multiple-root cases
as no-winner blocks while healthy, and lets no-quorum or finality saturation
without a complete pair fall through to the existing voting and due sequence.
Raw proposal or certificate bytes are not exposed through a public command or
runtime-facing observation.

`drain_current_finality_inbox_and_reset` losslessly returns every exact
finality proposal and proposal precommit and resets only finality entries,
accounting, and saturation. It changes neither voting inbox, signing state, due
observation, timer, pending command, nor any durable authority file, and grants
no reinsertion or evidence-routing policy. Successful height finality likewise
does not silently clear any inbox: all higher, current-voting, finality, and
nil-precommit entries, counters, saturation states, and ambiguity latches remain
byte-exact and may be stale and charged until their existing class-specific
drains.

The fourth inbox follows
`fixed-validator-node-current-round-nil-precommit-inbox-v0.md`. It has separate
positive entry and logical canonical-input-byte limits for fully authenticated
exact-current `Precommit/Nil` votes. Exact parent-bound canonical replay is no-
growth; every byte-distinct signature variant remains retained while capacity
permits. The first nonduplicate declared-capacity or checked-accounting failure
preserves the retained prefix and exact rejected event and latches an immutable
nil-precommit-class saturation reason. Collection reservation failure is no-
state and does not latch saturation.

For the exact live parent and position, the crate-private classifier selects
the lexicographically smallest complete canonical variant per active signer,
counts each signer once without renormalizing offline weight, and applies the
existing exact-batch constructor only for `Precommit/Nil`. Empty, insufficient,
or exact-two-thirds evidence is not actionable. There is only one admitted
target class, so classification makes no target choice and has no ambiguity
latch. A strict-supermajority prefix remains actionable even after saturation;
otherwise saturation falls through to lower-priority work. A denied input
cannot introduce a competing target because every admitted and retained vote
already has the same exact role and target.

`drain_current_nil_precommit_inbox_and_reset` returns one
`FixedValidatorNodeDriverCurrentNilPrecommitDrainV0`; its `into_parts` exposes
the continuing driver and an exact-size iterator of raw `[u8; 214]` canonical
nil precommits. It clears only that inbox's entries, accounting, and saturation.
It changes none of the other three inboxes, signing state, lock or valid
evidence, due observation, timer, pending command, or durable authority files
and grants no reinsertion or evidence preference.
Successful same-height round progression likewise preserves all four inboxes,
counters, saturation states, and existing ambiguity latches byte-exact until
their independent drains.

While the driver survives, the higher-round combined inbox retains distinct same-root
proposal variants, distinct canonical signature variants, and competing targets
without eviction or preference while healthy. Exact duplicates are no-growth.
The first nonduplicate declared-capacity or checked-accounting overflow
preserves the pre-attempt higher-round set and enters the higher-round deny-only
saturation state. Higher-round saturation blocks later higher-round, ordinary
current, and due-event admission, while separately budgeted proposal-finality
and nil-precommit events remain admissible. Only proposal finality can act
before the higher block; higher-round, nil-precommit, ordinary-current, and due
action or transition remains blocked so an arrival-dependent retained
higher-round prefix cannot become actionable after another valid input was
denied. Because the command gate runs first, no new saturation can be latched
while a command is already pending. Proposal finality may nevertheless preserve
pre-existing higher-round saturation alongside its pending successor arm.

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
arm command. A signed-vote transition instead invalidates the source timer and keeps
only its checked successor generation with the pending publication; emitting
that publication prepares the successor arm command for one still later step.
Generation overflow fails closed before either transition begins. Explicit
proposal authoring preserves this ticket and generation and does not create a
successor, including when the generation has no successor.

Returning one exact current ticket records only that the external runtime has
classified this issued timer as due. A foreign-driver, stale-generation,
wrong-context, wrong-position, wrong-phase, duplicate-consumed, or otherwise
noncurrent ticket cannot close a phase. A ticket contains no timestamp,
deadline, duration, monotonic-clock reading, backoff value, or proof that real
time elapsed. The driver therefore prevents stale timeout reuse but deliberately
does not decide or verify when a timeout should become due.

The due observation remains subordinate first to the exact-current finality
policy, then to complete actionable higher-round evidence, then to an exact-
current nil-precommit quorum, and then to ordinary current evidence admitted
before that exact active phase was marked due. A unique current proposal
therefore beats Proposal due, and a sole matching current proposal- or nil-
prevote quorum beats Prevote due. A finality quorum missing its proposal,
multiple finality roots with fewer than two complete proposal-backed quorums,
or simultaneously actionable proposal and nil prevote quorums block the due
transition under their respective policies. Two complete proposal-backed
finality roots instead terminally halt before the due transition. Current
voting evidence submitted after the phase-local due observation is returned as
late and cannot change the frozen voting choice; finality and nil-precommit
evidence intentionally have no phase-local due fence. Within every admitted
evidence class, peer identity and arrival order grant no preference.

## Deterministic step selection

A consuming `FixedValidatorNodeDriverV0::step` first emits any already pending
command and does not also perform a transition. Event admission is denied while
that command is pending, so later saturation or a potentially fatal admission
cannot overtake its transfer. With no pending command, the step first classifies
the exact-live current finality inbox. A latched finality saturation without the
structural possibility of a complete retained pair, or the absence of an exact
branch-coordinate/current-position precommit, is resolved before sequential
proposer-round reconstruction. No quorum and class-local finality saturation
without a complete pair fall through. While the inbox remains healthy, one
quorate root without its proposal blocks all lower-priority work until a
matching proposal arrives or the finality inbox is drained. Multiple quorate
roots with fewer than two proposal-backed quorums likewise choose no winner and
block while healthy. A later denied distinct finality event may latch
saturation, which supersedes either incomplete derived block and restores lower-
priority fallthrough until finality drain. It cannot erase a complete retained
proposal-backed conflict pair.

One uniquely proposal-backed finality quorum precedes higher-inbox saturation
or ambiguity, nil-precommit round progression, current-inbox saturation or
ambiguity, every voting action, and the exact due timeout. The driver fallibly
owns the selected proposal inputs,
retains the classifier-built certificate, and preflights the next timer
generation before consuming its sole scope into
`commit_current_round_finality`. That existing coordinator repeats complete
proposal and certificate verification and is the only path that may mutate the
finality journal, signer journal, anchors, branch, or live signer.

Two proposal-backed quorate roots precede unique finality and every lower-
priority evidence class, even when a later denied finality input has latched
saturation. The driver selects the two lowest complete roots, the established
least proposal tuple per root, and the established least vote variant per signer
only for deterministic witness bytes. It fallibly copies both complete triples,
does not preflight a successor timer, and consumes the scope into
`commit_current_round_preselection_conflict`. That coordinator independently
re-verifies and seals both proofs against one exact round and parent before the
finality journal may append one neutral tag-`03` halt and the signer may append
tag `0b`. Success returns `FinalityStopped` with no driver, scope, selected
branch, replacement timer, command, or vote.

A coordinator pre-effect rejection restores its returned unchanged scope into
the same driver and returns a typed step rejection without falling through.
Successful new finality returns the unchanged
`FixedValidatorNodeFinalitySelectionV0` in a distinct step outcome, installs
the coordinator's child-height round-zero Proposal scope, invalidates the old
timer and due observation, and records exactly one pending child arm command.
All four inboxes and their latches remain unchanged and may be stale until
explicit drain. A defensive same-value replay returns its typed
`AlreadyFinalized` selection without claiming a height change or replacing the
timer. A durable finality conflict returns only the existing paired terminal
stop; every fatal finality error returns no driver or scope and requires strict
restart.

Only after the finality policy falls through does higher-inbox saturation
globally block driver work. Current-inbox saturation blocks current action and
the due transition but still permits independently budgeted higher-round escape
and nil-precommit progression. Any fatal coordinator failure consumes the
driver and its sole signing scope and returns no driver on which another step
could act; it also drops all four process-local inboxes and their retained
evidence with that volatile owner. Otherwise, the step derives the exact
current branch position and phase from the privately owned scope and evaluates
the three remaining retained evidence sets in the order defined below.

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

If no higher-round pair is actionable or blocking, the driver considers the
nil-precommit inbox for the exact live parent coordinate and position. It
chooses the lexicographically smallest complete canonical variant per active
signer and counts that signer once against the unchanged total active weight.
A strict-greater-than-two-thirds retained set is actionable even when the class
is saturated; an empty, insufficient, exact-two-thirds, or saturated
nonquorate set falls through without creating a block or transition.

The absence of an exact parent-coordinate/current-position nil precommit is
resolved before sequential round reconstruction. Only a matching
preclassification result derives the typed round for full quorum construction.
This bounds idle and stale-only work without granting validity or transition
authority.

One actionable nil-precommit batch precedes ordinary current voting and due
work. The driver preflights the next timer generation, then supplies the exact
selected vote references and its existing work ceiling to
`advance_round_for_nil_precommit_vote_batch`. That coordinator repeats complete
current-round, successor-capacity, context, position, role, target, membership,
signature, distinct-signer, and strict-threshold verification. A pre-effect
rejection restores the unchanged scope and all volatile state to the same
driver and does not fall through. A fatal derivation or session error returns
no driver or scope and requires strict restart.

Success moves only the same branch and height from `R` to `R + 1` Proposal,
preserves the exact lock and complete valid-value evidence, writes no signer or
finality journal or anchor bytes, finalizes no value, invalidates the source
timer and due state, and records one successor timeout-arm command. It emits no
signed-vote command and preserves all four inboxes, counters, saturation
states, and existing ambiguity latches byte-exact until independent drain.

If no nil-precommit quorum is actionable, current saturation or a latched
current dual-quorum ambiguity blocks every current evidence admission, action,
and due transition until current-only drain. Otherwise, live-position byte-
distinct proposal ambiguity denies later current proposal and either prevote
admission and blocks current action and the due transition for that position
while higher-round escape remains available.

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
block current evidence admission, action, and the due transition until explicit
current-only drain, even if independently prioritized higher-round or nil-
precommit evidence changes the live position. Both admission and action remain
available in those independent resource and authority classes. The ambiguity
does not accuse a signer, discard evidence, or grant punishment authority.

Only if no finality, higher-round, nil-precommit, or ordinary current evidence
action or block is available may an exact current due observation invoke the
coordinator corresponding to the node-derived live phase:

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
higher-round catch-up or nil-precommit advance into a current action, chains
either current vote into the next phase, consumes more than one due
observation, invokes more than one consuming coordinator, or emits more than one
command. A signed-vote transition records only its pending `PublishVote` plus an
optional losslessly released proposal token; only higher-round pairing supplies
that token as `Some`, while current and due votes supply `None`. A separate
later step transfers that command and prepares the successor phase's
`ArmPhaseTimeout`, and another step emits that arm command. An ordinary step transition without
a vote prepares only the successor phase's arm command. Receiving a
command does not acknowledge network delivery, peer receipt, relay, payload
persistence, inclusion, real-time scheduling, or finality.

## Determinism boundary

For the same live scope state, limits, work ceiling, exact due state, and the
same retained higher-round, current-voting, and nil-precommit sets, every
permutation of insertion order yields the same step classification and selected
canonical representatives. The nil-precommit result remains deterministic for
the same saturated retained prefix, but makes no completeness claim about
inputs denied after saturation. Separately, the same exact live position and
complete retained finality set yields the same finality classification, block
or ready decision, and local representatives. This includes a saturated prefix
that already contains two distinct proposal-backed strict-supermajority roots:
the two lowest complete proposal signing roots and each root's canonical
representatives are selected independently of insertion order. Inputs denied
after saturation are absent from that claim and cannot become evidence. A ready
pair still reaches the independently stateful, fully verifying finality
coordinator. These are frozen-snapshot permutation claims only. They do not
claim a complete network view, simultaneous observation, deterministic results
across unequal retained sets, fairness across repeated drains and reinsertion,
operating-system event ordering, or independence from when an external runtime
invokes `step` or classification.

Peer identity and arrival order are absent from representative and quorum
classification within every fully admitted retained set. They cannot grant
validity, break ambiguity, or select a proposal or round. Only ordinary current-
voting admission has the explicit phase-local due fence; peer identity does not
decide whether any event passes that fence.

## Failures, command custody, and restart

Proposal, vote, ticket, ceiling, exact-identity, phase, or no-action admission
rejection causes no signer, consensus, or durable effect and preserves the live
scope and relevant retained prefix. The first nonduplicate declared-capacity or
checked-accounting rejection may additionally latch saturation while returning
the exact rejected event. Higher-round saturation or actionable ambiguity
blocks ordinary current and due work until full higher-inbox drain-and-reset. It
still permits separately budgeted finality and nil-precommit admission, while
only proposal finality can act ahead of the higher block. Current saturation or
latched dual-quorum ambiguity blocks ordinary current evidence admission,
current action, and the due transition until current-only drain but permits
higher and nil-precommit admission and action. Current proposal ambiguity is
derived from the retained live-position set, denies later current proposal and
either prevote admission, blocks current action and the due transition, and
becomes nonactionable after authenticated advancement; it is never resolved by
choosing a variant. Pending commands deny every event admission until they
transfer; no rejection creates a signed command.

Nil-precommit-class saturation preserves the rejected event and retained
prefix and blocks only later nil-precommit admission until nil-precommit-only
drain. An already retained strict supermajority remains actionable; a
nonquorate prefix falls through without blocking ordinary current or due work.
Classifier reservation or constructor rejection returns the unchanged driver
without fallthrough. Complete re-verification rejection likewise restores the
unchanged scope and all four inboxes to the same driver; a fatal round-
derivation or session error returns no driver and requires strict restart.

Finality-class saturation preserves the rejected finality event and retained
finality prefix and blocks only later finality admission. If that retained
prefix does not already contain two distinct proposal-backed
strict-supermajority roots, classification falls through to higher-round,
nil-precommit, ordinary current-voting, and due work until finality-only drain.
If the retained prefix does contain that pair, classification remains allowed
and the terminal paired-conflict action has priority over every lower class;
the rejected event remains outside the evidence set and cannot affect either
canonical witness.

Finality-class missing-proposal and multiple-quorum classifications with fewer
than two complete proposal-backed roots instead block lower-priority work
without choosing a value or creating durable conflict meaning. An explicit
classifier scratch-reservation failure or typed certificate-construction
rejection returns the unchanged driver without falling through and changes no
retained bytes, saturation, signing state, or durable state; this is not
exhaustive process-allocation-failure recovery.

Complete finality re-verification rejection likewise returns the coordinator's
unchanged scope to the same driver, preserving all inboxes, latches, timer, and
due state. Once sealing or durable coordination begins, every no-scope finality
error is fatal even when it carries an already durable selection or halt; the
driver never interprets that as rollback or reusable evidence.

Fatal errors are outside that surviving-owner contract even when they occur
before a consuming coordinator begins. Authenticated prevote-round derivation,
frozen-selection or current-nil-precommit round derivation, checked timer-
generation exhaustion, and any later fatal coordinator path return neither
driver nor signing scope and drop the process-local inboxes. The durable stores
remain bounded by their last completed anchored prefix, and continuation
requires strict anchored reopen into a fresh driver.

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
transition. Explicit proposal publication transfers its exact owned payload
without preparing another command. Only higher-round pairing transfers the exact selected token as
`Some` inside its publication; current-evidence and timeout-driven vote publications
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
- automatic proposal source selection, proposal self-admission, general
  higher-round quorum observation,
  collection, routing, or arbitration, automatic lower-round single-proof
  finality acquisition or routing, automatic acquisition or routing for
  candidate-backed direct-child or conflict evidence or a missing proposal, durable
  handling of incomplete or broader multi-root cases beyond the exact retained
  proposal-backed pair and explicit lower-round paired submission, caller-selected
  branch or winner choice, rollback, reorganization, candidate promotion,
  checkpoint synchronization, or store repair; the explicit
  direct-child bridges add only caller-ordered submission after current-finality
  fallthrough and do not join the ordinary `step` selection order;
- artifact-payload persistence or candidate- or payload-store durable entry or
  byte insertion, replacement, refresh, promotion, or deletion; an integrity-
  read failure may still poison only its owning live source handle under that
  store's existing reopen contract;
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
