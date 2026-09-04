# Fixed-Validator Node Finality V0

## Authority and scope

This document defines the synchronous live-finality coordination boundary for
one closure-scoped fixed-validator V0 node signer. It composes the existing
sealed consensus transition, exact-current-round proposal-sealing boundary,
strictly lower-round boundary, or candidate-backed verification boundary with
the anchored finality journal and anchored per-key vote-safety session. The
separate-input boundaries accept either an existing canonical precommit
certificate or, where explicitly provided, one exact caller-routed signed
precommit batch that must construct that same canonical certificate. They
create no way to select or rank a transition or vote batch.

The sealed-transition ingress accepts one
`OwnedVerifiedFixedConsensusTransitionV0`. Its private fields prove that
complete typed branch verification already bound the exact parent coordinate,
consensus position, value, canonical envelope, canonical artifact payload, and
immutable child branch.

The supplemental exact-current-round ingresses instead accept separate complete
canonical proposal-control bytes, one owned complete canonical artifact
payload, either one exact canonical non-nil precommit certificate or one exact
signed-precommit batch, and an inclusive caller-local round ceiling. They derive
the signer's exact current round from the node-owned branch and signer position,
fully admit the proposal against that round, seal it only with a matching
certificate or a canonical certificate constructed all-or-nothing from the
matching batch, and convert the result to the same private-field owned
transition before finality begins. The caller supplies no round cursor,
snapshot, parent, proposer, proposal root, or transition.

The paired exact-current preselection-conflict ingresses accept two complete
proposal-control and owned-payload inputs with either two canonical certificates
or two exact signed-precommit batches, plus one shared inclusive caller-local
round ceiling. They derive one exact node-owned round, independently verify and
seal both triples against that same selected parent, require distinct exact
values and proposal roots, and only then consume the two private-field
transitions into the anchored neutral halt. Successful batches canonicalize
signer order and the successful pair canonicalizes root order; caller or vote
ordering grants no winner authority. Pre-effect rejection diagnostics may
preserve applicable caller-order detail, including the supplied side or a
failing vote index.

The separate strictly lower-round certificate ingress accepts the same complete
certificate input shape and caller-local work ceiling. It canonically frames
the precommit certificate only to obtain an unauthenticated routing position,
requires that position to name the node branch's next height and a round
strictly earlier than the signer round, bounds sequential round derivation, and
then completely verifies the proposal, payload, producer authorization,
positioned fixed set, and certificate at that derived round. Its exact-batch
sibling instead requires an explicit `evidence_round` before doing batch work,
requires that round to be strictly earlier than the signer round and within the
caller-local ceiling, derives it sequentially, and then requires the proposal
and every supplied vote to authenticate that exact position. Only either
complete verification result becomes the same private-field owned transition.
Neither certificate framing, explicit routing metadata, nor caller submission
establishes certificate validity or finality.

The paired strictly lower-round preselection-conflict ingresses accept two
complete proposal-control and owned-payload inputs with either two canonical
certificates plus one shared caller-local ceiling, or two exact signed-
precommit batches plus one shared explicit route. The certificate form
independently derives and authenticates each routed position before requiring
equality. The batch form derives the one explicit position once and requires
both proposals and every vote to authenticate it. Each retains both resulting
private-field transitions only inside the consuming call before the same
neutral halt. A cross-position or separately routed pair is not classified and
grants no claim about the validity, compatibility, preference, or safety of
evidence across different rounds.

These direct ingresses are supplemental rather than the node's sole finality
policy. Exact-current and strictly lower evidence use distinct methods, while
the existing sealed-transition and candidate-backed ingresses remain separate.
None of these direct ingresses discovers, chooses, buffers, or automatically
routes an event, replays an already selected value, or admits a selected-height
sibling conflict. Higher-round evidence continues through the existing bounded
certificate-authenticated phase catch-up followed by exact-current admission.

The candidate-backed direct-child ingresses instead require one exact
caller-selected unselected direct-child `ArtifactBlockId`, caller-routed
matching-chain candidate and Foundation payload stores, and an inclusive
caller-local round ceiling. The existing envelope ingress accepts one complete
canonical finality envelope, integrity-reads the exact retained block and
payload, fully verifies the envelope against the current selected head under
both round ceilings, and only then commits the internally sealed transition.
Its exact-batch sibling accepts proposal-control bytes, an exact
signed-precommit batch, and an explicit `evidence_round`; it requires the
caller-local ceiling not to exceed the persisted finality ceiling and the
evidence round not to exceed that caller ceiling, derives the named round,
integrity-reads the same exact block and payload, completely verifies the
proposal, and constructs and seals only a matching non-nil precommit
certificate. To preserve the existing envelope ingress contract, this path
accepts a current, lower, or higher round relative to the signer when it fits
both ceilings. That compatibility is not a preference or catch-up rule.

The separate candidate-backed conflict ingress and its exact-batch sibling
accept the same caller-selected target and stores only for a height already
retained by finality. The envelope form accepts one complete canonical envelope;
the batch form accepts separate proposal-control bytes, one exact caller-routed
signed-precommit batch, and an explicit evidence round within the caller and
persisted ceilings. Both reject an evidence-free value equal to the selected
value before source reads, fully verify a preliminarily distinct value against
that height's exact retained selected parent, and admit only the existing
terminal sibling-conflict result. The stores supply availability bytes only and
receive no durable mutation; source-integrity failures retain each store's
existing poison-and-reopen boundary.

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
exposes read-only diagnostics but withholds raw round advancement,
current-round decision, vote-preparation, acknowledgement, key-use, finality
height-transition, and conflict-stop methods. Consuming node coordinators own
the complete current-round durable sequence and bounded round progression. The
node-owned finality journal is therefore the exclusive source of height and
stop authority for this scope. Only `commit_verified_finality`,
`commit_current_round_finality`, `commit_lower_round_finality`,
`commit_candidate_backed_finality`, and their three height-advancing exact-
precommit-batch siblings may couple its height capability into the signer.
`commit_verified_finality` and the separate
`commit_candidate_backed_finality_conflict` plus its exact-precommit-batch
sibling may instead couple an exact anchored selected-sibling stop capability
into the signer, while
`commit_current_round_preselection_conflict` plus its exact-precommit-batch
sibling and
`commit_lower_round_preselection_conflict` plus its exact-precommit-batch
sibling may couple only the neutral paired-preselection stop capability. There
is no public mutable-journal or raw signing-session escape hatch. A continuation
scope is returned only by a complete nonterminal outcome; none of the conflict-
specific methods has a continuation success path.

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
   or construct a certificate from the complete supplied batch and seal it,
   requiring non-nil precommit role and the exact same context, height, current
   round, proposal signing root, and positioned fixed-set snapshot. Exact-batch
   construction rejects the whole batch rather than filtering entries.
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

A caller-ceiling violation, proposal rejection, certificate rejection, or
exact-batch rejection occurs before a transition or finality effect exists and
returns the same unchanged signing scope with a typed rejection. None of those
paths changes volatile signer state or either journal or anchor. Submission,
successful framing, explicit routing, or caller classification alone grants no
proposal, certificate, or finality authority.

## Paired exact-current preselection conflict

`commit_current_round_preselection_conflict` and its exact-precommit-batch
sibling repeat steps 1 and 2 once, then perform steps 3 and 4 independently for
the first and second complete input triples while both borrow the same typed
round. The certificate form seals each proposal from its supplied canonical
certificate. The batch form constructs each certificate all-or-nothing from
its complete exact batch and requires every vote to authenticate that one
derived position, precommit role, and proposal root. Failure of either
proposal, certificate, or batch returns the unchanged scope with a
side-specific typed rejection; neither verified half is reusable authority.
Only after both proofs become owned sealed transitions does either method
release the round borrow and consume the scope.

The consuming stage asks only the anchored finality journal to verify their
same position, exact unselected parent, distinct values and roots, canonicalize
root order, and append one tag-`03` terminal frame. It never invokes the
single-transition commit and never publishes a finality selection or signer-
height capability. After the finality frame and anchor are durable, the existing
opaque stop handoff carries the neutral halt kind into one tag-`0b` signer stop
and vote-anchor update. Success returns the existing paired terminal result and
no continuation scope.

Neither method accepts root, parent, position, ordering, or winner metadata from
the caller. A classifier may supply the input bytes, but possession, inbox
retention, saturation state, peer provenance, caller ordering, and vote ordering
remain non-authoritative. Successful inputs are completely rechecked and
canonicalized, while rejection diagnostics may preserve applicable side or
input-order detail.

## Strictly lower-round admission

The strictly lower-round ingress performs a separate bounded pre-effect stage:

1. Read the persisted finality ceiling and signer position, derive the
   node-owned branch's next height, require it to equal the signer height, and
   require the signer round not to exceed that persisted ceiling.
2. Canonically frame the supplied precommit certificate only far enough to
   obtain its unauthenticated position. Reject malformed framing or a height
   different from the exact branch next height before sequential round work.
3. Require the routed certificate round to be strictly less than the signer
   round and no greater than the caller's inclusive work ceiling. These are
   specialized ingress conditions, not consensus-validity rules for equal or
   higher-round certificates.
4. Sequentially derive that exact branch round, then fully verify the separate
   proposal-control and owned artifact payload against its context, height,
   ancestry, fixed set, scheduled proposer, state commitment, artifact
   transition, producer authorization, and any proof-derived valid round.
5. Fully verify and seal the admitted proposal only with the complete matching
   non-nil precommit certificate, then convert it to one
   `OwnedVerifiedFixedConsensusTransitionV0` and enter the existing finality and
   signer-height handoff.

The signer's later phase, lock, valid value, or pending durable work does not
veto a completely verified earlier-round finality proof. A pending signer
operation may therefore allow finality to become durable before the height
handoff fails, after which the scope is consumed and strict restart remains the
only durable-prefix classifier. Malformed, wrong-height, equal-or-higher-round,
caller-cap, proposal, payload, or certificate rejection before the owned
transition exists returns the unchanged scope and changes neither volatile
signer state nor any journal or anchor.

The exact-batch sibling uses this same pre-effect boundary with a deliberately
different routing preflight. It checks its explicit `evidence_round` against
the signer and caller ceiling before proposal decoding or vote work, derives
that exact round, completely admits the proposal, and then passes every signed
precommit through the unchanged exact-batch constructor for only that proposal
root. A proposal or any vote at another round cannot silently retarget the
operation. Empty, over-bound, malformed, foreign, wrong-position, wrong-role,
wrong-target, duplicate, inactive, invalid-signature, or insufficient batches
are rejected as a whole and return the unchanged scope.

## Paired strictly lower-round preselection conflict

`commit_lower_round_preselection_conflict` applies the node-coherence and
persisted-ceiling preflight once, then independently applies strictly lower-
round certificate-admission steps 2 through 5 to the first and second complete
input triples under the same signer upper bound and caller-local ceiling. Each
certificate supplies only its own unauthenticated routing position until its
proposal, payload, producer, positioned fixed set, and complete non-nil
precommit certificate all verify. A first- or second-side rejection drops any
privately verified half and returns the exact unchanged scope without a write or
reusable proof output.

After both triples become owned transitions, the method requires their
authenticated positions to be identical. A mismatch is a pre-effect typed
rejection; it is not a cross-round conflict classification and does not make
either transition preferred. Only an equal-position pair consumes the scope
into the existing tag-`03` neutral halt and exact-anchor tag-`0b` signer-stop
sequence. The finality journal independently rechecks the shared parent,
position, distinct values and roots, and canonical root order. Success returns
only `FinalityStopped`, never a selected child, branch, or continuation scope.

`commit_lower_round_preselection_conflict_vote_batches` is the explicitly
routed exact-batch sibling. One shared `FixedValidatorNodeFinalityRoundRouteV0`
names the sole evidence round and inclusive caller-local ceiling for the whole
operation. After the same node-coherence and persisted-ceiling preflight, the
method rejects a route that is not strictly below the signer or exceeds the
caller ceiling before proposal decoding or vote work, derives that one typed
round once, and independently admits both complete proposal/payload/batch
triples against it. Every vote must authenticate that exact position, precommit
role, and its own proposal root, and each whole batch passes the unchanged all-
or-nothing exact quorum constructor. A route, first-side, or second-side
rejection returns the unchanged scope without a write or reusable verified
half. Because the one route fixes both authenticated positions, only the two
sealed transitions enter the same tag-`03`/tag-`0b` neutral halt; the method
accepts no separate side route and assigns no meaning to cross-round evidence,
batch order, caller order, or provenance.

## Candidate-backed exact-batch admission

The candidate-backed exact-batch ingress performs this bounded pre-effect
sequence:

1. Read the persisted finality round ceiling and require the caller-local
   inclusive ceiling not to exceed it.
2. Require the explicit `evidence_round` not to exceed the caller-local ceiling,
   then sequentially derive only that branch round. The signer round is not an
   upper or lower bound for this compatibility path.
3. Structurally admit the proposal's exact context, next height, and
   caller-selected target before source reads; require the candidate store to
   name the branch's artifact chain; integrity-read the exact retained block and
   its exact Foundation payload; and require the retained block bytes to equal
   the proposal's embedded block.
4. Fully verify the proposal, payload, producer authorization, state transition,
   fixed-set position, and any valid-round proof at the derived round.
5. Construct one canonical non-nil precommit certificate from the complete
   exact batch and seal the proposal only when every supplied vote authenticates
   that same context, position, role, and proposal signing root.
6. Convert only the sealed proof to the private owned transition, preserve its
   candidate-backed diagnostic origin, and enter the ordinary consuming
   finality and signer-height handoff.

Caller-cap, evidence-round, structural proposal, availability, source-integrity,
complete proposal, or exact-batch rejection returns the unchanged scope before
any node effect. Candidate and payload stores receive no write; an integrity
failure retains the affected store's existing poison-and-reopen contract. A
round above the signer is accepted only because the established
candidate-envelope path is signer-independent and both explicit work ceilings
bound reconstruction. It grants no automatic catch-up, evidence preference, or
branch authority.

## Candidate-backed finalized-sibling exact-batch admission

`commit_candidate_backed_finality_conflict_vote_batch` is the exact-batch
sibling of the existing deny-only candidate-backed finalized-sibling ingress.
The caller supplies one exact target, proposal-control byte string, complete
signed-precommit batch, `evidence_round`, inclusive work ceiling, and both source
stores. The operation requires healthy finality, applies the persisted ceiling
before the caller ceiling and the caller ceiling before proposal work, bounds
and decodes only enough proposal value to authenticate the context and target,
requires that value's positive height already to be selected, and rejects the
selected value before reading either source.

For a preliminarily distinct value, the anchored finality owner obtains that
height's replay-retained selected parent rather than the live signing branch,
derives only the explicit round, integrity-reads the exact candidate and
Foundation payload, completely verifies the proposal, producer, state
transition, and positioned fixed set, and applies the unchanged all-or-nothing
batch constructor for the matching non-nil precommit role and proposal root.
Only the resulting private-field owned transition may enter the existing
selected-sibling terminal halt. Identical evidence produces the same canonical
envelope and conflict identities as the envelope ingress.

Unlike the direct-child candidate-backed batch adapter, every outcome consumes
the signing scope to preserve the established candidate-conflict contract.
Pre-append rejection changes no finality or signer authority file. Once the halt
append begins, ambiguous durability remains strict-restart-only; success routes
only the exact anchored halt capability into the independent signer stop and
returns no branch or continuation scope. The target, route, source presence,
vote order, and caller provenance grant no observation, preference, selection,
winner, rollback, or reusable-proof authority.

### Driver-owned terminal routing exception

After its existing pending-command custody gate, the long-lived node driver may
consume its sole signing scope through exactly this finalized-sibling batch
ingress. The caller supplies the target, proposal bytes, exact precommit batch,
evidence round, and borrowed stores; the driver supplies only its already bound
inclusive round-work ceiling. A pending command returns the unchanged driver
before any proof or source work. Once the gate passes, success returns only the
paired terminal evidence and every error consumes the driver under this
section's unchanged strict-restart contract.

This bridge is neither an event nor an inbox action. It does not acquire,
retain, group, rank, or automatically route evidence, choose a peer or sibling,
or define priority among multiple caller-known conflicts. Caller selection and
store or peer provenance grant no validity, finality, winner, rollback, or
branch-selection authority.

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

`commit_current_round_finality` and
`commit_current_round_finality_vote_batch` first complete every applicable
exact-current-round admission step above without changing node state. They then
delegate only the resulting owned transition to `commit_verified_finality` and
enter the complete five-step anchored finality and signer handoff. Once that
commit begins, every rejection or ambiguous durability result consumes the
scope, and strict restart remains the only durable-prefix classifier. The
exact-current branch-relative construction names one unselected direct child,
so neither ingress claims the sealed ingress's already-selected replay result
nor either sibling-conflict path.

`commit_current_round_preselection_conflict` and its exact-precommit-batch
sibling complete both exact-current admissions before changing node state, then
append and anchor one paired finality halt without entering the ordinary
single-transition commit. They issue no height capability and advance no
branch. The coordinator obtains the exact anchored neutral stop capability,
appends and anchors one tag-`0b` signer stop, and only then returns
`FinalityStopped`. A failure at either durable stage returns no scope; strict
restart alone classifies the finality and signer prefixes, and no earlier
durable effect is rolled back or reinterpreted.

`commit_lower_round_finality` and
`commit_lower_round_finality_vote_batch` first complete every applicable
strictly lower-round admission step above without changing node state. They
delegate only the fully verified owned transition to
`commit_verified_finality` and then use the same five-step anchored handoff and
consume-and-restart failure boundary. Their local `evidence round < signer
round` condition grants no preference or invalidity claim over equal or
higher-round evidence handled through the existing paths. Like the
exact-current ingresses, they name one unselected direct child and claim no
selected-value replay or sibling-conflict result.

`commit_lower_round_preselection_conflict` completes both independently bounded
certificate admissions and the authenticated-position equality check before
changing node state. Its exact-batch sibling instead completes the shared route
preflight and both independently sealed batch admissions at the one derived
position before changing state. Both then use the same paired finality append,
neutral stop capability, anchored signer stop, consume-on-failure boundary, and
strict-restart classification as `commit_current_round_preselection_conflict`.
Neither issues a height capability, selects a child, or grants a cross-round
interpretation.

`commit_candidate_backed_finality` first applies the complete read-only source
and envelope verification described above. It then commits exactly one new
direct child through the same anchored finality pair and enters steps 2 through
5 of the shared signer handoff. One explicit call advances at most one height.
The candidate and payload stores are not participants in either anchored pair
and receive no durable insert, replacement, mark, refresh, or deletion from
this call.

`commit_candidate_backed_finality_vote_batch` performs its two ceiling checks,
derives the explicit evidence round, and applies the complete read-only source,
proposal, and exact-batch verification described above. It then tags the
resulting owned transition with the caller-selected target and enters the same
commit path as `commit_candidate_backed_finality`. This private origin tag
changes only diagnostic outcome metadata: success and every post-finality
signer-handoff error retain `CandidateBackedFinalized`, while finality validity,
selection, persistence, and signer-height authority remain unchanged.

`commit_candidate_backed_finality_conflict` consumes the scope and applies the
deny-only selected-height preflight and complete retained-parent verification
described above. A same-selected-value or unselected-height input returns an
error and no scope before source access. A distinct value can reach finality
only after complete authentication; its anchored terminal halt then enters the
same stop-capability and signer-stop sequence as the sealed-transition path.
The method returns only the paired terminal evidence after both anchors advance.
`commit_candidate_backed_finality_conflict_vote_batch` preserves that exact
ordering and consuming outcome while replacing only the prebuilt envelope with
the explicitly routed proposal and all-or-nothing signed-precommit batch. The
driver-owned terminal wrapper first transfers any pending command, injects only
its existing local round ceiling, and otherwise preserves this method's exact
verification, ordering, terminal evidence, and consume-on-error behavior.

## Nonterminal outcomes

A newly selected direct child returns `Finalized` metadata naming its exact
authenticated position, ancestry identity, complete-envelope identity, and
anchored finality state identity. Continued signing authority appears only
beside this metadata after the ordered signer handoff completes.

An exact-current caller-cap, proposal, certificate, or exact-batch rejection
returns a typed reason together with the unchanged signing scope. It is a
pre-effect outcome, not a finality-commit error, and therefore carries no
finality selection metadata. Exact-current success uses the ordinary
`Finalized` result; it does not introduce another finality identity or authority
source.

A lower-round malformed-position, wrong-height, not-earlier, caller-cap,
proposal, payload, certificate, or exact-batch rejection likewise returns a
typed reason with the unchanged scope before a finality effect exists.
Lower-round success uses the ordinary `Finalized` result and introduces no
additional identity, selection rule, or authority source.

A lower-round paired rejection identifies shared route metadata, the first or
second lower-round proof, or the mismatch between independently authenticated
certificate positions, and returns the unchanged scope before finality. This
diagnostic route or side and the caller order are not the journal's canonical
witness order. Equal-position success is terminal and therefore is not a
nonterminal finality selection.

A candidate-backed child returns `CandidateBackedFinalized` metadata naming
the exact caller-selected target plus the same authenticated position,
ancestry, complete-envelope, and finality-state identities. It returns beside
continued signing authority only after the same complete signer handoff. The
candidate-backed direct-child boundary has no replay or conflict result; stale,
deep, already-selected, or sibling input is rejected instead.

The candidate-backed exact-batch sibling returns a typed pre-effect rejection
with the unchanged scope for caller-cap, evidence-round, proposal, source, or
batch rejection. Its success and any known-success handoff error preserve the
same `CandidateBackedFinalized` metadata as the envelope path, including the
exact target and canonical envelope identity. This metadata parity does not
make candidate provenance a validity or selection source.

If the generic sealed-transition ingress's exact value is already selected at
its retained height, the finality journal returns `AlreadyFinalized`. This
classification is based on the selected value, not on byte identity of its
evidence variant: a later round may carry a different valid envelope for the
unchanged value. The retained first envelope identity remains authoritative,
neither journal or anchor writes, and the already aligned branch and signer are
returned unchanged. The replay does not replace finality evidence or move the
signer. The exact-current and lower-round ingresses do not claim this replay
classification.

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
branch-relative verification is mandatory. The exact-current and lower-round
direct-child ingresses are not sibling-conflict paths and make no such outcome
claim.

When either paired direct ingress independently verifies two distinct
unselected direct-child transitions for the same exact position, the finality
journal instead appends and anchors one neutral paired-preselection record. It
does not install either value before stopping. The coordinator routes only that
halt kind and canonical witness identities into the distinct neutral signer-
stop tag. No caller order, root order, proposal representation, certificate
representation, or retained-inbox state becomes a selected branch or reusable
proof authority.

Only after the signer-stop record and independent vote anchor synchronize does
the coordinator return `FinalityStopped`, pairing the exact finality halt with
the matching per-key stop. It never returns a branch or signing scope from this
path. The conflict records evidence and stops; it does not choose a winning
sibling, roll back the retained selected value, or revoke bytes that a caller
already received before the stop.

## Failure and restart

Every error after an owned transition or owned transition pair enters finality
consumes the scope and returns no signing authority. Exact-current, paired
exact-current, lower-round single or paired, and candidate-backed direct-child
exact-batch pre-effect input failures are earlier typed rejection outcomes that
return the unchanged scope. The candidate-backed finalized-sibling envelope and
exact-batch methods instead preserve their stricter consume-on-every-outcome
contract even when a pre-append rejection changed no authority byte.
Error stages distinguish:

- finality commit rejection or ambiguous finality durability;
- exact-current or lower-round node-coherence failure before finality admission;
- candidate source, envelope, proposal, or exact-batch rejection, or ambiguous
  candidate-backed finality durability;
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
- proposal, vote, quorum-certificate, or competing-evidence buffering or
  collection, multi-batch aggregation, entry filtering, competing-target
  construction, or preference; the exact-batch siblings construct only one
  canonical certificate from the complete caller-routed batch;
- network transport, peer discovery, provenance trust, or peer-selected
  admission;
- automatic late or lower-round evidence observation, event selection or
  routing, higher-round direct finality ingress beyond the existing
  checkpoint-then-current path, any claim that either direct input is the node's
  sole finality policy, or automatic finality retry;
- cross-round conflict pairing or interpretation, separately routed batch
  pairing, and driver-, inbox-, or network-owned batch-pair acquisition;
- candidate discovery, branch discovery, sibling ranking or winner selection,
  signer-relative candidate-round preference, rollback, source mutation, or
  multi-height promotion;
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
automatic candidate selection, peer-driven promotion, or conflict-triggering
policy outside the exact driver-owned paired-preselection rule requires a
separate explicit authority and policy decision. The exact-current single or
paired, lower-round single or paired, and candidate-backed exact-batch
integrations intentionally stop at separate complete caller-supplied bytes and
do not observe or choose events. They neither replace the paired driver ingress
or the other finality ingresses nor infer that no other finality evidence
exists.
