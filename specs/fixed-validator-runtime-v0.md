# Fixed-Validator Runtime V0

## Scope and authority

`PROD-020-044` defines one caller-driven, process-local runtime in
`naome-runtime`. `FixedValidatorRuntimeV0` owns one existing
[node driver](fixed-validator-node-driver-v0.md), one
[direct-delivery network](fixed-validator-consensus-transport-v0.md), and the
bounded volatile custody described here. The caller supplies the already
constructed driver and network, an ordered publication target list, and explicit
phase-duration policies. The runtime spawns no task. The caller polls it,
explicitly supplies a proposal source, or drains an inbox under `PROD-020-045`.
`PROD-020-046` adds caller raw-input submission, both existing store-backed
authoring forms, and explicit complete-proof operations without dismantling
this owner. The caller chooses every submission; none is automatically inferred
from a raw message, inbox, publication, source store, or transport event.

Consensus retains verification and transition semantics; storage retains durable
signing and finality authority; the node driver retains its sole signing scope,
command custody, inboxes, and step precedence. The runtime grants none of those
authorities to a network peer, routing hint, clock, receipt, or queue order.
Noise identities remain independent of consensus signing keys.

Construction accepts at most eight distinct targets, each in the network's
static configuration. Configuration establishes neither connectivity nor trust.
It checks timing arithmetic for all three phases through the driver's inclusive
round ceiling before taking custody. Rejection returns the driver, network,
targets, timing policy, and reason without stepping the driver or sending bytes.
Empty target lists are permitted and still require ordinary local admission.

## Exact local timing

Each Proposal, Prevote, and Precommit policy has a caller-supplied positive base
and positive per-round increment. There are no defaults. For the full `u64`
round `R`, the duration is `base + R * increment`. Nanosecond multiplication and
addition use checked `u128` arithmetic; conversion to `Duration` and addition to
the monotonic Tokio `Instant` are checked. No round narrowing is permitted.
A duration or deadline overflow is an explicit error.

A deadline begins when the runtime observes an exact `ArmPhaseTimeout` ticket.
Wrapping an already-armed driver begins its runtime deadline when that ticket
is first observed; it does not reconstruct earlier elapsed time. The runtime
retains the opaque ticket's context, position, phase, generation, and lineage.
These process-local deadlines do not define canonical validity, establish a
production timing recommendation, or prove elapsed time to another node.

`next_event` first transfers a pending arm or driver command. Without an owned
publication, ordinary retained driver work is stepped before a new timeout or
input observation. A transition that supersedes an active ticket discards
only its old runtime deadline. A newly installed ticket receives a new deadline;
a stale lineage is never submitted as the fresh driver's due event.

At input observation, an already due exact timer precedes any buffered or
newly polled input. The timer branch also wins a ready `select` tie. If polling
the network crosses the deadline, the complete event is stored in the single
input slot before the due event is admitted. Acceptance uses the driver's
existing due fence and removes the runtime deadline; it does not itself close a
phase or sign a vote.

A `DriverBlocked` or `DriverRejected` step yields once, then permits fresh strict
input instead of repeating an unchanged step indefinitely. Every completed
strict admission attempt, including rejection, re-enables one step because a
rejection may latch capacity state. An accepted due event also re-enables it.
Every successful explicit inbox drain re-enables ordinary step classification.
Pending commands always take precedence over this suppression.

The existing monotone higher-inbox block may reject `TimeoutDue`. In this case
the original expired ticket and deadline remain retained, but that exact ticket
is not continuously observed again. The same higher block already rejects
ordinary current voting and higher inputs. Existing current-finality proposal,
proposal-precommit, and nil-precommit admission exceptions remain available;
ready proposal finality can execute ahead of the block. A changed active ticket
clears the suppression. Command-pending and timeout-mismatch rejections do not
receive this exception or restart a deadline.

An explicit higher-inbox drain also clears this rejected-ticket suppression,
retaining the original ticket and expired deadline. Normal pending-command,
publication, and retained-work ordering still applies before the next due
observation; a drain does not itself accept due state or execute a transition.
Draining another inbox does not clear higher-inbox rejected-ticket suppression.

## Caller input custody

`queue_input` accepts one caller-owned `ConsensusPushMessage` in the same single
slot used by buffered network events. It first refuses an unavailable driver,
then an occupied slot, then a message outside the direct transport's existing
body-length bounds. Every refusal returns the exact original message, including
its allocation pointers, lengths, and capacities. No second slot, copy,
reservation, routing, admission, timer observation, driver step, or transport
work occurs. Length acceptance does not establish canonical validity and does
not inspect spare allocation capacity.

Successful queueing stores only the original raw message. Pending commands,
publication handling, retained driver work, and exact due precedence still
control its later observation through `next_event`. A caller input blocks
another transport poll and precedes a new publication peer attempt, just as an
already buffered network event does. Queueing does not clear a yielded-step
marker, due fence, rejected-ticket marker, or inbox latch. A drain performs no
automatic resubmission; a caller may explicitly queue bytes recovered from a
report, publication, or drain for fresh admission against the then-current state.

Caller admission uses the same descriptive routes, complete copy reservation,
and independent strict driver checks below. Its report identifies `CallerInput`,
has `receipt_queued = None`, and returns the exact original allocations even
when routing, reservation, or either strict admission rejects. This establishes
no peer provenance and queues no transport receipt. An interrupted fatal
admission retains the report under the existing `failed_admission` boundary.

## Descriptive routing and strict admission

The bounded unverified inspectors reuse existing canonical proposal-prefix,
producer-body, and vote-body parsers. They establish only descriptive fields;
they do not verify signatures, membership, payloads, proof validity, or live
branch state. Proposal routing reads the producer's current round, never the
optional earlier valid-round certificate. The complete original inputs must
still pass the selected driver admission path.

| Descriptive input at the driver's height | Ordinary driver route |
| --- | --- |
| Current proposal | Current finality proposal first, current voting proposal second |
| Current proposal prevote | Current proposal prevote |
| Current nil prevote | Current nil prevote |
| Current proposal precommit | Current proposal precommit |
| Current nil precommit | Current nil precommit |
| Higher proposal | Higher proposal with its descriptive producer round |
| Higher proposal prevote | Higher proposal prevote |

Wrong contexts, different heights, lower rounds, unsupported higher vote forms,
and malformed descriptive headers yield a routing error with the exact peer or
caller input. Rejected headers establish no authoritative statement about consensus
validity. This owner does not automatically invoke the driver's explicit
lower-round finality, certificate catch-up, candidate-backed, or conflict APIs.

A current proposal needs two independent complete raw copies. All route copies
are reserved before the receipt is queued or either admission starts. The two
strict admissions run sequentially, finality first, with no intervening driver
step or timer observation. The second is attempted even if the first rejects.
One route's success is retained when the other rejects; no rollback or shared
verified token is implied. Duplicate and capacity outcomes remain the driver's
existing outcomes.

A remote admission report returns authenticated transport source, whether a
receipt was queued, the original input allocations, and independent route
results. Caller reports preserve the original input without transport provenance
or receipt handling. Local reports identify local publication and leave the original in
its publication owner. `completed` means every prepared route returned a normal
admission result; `all_admitted` additionally requires at least one route and
success on every result. A routing failure or interrupted fatal/future outcome
cannot satisfy it. Historical success on an earlier route does not imply its
volatile inbox survives a later fatal driver error.

## Publication custody and backpressure

The runtime retains at most one original typed publication. A proposal keeps
its signed control and exact payload. A vote keeps its signed bytes and its
separate `released_proposal`, including `Some` after a higher-round checkpoint.
The released token is neither forwarded nor implicitly re-admitted for finality.
A caller may take it after publication transfer for a separate explicit action.

For an owned publication, `next_event` uses this order:

1. Transfer any successor driver command, including the vote's next arm.
2. Attempt ordinary strict local admission once, using bounded raw copies.
3. Return a completed publication with all original custody and peer outcomes.
4. Process one already buffered network event or caller input behind the due-timer gate.
5. Start the next unattempted peer delivery, in configured target order.
6. When all peer attempts have started but some remain pending, observe the
   exact timer or network through the same due-first gate.

One fallible copy is submitted per peer. A synchronous refusal records its
reason while preserving the original publication. An in-flight ticket remains
owned until an exactly correlated receipt or asynchronous failure is consumed.
Unmatched terminal events are returned intact. Each peer is attempted only once;
receipt, refusal, and asynchronous failure are terminal outcomes. A failure may
occur after the peer received bytes. Neither receipt nor local admission proves
remote admission, durable delivery, or finality.

The sole publication prevents another signed publication or ordinary driver
transition from being released until its local attempt and all peer attempts
are terminal and the completed owner transfers. Input admission and timer
observation can continue while a delivery is pending. Reservation failure
retains the publication or arm for an explicit subsequent call; it does not
initiate a transport retry.

`author_proposal` accepts only an explicit direct fresh or retained-valid source
through the existing driver authoring gate. Publication backpressure, queued
input/command/arm, an unobserved arm, or an observed deadline returns that source
intact before invoking the driver. Once forwarded, the driver's consuming
source contract applies, including rejection and retained-work outcomes. The
runtime does not choose a source or grant a separate signing path.

`author_candidate_backed_fresh_proposal` accepts the caller's exact target and
borrowed candidate/payload stores. `author_payload_store_backed_retained_proposal`
accepts a borrowed payload store and uses only the driver's private retained
value to derive its address. Both share the direct authoring runtime gate and
return `StoreAuthoringBusy` or `StoreAuthoringUnavailable` before source access.
Once eligible, they invoke their existing driver methods unchanged, including
ordinary retained-work priority, source/proposer/phase checks, full verification,
and anchored signer effects. Store presence supplies availability only. Missing
or rejected sources preserve the continuing driver for explicit insertion/retry
or direct fallback. Integrity failure may poison the owning source handle under
its existing contract; the runtime does not repair or retry it. Successful
authoring queues the exact resolved payload with the signed control, so later
publication does not read a source store again.

## Explicit complete-proof operations

All seven methods are synchronous caller selections. They neither observe a
clock or network event nor call `step` before delegation. Controls, certificates,
exact signed-vote batches, explicit routes, targets, and borrowed stores pass
unchanged into the corresponding existing driver method. The runtime exposes no
mutable driver or general signing-scope callback.

| Runtime methods | Existing driver operation |
| --- | --- |
| `advance_to_higher_round_quorum`, `advance_to_higher_round_vote_batch` | Fully verified higher-round checkpoint under the construction-time ceiling |
| `commit_lower_round_finality`, `commit_lower_round_finality_vote_batch` | Complete direct strictly lower-round finality |
| `commit_candidate_backed_finality_vote_batch` | Exact candidate-backed direct-child finality |
| `commit_candidate_backed_finality_conflict_vote_batch` | Historical selected-sibling conflict |
| `commit_lower_round_preselection_conflict_vote_batches` | Independently verified lower-round pair and neutral halt |

The five positive methods return runtime `Busy` while a publication, pending
runtime arm, or pending driver command remains owned. An unavailable driver
returns `DriverUnavailable`. These are pre-invocation refusals, distinct from a
delegated driver rejection. Direct lower-finality methods return their original
owned payload beside the refusal; borrowed inputs remain with the caller.
Buffered input, phase, an absent runtime timer, an expired deadline, and accepted
due state add no runtime gate. The existing driver still gives unresolved exact
current finality priority over all five methods and retained actionable or
blocked higher evidence priority over higher checkpoints. It does not silently
step that work or consume the buffered input first.

An explicit terminal conflict attempt waits only for pending driver commands to
transfer. Once they have transferred, a publication, in-flight ticket, pending
runtime arm, buffered input, phase, or expired/accepted due state does not delay
the attempt. This exception applies only to the two explicitly called conflict
methods; neither raw admission nor ordinary polling automatically invokes it.
A runtime refusal of a lower pair returns both original owned payloads in
argument order. After either positive or terminal delegation, the driver's
existing consuming-input contract applies to every outcome.

Every known continuing driver is restored. Typed rejections and unresolved-work
outcomes preserve the exact runtime markers and custody. A higher checkpoint
re-enables ordinary classification and discards its superseded deadline; its
quorum role determines the existing destination Prevote or Precommit phase,
without signing or setting a new lock/valid value. A finality result does this
only when its returned position changed. No-write same-position results retain
the exact deadline and markers. The next ordinary poll transfers the driver's
queued destination arm. Buffered input remains raw across the operation and
later receives ordinary admission against the resulting state; it is neither
promoted, discarded, nor reinterpreted as a complete proof.

A lower-pair pre-effect rejection restores the driver, including while a
publication remains outstanding. A verified distinct pair records the existing
neutral `PreselectionPair` halt; neither input becomes a selected winner. A
verified historical candidate conflict records the existing `SelectedSibling`
halt against the retained selected parent. Both preserve the exact paired
finality-halt and signer-stop evidence. Candidate-conflict processing consumes
the driver even on a pre-append error; a lower pair also consumes it once sealed
evidence enters its finality coordinator. These existing error distinctions are
returned without inventing recovery.

Every terminal or fatal outcome leaves no runtime driver. `next_event` then
returns `DriverUnavailable` without local admission, signing, timer observation,
or another publication send attempt. Original publication bytes, any released
`Some` token, local-attempt marker, per-peer outcomes/in-flight tickets, pending
runtime arm, timer, buffered input, and failed-admission report remain available
through `into_parts`. Already queued transport cannot be recalled; explicit
transport service can still progress that existing work. Only strict anchored
reopen classifies the durable prefix and may create a fresh owner. Unsupported
future driver outcomes transfer intact with any driver they own.

## Transport service, bounds, and failure

`poll_transport_once` polls the network once without observing a timer, admitting
input, stepping the driver, or starting a publication send. It can service a
queued receipt while the caller holds driver work. At most one returned network
event is buffered; an occupied input slot prevents another poll. A pending poll
is not proof that a receipt was flushed. Only the peer's correlated successful
receipt proves transport completion. No implicit incoming-message forwarding,
outbound retry, silent inbox drain, or eviction occurs.

The direct transport's one shared inbound/outbound consensus stream per
connection, eight shared outbound permits, ingress budgets, and connection
limits remain unchanged. Crossed sends can fail. A caller can explicitly
serialize exchanges using bounded transport service and buffered admission; no
fairness, reserved capacity, delivery completeness, or liveness is guaranteed.

Bounds are compositional, not one total-memory ceiling: the existing transport
owns its separate inbound budgets and shared outbound permits; the driver owns
four separately bounded inboxes; the runtime owns one original publication with
at most eight ordered peer states, one timer/arm, one shared slot containing
either a `NetworkEvent` or a body-length-bounded caller message, and at most one
interrupted admission report. A buffered unrelated event can
carry that protocol's own bounded payload. Copies needed for strict admission
and sending are additional bounded allocations. Caller-retained returned events
and reports, together with inbox drain iterators, require a separate caller-owned
memory bound. These byte-length limits do not bound spare `Vec` capacity or
total allocator use.

Dropping a borrowed `next_event` future preserves stored driver, publication,
ticket, and input custody; it does not cancel queued transport work. No await
occurs after consuming the driver or removing an event for admission.
`into_parts` explicitly transfers every surviving owner and marker. Its
`pending_network_event` and `pending_caller_input` fields are mutually exclusive.
A route-copy
allocation error returns the original unacknowledged inbound handle, including its response path. Closed-channel acknowledgement
still preserves original source and input, with `receipt_queued = false`.

A fatal driver operation leaves no usable driver. Subsequent `next_event` returns
`DriverUnavailable`; only separately retained runtime custody survives. Strict
anchored reopen alone classifies durable prefixes and creates a fresh driver.
The runtime adds no rollback, repair, durable outbox, recovered inbox, recovered
pending command, inherited due event, or persistent timer lineage. Future
unsupported dependency outcomes transfer intact, including any driver they own.

## Explicit inbox recovery

`PROD-020-045` exposes the driver's four existing full lossless drains without
tearing down the runtime:

| Runtime method | Returned existing driver inbox drain |
| --- | --- |
| `drain_inbox_and_reset` | Higher proposals and proposal prevotes |
| `drain_current_inbox_and_reset` | Current proposals and proposal/nil prevotes |
| `drain_current_finality_inbox_and_reset` | Current finality proposals and proposal precommits |
| `drain_current_nil_precommit_inbox_and_reset` | Current nil precommits |

The caller selects exactly one class per synchronous call. `Some(drain)`
transfers the complete existing class-specific iterator, including stale charged
evidence, exact canonical bytes, and any existing higher proposal token. An empty
live inbox returns `Some(empty)`. Only that driver's existing class drain clears
its accounting and blocking state. `None` means no driver survives and changes
no runtime field; it cannot recover from a fatal operation.

Each successful drain restores the same continuing driver and re-enables its
ordinary step classification. Only the higher drain clears rejected-ticket
suppression, as specified above. All other inboxes and their blocking, position,
phase, accepted due state, active ticket, exact deadline, pending arm and driver
command, publication bytes and released `Some` token, per-peer delivery state and
in-flight tickets, buffered peer/caller input, failed-admission report, and durable
authority remain unchanged. No network poll, send attempt, receipt completion,
admission, signature, transition, or timer observation occurs during a drain.

The publication's local-admission-attempt marker remains unchanged even when the
caller drains bytes previously counted from that publication. Polling again does
not silently reinsert them. The caller remains responsible for retained drain
memory and any later explicit input submission, which must pass ordinary strict
admission and its current context, phase, due, and capacity gates. No automatic
eviction, filtering, reinsertion, evidence preference, or extra signing or
finality authority is introduced. Recovery preserves volatile custody; it does
not make it durable or reconstruct it after teardown.

## Verification and exclusions

`crates/naome-runtime/tests/runtime.rs` drives two real Unix loopback Noise
networks through runtime-owned anchored proposals and votes to the same selected
child. The equal-weight case needs both remote votes and serializes the five
streams explicitly. The weighted case also strictly reopens both nodes at that
child without a catch-up allowance. `tests/cases/adversarial.rs` covers independent
partial admission, malformed and unsupported raw inputs, blocked finality
repair, exact deadline precedence, retained-work precedence, checked construction,
higher-inbox blocked deadlines, injected signer-anchor failure, and original
`Some` token custody through cancellation, refusal, receipt, and asynchronous
failure. Consensus inspector tests distinguish descriptive routing from strict
verification and earlier valid-round evidence.

`tests/cases/recovery.rs` exercises original rejected deadlines after class
drains, due precedence over a real buffered inbound proposal, explicit recovery
from stale current/finality saturation followed by a second selected height,
and exact class custody across two nil rounds with small inbox budgets. The
second-height cases have one consensus validator: one uses a separate transport
peer to re-supply the rejected proposal, and the other uses caller queueing with
an isolated transport. Neither is multi-validator progress evidence. The adversarial publication vectors additionally drain with
a pending successor arm and an in-flight `Some` publication, preserve buffered
input and an accepted due fence across drains, retain finality priority after
higher recovery, and return `None` after injected driver failure.

`tests/cases/caller_input.rs` checks lossless queue refusal, slot occupancy,
strict corrupt-input rejection, and command/due precedence. Existing adversarial
vectors also cover caller partial admission, a buffered-peer slot refusal,
publication custody, and queued caller input surviving an injected fatal step.
`tests/cases/store_authoring.rs` proves explicit missing-source insertion/retry,
initial-command and caller-input backpressure before the first corrupt payload
read, and actual round-one retained authoring with exact lock/valid certificate
and byte-identical strict-reopen replay. The round continuation uses one
consensus validator and explicit finality drain before advancing.

`tests/cases/explicit_proofs.rs` checks both higher-proof forms with a real
proposal-prevote quorum, expired or accepted due state, buffered caller input,
rejection/retry and checkpoint reopen. Both direct lower forms finalize from
all three due phases established through public driver calls. Candidate finality
covers explicit source insertion/retry and strict child reopen. All five preserve
retained-current-finality precedence without a hidden step and preserve owned
payloads on runtime backpressure. `tests/cases/terminal_proofs.rs` uses separately
anchored conflicting proposals and real in-flight Noise tickets to check both
terminal paths, exact halt identities, consuming no-write errors, strict reopen,
and independent input/publication custody; the lower pair also retains a real
released `Some` token. Queued sends are not claimed to have been recalled.

These are bounded local tests, not deployment, multi-process/devnet,
production-timeout calibration, latency benchmarks, general distributed
liveness, exhaustive allocation/I/O faults, or non-Unix filesystem runtime
evidence. Automatic artifact acquisition, broader finality routing, automatic
source selection, general gossip, durable delivery, reserved control capacity,
node binaries, key loading/rotation, remote signing, and dynamic validators
remain outside this slice.
