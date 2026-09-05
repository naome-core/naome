# Fixed-Validator Runtime V0

## Scope and authority

`PROD-020-044` defines one caller-driven, process-local runtime in
`naome-runtime`. `FixedValidatorRuntimeV0` owns one existing
[node driver](fixed-validator-node-driver-v0.md), one
[direct-delivery network](fixed-validator-consensus-transport-v0.md), and the
bounded volatile custody described here. The caller supplies the already
constructed driver and network, an ordered publication target list, and explicit
phase-duration policies. The runtime spawns no task and advances only when
polled or when the caller explicitly supplies a proposal source.

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
network observation. A transition that supersedes an active ticket discards
only its old runtime deadline. A newly installed ticket receives a new deadline;
a stale lineage is never submitted as the fresh driver's due event.

At network observation, an already due exact timer precedes any buffered or
newly polled input. The timer branch also wins a ready `select` tie. If polling
the network crosses the deadline, the complete event is stored in the single
input slot before the due event is admitted. Acceptance uses the driver's
existing due fence and removes the runtime deadline; it does not itself close a
phase or sign a vote.

A `DriverBlocked` or `DriverRejected` step yields once, then permits fresh strict
input instead of repeating an unchanged step indefinitely. Every completed
strict admission attempt, including rejection, re-enables one step because a
rejection may latch capacity state. An accepted due event also re-enables it.
Pending commands always take precedence over this suppression.

The existing monotone higher-inbox block may reject `TimeoutDue`. In this case
the original expired ticket and deadline remain retained, but that exact ticket
is not continuously observed again. The same higher block already rejects
ordinary current voting and higher inputs. Existing current-finality proposal,
proposal-precommit, and nil-precommit admission exceptions remain available;
ready proposal finality can execute ahead of the block. A changed active ticket
clears the suppression. Command-pending and timeout-mismatch rejections do not
receive this exception or restart a deadline.

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
and malformed descriptive headers yield a routing error with the exact remote
input. Rejected headers establish no authoritative statement about consensus
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
results. Local reports identify local publication and leave the original in
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
4. Process one already buffered network event behind the due-timer gate.
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
at most eight ordered peer states, one timer/arm, one buffered `NetworkEvent`,
and at most one interrupted admission report. A buffered unrelated event can
carry that protocol's own bounded payload. Copies needed for strict admission
and sending are additional bounded allocations. Caller-retained returned events
and reports require a separate caller-owned memory bound.

Dropping a borrowed `next_event` future preserves stored driver, publication,
ticket, and input custody; it does not cancel queued transport work. No await
occurs after consuming the driver or removing an event for admission.
`into_parts` explicitly transfers every surviving owner and marker. A route-copy
allocation error returns the original unacknowledged inbound handle, including its response path. Closed-channel acknowledgement
still preserves original source and input, with `receipt_queued = false`.

A fatal driver operation leaves no usable driver. Subsequent `next_event` returns
`DriverUnavailable`; only separately retained runtime custody survives. Strict
anchored reopen alone classifies durable prefixes and creates a fresh driver.
The runtime adds no rollback, repair, durable outbox, recovered inbox, recovered
pending command, inherited due event, or persistent timer lineage. Future
unsupported dependency outcomes transfer intact, including any driver they own.

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

These are bounded local tests, not deployment, multi-process/devnet,
production-timeout calibration, latency benchmarks, general distributed
liveness, exhaustive allocation/I/O faults, or non-Unix filesystem runtime
evidence. Automatic artifact acquisition, broader finality routing, automatic
source selection, general gossip, durable delivery, reserved control capacity,
node binaries, key loading/rotation, remote signing, and dynamic validators
remain outside this slice.
