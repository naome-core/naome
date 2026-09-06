# Fixed-validator V0 runtime partition simulation

## Selected property and authority

`SEC-012-002` exercises the existing fixed-validator V0 Runtime owner after a
nonempty finalized prefix. Four independently anchored honest signers remain
inside their original runtime owners for each complete execution. All four
first finalize the same H1 artifact through actual runtime proposal authoring,
publication, self-admission, caller-input delivery, and finality. No finality
proof, selected branch, or signing scope is installed by the test scheduler.

The H2 partition must preserve each unfinalized recipient's exact H1 finality
journal and anchor images. A recipient may finalize H2 only with successfully
admitted matching precommits whose distinct signer weight strictly exceeds two
thirds of the unchanged fixed total. Every honest selected value must extend the
same H1 prefix; even legitimate H2 finality must preserve the exact H1 journal
prefix. Insufficient connectivity does not lower the denominator or make a
timeout a source of finality authority.

This is a test of the existing runtime composition, including its single raw
input slot, self-admission, publication custody, and deadline ordering. It
changes no production code, protocol rule, API, signing boundary, persistence
format, proposer rule, routing policy, or timeout policy. `SEC-012` remains
`IN_PROGRESS`.

## Corpus and finite bounds

The following seven cases each execute twice: ascending owner order with FIFO
caller queues and one copy, and descending owner order with LIFO caller queues
and two copies. The second schedule can deliver messages across phase changes;
ordinary runtime routing and admission report the resulting stale inputs.
Every vote is also re-supplied to its own publisher through the caller slot,
separately from the runtime's ordinary self-admission. The scheduler never
directly admits an event to, steps, or replaces the owned driver.

Keys are sorted by their actual raw consensus key bytes before assigning the
fixed weights. H1 is fully connected in every case. H2 uses:

| Case | Fixed weights | H2 groups | Required H2 result |
| --- | --- | --- | --- |
| Unit split | `[1,1,1,1]` | `{0,1}` / `{2,3}` | Neither `2/4` group finalizes |
| Exact threshold | `[2,1,1,2]` | `{0,1,2}` / `{3}` | Three keys with `4/6` cannot finalize |
| Below threshold | `[4,1,1,1]` | `{0}` / `{1,2,3}` | Neither `4/7` nor `3/7` finalizes |
| Unit majority | `[1,1,1,1]` | `{0,1,2}` / `{3}` | Only the `3/4` group finalizes |
| Weighted majority | `[3,2,1,1]` | `{0,1}` / `{2,3}` | Only the two-key `5/7` group finalizes |
| Precommit cut, unit | `[1,1,1,1]` | `{0,1}` / `{2,3}` | All four publish non-nil precommits; neither group finalizes |
| Precommit cut, exact threshold | `[2,1,1,2]` | `{0,1,2}` / `{3}` | All four publish non-nil precommits; `4/6` remains insufficient |

Cold cuts drop every cross-group H2 message. Precommit cuts deliver proposals
and prevotes while withholding cross-group precommits, including later nil
precommits. Dropped envelopes are counted and never restored. No envelope is
manufactured with an honest private key: all inputs come from the actual typed
runtime publications. Proposal signatures are independently reverified against
the branch-derived proposer; vote signatures, actors, positions, roles, and
targets are independently checked before the publication is routed.

In each negative execution, all four original owners reach at least H2/R2
without finalizing H2. They must each actually publish both a prevote and a
precommit at H2/R0. In the precommit-cut cases all four R0 precommits must be
non-nil, and each recipient's successfully admitted signer mask must equal its
exact component before time advances. Positive controls stop after the
permitted majority finalizes H2; the minority retains H1. No minority recovery
or partition healing is performed by this corpus.

The runtime retains its original four inboxes, each limited to 128 entries and
1 MiB, without draining or resetting any class. Each caller queue is bounded to
256 envelopes. The runtime's inclusive round ceiling is four. At least 8,000
visible runtime events, failure to reach the prescribed round condition in 20
scheduling iterations, a nonempty queue at quiescence, unexpected rejection,
saturation, blocking, or loss of a live driver fails the test.

## Clock, custody, and the admission oracle

An isolated transport with no configured peers or publication targets prevents
socket delivery. Completed publication copies pass through the existing public
`Runtime::queue_input` path. Queue acceptance is checked to change no durable
authority. It establishes raw custody only; admission occurs later through
`Runtime::next_event`.

Tokio time is explicitly paused. The test selects the already-supported local
duration of one second plus one millisecond per round for each phase. It polls
each owner once per scheduling visit and asserts that this never advances
virtual time. Pending futures are dropped while retaining the same owner. Only
explicit advancement to an observed runtime deadline changes virtual time;
there is no direct timeout-ticket injection or forced driver phase transition.

Every negative execution also queues an exact already-published local
precommit into an idle owner's raw caller slot, then advances to that owner's
Precommit deadline. The next event must mark that exact deadline due before
the buffered input is admitted. All four of that owner's authority images must
remain unchanged at this observation, and transport-only polling must report
the caller slot still occupied. Subsequent ordinary owner work consumes the
input under the resulting live position's normal routing rules.

The oracle associates each local admission report with the runtime's currently
owned typed publication and each caller report with its exact queued envelope.
Only a successful `CurrentProposalPrecommit` admission updates that recipient's
`(height, round, proposal root)` signer mask. Self-admission and caller resupply
share the same signer bit. Neither publication preparation, completion,
`local_admission_attempted`, queue acceptance, nor rejected routing/admission
contributes weight. An observed finality must satisfy independent small-integer
`3 * admitted_weight > 2 * fixed_total` arithmetic. Across H1 and H2, each execution must also observe actual local and caller
precommit admissions and no-growth duplicates. Reports containing no insertion
must preserve every exposed inbox entry and byte counter.

Every visible event, poll, queue transfer, and explicit authoring action checks
the honest selected heads and finality images. Admission reports alone must
preserve all four authority images. The test derives one private expected H2
branch from the actual H1 publications only after all four owners have already
finalized H1; this expected branch is never installed in an owner or supplied
as finality evidence to a recipient.

## Evidence limits

These fourteen executions exercise real runtime ownership, signatures,
verification, and anchored journal writes with deterministic caller-input
delivery. They do not establish Noise transport or real-socket partitions,
separate processes, arbitrary schedules or topologies, arbitrary weights or
Byzantine coalitions, dynamic validators, crash/restart behavior, I/O-fault
coverage, general partition safety, eventual liveness, healed convergence,
multi-region timing, deployment, or production readiness. The separate driver
corpus remains specified in `fixed-validator-partition-simulation-v0.md`.
