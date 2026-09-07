# Fixed-Validator Recovery Simulation V0

## Selected properties and boundaries

This suite exercises the artifact-only fixed-validator V0 implementation. Its
selected safety properties are: an honest signing slot never exposes conflicting
canonical messages; finality requires a recipient-local strict supermajority
under the immutable total weight; and honest selected histories do not conflict.
Raw admission and failed authority reopen must not advance canonical state.

The delivery and actor schedules are finite and deterministic. They do not
quantify over arbitrary delays, partitions, failures, or adversarial schedules.
Controlled recovery assumes the documented honest quorum, available valid
proposal data, eventual delivery of the designated original messages, and the
explicit phase-event schedule. No timeout calibration or general liveness
assumption is introduced into production consensus.

## Delivery faults

`driver/partition/delivery_faults.rs` extends the existing four-owner partition
simulator with a reusable bounded logical-time delivery queue. The scheduler
uses the documented xorshift operations and fixed seeds 7, 29, and 101 solely to
order test delivery. Each entry has a logical delivery coordinate and order;
re-running a seed must reproduce the complete `(tick, order, recipient)` trace.
The queue is limited to 8,192 pending entries, actor execution to 4,000 steps,
and each basic delivery execution to 100 logical ticks. Exceeding a bound fails
the test rather than reporting success.

Five policies exercise duplication, reordering, delay, precommit loss, and their
combination. The four honest actors use unit weights or weights `[3, 2, 1, 1]`.
Each of the 30 policy/profile/seed combinations runs twice, for 60 executions.
Honest proposals and votes come only from real anchored driver publication
commands. Exact duplicate admission is observed at the driver boundary; late
inputs may be rejected, but every rejection must leave all authority images
unchanged. The scheduler does not silently deduplicate incoming traffic.

The loss policy drops precommits and first checks an unfinalized prefix with no
recipient precommit quorum. Recovery explicitly replays original sender-owned
signed bytes; it does not manufacture a vote or treat a dropped delivery as
successful. All four recipients must then select the same artifact. The oracle
counts each actual admitted precommit signer once per recipient and root,
independently computes the strict immutable-total threshold, and checks the
selected history after every admission and step.

These cases are the bounded evidence for `TEST-006` through `TEST-009`.

## Competing authorized proposals

Three further seeded schedules use four honest actors of weight 2 and one
Byzantine key of weight 3, below one third of total weight 11. At the scheduled
round-zero proposer position, the Byzantine key sends two separately valid
proposals to groups of three and one honest actors and signs conflicting
agreement messages. Every honest actor must actually prevote the proposal it
received. The three-actor group obtains the sole proposal-prevote quorum and
actually signs proposal precommits; the minority signs nil. Precommit delivery
is withheld, and all actors must remain unfinalized.

Healing replays the original precommits and supplies the already-authorized
majority proposal to the minority's finality path. Delays may expose a healthy
missing-proposal block or current proposal ambiguity; neither may cause a
conflicting signature or finality. Only the majority proposal may finalize,
and healing must create no replacement honest votes. The same complete
recipient-local quorum oracle remains active.

This supplies bounded `TEST-012` and `TEST-016` evidence. The existing cold and
precommit partition matrix remains required, including its below-threshold,
exact-two-thirds, weighted quorum, Byzantine bridge, and finite healing cases.

## Independently restarted actors

`driver/recovery_simulation.rs` owns each of four real driver/journal pairs in
its own scoped worker. The test sends one command and waits for its response
before the next command, so thread scheduling does not select a consensus
ordering. Restart destroys only the selected actor's volatile driver and both
journal owners, then strictly reopens them; the other three remain live.
Each actor is limited to 2,000 commands and each ordinary pump to 16 steps.

Six schedules cover each possible lagging actor with unit weights and each
weight-1 lagger with weights `[3, 2, 1, 1]`. The connected three actors form a
strict supermajority and produce actual signed nil votes after two rounds of
explicit due events. The lagger collects their round-two prevotes and
checkpoints without signing. The schedule then checks:

1. Restart before transferring the new arm preserves the exact checkpoint,
   loses only volatile inbox custody, and rejects the old timer lineage.
2. Re-delivered current nil votes cause the existing nil-precommit and
   sequential-round paths. Restart after the unpersisted round-three advance
   restores durable round-two Precommit, and the same real nil quorum restores
   round three without another signature.
3. After healing, the actual scheduled proposer authors one valid artifact.
   Restart before its publication must preserve the exact completed proposal,
   and explicit authoring retry must replay those bytes without another write.
   Real honest prevotes produce precommits. Restart of the lagger after durable
   signing but before publication preserves its exact completed precommit and
   complete round-three lock, value, valid round, and certificate proof.
4. Explicit replay of that original completed vote, re-admission of lost
   proposal custody, and real precommit delivery lead all four actors to the
   same height-one finality. No resumed actor can sign a replacement lower-phase
   vote. Each actor is then independently reopened at child height two.

The oracle verifies the signer, context, position, role, and exact bytes of all
28 expected honest signing slots (27 votes and one proposal) in each schedule, including completed but
previously unpublished votes. It checks every expected slot, unchanged finality
through the pre-heal prefix, recipient-local quorum weight at selection, exact
shared finality images, and strict post-finality restart.

These finite executions provide `TEST-011`, `TEST-013`, and `TEST-014` evidence.
They are deterministic actor simulations, not operating-system process kills.
Separate Unix binary tests in `cases/higher_collection.rs` use SIGKILL after a
real runtime checkpoint and verify strict restart with no publication.

## Corruption and interrupted persistence

After each actor scenario shuts down all owners, the suite corrupts each
nonempty finality-journal, finality-anchor, vote-journal, and vote-anchor file of
the lagging actor, one file at a time at its first, middle, and last byte. Every
strict reopen must fail and leave the corrupted authority images unchanged.
Restoring the original fixture bytes must permit strict reopen. These complete
image mutations are the selected `TEST-015` evidence; they are not a claim about
repairing corruption or accepting torn suffixes.

`fixed_validator_vote_safety_journal/tests/faults.rs` additionally injects every
supported anchor-replacement operation failure during the first nil-precommit
completion after an anchored higher-round checkpoint. Each failure must fire,
return no signature, and poison the live owner. A journal ahead of its anchor
must fail strict reopen; when replacement completed before the directory-sync
failure, stabilized reopen may return only the exact control-run completed
bytes and phase, and must reject lower-round session issuance.

This new path composes with the required existing append-fault matrices for
lineage, prepare, higher checkpoint, completion, and recovery/stabilization, and
the node-level collected-checkpoint anchor-failure regression. Together they
provide the bounded `TEST-026` evidence. Anchor operation injection and SIGKILL
cases are Unix-specific; deterministic actor/delivery tests and scripted append
faults are compiled and exercised on their supported CI platforms. No runtime,
restart, or live-network result is inferred from a static review or a successful
build alone.
