# Fixed-validator V0 process kill under partition

## Contract and authority

`SEC-012-005` checks one actual Unix process crash after a distributed non-nil
lock, followed by strict restart and continued voting under permanent isolation.
It refines the decided partition-safety requirement using the existing process,
runtime, signing, and anchored-journal contracts. It adds no production behavior.
The test is `crates/naome-validator/tests/cases/partition_process_restart.rs`.

Four independently anchored `naome-validator` children generate every honest
proposal and vote themselves. The harness supplies ordinary configuration and
two `author_fresh` commands, closes opaque TCP gates, kills and reaps one child,
and starts a replacement in explicit `open` mode. It supplies no driver event,
timeout ticket, signing effect, quorum proof, selected history, or manufactured
honest signature. Original proposal source files are removed before restart.
The harness does not grant signing, finality, recovery, or transport authority.

## Distributed lock and exact crash checkpoint

The four raw-key-sorted validators have immutable unit weights. The shared
process-partition setup first establishes the complete Noise/Yamux mesh,
finalizes a common H1 artifact, drains every publication with three correlated
received outcomes, and obtains quiescent H2/R0 Proposal status from all owners.

Before H2 authoring, the harness cuts every leaf-to-leaf path and requires both
endpoints to report disconnection. The actual H2 proposer is the remaining
star's center. Each leaf can receive only its own and the center's prevote:
`3 * 2 <= 2 * 4`, insufficient for a non-nil precommit. The center can receive
at least three actual prevotes and form a strict quorum. Its single non-nil
precommit is insufficient for finality anywhere, even when fully delivered.

The center must report H2/R0 Precommit, admit its actual local proposal
precommit, and finish all prepared publications. Only successful H2 proposal
prevote admissions preceding that transition contribute to the saved set of
actual consensus keys. Peer receipts are checked separately from signatures.
All three leaves must admit the real proposal through both routes, admit their
local prevote, and retain its valid signed bytes; none may acquire a lock.

The harness then permanently cuts all remaining center paths, sends an actual
process kill, and requires OS-reported SIGKILL termination. An intervening
ordinary error exit cannot satisfy the crash oracle. The other three original
children remain alive. Only after reaping does parent-owned strict inspection
open the center's anchored finality and vote pairs under the existing
spawn/journal guard. It requires H1 finality, matching persisted bounds, no
terminal cause or pending preparation, and exact H2/R0 Precommit recovery with
the non-nil R0 lock and complete valid-value certificate. A later coordinate,
pending preparation, or failed strict replay fails this checkpoint; no retry,
repair, or alternate crash point turns it into a pass.

The public anchored recovery capability and recovered signing session are used
only for diagnostics. No signing method is called. All authority images must
remain byte-identical through inspection, and every parent handle and guard is
dropped before the replacement child starts.

## Restart, deadlines, and signing evidence

The replacement uses the same journals, anchors, keys, context, immutable set,
and persisted limits. Its ready report must restore H2/R0 Precommit and H1's
selected head with empty inboxes, no publication, and no due timeout. Fresh
driver construction has its normal initial timeout-arm command pending; the
runtime has not yet armed its timer. Authority images must still match the
post-crash snapshot at this checkpoint.

With every gate blocked and no new proposal command or peer admission, four
admitted real deadlines advance the replacement through R1 Proposal, a locked
value prevote, nil precommit without quorum, and R2 Proposal. The replacement
is shut down first to bound that final checkpoint; the other original children
must have remained alive throughout. This does not require their slower timers
to reach R2. All normal shutdowns require released locks and successful exit.

Strict stopped-owner inspection verifies retained completed votes against the
exact context, actual key, position, and role. Every pre-crash center vote must
retain identical canonical bytes after restart. Exactly two new votes must
exist: H2/R1 prevote for the original locked value and H2/R1 nil precommit.
Final recovery must restore durable R1 Precommit and the exact R0 lock and
complete valid-value certificate; the R2 Proposal advance is volatile.

The saved R0 certificate is independently verified against the immutable set.
Every certificate signer must belong to the center's successful pre-transition
admissions. Its canonical bytes and identity must be reproducible from those
signers' actual retained R0 prevotes, collected only after their children exit.
This is a completed-vote oracle, not an inventory of wire emissions. JSONL peer
labels and publication counts alone never prove signed weight.

Every observed partition milestone and final shutdown preserves the exact H1
finality journal and anchor bytes at all four owners. Strict replay verifies
the exact common artifact, payload, artifact-set root, and consensus ancestry
without changing any authority image. Every gate must retain exactly its one
original forwarded connection and observe refused redials; the replacement
must never establish a peer session or admit peer input.

## Bounds and evidence limits

Original processes use 60-second phase bases plus one millisecond per round;
the explicitly configured replacement uses five seconds plus one millisecond
per round. These are test scheduling bounds, not timer persistence or production
timing recommendations. The existing 45-second milestone, 4,096-event
transcript, gate-worker, inbox, and persisted replay/preparation bounds from
the [process-partition corpus](fixed-validator-process-partition-v0.md) apply.
The three survivors retain their original processes, timers, and inboxes.

This is one finite local Unix process-kill and loopback partition execution.
It adds no automatic restart, retry, evidence resupply, inbox disposal, healing,
general crash or power-loss recovery, partial-write fault injection, Byzantine
schedule, dynamic validators, general safety or liveness, deployment, or
production-readiness claim. `SEC-012` remains `IN_PROGRESS`. The separate
[runtime-owner restart corpus](fixed-validator-partition-restart-v0.md) retains
its own delivery and lifecycle evidence boundary.
