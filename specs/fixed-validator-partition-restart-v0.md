# Fixed-validator V0 partitioned owner restart

## Contract and authority

`SEC-012-004` checks one finite lifecycle boundary: a validator that acquired a
real distributed non-nil lock strictly reopens its original anchored journals
and continues isolated voting while the other three runtime owners remain in
their original signing lifetimes. Restart must not erase prior signing intent,
recreate volatile finality evidence, clear the durable lock, or relax quorum.

The test in `crates/naome-runtime/tests/cases/partition_restart.rs` uses the
ordinary startup and runtime APIs. It supplies no driver event, timeout ticket,
lock, signing state, finality proof, or manufactured honest signature. It adds
no production behavior, retry, evidence resupply, inbox disposal, healing,
automatic recovery, or protocol policy. General `SEC-012` remains unfinished.

## Execution

Four distinct raw-key-sorted validators have immutable unit weights and
independent finality/vote journals and anchors. All four first finalize the same
H1 artifact through actual runtime proposal and vote publication and ordinary
local/caller admission. H2 starts from that shared nonempty finalized prefix.

The H2/R0 proposal and prevotes reach all owners. Cross-component precommits
between `{0,1}` and `{2,3}` are withheld, so every owner publishes a real non-nil
precommit but receives only its two-key component's precommits. Independent
integer arithmetic rejects `2/4` as a strict quorum. No H2 finality occurs, no
deadline has elapsed, and all caller queues and publications are drained.
Every subsequent cross-component input, including later prevotes, is dropped.
The withheld messages are never restored.

Owner 3 then exits its complete awaited signing callback, closing both journal
pairs. The other three runtimes and signing callbacks remain live. Strict
startup opens the same four directories with the same configuration and key;
it must classify ready, preserve every authority image, and restore H2/R0
Precommit with the exact locked and valid H2 value, lock/valid round zero, and
complete canonical prevote certificate.

The recovered certificate is independently decoded against the unchanged
position snapshot. Every signer must occur in this recipient's successful
prevote admissions captured at its original Precommit transition. Rebuilding
the certificate from those exact admitted signed bytes must reproduce both its
bytes and identity. The test permits the actual selected quorum subset; global
publication or later recipient admission cannot substitute for those inputs.

The replacement runtime starts with empty inboxes, no publication, no failed
admission, no timer, and an empty caller/network slot. Its new Precommit arm
uses generation zero and a future deadline for the recovered position. No old
ticket is injected. An additional ordinary poll must find no reconstructed
publication or input. Reopen, session issuance, construction, and the new arm
leave all four owners' authority images unchanged.

Only actual runtime deadlines advance virtual time and voting. The restarted
owner and each surviving owner must emit an H2/R1 prevote for locked value A,
admit its component peer's matching prevote, emit a nil precommit without a
quorum, and reach H2/R2 Proposal. Owner 3's new prevote and precommit must be
observed after its restart; its vote authority bytes must advance, while every
owner's H1 finality journal and anchor remain byte-identical.

A final strict reopen of owner 3 verifies the newly persisted H2/R1 Precommit
state and the unchanged R0 lock and complete valid certificate. The observed
R2 Proposal advance was volatile: this expected recovery to R1 does not erase
a signed intent or require recovery to an unpersisted coordinate. That final
reopen and diagnostic scope also preserve every authority image.

## Oracle and bounds

One observer survives every owner generation. It strictly verifies every
published vote's fixed context, actual public key, height, round, role, and
target, then records its target and canonical bytes under that complete vote
slot. Repeated emission within one owner lifetime fails. A later lifetime may
re-release only identical completed bytes for the same intent; changing a
target or its canonical bytes fails. This signing history is never reset.

Recipient admission accounting is separate. Only owner 3's volatile prevote
and precommit records are cleared on its restart; the other owners retain
their original custody and observation history. The saved pre-transition
prevotes are used only to verify durable lock evidence and are never delivered
again. Owner 3 must acquire its later peer prevote through fresh ordinary
admission, and it must retain no proposal-precommit admission after restart.
Every poll, caller transfer, and authoring step checks the unfinalized durable
prefix; the currently polled owner's selected head is also checked.

This one FIFO caller-input execution reuses the existing isolated transport,
four inboxes of 128 entries and 1 MiB each, 256-envelope caller queues, 8,000
event ceiling, inclusive round ceiling four, and one-second phase base plus
one millisecond per round. At most twelve deadline advances may reach the
post-restart endpoint. Existing fourteen runtime partition executions retain
their separate schedules and assertions.

This is local Unix runtime teardown/reopen and continued-voting evidence with
real signatures and anchored I/O. It is not process termination, power loss,
partial-write injection, arbitrary crash scheduling, network reconnection,
partition healing, general partition safety or liveness, dynamic validators,
deployment, or production-readiness evidence.
