# Fixed-Validator Higher-Round Recovery V0

## Authority and scope

`PROD-020-064` extends the existing fixed-validator V0 driver and bounded runtime
to collect individually authenticated higher-round prevotes and precommits,
with either nil or proposal targets. A healthy complete retained snapshot may
supply one uniquely actionable quorum to the existing anchored higher-round
checkpoint coordinator. This checkpoint changes only the authenticated round
and role-corresponding phase. It preserves the exact lock and complete retained
valid value, valid round, and proof.

The collector grants no proposal validity, block selection, finality, branch
choice, peer trust, discovery, or new signing authority. An opaque proposal root
in a vote does not establish that its proposal or artifact is available. The
existing separately verified proposal-plus-prevote pairing path can still
perform its established locking and signing operation; collection does not
expand that operation's authority.

## Admission and shared custody

`HigherRoundVote` owns one complete canonical signed vote. Before retention the
driver verifies framing, signature, and consensus context, requires the live
height and a strictly higher round, checks both its construction-time ceiling
and the persisted finality ceiling, derives that exact bounded branch round,
and performs its role-and-target-specific active-set admission. The existing
`HigherRoundProposalPrevote` event retains its strict proposal-prevote admission
contract. Both routes feed the same private higher inbox.

The existing positive `limits.higher` entry and canonical-input-byte limits are
shared by all proposal tokens and all byte-distinct signed votes. A proposal
still costs one entry and its control plus artifact bytes. Every vote costs one
entry and its complete fixed canonical width. There is no second vote budget,
new process configuration field, or changed canonical wire or journal format.
Exact parent-bound canonical duplicates do not grow custody. Strict-valid
signature variants and equivocations remain distinct charged inputs.

Invalid or out-of-range inputs return their exact original event without
changing custody or authority. A first capacity denial preserves the entire
prefix and latches the existing immutable saturation reason. Saturation denies
ordinary higher admission and all higher selection, even if the retained prefix
already contains a quorum. Allocation failure before insertion preserves the
healthy owner. These are local retained-input bounds, not total process-memory
or allocation-abort guarantees.

## Complete snapshot and precedence

After pending command transfer, ordinary classification retains these rules:

1. Every existing non-fallthrough exact-current finality classification retains
   priority, including missing-proposal and conflicting-evidence outcomes.
2. A latched higher ambiguity or higher saturation blocks ordinary progression.
3. The collector examines all relevant higher votes in the complete healthy
   inbox snapshot, including proposal prevotes admitted through the older route.
   Groups are identified by exact parent, height, round, role, and target.
4. Within each group, canonical bytes break ties only between signature variants
   for the same signer. Each signer contributes once. The existing exact-batch
   builder reverifies the complete selected signer set against the unchanged
   active-set denominator. A group is actionable only above two thirds of total
   active agreement weight; equality is insufficient.
5. Two actionable identities, including identities differing only in round,
   role, or target, latch a deny-only ambiguity. No largest-round, arrival-order,
   role, proposal-presence, or target preference resolves it. The first two
   identities in sorted order are diagnostic witnesses only.
6. With no ambiguity or selection failure, existing uniquely actionable
   proposal-bearing higher-round work retains its established execution path.
   Otherwise one unique quorum enters checkpoint-only execution. If there is
   no quorum, the existing current nil-precommit, current voting, and due-work
   classifications continue unchanged.

Selection time and the retained network view remain local. Uniqueness means
uniqueness in this complete bounded snapshot, not uniqueness across all future
messages or other nodes. Sorting does not make the certificate's signer subset
globally canonical. Certificate construction and encoding keep their existing
allocation behavior.

Explicit higher-certificate and vote-batch calls also return retained higher
work as unresolved before inspecting caller input. Their caller-selected proof
cannot override an actionable collected quorum or its ambiguity. Current
finality remains admitted through its existing bypass of higher blockers.

## Checkpoint, timer, disposal, and restart

Execution preflights the next timer generation, then delegates the canonical
certificate to the existing fully verifying node coordinator. The coordinator
synchronizes the signer checkpoint and independent anchor before the target
state can become live. A prevote quorum installs that higher round's Prevote
phase; a precommit quorum installs its Precommit phase. Neither means the next
phase or the next height. Success clears the old due observation and queues one
replacement phase arm without publishing a proposal or vote.

The checkpoint operation retains all inbox inputs and accounting. Under
`PROD-020-065`, a later driver step may atomically re-verify and move newly
exact-current higher evidence into the existing current resource classes,
subject to their independent budgets and explicit refusal/disposal policy.
That later ordinary action independently applies the existing signing or
finality contract. Caller redelivery and explicit proof operations remain
available; neither is required for already retained reusable evidence.

Higher ambiguity and saturation require the existing explicit full higher
inbox drain/disposal. The drain returns proposal tokens, the existing
`ProposalPrevote` items, and `QuorumVote` items for nil prevotes and precommits,
without losing canonical bytes or allocating per drained vote. It resets only
that custody and its deny-only latch; it grants no evidence preference.

Pre-effect rejection preserves the returned driver. Fatal derivation,
generation, checkpoint, or anchor failure returns no driver and requires strict
reopen. Restart reconstructs the anchored signer state, including lock and
complete valid proof. By default it starts with empty volatile inboxes. The
explicit `PROD-020-065` evidence journal can reconstruct bounded raw custody
through full re-verification; it cannot restore selection intent or resurrect a
signed publication command. Existing publication-journal recovery, when
explicitly configured, remains separate.

The runtime routes higher proposal prevotes through their existing event and
higher nil prevotes and both precommit forms through `HigherRoundVote`. Routing
headers remain untrusted hints; a recognized role still requires full signature
and node admission. Process `submit_vote`, authenticated peer delivery, and the
existing disposal command use this behavior without new commands.

## Evidence boundaries

Node tests cover role/target/source-phase/due-state parity with explicit
certificates, strict immediate reopen, shared entry and byte capacity,
lossless ambiguity disposal, exact-two-thirds and weighted positive controls,
byte-distinct valid signature variants, malformed/stale/inactive input,
current-finality priority, preserved nonempty lock/valid proof, and anchor
failure. Runtime regression tests retain malformed-header rejection after the
new route becomes supported. Unix process tests submit all four vote forms,
SIGKILL after checkpointing, strictly reopen, and retry a quorum after explicit
shared-inbox disposal. With `PROD-020-065`, nil evidence may continue through
ordinary current gates after the checkpoint; checkpoint parity is measured at
the successor-arm boundary, before that reuse.

The expanded deterministic multi-actor, delivery-fault, corruption, and signer
fault evidence is specified separately in
`fixed-validator-recovery-simulation-v0.md`. These bounded executions establish
neither general safety nor general liveness, production timing, arbitrary
partitions, dynamic-validator behavior, or a production-network claim.
