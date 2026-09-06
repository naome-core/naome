# Fixed-validator process source-backed proofs V0

## Scope and authority

This profile implements `PROD-020-056` inside the Unix
[`naome-validator` process](fixed-validator-process-v0.md). It exposes the two
existing runtime candidate-backed exact signed-precommit-batch operations using
the process-owned candidate and payload handles defined by the
[artifact-source profile](fixed-validator-process-artifact-acquisition-v0.md).
It adds no source ownership mode or protocol rule.

The caller supplies one exact candidate ID, proposal-control file, ordered vote
files, and evidence round. Candidate retention, payload availability, a network
response, and the caller's choice are not consensus evidence. The existing
runtime, driver, node, and anchored coordinator independently verify the entire
branch-relative proof before granting selection or a terminal conflict halt.

This component does not grant automatic evidence collection, grouping, ranking,
target choice, phase chaining, conflict invocation, peer provenance, source
population or serving, repair, rollback, retry scheduling, job resumption,
dynamic-validator, remote signer, or production-liveness authority. It changes
no canonical bytes, network messages, proof semantics, or key-custody contract.

## Strict commands and source custody

Each command is one strict JSON object in the existing bounded JSONL frame. Its
only fields are `command`, unsigned integer `id`, and these required fields:

| Command | Fields |
| --- | --- |
| `finalize_candidate_votes` | `target`, `evidence_round`, `control_file`, `vote_files` |
| `halt_candidate_conflict_votes` | `target`, `evidence_round`, `control_file`, `vote_files` |

`target` is an exact artifact-block ID encoded as 64 lowercase hexadecimal
characters. `evidence_round` is a full-width JSON unsigned integer, passed
unchanged to the existing bounded round derivation. It is not a caller-chosen
ceiling. `control_file` is a path string and `vote_files` is an ordered array of
path strings. There is no caller payload file, store directory, height, parent,
proposal root, winner, or replacement branch field. Unknown and duplicate
fields, missing fields, non-object commands, and wrong types are schema errors.

Schema validation precedes all dispatch. Without configured sources, either
command reports `command_rejected` with `sources_disabled`. While an acquisition
owns the stores, either reports `sources_busy`, even if its typed target or
proof paths are invalid. Both checks precede typed input, file loading, and
source access. The active cursor is neither advanced nor cancelled by that
refusal. The caller can separately cancel acquisition and submit another
command. Existing direct-file historical proof commands remain available during
acquisition; their fatal outcomes retain the ordinary acquisition cancellation
and owner-disposal path.

With idle stores, the process parses the target (`source_block_id` on error),
then requires one through `MAX_ACTIVE_VALIDATORS` vote paths
(`proof_vote_count`) before opening any proof file. It loads the proposal control
with `CONSENSUS_PUSH_MAX_PROPOSAL_BYTES` and each vote independently with
`CONSENSUS_PUSH_VOTE_BYTES`, using the existing bounded regular-file/no-follow
reader and configuration-relative path resolution. Each vote must have exactly
the fixed wire width (`proof_vote_length` for short input). Existing file errors
remain `command_rejected`. Files are not merged, deduplicated, reordered,
normalized, or decoded by the adapter. Duplicate votes reach complete consensus
verification and cannot gain threshold weight.

These adapter errors precede runtime invocation and preserve signing authority.
Bounded file reads may precede a runtime refusal. Actual candidate and payload
reads remain behind the runtime's independent custody and proof gates. Every
command is one attempt; loaded files are dropped afterward, with no queued retry.

## Candidate selection

`finalize_candidate_votes` invokes
`commit_candidate_backed_finality_vote_batch` with borrowed source stores and
the exact caller inputs. The existing positive gate refuses while publication,
a pending runtime timer arm, or a pending driver command owns custody. A missing
driver reports `proof_refused` / `driver_unavailable` and stops the process;
ordinary backpressure reports `proof_refused` / `busy` and continues. Both report
zero `refunded_payloads_discarded`, because no owned payload was supplied.

The driver's retained current-finality classification precedes candidate work;
a non-fallthrough classification, including `current_finality_unresolved`, is
preserved. Complete verification uses the exact unselected direct child of the
live branch, its retained candidate bytes, independently verified canonical
payload, authorized proposal, and exact non-nil precommit batch. Lower, equal,
and higher evidence rounds relative to the signer remain eligible under the
existing driver and persisted finality ceilings. The adapter neither checkpoints
to a higher round first nor restricts this API to lower/current rounds.

Before authority effects, proof or source rejection reports
`candidate_finality_rejected` and preserves the live driver and its timing and
inbox custody. Success reports `finality` with the bounded post-command state,
advances the paired finality and signer authorities, and continues at only that
direct child's height, round-zero Proposal. The runtime queues one matching
child timer arm and preserves charged inboxes. This operation does not itself
sign or publish a new proposal or vote.

Every fatal candidate error consumes the driver and reports `proof_failed`,
`operation: candidate_finality`, and `strict_restart_required: true`. This
includes current-finality round reconstruction and successor timer-generation
exhaustion before source reads or authority effects, as well as failures after
effects begin. These fatal errors are distinct from typed continuing proof or
source rejection. The process performs its existing fatal disposal and releases
all owners before reporting completion.

## Historical candidate conflict

`halt_candidate_conflict_votes` invokes
`commit_candidate_backed_finality_conflict_vote_batch`. With idle sources, only
driver availability and pending driver-command custody gate delegation.
Publication, a pending runtime timer arm, buffered input, phase, due timing, and
retained current-finality evidence do not add positive-proof gates to this
terminal operation. Runtime refusals have the same zero-payload diagnostic.

The existing coordinator loads the caller's exact candidate and derives the
proof coordinate from its replay-retained selected parent. The proof must be a
fully verified distinct sibling at an already selected height. Its explicit
round remains independently bounded, without reference to the current signer's
height or round. A valid proof anchors the existing `SelectedSibling` finality
halt and matching independent signer stop. The process reports
`finality_stopped`, the exact selected and conflicting ancestry IDs, and equal
`finality_state_id` / `signer_finality_state_id`. It installs no operable sibling
head or winning branch.

Every delegated outcome consumes the driver, including missing source entries,
malformed proof, duplicate votes, wrong target, or same-selected-value rejection
before any writes. Errors report `proof_failed`,
`operation: candidate_finality_conflict`, and `strict_restart_required: true`.
The post-command state has no driver. Independent publication and timer custody
remain available only for the existing fatal disposal report; the process does
not continue signing, retry the proof, or recall network work already sent.

## Source integrity, persistence, and evidence

Proof operations perform integrity reads through the existing stores; they do
not append, rewrite, delete, repair, or promote source entries. Integrity failure
may poison only the affected live source handle while archive bytes remain
unchanged. This is separate from the positive/consuming authority distinction.

Strict restart classifies the actual durable prefix. Successful candidate
selection reopens at its exact child. A fully anchored sibling halt reopens as
`startup_finality_stopped`. A consuming pre-append rejection with healthy stores
can reopen the unchanged selected authority. Damaged enabled sources fail
`source_candidates_open` or `source_payloads_open` before authority startup.
Ambiguous finality/signer journal-anchor updates can fail strict authority open;
there is no rollback, repair, or cross-file atomicity claim.

Process evidence resides in
`crates/naome-validator/tests/cases/artifact_acquisition/source_proofs/`. It uses
actual Unix validator subprocesses, SDK source peers with Noise identity only,
canonical source archives, and proposal/vote fixtures produced by anchored
signers. Conflicting fixtures use independent throwaway signer journals and
deliberately supply conflicting evidence; they do not demonstrate an honest
signer equivocating or general Byzantine safety. Held requests and an actual
process-produced in-flight precommit exercise source and publication custody.
The vectors cover restart and selected anchor-collision faults, not deployment,
power-loss durability, exhaustive I/O faults, production timing or liveness, or
non-Unix process execution.
