# Fixed-validator process source bundles V0

## Scope and authority

`PROD-020-057` exposes offline current-head candidate-bundle export and strict
unselected staging in the Unix [validator process](fixed-validator-process-v0.md).
Both commands borrow its existing idle [artifact sources](fixed-validator-process-artifact-acquisition-v0.md)
and the live driver's sealed selected-history capability. They delegate to the
existing [canonical bundle and staging contract](candidate-branch-recovery-bundle.md).
No canonical format, network message, consensus verification, signer operation,
or storage commit order changes.

Export reads sources and creates one caller-named file. Staging can append only
to the candidate and payload stores. Neither operation changes selected history,
finality or signer journals and anchors, signs, publishes, or selects a branch.
An independently submitted [source-backed proof](fixed-validator-process-source-proofs-v0.md)
or authoring command must pass its complete existing authority gates afterward.
Candidate retention and bundle integrity are not consensus evidence.

This component does not grant selected-state import or installation, selected
history backup, virtual-genesis-prefix export, source or bundle serving, network
bundle acceptance, peer/target choice, automatic phase chaining, proof collection,
retry, repair, rollback, provenance, cross-file atomicity, dynamic consensus,
key rotation, remote signing, production custody, or production-liveness authority.

## Strict commands and dispatch

Each input is one strict object in the existing bounded JSONL command frame.
The only fields are `command`, unsigned integer `id`, and these required fields:

| Command | Fields |
| --- | --- |
| `export_candidate_bundle` | `target`, `bundle_file`, `max_blocks`, `max_payload_bytes`, `max_bundle_bytes` |
| `stage_candidate_bundle` | `target`, `anchor`, `bundle_file`, `max_blocks`, `max_payload_bytes`, `max_bundle_bytes` |

`target` and `anchor` are exact artifact-block IDs: 64 lowercase hexadecimal
characters. `bundle_file` is a path string resolved against the configuration
directory, including the existing absolute-path behavior. Every limit is a
positive JSON unsigned integer. `max_blocks` must fit `usize`; the two byte
limits retain all 64 bits. Limits are independent, caller-local bounds on the
whole bundle, not persisted retention policy or consensus limits. There is no
implicit default, anchor choice for export, directory override, or authority field.
Missing, duplicate, unknown, incorrectly typed and non-object inputs fail schema
validation; numeric strings are not accepted as limits.

Dispatch order is schema, source availability/custody, surviving driver, exact
target, staging anchor if present, and positive/representable limits. Active
acquisition returns `command_rejected` / `sources_busy` before typed selectors,
limits, files or source reads. Disabled sources return `sources_disabled`;
missing driver returns `driver_unavailable`. These refusals neither advance nor
cancel acquisition. Source reuse requires a separate explicit cancellation.
Invalid IDs report `source_block_id`; unrepresentable block limits report
`bundle_block_limit`; zero limits report `bundle_limits`.

With idle sources, these are synchronous commands borrowing shared selected
history. Publication, pending timer arm, pending driver command, inbox contents,
current-finality classification and due timing add no transfer gate. The commands
preserve those owners and queues. Ordinary input, runtime work, signals and
writer-failure observation resume after the bounded operation returns; there is
no asynchronous transfer cursor or promise to interrupt validation or filesystem
work. All transfer outcomes use the ordinary nonfatal command path.

## Current-head export and output files

The process calls `export_candidate_branch_recovery_bundle_v0` with the caller's
exact target, live selected history, both sources and all three limits. It
preserves the lower chain-context-before-selected-health ordering. The anchor is
the current selected head. Any already selected target or candidate path meeting
an older selected ancestor instead of that head is rejected. Access to the retained verified
selected snapshot, candidate integrity/path checks, payload integrity and complete
candidate-branch replay, independent limits and canonical encoding finish before opening the
destination. Export appends nothing to either source; an integrity read failure
can poison only its affected source handle.

After complete validation the process creates a new file with `create_new` and
owner-only requested mode `0600` (subject to the process umask), writes the whole
encoding, synchronizes that file, then synchronizes its parent directory before
reporting `bundle_exported`. Parent directories must already exist. Any existing
destination, including a regular file, directory, symlink, dangling symlink or
FIFO, is refused without overwriting it. A missing output acknowledgement does
not establish absence of effects.

`bundle_exported` reports `anchor`, `target`, `block_count`, decimal-string
`payload_bytes` and `encoded_bytes`. `bundle_export_failed` reports a compact
`code` and `output_created`, which describes creation by this attempt, not whether
the caller's path exists. Source/validation failures occur before creation.
File failures distinguish `bundle_file_create`, `bundle_file_write`,
`bundle_file_sync` and `bundle_directory_sync`. After successful creation, any
failure can leave partial, complete or ambiguously durable output; it is retained.
The process does not remove, replace, resume or retry that file. Success does
not claim atomic publication or protection against external directory mutation.

## Strict unselected staging

The process opens the input with the existing no-follow, nonblocking,
regular-file check on the same descriptor and reads at most `max_bundle_bytes`.
It probes one further byte on that descriptor only when the cap was reached;
an extra byte returns `file_too_large` before lower staging. This does not add
one to a full-width cap or narrow it. A small regular file under `u64::MAX` is
accepted by the reader. Open, metadata, type and read failures retain the existing
`command_rejected` file codes. The input path is never rewritten or removed.

The owned bytes pass directly to `stage_candidate_branch_recovery_bundle_v0`
with the exact caller anchor and target. The adapter preserves lower ordering:
complete strict decoding and all bundle bounds precede immutable chain-ID
checks, then encoded expected anchor/target checks, then the first selected
snapshot health check and lookup. Access to retained verified selected snapshots,
complete supplied-path validation and both stores' whole capacity/conflict
preflight precede any source commit. A correctly framed bundle with a valid digest can still fail
complete artifact validation. A digest is not a signature or proof of validity.

The anchor must be retained selected history; it need not equal the current
head. An exact contiguous already-selected prefix is replay-verified and omitted
from staging. All bundle bounds still apply to that prefix. Only the remaining
unselected suffix is retained, all candidate entries first and all payload entries
second. The target must remain unselected. Repeating the same valid command can
acknowledge existing exact entries without inserting them; after separate
finalization selects the target, the same staging command is rejected.

Success reports `bundle_staged`, exact `anchor` and `target`,
`selected_prefix_count`, `candidate_block_count`, `candidate_inserted_count`,
`payload_inserted_count`, and decimal-string `encoded_bytes`. Failure reports
`bundle_stage_failed`, `code`, decimal-string `encoded_bytes`, and four independent
lower-layer counters: `candidate_acknowledged_count`, `candidate_inserted_count`,
`payload_acknowledged_count`, and `payload_inserted_count`. Existing entries count
as acknowledgements, not new insertions. Candidate and payload prefixes can differ.
These counters describe returned acknowledgements; an unacknowledged operation
can still have committed ambiguously. Zero counters do not prove zero durable
effects. There is no rollback or atomic transaction across stores.

Both lower outcomes return the exact owned input bytes. The process explicitly
discards that allocation and reports `bundle_bytes_discarded: true`, while
preserving the caller's file for any independently chosen later attempt. It
does not automatically reopen, retry, repair or resume a partial prefix.

## Diagnostics and persistence evidence

Compact export codes distinguish chain/selected history, selected target,
missing candidate/payload, candidate/payload integrity reads, divergent ancestry,
branch validation and each bundle limit. Other resource, arithmetic or future
failures report `export_failed`. Staging codes distinguish `bundle_decode`,
chain/selected history, anchor/target checks, branch validation, candidate and
payload preflight/conflicts/capacity, `candidate_commit`,
`payload_commit_validation` and `payload_commit`. Other resource, arithmetic or
future failures report `stage_failed`; that category makes no preflight/no-write
claim. `bundle_decode` includes resource and limit failures as well as malformed
or corrupt bytes.

Every delegated outcome includes the ordinary `state` and idle `sources`
diagnostics. Source counts are cached retention/poison state, not a fresh integrity
audit, recovery guarantee or authority. Reports include neither raw bundle or
payload bytes, caller paths, nor unbounded lower error text. Output delivery
failure after an operation retains its effects and uses the existing process
shutdown/disposal path; a missing report cannot authorize an implicit retry.

Strict restart reopens the existing durable source prefixes and independent
authority journals. An incomplete source framing tail follows the lower store's
ordinary open behavior; a complete corrupt source record fails closed before
authority startup. These commands introduce no persisted bundle identity,
provenance or selected-state checkpoint.

Actual Unix process vectors in
`crates/naome-validator/tests/cases/artifact_acquisition/source_bundles/` cover
SDK-byte-identical non-genesis export, offline transfer between process instances,
an older selected anchor and selected prefix, suffix-only staging, idempotent
retry, separate signed-proof consumption, exact finality and source reopen,
independent bundle and store limits, strict schema/file refusal, full-width caps,
output collisions, framed-invalid payload/context rejection, source corruption,
current-head divergence, active acquisition and a real in-flight process
precommit whose original receipt survives both commands.

One process vector appends an incomplete byte to a live candidate log. Staging
acknowledges an existing first entry, then refuses the absent next entry at the
store-length gate and poisons candidates. It demonstrates a commit-phase refusal
after an existing-entry acknowledgement, with unchanged damaged source bytes;
ordinary reopen removes only the incomplete tail and a separate identical-input
retry completes. It does not demonstrate a newly written partial commit or an
actual write/fsync failure. Lower candidate and payload ambiguity remains separate
injected-fault evidence in
`crates/naome-storage/src/artifact_chain_journal/tests/candidate_branch_recovery_staging.rs`.
Process evidence does not establish power-loss durability, exhaustive I/O faults,
deployment, distinct-validator quorum formation, Byzantine safety, non-Unix process
execution or production timing/liveness.
