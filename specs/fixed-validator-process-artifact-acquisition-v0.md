# Fixed-validator process artifact acquisition V0

## Scope and authority

`PROD-020-055` adds an optional source consumer to the Unix
[`naome-validator` process](fixed-validator-process-v0.md). The process owns one
chain-scoped candidate store, one Foundation-scoped canonical payload archive,
and at most one explicitly started acquisition phase. It composes the existing
[runtime artifact exchange](fixed-validator-runtime-v0.md#explicit-artifact-exchange)
and [store-backed authoring](fixed-validator-node-driver-v0.md) operations.
It changes no consensus, artifact, journal, anchor, or transport encoding.

Acquisition can retain unselected structural blocks and independently validated
payloads. This component does not grant signing, consensus admission, branch
selection, finality, peer truth, availability, provenance, or recovery authority.
Authoring is a separate explicit command through the live anchored signer.
Completing either phase starts no other phase or proposal. A reconstructed
multi-block tip is not immediately authorable unless its parent is the current
signing branch's exact artifact head.

There is no candidate/payload serving policy, automatic source population from
file-backed authoring or received consensus messages, source discovery, target
selection, retry schedule, automatic conflict invocation, selected-state
recovery-bundle installation, or durable job/outbox. Separate
[offline bundle commands](fixed-validator-process-source-bundles-v0.md) can export
from the live current head or stage only unselected source entries. The independent opt-in
[complete-proof provider](fixed-validator-proof-provider-v0.md) retains its own
selected-history-only response contract.

## Optional source ownership

Omitting `[sources]` preserves the existing process configuration. To enable
sources, supply all fields below in the existing bounded TOML file:

```toml
[sources]
mode = "create"
candidate_directory = "candidates"
payload_directory = "payloads"
candidate_entries = "16"
payload_entries = "16"
payload_bytes = "1048576"
```

Both directories must already exist. Relative paths resolve against the
configuration directory. `sources.mode` is independently either `create` or
`open`; it is not inferred from the authority journals' top-level `mode`.
Unknown, missing, duplicate, and incorrectly typed fields fail configuration.
The three limits are canonical unsigned decimal strings without leading zeros;
entry limits must fit positive `usize`, and payload bytes must fit positive
`u64`. These are caller-local lower-store retention limits, not protocol limits
or a process-wide memory ceiling. They are not persisted and may change on open
only when the retained contents satisfy the new limits.

Configuration preparation checks both source directories and all limits before
opening either store or provisioning authority. After preparation, the process
creates or opens candidates first, synchronizes that directory, then creates or
opens payloads and synchronizes that directory. Only after both succeed does it
provision/open authority journals or issue/catch up a signing session. Source
open failure therefore cannot advance authority journals. Creation never falls
back to opening existing files, and open never creates a missing log.

The process uses each lower store's existing chain binding, integrity checks,
lock namespace, append acknowledgement, poisoning and replay rules. In
particular, source open can recover an incomplete framing tail under those
rules; this is distinct from the finality journals' exact anchored no-repair
contract. A complete corrupt source record fails closed. An earlier complete
source prefix can remain after a later source or authority startup failure.
There is no cleanup transaction, rollback, or atomicity across the source
stores and authority journals.

The awaited process owner retains both store handles through ordinary runtime
work. No task or I/O worker receives source-store or signing authority. On every
exit the acquisition cursor, source handles and runtime are disposed within the
awaited ownership lifetime. The existing `stopped.locks_released` report is
emitted only after both source and all authority owners have been released.

## Explicit commands and bounds

All commands use the existing strict bounded JSON object framing and exact
`u64` numeric request `id`. Unknown or duplicate fields, array-form commands and
incorrect field types are rejected with `command_schema` and null `id`.

| Command | Additional required fields |
| --- | --- |
| `sources_status` | none |
| `cancel_acquisition` | none |
| `acquire_ancestry` | `target`, `peer_id` |
| `acquire_ancestry_fallback` | `target`, `peer_ids` |
| `acquire_anchored_ancestry` | `target`, `anchor`, `peer_id` |
| `acquire_anchored_ancestry_fallback` | `target`, `anchor`, `peer_ids` |
| `acquire_payloads` | `target`, `peer_id`, `max_blocks` |
| `acquire_payloads_fallback` | `target`, `peer_ids`, `max_blocks` |
| `author_candidate` | `target` |
| `author_stored_retained` | none |

`target` and `anchor` are exact 32-byte artifact-block IDs encoded as 64 lowercase
hexadecimal characters. `peer_id` is a parseable peer-ID string. `peer_ids` is a
caller-ordered list of one through eight such strings. `max_blocks` is a JSON
unsigned integer that must fit positive `usize`.

Schema validation comes first. Disabled sources reject starts, store-backed
authoring, the separate [source-backed proof commands](fixed-validator-process-source-proofs-v0.md),
and [offline bundle commands](fixed-validator-process-source-bundles-v0.md)
with `sources_disabled`. While an acquisition owns the source borrow,
all six starts, both store-backed authoring commands, both source-backed
proof commands, and both bundle commands reject with `sources_busy`, before their typed input, file
loading, or source access. With idle sources,
the process eagerly parses peer strings, fallback list counts, block IDs and
the positive payload reconstruction limit, including for cached completion.
Anchored forms parse the anchor before peers and target; other starts parse
peers before target. Errors use `source_peer_id`, `source_peer_count`,
`source_block_id`, or `source_block_limit`. Remaining peer configuration,
duplicate, connectivity, integrity and capacity checks keep the lower APIs'
existing order, including their lazy peer inspection of completely retained
paths.

The four ancestry commands preserve the fixed 16-block backward-walk bound.
Fallback tries only the supplied peers in their supplied order for each missing
address under the existing operation rules. Each physical block request retains
the transport's 30-second attempt timeout; there is no new aggregate job
deadline. Payload reconstruction uses its explicit `max_blocks`, fetches
missing exact committed payloads in forward order, and retains the existing
120-second absolute deadline for each missing artifact shared across that
artifact's fallback attempts. This is not a 120-second deadline for the entire
multi-artifact job. The configured source retention limits remain independent.

For example, after establishing a configured peer session, an operator may
issue `acquire_ancestry`, await its completion, separately issue
`acquire_payloads` for that target and an explicit bound, and then separately
issue `author_candidate`. Each command re-enters its own existing checks; a
previous success grants no permission for the next command.

## Live history, custody and reports

A start borrows only the current runtime's sealed selected history for that
call. While the phase awaits a response, the same fair command/signal/runtime
poll continues. An exact terminal accepted by that cursor's nonconsuming
correlation predicate is routed through the corresponding runtime advance
operation. Peer equality alone is insufficient. Other runtime work, ordinary
commands and the independently enabled proof provider continue normally.

Current-head ancestry checks the selected head again before a found response
can insert a block; head drift fails with `source_selected_head_changed`.
It does not promise immediate cancellation on head advancement before that
lower check. Explicit-anchor ancestry instead rechecks the retained selected
anchor and unselected path, permitting unrelated head advancement. Each payload
start repeats its own current selected-history/path checks; once started, it
can complete from its captured immutable artifact snapshot after the live head
changes. The process reports completion metadata and discards the reconstructed
snapshot. It never installs that snapshot in the signer.

A synchronous cached completion produces one `command_result` whose outcome is
`acquisition_complete`. An asynchronous start instead produces
`acquisition_started`, followed by zero or more top-level
`acquisition_progress` reports and exactly one terminal report for the original
`id`: `acquisition_complete`, `acquisition_failed`, or `acquisition_cancelled`,
provided output remains writable. Job metadata includes its kind, target and
completion flag, and, while pending, its exact pending block and peer. Ancestry
also exposes its anchor; pending payload work exposes its artifact ID, while
completed payload work exposes its anchor and validated block count. Reports
contain no payload, proof, signing key or source provenance.

Idle `sources_status` reports enabled state, null acquisition, and each healthy
store's retained count plus decimal-string payload bytes. A poisoned store's
counters are null. These are retention counters, not fresh integrity scans or
validation claims. Active status reports the original acquisition `id` and job
metadata instead of accessing borrowed store counters. Disabled status reports
`enabled: false` and null acquisition.

`cancel_acquisition` with no active phase acknowledges `active: false`. With an
active phase, it consumes that cursor, acknowledges `active: true` and the
original acquisition ID, and emits the original ID's cancellation terminal.
Cancellation preserves acknowledged source prefixes and releases the source
borrow. It does not recall physical transport or immediately make its shared
peer slot reusable. Late terminals drain through ordinary transport and are
reported/disposed; they cannot append source data without a live cursor.

Source failures end that attempt without consuming a healthy runtime driver.
Candidate integrity/insert failures use `source_candidate_store`; ancestry
request-start and unavailable outcomes use `source_request_start` and
`source_block_unavailable`; other ancestry failures use
`source_ancestry_failure`. Payload operation failures use
`source_payload_failure`. A runtime advance preflight refusal refunds the exact
cursor and terminal to this private adapter, which explicitly cancels/disposes
them and reports `source_advance_refused`. There is no automatic resubmission.
Shutdown, EOF, signals and fatal ordinary runtime/command outcomes cancel any
active phase before normal owner disposal; output failure releases ownership
even when a terminal report cannot be delivered. A writer failure retains a
wakeup for the awaited owner, so idle open stdin and a held network request do
not delay source/authority release until another command or consensus deadline.

Artifact requests and publications share the unchanged per-peer slot and
aggregate transport permits. Either may refuse the other. An ordinary
publication's peer attempt remains one-shot; finishing or cancelling acquisition
does not retry it. Restart restores only lower durable sources and authority
state. It restores no acquisition ID, cursor, pending response, retry or job.

## Separate anchored authoring

`author_candidate` invokes the existing candidate-backed fresh authoring path.
Runtime backpressure and live driver phase, proposer and retained-value checks
precede source access. The exact requested block and its exact archived payload
must then pass full validation against the live signing branch before anchored
signing intent and signed proposal release.

`author_stored_retained` accepts no caller target or certificate. The signer's
private retained value determines the payload address. The existing retained
proposal path verifies its complete artifact child and original valid-round
certificate again. Neither command changes source retention or bypasses existing
runtime work, publication custody, or authoring eligibility. They produce the
ordinary `proposal_authored`, `proposal_rejected`, or authoring-backpressure
outcomes. Source rejection leaves ordinary explicit file-backed authoring usable
when its separate live checks pass.

## Evidence and limits

The actual Unix process tests in
`crates/naome-validator/tests/cases/artifact_acquisition/` cover all six network
forms from empty stores, authenticated unavailable-first fallback, separate
fresh authoring and finality at two actual validators, source and authority
reopen, exact real R0 certificate retention in R1 authoring and strict signer
recovery, head/anchor/captured-snapshot interleavings, prefix cancellation and
late responses, shutdown/signals/EOF, closed stdout with an active acquisition
and idle open stdin, blocked output, strict schema and limits, ordered source
startup failure, invalid resulting roots, live source poisoning, shared peer
capacity and a real phase deadline during acquisition.

Their SDK peers own only Noise identities and unsigned source data; actual
validator processes create honest signatures. Semantically invalid block
commitments are tested through public transport APIs; this is not an additional
malformed-wire codec implementation. Existing lower codec and storage fault
tests retain their separate coverage. These finite process tests do not prove
general Byzantine safety/liveness, power-loss durability, crash atomicity across
files, public-network performance, deployment readiness, or dynamic consensus.
