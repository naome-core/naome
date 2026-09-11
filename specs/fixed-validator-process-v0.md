# Fixed-Validator Process V0

## Scope and authority

`PROD-020-049` defines the Unix `naome-validator` executable,
`PROD-020-050` adds explicit complete-proof commands, `PROD-020-051`
adds explicit class-selected inbox disposal, `PROD-020-052` adds explicit
exact-current paired-conflict submission, and `PROD-020-053` adds both direct
exact-current single-finality proof forms. `PROD-020-054` adds both direct
historical selected-sibling proof forms. It owns one
explicitly configured local fixed-validator signer through
`FixedValidatorNodeReadyV0::run_with_signing_session_async`, constructs the
existing driver and runtime within that lifetime, and accepts explicit operator
commands on stdin. Consensus verification, proposal eligibility, signing intent,
anchoring, finality selection, and strict restart remain defined by
[startup](fixed-validator-node-startup-v0.md),
[driver](fixed-validator-node-driver-v0.md), and
[runtime](fixed-validator-runtime-v0.md).

`SEC-003-003` adds the explicit opt-in
[retained-proof provider](fixed-validator-proof-provider-v0.md). It serves
already committed complete proofs to configured peers without changing the
signer's authority or the ordinary runtime schedule.

`PROD-020-055` separately adds the optional
[artifact-source consumer](fixed-validator-process-artifact-acquisition-v0.md):
explicit source-store ownership, six bounded acquisition forms, cancellation
and status, and separate live-checked store-backed fresh/retained authoring.
`PROD-020-056` adds two explicit [source-backed proof commands](fixed-validator-process-source-proofs-v0.md)
for candidate finality and a historical selected-sibling halt using those stores.
`PROD-020-057` adds explicit offline [candidate-bundle export and unselected staging](fixed-validator-process-source-bundles-v0.md)
through the same stores and live selected history.

`PROD-020-058` makes the [crash-recoverable consensus publication lifecycle](fixed-validator-publication-lifecycle-v0.md)
mandatory before ready: original signed bytes share the anchored completion
boundary, delivery progress is separate and durable, and strict restart resends
unacknowledged messages without signing again. It also reserves outbound
consensus capacity above archive and acquisition traffic.
`PROD-020-059` adds optional `[network].publication_retry_millis` for one
explicit positive periodic delivery interval. Omitting it preserves the
restart/reconnection-only profile; configuring it retries exact original
unacknowledged messages through the same durable delivery lifecycle.

`PROD-020-060` adds explicit [bounded validator proof catch-up](fixed-validator-process-proof-catch-up-v0.md)
from one caller-selected configured peer. Each downloaded direct-child proof
passes complete live-branch verification and the existing anchored signer
handoff; the finite job stops on drift, refusal or failure and never resumes
automatically after restart.

`PROD-020-062` adds explicitly opted-in [artifact-source serving](fixed-validator-process-source-serving-v0.md)
from retained source stores, including unselected entries, with temporary
unavailability during exclusive acquisition.

The executable supplies local process ownership, seed-file loading, JSONL
commands, and diagnostic disposal on shutdown. `PROD-020-066` additionally
permits one explicitly started current-height proposal job, as specified below.
`PROD-020-067` adds the optional finite-plan supervisor described below.
`PROD-020-069` extends it with a bounded post-startup candidate inbox and a durable
local preference among fully validated candidates. `PROD-020-071` adds
[direct configured-publisher offers](candidate-offer-intake-v0.md), durable
per-publisher intake and a source-only publisher process. It grants no automatic
network discovery, relay, globally agreed candidate ranking, certificate acquisition beyond the
bounded configured-peer catch-up paths, artifact serving beyond
the separately opted-in retained complete-proof and artifact-source responses,
automatic inbox clearing, repair, dynamic
validator, key rotation, production timeout calibration, hardware custody, or
distributed-liveness authority. In accordance with `PROD-023`, no remote
consensus-signer service or configuration is supported. This implements only
the process's local-key boundary; it does not close `PROD-023`'s dependency on
the complete `PROD-020` parent.

## Bounded current-height proposal job

`propose_height` takes exactly `id` and `target`. The target is one canonical
lowercase 32-byte artifact-block ID in the configured source stores. Starting
requires a live runtime and enabled, currently available source ownership; it
binds the job to the runtime's current consensus height. There is at most one
job. Starting another reports `proposal_busy`. This command does not accept a
caller height, round, signer, signature, or deadline and does not acquire data.
This explicit command's job is not restored after process restart; the separate
supervisor can derive a new job from its bound configuration and recovered state.

Between ordinary session polls, an active job may make at most one bounded
authoring attempt. It waits outside Proposal phase and while acquisition
exclusively borrows the source stores. At a new round it first checks the
anchored completed-publication history: a proposal already completed in that
exact round, including a manual or recovered proposal, suppresses another job
attempt. An unscheduled-proposer result likewise finishes the job's work for
that round. A successful authoring attempt finishes that round's work and leaves
the original signed publication in ordinary runtime custody. Only another live
round at the same height can allow another attempt.

Every attempt uses the unchanged store-backed runtime and driver authoring
coordinators. Startup recovery, active publication, pending arm/input, observed or
elapsed deadline, and driver work retain their existing priority before source
access or signing. A completed live historical retry opens the bounded ordinary
opportunity specified by `PROD-020-068`, including these existing authoring checks.
The job first offers its exact fresh target; only the sealed
`RetainedValidValueRequired` result redirects it to the signer's retained valid
value and complete earlier-round certificate. This result precedes fresh-source
reads. Missing retained payload never permits fallback to the fresh candidate.
There is no fresh-target replacement, alternative-peer lookup, highest-round
preference, or relaxation of proposer, lock, signature or finality checks.

Runtime busy, unresolved driver work, and absent candidate or payload are wait
states. Ordinary events or source-changing commands may make a later bounded
attempt possible; the job adds no busy loop, timer, immediate retry loop, source
acquisition, inbox disposal or capacity expansion. A permanent source error or
other semantic authoring rejection stops the job without consuming a healthy
runtime. An existing fatal authoring result still terminates process ownership.
The job stops when the height changes or runtime authority disappears, including
height changes caused by independently valid proof synchronization. Waiting
intent coexists with source acquisition and proof synchronization; it does not
borrow their requests or suppress their cancellation and status handling.

`proposal_status` takes exactly `id` and returns the current job or null.
`cancel_proposal` takes exactly `id`, removes only job intent, and is available
even during exclusive source acquisition. Cancellation does not retract an
already completed signature, cancel its publication, clear evidence, or roll
back anchored progress. While a job is active, all four manual fresh/retained
authoring commands report `proposal_busy` before source or file access.
Cancellation takes effect when the session observes that command; it cannot
undo an earlier attempt. Shutdown, signals and EOF dispose job intent through
the existing owner teardown. Strict restart retains signed history and delivery
recovery, but always starts with no proposal job.

Command results report `proposal_job_started`, `proposal_job_status`, or
`proposal_job_cancelled`. Asynchronous reports use `proposal_job_waiting` on a
wait-state change, `proposal_job_attempt` with the existing authoring outcome,
and `proposal_job_stopped` with the reason and final job diagnostics. The job
diagnostics contain its ID, bound height, exact target, observed round, wait
state, and whether that round's work has finished. They are not signer authority.

The process tests in `tests/cases/artifact_acquisition/proposal_job.rs` and
`retained.rs` exercise authenticated publication and weighted finality after a
missed proposer, source absence and corruption, retained-value preference,
command exclusion, acquisition/deadline contention, cancellation with held
publication, and strict restart without job resumption. This is bounded local
process evidence, not a production-timeout, candidate-ranking, dynamic-validator
or general distributed-liveness claim.

## Optional autonomous height supervisor

`[supervisor]` opts the process into one bounded local scheduling policy:

```toml
[supervisor]
targets = ["<height-1 block ID>", "<height-2 block ID>"]
peers = ["<configured peer ID>", "<next configured peer ID>"]
interval_millis = "1000"
acquisition_blocks = "16"
```

`targets` contains 1–256 canonical block IDs in height order starting at height
1. This finite-plan mode neither discovers nor ranks candidates. `peers` is a nonempty,
duplicate-free ordered subset of the static configured peers, bounded by the
existing static-peer limit. `interval_millis` is a positive canonical `u64`
decimal string with checked monotonic deadline addition. `acquisition_blocks`
is a canonical decimal string in 1–256. Source stores, durable evidence, and
publication retry must also be configured. Source/proof serving remains a
separate explicit opt-in.

Before the first runtime poll, the exclusive signer owner creates and syncs
`vote_journal/supervisor-policy-v0.json`, then syncs its directory. Strict reopen
requires byte-identical serialized supervisor fields and stabilizes the matched
regular file and directory again. Missing, changed, nonregular or corrupt policy
refuses startup; omitting supervisor configuration while its policy file exists
also refuses startup. No migration, cursor, acknowledgement, signature or
selected-history authority is stored in this file.

Recovered driver height and selected history determine the next job. A retained
valid value takes precedence over configured fresh targets and requires its own
payload; it never falls back to another candidate. Fresh work requires the
configured predecessor to equal the selected head. Plan exhaustion, divergence,
or an invalid fresh target stops fresh authoring while ordinary voting,
publication retry and complete-proof following continue. A height change derives
the next job. All proposal attempts retain the existing role, round, phase,
retained-proof, source-validation and anchored signing gates.

One periodic scheduler alternates single-height complete-proof requests with
ancestry/payload acquisition for a missing proposal source. Each request class
has its own cursor through configured peers, and existing request/work limits
and deadlines remain binding. An unavailable or invalid remote response permits
the next peer on a later interval. Local source read/archive failures and
detected source corruption, including authoring and serving paths, stop the
autonomous owner; they never repair the source or substitute empty state.
The separate explicit source recovery restart below may provision a new source
generation after this owner has stopped; it does not continue the failed owner.

When current finality is waiting for a proposal, an envelope response may supply
its bounded raw proposal and payload to the existing one-slot input queue.
Extraction grants no proof authority: ordinary routing, signature and branch
verification, durable evidence admission, and finality priority still apply.
Queue acceptance is not committed progress. No inbox is cleared and no conflict,
refusal, saturation, or unresolved-finality guard is bypassed.

EOF closes command input without stopping the supervisor. Status commands and
explicit shutdown remain available; commands that would replace or compete with
supervised work are rejected. Signals and output failure preserve their existing
shutdown behavior. Restart rederives volatile jobs and retries requests; completed
signed publications recover through their original durable bytes. Pending signing
preparations and anchored terminal states retain existing fail-closed startup:
this does not promise recovery from every arbitrary crash point.

### Continuous candidate inbox

Instead of nonempty `targets`, the supervisor may configure
`candidate_inbox = "candidate-inbox.json"`. The path resolves against the
configuration directory; an empty path is rejected. This mode accepts new local
hints after startup without a height-ordered startup plan. The same immutable
policy binding includes the inbox path; finite-plan policy bytes remain
unchanged. Switching modes on an existing signer is not a migration path.

An external publisher atomically replaces a bounded regular JSON file:

```json
{"candidates":["<canonical block ID>","<another canonical block ID>"]}
```

Each observation reads at most 20,000 bytes from one nonblocking, no-follow
regular descriptor and accepts at most 256 entries before deduplication. Every
ID must be canonical; unknown or duplicate object fields are rejected. Empty,
absent, malformed, oversized or nonregular intake provides no eligible batch.
Read/parse refusal emits `supervisor_inbox_waiting` without exposing input bytes
or changing durable preference. The publisher owns replacement and retention;
the validator never edits, acknowledges or deletes this inbox.

At most once per supervisor interval, with idle source ownership and no retained
value or stopped fresh job, the owner observes the batch in ascending canonical
block-ID order. Candidates must belong to the configured source chain, extend
the exact replay-verified selected head, have a complete local canonical payload,
and pass the selected snapshot's full child validation, including proof admission
and artifact-set roots. Invalid or nonextending candidates are skipped. The first
fully validated candidate is the lowest ID in this local observed eligible set;
unavailable candidates are not members of that set. This is local proposer
preference, not globally agreed candidate ordering, finality, or peer authority.
Role, phase, round, retained-value and signing gates still apply when authoring.

When no eligible candidate exists, missing candidate or payload bytes use the
existing bounded configured-peer acquisition path. Complete-proof polling still
alternates with acquisition. The missing-hint cursor advances after a configured
peer cycle, so equal hint and peer counts cannot permanently bind a hint to one
unavailable peer. Cursors are volatile and restart from the configured order;
changing external batches carries no fairness or response-time guarantee.
Source integrity failures remain fatal and are not repaired by inbox intake.

Before any job may author the chosen fresh value, the exclusive signer owner
syncs `vote_journal/supervisor-choice-v0.json`. Its bytes are canonical JSON for
`null` or `{height,parent,target}` (canonical decimal height and canonical IDs),
followed by one newline and the lowercase SHA-256 of those JSON bytes. Create
syncs `null` and the directory. Replacement writes and syncs a newly created
`supervisor-choice-v0.pending`, renames it over the choice file, and syncs the
directory before exposing the preference. An interrupted temporary entry may
be unlinked under the owner lock before another replacement; it is never read
as authority. Any replacement failure stops the owner before fresh authoring.

Strict reopen requires the bounded regular choice file, verifies exact canonical
encoding and checksum, and stabilizes the file and directory. A future height or
a different parent at the current height refuses work. An older choice is
superseded by journal-derived height advancement; a current choice survives inbox
replacement, omission and round changes. Retained consensus values always take
precedence. Only the latest local preference is retained here: this file is not
a signing journal, rollback anchor, selection certificate or source of consensus
position, and authoring revalidates its bytes through the original source gates.

Continuous intake removes the finite startup target horizon. Existing source,
evidence, signer-journal, round and runtime limits remain binding; it does not
provide unbounded retention, live source-store mutation by another owner,
automatic corruption repair or recovery of interrupted signing preparations.

### Direct configured-publisher intake

The [Direct Candidate Offer Intake V0](candidate-offer-intake-v0.md) contract
defines the mutually exclusive network intake mode, exact durable-receipt
boundary, per-publisher replacement bounds and source-only publisher invocation.
It reuses the validation, durable choice and retained-value precedence above.

### Explicit source recovery restart

`PROD-020-070` permits an operator-requested restart with both process and source
`mode = "open"`, an existing supervisor, and an additional source field:

```toml
[sources]
mode = "open"
candidate_directory = "candidates"
payload_directory = "payloads"
candidate_entries = "128"
payload_entries = "128"
payload_bytes = "1048576"
recovery_directory = "source-recovery-1"
```

The operator provisions the recovery directory before starting the process.
The named original candidate and payload directories remain present and are
never opened, repaired, moved, truncated or deleted by this recovery path.
Their complete corrupt generation remains available for inspection. Recovery
starts fresh bounded source retention, not a salvage scan or a promise to
restore every old cache entry. No configuration value is a signing, finality,
branch-selection or source-validity authority.

Named original source, recovery and protected directories must be real
directories. The recovery directory's canonical path must
neither contain nor lie within either original source directory, any of the four
authority directories, or the configured evidence directory. Directory aliases
are checked after canonicalization; a symlink used as a named recovery or child
directory is rejected. One no-follow regular `source-generation.lock` holds an
exclusive lock for the complete source-owner lifetime. Only an otherwise empty
recovery directory may initialize. It creates fixed `candidates` and `payloads`
subdirectories and uses the ordinary bounded store constructors. After both
store files and their directories are synchronized, it creates and synchronizes
`source-generation-v0.json`, then synchronizes the recovery directory before
returning sources to ordinary startup.

The seal is the exact compact JSON tuple
`[0,[chain-ID bytes],"canonical original candidate path","canonical original payload path"]`
with no trailing newline. It binds provenance and format, not consensus
authority. Subsequent starts with the same configuration acquire the generation
lock, require exactly these four directory entries, match and synchronize the
same bounded regular seal descriptor, and strictly open both existing child
stores under the supplied limits. A changed binding, malformed or missing seal
on a populated generation, partial store construction, unexpected entry,
nonregular file, exceeded retention bound or corrupt replacement store refuses
startup. Such a generation is retained; another replacement requires another
explicitly configured fresh directory. There is no automatic generation loop,
in-place repair, silent retry with empty stores or cross-file atomicity claim.

Source initialization may finish even if subsequent authority startup refuses;
it confers no ready state or right to sign. Finality and signer journals and
anchors, publication/evidence custody, immutable supervisor policy and the
persisted current-height choice retain their normal strict reopen rules.
Pending signing preparations and terminal signer/finality states remain denied.
Retained valid values and completed publication history still take precedence
over fresh authoring. Missing exact bytes use the existing supervisor's bounded
configured-peer ancestry/payload acquisition and complete-proof following;
structural candidates remain raw input, while payload admission and eventual
authoring still require complete branch-relative validation. Peers gain no
validity or selection authority. A crash after generation sealing reopens that
same generation and reconstructs only ordinary journal-derived runtime state;
volatile requests restart through normal acquisition. Detected live corruption
still stops the process, including corruption in a recovery generation.

## Invocation and configuration

Build with `cargo build -p naome-validator --release --locked` and invoke
`target/release/naome-validator /absolute/path/validator.toml`. Exactly one
configuration path is required. Non-Unix builds return an unsupported-platform
failure before opening configuration or authority files. There is no daemon
fork, service installation, configuration reload, or hidden environment override.

The UTF-8 TOML file is at most 65,536 bytes. Every field listed below is required;
the additional `[network].serve_finality_proofs` and
`[network].serve_artifact_sources` booleans are optional and default to `false`.
Enabling artifact-source serving requires `[sources]` before authority provision. The optional `[network].publication_retry_millis` is a canonical
positive unsigned decimal `u64` string with checked monotonic deadline addition;
it has no default and may be changed or omitted on strict restart. Unknown fields
and tables, including remote-signer configuration,
are rejected. Version
is the integer `0`, and mode is exactly `"create"` or `"open"`. Relative paths
in configuration and commands resolve against the configuration file's parent
directory, not against a source file or an inferred data directory. Directories
must already exist. No directory layout is created implicitly.

| Table | Required fields |
| --- | --- |
| Root | `version`, `mode`, `deployment_discriminator`, `genesis_id`, `protocol_version`, `signing_seed_file` |
| Each `[[validators]]` | `consensus_key`, `weight` |
| `[directories]` | `finality_journal`, `finality_anchor`, `vote_journal`, `vote_anchor` |
| `[network]` | `identity_seed_file`, `listen`, `peers`, `publication_targets` |
| Each network peer | `peer_id`, `address` |
| `[limits]` | `finality_max_round`, `vote_preparations`, `proposal_preparations`, `recovery_max_round`, `catch_up_heights`, `driver_max_round` |
| Each `[limits.higher]`, `[limits.current]`, `[limits.finality]`, `[limits.nil_precommit]` | `entries`, `bytes` |
| Each `[timeouts.proposal]`, `[timeouts.prevote]`, `[timeouts.precommit]` | `base_millis`, `round_increment_millis` |

The deployment discriminator, genesis ID, and consensus public keys are exactly
64 lowercase hexadecimal characters. `protocol_version` is an unsigned `u32`
TOML integer. Weights, all limits, and millisecond durations are canonical
unsigned decimal **strings**, with no sign, separator, whitespace, or redundant
leading zero. This preserves full `u128` weights and `u64` rounds without TOML's
signed-integer narrowing. Inbox entry counts must also fit the host `usize`.

The exact fixed set is checked through virtual-genesis branch construction:
no empty/oversized set, duplicate key, zero weight, or overflowing total is
accepted. The derived local signer must be in that set. Finality/vote/proposal
replay limits and each inbox's two budgets are positive. Recovery-round,
catch-up-height, and driver-round ceilings may be zero. These are independent
budgets; no ordering between the configured driver and finality ceilings is
introduced. Actual signer positions must satisfy the existing driver checks.
On reopen, persisted replay/activation limits must match their existing headers
and records; changing a configuration value does not migrate them.

Each phase has an explicit positive base and positive round increment. Checked
`base + round * increment` duration arithmetic and monotonic deadline addition
are preflighted through the configured driver ceiling. The example magnitudes
in process tests are test inputs, not production timing recommendations.

Network addresses are literal `/ip4/IP/tcp/PORT` or `/ip6/IP/tcp/PORT`
multiaddresses. Listener port zero requests an ephemeral port; peer ports must
be nonzero. DNS, UDP, and additional address components are rejected in V0.
There are at most eight distinct static peers, none equal to the independently
derived local Noise identity. `publication_targets` is an explicit ordered
subset of those peers with no duplicates; `[]` is valid. These values confer
neither consensus membership nor connectivity. Existing static-peer dialing
ownership remains determined by raw `PeerId` ordering.

For example, the network table uses these forms (replace the identity, peer ID,
and endpoint with the operator's own values):

```toml
[network]
identity_seed_file = "noise.seed"
listen = "/ip4/127.0.0.1/tcp/7000"
peers = [{ peer_id = "<configured peer ID>", address = "/ip4/127.0.0.1/tcp/7001" }]
publication_targets = ["<configured peer ID>"]
```

## Local seeds and provisioning

`signing_seed_file` and `network.identity_seed_file` contain exactly 32 raw
bytes each. They must contain different seeds. The process neither generates,
derives one from the other, rotates, nor persists seed material. Each file is
opened once with no-follow and nonblocking flags, then examined through that
same descriptor: it must be regular, owned by the effective user, and have no
group or other permission bits. Symlinks, directories, FIFOs, incorrect lengths,
and wrong permissions fail closed. A bounded read prevents growth from escaping
the byte cap. Temporary seed buffers are zeroized. No seed, configuration text,
source payload, or full parser error is included in diagnostics.

These file checks do not establish hardware custody, absence of backups or hard
links, resistance to a privileged or same-user adversary, or durable runtime
recovery. They do not change the existing signing-key implementation's memory
properties. Configuration and command source files also use bounded no-follow,
nonblocking regular-file reads, without the seed-only ownership/mode checks.

All configuration-computable checks, seed checks, supported TCP address checks,
and signal/reader setup occur before provisioning. They leave the four authority
directories unchanged on rejection. Create and open never fall back to one
another. Existing creation and strict-reopen ordering remains binding: lock
files may be created during an unsuccessful open, and permitted tail handling,
proposal activation, stop propagation, and signer catch-up can leave their
existing durable prefixes. Later I/O or bind failures do not roll back those
prefixes. No general no-write claim applies to failed startup after preflight.

Only a ready startup classification proceeds to awaited scope issuance and
catch-up, then driver/runtime construction. Pending vote, pending proposal,
signer-stop, and finality-stop classifications return distinct diagnostic codes
without entering the event loop. A `ready` report means this owning lifetime
and runtime exist; `listening` and `peer_session`/`established` are separate
network observations, not implied by readiness.

## Operator commands

Input is a newline-terminated JSON object. Each frame has at most 65,536 bytes excluding
the newline. All fields are required, unknown fields are rejected, and `id` is
an unsigned `u64` JSON integer echoed unchanged in the command response. It is
a correlation label, not a deduplication or replay-protection token. Reusing an
ID submits another command. Opaque binary inputs are read from explicit files;
they are never supplied as unbounded inline JSON arrays.

| `command` | Additional fields | Operation |
| --- | --- | --- |
| `status` | None | Read driver position/head, inbox counts, timer and publication diagnostics |
| `shutdown` | None | End ordinary processing and dispose of current volatile custody |
| `sync_finality` | `peer_id`, `count` | Fetch and commit 1–16 successive complete direct-child proofs |
| `sync_status` | None | Read the current volatile proof catch-up job |
| `cancel_sync` | None | End the current proof job without undoing its anchored prefix |
| `discard_inbox` | `inbox` | Drain and discard exactly one explicitly selected inbox class |
| `author_fresh` | `block_file`, `payload_file` | Decode the exact canonical block and submit `Fresh` with the exact payload |
| `author_retained` | `payload_file` | Submit `RetainedValid`; the signer derives eligibility and retained value |
| `submit_vote` | `vote_file` | Queue an exact raw vote for later runtime routing and strict admission |
| `submit_proposal` | `control_file`, `payload_file` | Queue raw control and payload for later routing and both strict proposal routes |
| `advance_higher_quorum` | `certificate_file` | Submit one exact complete higher-round quorum certificate |
| `advance_higher_votes` | `evidence_round`, `role`, `target`, `vote_files` | Submit one complete signed-vote batch with the caller's exact route |
| `finalize_current_quorum` | `control_file`, `payload_file`, `certificate_file` | Submit one complete finality proof at the owned current round |
| `finalize_current_votes` | `proof` | Submit the exact-current proof using exact signed precommit files |
| `finalize_lower_quorum` | `control_file`, `payload_file`, `certificate_file` | Submit one complete direct strictly lower-round finality proof |
| `finalize_lower_votes` | `evidence_round`, `proof` | Submit the direct lower proof using exact signed precommit files |
| `halt_lower_conflict` | `evidence_round`, `first`, `second` | Independently verify two explicit lower-round proofs for a neutral paired halt |
| `halt_current_conflict` | `first`, `second` | Independently verify two exact-current proofs for a neutral paired halt |
| `halt_historical_envelope` | `envelope_file`, `payload_file` | Verify one complete historical sibling against its retained selected parent and halt |
| `halt_historical_votes` | `evidence_round`, `proof` | Verify a historical sibling using an exact signed-precommit batch and halt |

For example:

```json
{"command":"author_fresh","id":1,"block_file":"block.bin","payload_file":"payload.bin"}
{"command":"status","id":2}
{"command":"shutdown","id":3}
```

Block reads use `ARTIFACT_BLOCK_BYTES`; control, payload, and vote reads use the
existing consensus-push maximum/exact widths. Actual reads are capped even if
files grow. Command parse/source failures produce `command_rejected`. Successful
queueing reports `input_queued`, which establishes no validity. Authoring returns
the runtime's actual outcome, including busy, rejected, or pending ordinary
work. Operator command rejections are not automatically retried. Refunded
sources and transferred reports/publications are diagnosed and discarded by
this profile. The independent anchored publication source and durable receipt
snapshot retain unacknowledged consensus debt after those reports are disposed.

A dedicated input thread holds partial frame bytes across runtime polls. The
channel contains at most one frame, with at most one additional frame being
read or waiting to enter it, plus bounded standard-I/O buffering. Malformed JSON
or UTF-8 rejects only that framed command. Oversized input or EOF within an
unterminated frame ends the process with failure and never reparses a suffix as
a fresh command. Clean EOF requests shutdown. Bytes buffered in stdin or in the
reader without a response are explicitly unacknowledged and discarded.

## Explicit inbox disposal

`submit_vote` and authenticated peer input now admit higher-round nil prevotes
and both precommit targets through the same fully verifying runtime/driver
boundary as higher proposal prevotes. The existing `[limits.higher]` budget
covers all these votes and proposals together. A unique complete healthy quorum
may cause a `transitioned` event and replacement timer without publication or
finality; ambiguity or saturation requires existing explicit disposal. The
checkpoint and empty-on-restart volatile custody contract is defined in
`fixed-validator-higher-round-recovery-v0.md`. No command, configuration field,
wire format, or journal format is added.

`discard_inbox` requires `inbox` to be exactly one JSON string: `higher`,
`current`, `finality`, or `nil_precommit`. Numeric tags, enum-shaped objects,
arrays, case variants, missing or duplicate fields, unknown fields, and an
implicit all-class selection are rejected by the command schema. For example:

```json
{"command":"discard_inbox","id":5,"inbox":"finality"}
```

The command invokes exactly the corresponding existing runtime drain-and-reset
operation, counts its complete class-specific iterator, and drops that iterator
before reporting `inbox_discarded`, the selected `inbox`, `discarded_items`, and
post-disposal `state` using the ordinary status shape. Empty classes return
zero. An unavailable driver returns `driver_unavailable` without a drain;
normal fatal process handling already stops the process before another command.

This is explicit disposal of the selected volatile evidence, including any
proposal payloads owned by that inbox. It creates no export, retry copy, durable
recovery record, source-file write, or automatic resubmission. The report's
count is diagnostic. A command may have taken effect before its output is lost;
output failure uses the existing teardown path without rollback. Request IDs
remain correlation labels: repeating an ID performs another disposal and may
discard evidence admitted since the earlier command.

The runtime clears only the selected class's accounting and blocking state and
re-enables ordinary classification. It preserves other inboxes, selected head,
live height/round/phase, accepted due state, active timer and deadline, pending
arm and command, buffered input, publication bytes and released proposal token,
local-admission-attempt marker, and per-peer delivery custody. No signature,
transition, file read, transmission, timer restart, or runtime poll occurs
inside the disposal command. Normal runtime scheduling resumes afterward and
may perform already-authorized work. Only higher-class disposal reopens a
higher-block-rejected due ticket, preserving its original expired deadline;
clearing another class leaves that suppression in place.

Capacity freed by disposal does not re-admit a previously rejected input or a
publication whose local admission was already attempted. The operator must
explicitly resubmit owned source bytes through an existing command. Completing
an in-flight publication likewise does not reinsert disposed local evidence.
Strict restart restores only underlying anchored signer/finality state; it
reconstructs no discarded inbox or timer. The publication lifecycle independently
recovers exact signed messages and redoes current local admission. This command adds no
evidence preference, conflict resolution, consensus validity, signing,
selection, or finality authority.

## Explicit complete proofs

The ten complete-proof commands call the corresponding existing
`FixedValidatorRuntimeV0` methods exactly once. They do not collect, group,
rank, filter, deduplicate, sort, or infer evidence. A file path, caller-supplied
route, successful read, or parsed command establishes no proof validity. Only
the runtime's existing fully verifying driver coordinators can checkpoint,
finalize, or halt. No new wire envelope or durable input queue is introduced.

`evidence_round` is an unsigned `u64` JSON integer. The batch higher command
requires `role` to be `"prevote"` or `"precommit"`, and `target` to be exactly
`{"kind":"nil"}` or `{"kind":"proposal","root":"<64 lowercase hex>"}`.
The route is passed literally to verification, including a full-width round;
it is not reconstructed from a vote header or selected from multiple roots.
Each nested `proof`, `first`, or `second` object contains exactly
`control_file`, `payload_file`, and `vote_files`. Unknown nested fields are
rejected. Command, target, and nested proof arrays are rejected; parsing retains
duplicate map entries so repeated fields are rejected rather than collapsed.
Both proofs in a lower pair use the one explicit evidence round.
`halt_current_conflict` instead accepts exactly `id`, `first`, and `second`
beside its command name. It rejects `evidence_round`, including the actual
current round, and accepts no root, parent, position, or winner metadata. The
node derives the live owned round and independently verifies both complete
proofs against it; the process does not extract a route from either proof.

`finalize_current_quorum` and `finalize_current_votes` likewise reject
`evidence_round`, even when it equals the live round, and accept no root, parent,
position, or winner. The node derives the owned round for complete verification.
These are positive proof submissions: retained healthy ready/missing/conflicting
current finality or a complete pair keeps priority; saturation without a complete
pair follows the existing positive-proof fallthrough rule. Thus an explicitly
configured capacity-one finality inbox cannot retain a proposal and quorum
together, but a complete explicit proof can finalize without changing its budget,
opening source stores, or advancing the round just to use lower-round finality.

`halt_historical_envelope` accepts exactly `id`, `envelope_file`, and
`payload_file` beside its command name. `halt_historical_votes` instead accepts
exactly `id`, `evidence_round`, and `proof`. Neither accepts a height, parent,
target, or winner; the envelope command also rejects `evidence_round`. Bounded
proof bytes identify only a preliminary value at an already selected positive
height. The node-owned journal rejects the selected value and an unselected
height before any commit, then completely verifies a distinct sibling against
the exact retained parent. Its evidence round need not match the later live
signer round. No input source or unverified value grants conflict authority.

Every `vote_files` array has between 1 and `MAX_ACTIVE_VALIDATORS` (256) paths.
Scalar parsing and both pair counts are checked before opening any proof source.
Each vote file must contain exactly `CONSENSUS_PUSH_VOTE_BYTES` (214) bytes;
all paths, duplicates, and vote order are retained. Quorum and precommit files
use their existing `VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH` and
`VerifiedPrecommitCertificateV0::MAX_BYTE_LENGTH` bounds (24,696 bytes each).
Historical envelope files use the existing
`VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH` cap.
Control and payload files retain their existing independent consensus-push
caps, including independently for both members of a pair. All source reads
use the existing bounded nonblocking, no-follow regular-file path. Every input
file is fully read before the sole runtime call. A parse, count, route-format,
or source-read refusal makes no proof call and changes no authority files as
part of that command; the surrounding runtime retains ordinary scheduling.

For example, explicitly submit a complete lower-round signed-precommit batch:

```json
{"command":"finalize_lower_votes","id":4,"evidence_round":0,"proof":{"control_file":"proposal.bin","payload_file":"payload.bin","vote_files":["a.precommit","b.precommit"]}}
```

The six positive commands preserve the runtime's publication, pending-arm,
and pending-driver-command backpressure. They report `proof_refused` with
`reason` `busy` or `driver_unavailable` before delegation. Both paired-conflict
and both historical-conflict commands wait only for driver-command transfer: publication, an in-flight
send, a timer or due state, and buffered raw input add no conflict gate. All
existing current-finality and higher-evidence priorities remain binding for
positive commands. Neither paired command classifies retained finality or runs
ordinary work before jointly verifying its complete inputs; a uniquely ready
retained first value cannot be selected by the explicit paired call. No complete-
proof command implicitly steps unresolved work. Current raw input
remains a separate admission path and never becomes an automatic proof call.

Command results include the actual post-call runtime `state`. Outcomes remain
distinct: `proof_refused`; continuing `higher_round_rejected`,
`current_round_finality_rejected`, `lower_round_finality_rejected`,
`lower_round_conflict_rejected`, or
`current_round_conflict_rejected`; existing
unresolved-work outcomes; `transitioned`; and `finality`. A higher checkpoint
supersedes the old deadline only under the runtime's existing advancement rule,
and a successful current- or lower-finality operation exposes the exact selected child and
next height. Refunded payload allocations are discarded and counted in
`refunded_payloads_discarded`; their source files remain untouched. Delegated
inputs follow the existing consuming-input contract. No outcome schedules a
retry or retains these proof inputs for restart.

A verified distinct pair reports `finality_stopped`, including its typed halt
kind, height, ordered ancestry IDs, anchored finality state ID, and that same
ID from the signer stop. These identities are diagnostics of the returned
terminal result, not an alternate authorization interface. No winner is
selected. A same-proof pair reaches the existing consuming non-distinct error:
it reports `proof_failed` with `strict_restart_required` and `operation`
`lower_round_conflict` or `current_round_conflict`, not a continuing
rejection or an anchored halt. Other consuming failures retain the existing
fatal handling. Both terminal and consuming-error paths stop processing,
dispose of surviving independent runtime custody, and release journals before
the final `stopped` report. Already queued network work cannot be recalled.
Strict open alone distinguishes a durable paired halt from a healthy or
ambiguous persisted prefix; the command never retries, repairs, or rolls back.

A fully verified historical sibling instead reports the existing
`finality_stopped` with halt kind `SelectedSibling`, its exact selected and
conflicting ancestry IDs, and matching anchored halt/stop state IDs. Later
selected history is retained only as pre-halt evidence; no sibling is installed
or exposed as an operable head. Every delegated historical error, including
malformed, same-selected-value, and next-height proof rejection before writes,
reports `proof_failed`, `operation` `historical_finality_conflict`, and
`strict_restart_required: true`. It consumes the driver and stops the process
under the same disposal and lock-release contract. Pre-invocation refusal
instead discards and counts its one refunded payload and permits continued
operation. This error boundary does not introduce a continuing historical retry.

Candidate-backed proofs and historical-sibling source lookup use the separate
[source-backed proof commands](fixed-validator-process-source-proofs-v0.md).
Selected-state recovery-bundle installation remains outside these complete-proof
commands. Separate [offline bundle commands](fixed-validator-process-source-bundles-v0.md)
export from the current head or stage only unselected source entries.
Optional source ownership and acquisition are defined by the separate
[artifact-source profile](fixed-validator-process-artifact-acquisition-v0.md).
Complete-proof commands do not drain inboxes; the separate
explicit `discard_inbox` command owns class-selected disposal. These proof
commands grant no automatic proof collection, conflict invocation, evidence selection, or production-liveness
authority.

## Events, shutdown, and restart

The process fairly selects between commands, Unix SIGINT/SIGTERM, and runtime
events. It preserves the runtime's own retained-work and due-before-input rules.
An output-writer failure wakes this owner, including with idle open stdin and
a pending source acquisition, to release its source and authority ownership.
It does not continuously retry blocked/rejected driver work or automatically
drain inboxes.
The optional source profile routes only its active cursor's exact correlated
terminals, and the optional proof provider routes its selected-history responses.
Other unrelated network events are reported and dropped, without serving source
artifacts, accepting network recovery bundles, or selecting additional evidence.

Reports are bounded JSONL. They distinguish `proposal_authored` (anchored signing
completion), `publication_prepared` (runtime custody), `peer_completed` with
`received` (correlated transport receipt synchronized in delivery progress),
`publication_recovered` (original anchored completion), per-route `admission` with explicit
caller/local-publication/peer provenance, and `finality` with selected head and
next position. A peer receipt is neither admission nor finality. A
`publication_complete` report includes failed/refused delivery states and any
released proposal-token custody being discarded; completion alone proves no
successful delivery. It also reports the remaining historical queue length as
`publication_recovery_remaining`, so interleaving before queue exhaustion can
be observed without inferring delivery or signing authority.

The dedicated output thread receives at most 32 reports, each at most 16,384
bytes excluding newline, plus one frame currently being written. It owns no
journal or signing capability. Queue saturation, disconnect, serialization, or
write failure stops the signing owner on its next output attempt. The final
flush waits at most two seconds after journal owners are dropped. A stalled
consumer can lose reports and cause nonzero exit, but cannot hold journal locks
through a blocked stdout write. Input/output threads are not joined at exit;
they own no authority state. Stdin flags are not modified.

On normal command/signal/EOF shutdown, `into_parts` collects the surviving driver
position and all four inbox counts, pending command, publication/token and each
peer attempt, input slot, failed-admission report, timer, pending arm, rejected
due ticket, and queued operator-frame count. These are disposal diagnostics.
The driver and network are dropped inside the callback. Only after the outer
signing future returns and drops both anchored journals may the final `stopped`
report state `locks_released`. Fatal runtime outcomes also stop; a broken report
channel may prevent a final custody report. No shutdown recalls queued sends or
turns discarded custody into delivered, admitted, durable, or recoverable work.

SIGINT/SIGTERM do not interrupt synchronous proof, filesystem, or signing work
inside a poll. No hard real-time shutdown bound or power-loss guarantee is
introduced. Successful shutdown exits zero; input framing errors, startup
refusals, fatal runtime outcomes, and output failure exit nonzero. Strict restart
reopens durable state into a fresh runtime with fresh timers. It reconstructs
original completed consensus publications and per-peer receipts through the
mandatory lifecycle, but no prior operator input, transport tickets, network
sessions or trusted inbox contents. Missing receipt snapshots, changed ordered
recipient identities and legacy proposals without payload bytes refuse startup
before ready; no implicit migration or source-file reload is provided.

## Evidence and limits

`crates/naome-validator/tests/process.rs` launches the compiled executable as
actual Unix child processes. The weighted `3:1` scenario schedules the weight-3
proposer, uses separate Noise seeds, sends its proposal/prevote/precommit to the
weight-1 receiver, checks all three source-correlated receipts and peer admissions,
checks both exact finalized child IDs, and strictly restarts both to height 2,
round 0, Proposal phase with unchanged authority images. This proves that
bounded one-way scenario; it does not establish reciprocal publication success,
equal-weight distributed liveness, automatic retries, deployment, or production
timeout suitability.

Additional process vectors cover an in-flight send and retained-inbox shutdown,
SIGINT with partial input and open stdin, EOF and explicit shutdown, a split
full-width request across an actual runtime timeout, malformed/oversized input,
raw queue acceptance followed by strict rejection, invalid source-file refusal,
preflight refusals before create/healthy-open writes, explicit-mode refusal,
pending vote/proposal and anchored terminal restart diagnostics, and stalled
stdout followed by successful strict reopen, including a full output socket
whose final-report timeout is not repeated as an error-report flush.
Foreign-user ownership is checked
in code but is not exercised through privileged ownership changes by these tests.

`crates/naome-validator/tests/cases/explicit_proofs.rs` additionally exercises
both higher forms with both vote roles, both lower-finality forms, exact
checkpoint/finality restart, bounded nested input and route refusals followed
by an explicit valid resubmission, and current-finality precedence followed by
ordinary exact-proposal completion. A process regression rejects nil-target
extra fields, numeric target-kind tags, and object-form roles before source
reads while preserving the valid scalar-role/nil-target form. Another rejects array forms at every command,
target, and nested-proof boundary while preserving duplicate-field rejection.
Separate throwaway anchored signers create
the adversarial conflicting proof fixtures. A distinct pair produces terminal
reopen refusal; an identical pair consumes the process's authority without
changing its journals and strictly reopens healthy. A real connected peer
paused with SIGSTOP holds a publication with a released proposal token in
flight: all positive commands remain busy, malformed pair rejection preserves
custody, and a valid pair durably halts while reporting that surviving custody
for disposal. These are bounded local Unix process observations, not general
multi-node liveness, production timing, or deployment evidence.

`crates/naome-validator/tests/cases/inbox_disposal.rs` exercises strict scalar
class parsing with full-width IDs, all four class counts and empty repeats,
class isolation with unchanged authority images, and retained nil evidence
after actual round progress. A `4:1` process fixture fills current/finality
budgets across height advancement, rejects the next proposal's two admission
routes, clears each class explicitly, and finalizes the exact next child only
after explicit identical-source replay; strict reopen reaches height 3. Higher
saturation rejects a due timeout; clearing other classes preserves the block,
and clearing higher yields admitted due work and progress before any replacement
arm. This process observation checks event order and timer presence; exact
ticket/deadline identity is covered by the existing runtime recovery tests.
A real connected peer paused with SIGSTOP holds a publication and released
proposal token in flight while individual class disposal preserves all other
reported state and authority images. Resuming the peer produces a correlated
receipt and completion without local reinsertion; strict reopen retains the
anchored higher checkpoint with empty inboxes. These are bounded local Unix
process and loopback observations, without deployment or production-liveness
evidence.

`crates/naome-validator/tests/cases/current_pair.rs` checks exact-current pair
schema and both batch-count preflights before any source read, including a
caller-supplied current `evidence_round`. A saturated finality inbox retains
only one incomplete proof; malformed first/second or valid noncurrent proofs
preserve the complete reported state and authority images, and an explicit
complete distinct pair halts in either input order without an intermediate
selection. Reports name the exact canonically ordered ancestry identities and
matching halt/stop state IDs; strict reopen refuses that anchored terminal
state. Identical valid proofs instead consume the driver without authority
writes and strictly reopen healthy. A real higher-round `Some` publication with
a connected SIGSTOP peer remains in flight across typed pair rejection and
terminal halt, with its reported custody preserved for disposal. These process
observations establish reported state and event order; the driver and runtime
tests separately check exact timeout and allocation identities. This adds no
deployment, production timing, or general distributed-liveness evidence.

`crates/naome-validator/tests/cases/current_finality.rs` checks both exact-current
forms with empty and saturated capacity-one finality inboxes, retained healthy
missing-proposal priority, a real higher-round checkpoint followed by exact-current
finality, noncurrent and malformed input rejection with explicit valid retry,
object/duplicate/unknown-field and batch-count refusals before source access,
independent file bounds, exact reported child head/height/round, and strict
unchanged-image child reopen. Injected finality and signer anchor failures
consume authority, release journal locks, and refuse strict reopen without
changing the surviving prefix. The existing in-flight publication tests include
both new positive forms and preserve their reported Busy state. These are local
Unix process observations; deployment and general distributed liveness are
unverified.

`crates/naome-validator/tests/cases/historical_conflict.rs` checks both direct
historical forms after two selected heights, exact height-one sibling halt and
strict terminal restart, and consuming malformed, same-selected, and valid
next-height rejection with byte-identical authority images and healthy height-three
reopen. Object, duplicate-field, caller-selector, count, and independent file-cap
refusals precede invocation and permit an explicit valid submission. A real
height-three publication with a connected SIGSTOP peer remains in flight across
historical halt or consuming rejection and is preserved in the disposal report.
Finality-anchor and signer-stop-anchor collisions expose their exact partial
authority images, release locks, and make strict reopen refuse the lagging pair.
These are bounded local Unix process and loopback observations; allocation and
timeout identity checks belong to the runtime tests, and deployment and general
distributed liveness remain unverified.

`SEC-012-003` adds three actual four-process cold-partition cases after a common
H1 prefix, using opaque TCP gates and unmodified process authoring, runtime
admission, and finality paths. Equal halves and a three-key exact two-thirds
component retain H1 through real timeout progression; a two-key 5/7 component
finalizes H2. The corpus requires internal voting traffic and receipts,
cross-link disconnection and rejected redials, exact minority finality images,
and healthy strict finality-journal replay with shared consensus ancestry.
Its complete bounds and evidence limits are defined in
`specs/fixed-validator-process-partition-v0.md`; it does not establish process
restart, arbitrary partition safety, deployment, or general liveness.

`SEC-012-005` adds one [process kill under partition](fixed-validator-process-partition-restart-v0.md)
execution using the existing executable and explicit open configuration. It
checks a distributed non-nil lock, strict process restart, subsequent locked
voting under real deadlines, and unchanged shared finality while three other
original processes remain alive. It adds no production process behavior.


## Explicit continuous proof following

`PROD-020-063` adds caller-selected `follow_finality` to the existing
[proof catch-up command contract](fixed-validator-process-proof-catch-up-v0.md).
It uses one configured static peer, a positive caller interval and bounded
passes of 1–16 heights, with fresh live-height derivation, transient retry,
terminal invalid-proof handling and shared `sync_status`/`cancel_sync` ownership.
Waiting allows source acquisition; active acquisition defers elapsed passes.
All proof verification, runtime custody and anchored signer handoff remain
unchanged. No following intent survives restart.


## Optional durable incoming evidence

The explicit local Unix profile may add:

```toml
[evidence]
directory = "evidence"
mode = "create" # use "open" for strict restart
```

The directory must already exist and is resolved relative to the configuration
file. Unknown fields, invalid modes and empty paths are rejected. This option
is independent of publication recovery and never implicitly creates a directory
or falls back to empty custody when open fails. Source-file opening follows
strict authority startup, so a create-mode source I/O failure may occur after
authority files have been provisioned. It releases the runtime on failure and
reports `evidence_journal`. Status includes `durable_evidence`.

Existing `submit_proposal`, `submit_vote` and authenticated peer admissions
use the runtime persistence fence. `discard_inbox` durably disposes exactly the
named class before reporting success. Restart verifies raw bytes again through
the node; it does not require the original caller proposal files or redelivery
of already saved evidence. The profile preserves the existing hard inbox
budgets, explicit saturation/ambiguity disposal and authority gates. See the
runtime contract for old/new image crash behavior, fatal write failures and
the absence of adversarial rollback protection.
