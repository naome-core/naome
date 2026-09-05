# Fixed-Validator Process V0

## Scope and authority

`PROD-020-049` defines the Unix `naome-validator` executable, and
`PROD-020-050` adds explicit complete-proof commands. It owns one
explicitly configured local fixed-validator signer through
`FixedValidatorNodeReadyV0::run_with_signing_session_async`, constructs the
existing driver and runtime within that lifetime, and accepts explicit operator
commands on stdin. Consensus verification, proposal eligibility, signing intent,
anchoring, finality selection, and strict restart remain defined by
[startup](fixed-validator-node-startup-v0.md),
[driver](fixed-validator-node-driver-v0.md), and
[runtime](fixed-validator-runtime-v0.md).

The executable supplies local process ownership, seed-file loading, JSONL
commands, and diagnostic disposal on shutdown. It grants no automatic proposal
source or evidence selection, certificate acquisition, artifact serving,
fallback routing, inbox drain, delivery retry, repair, durable outbox, dynamic
validator, key rotation, production timeout calibration, hardware custody, or
distributed-liveness authority. In accordance with `PROD-023`, no remote
consensus-signer service or configuration is supported. This implements only
the process's local-key boundary; it does not close `PROD-023`'s dependency on
the complete `PROD-020` parent.

## Invocation and configuration

Build with `cargo build -p naome-validator --release --locked` and invoke
`target/release/naome-validator /absolute/path/validator.toml`. Exactly one
configuration path is required. Non-Unix builds return an unsupported-platform
failure before opening configuration or authority files. There is no daemon
fork, service installation, configuration reload, or hidden environment override.

The UTF-8 TOML file is at most 65,536 bytes. Every field is required; unknown
fields and tables, including remote-signer configuration, are rejected. Version
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

Input is newline-terminated JSON. Each frame has at most 65,536 bytes excluding
the newline. All fields are required, unknown fields are rejected, and `id` is
an unsigned `u64` JSON integer echoed unchanged in the command response. It is
a correlation label, not a deduplication or replay-protection token. Reusing an
ID submits another command. Opaque binary inputs are read from explicit files;
they are never supplied as unbounded inline JSON arrays.

| `command` | Additional fields | Operation |
| --- | --- | --- |
| `status` | None | Read driver position/head, inbox counts, timer and publication diagnostics |
| `shutdown` | None | End ordinary processing and dispose of current volatile custody |
| `author_fresh` | `block_file`, `payload_file` | Decode the exact canonical block and submit `Fresh` with the exact payload |
| `author_retained` | `payload_file` | Submit `RetainedValid`; the signer derives eligibility and retained value |
| `submit_vote` | `vote_file` | Queue an exact raw vote for later runtime routing and strict admission |
| `submit_proposal` | `control_file`, `payload_file` | Queue raw control and payload for later routing and both strict proposal routes |
| `advance_higher_quorum` | `certificate_file` | Submit one exact complete higher-round quorum certificate |
| `advance_higher_votes` | `evidence_round`, `role`, `target`, `vote_files` | Submit one complete signed-vote batch with the caller's exact route |
| `finalize_lower_quorum` | `control_file`, `payload_file`, `certificate_file` | Submit one complete direct strictly lower-round finality proof |
| `finalize_lower_votes` | `evidence_round`, `proof` | Submit the direct lower proof using exact signed precommit files |
| `halt_lower_conflict` | `evidence_round`, `first`, `second` | Independently verify two explicit lower-round proofs for a neutral paired halt |

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
work. No rejection or completed delivery is automatically retried. Refunded
sources and transferred reports/publications are diagnosed and discarded by
this profile, not retained as a durable outbox.

A dedicated input thread holds partial frame bytes across runtime polls. The
channel contains at most one frame, with at most one additional frame being
read or waiting to enter it, plus bounded standard-I/O buffering. Malformed JSON
or UTF-8 rejects only that framed command. Oversized input or EOF within an
unterminated frame ends the process with failure and never reparses a suffix as
a fresh command. Clean EOF requests shutdown. Bytes buffered in stdin or in the
reader without a response are explicitly unacknowledged and discarded.

## Explicit complete proofs

The five complete-proof commands call the corresponding existing
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
rejected. Both proofs in a pair use the one explicit evidence round.

Every `vote_files` array has between 1 and `MAX_ACTIVE_VALIDATORS` (256) paths.
Scalar parsing and both pair counts are checked before opening any proof source.
Each vote file must contain exactly `CONSENSUS_PUSH_VOTE_BYTES` (214) bytes;
all paths, duplicates, and vote order are retained. Quorum and precommit files
use their existing `VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH` and
`VerifiedPrecommitCertificateV0::MAX_BYTE_LENGTH` bounds (24,696 bytes each).
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

The four positive commands preserve the runtime's publication, pending-arm,
and pending-driver-command backpressure. They report `proof_refused` with
`reason` `busy` or `driver_unavailable` before delegation. The paired-conflict
command waits only for driver-command transfer: publication, an in-flight
send, a timer or due state, and buffered raw input add no conflict gate. All
existing current-finality and higher-evidence priorities remain binding;
the command does not implicitly step unresolved work. Current raw input
remains a separate admission path and never becomes an automatic proof call.

Command results include the actual post-call runtime `state`. Outcomes remain
distinct: `proof_refused`; continuing `higher_round_rejected`,
`lower_round_finality_rejected`, or `lower_round_conflict_rejected`; existing
unresolved-work outcomes; `transitioned`; and `finality`. A higher checkpoint
supersedes the old deadline only under the runtime's existing advancement rule,
and a successful lower-finality operation exposes the exact selected child and
next height. Refunded payload allocations are discarded and counted in
`refunded_payloads_discarded`; their source files remain untouched. Delegated
inputs follow the existing consuming-input contract. No outcome schedules a
retry or retains these proof inputs for restart.

A verified distinct pair reports `finality_stopped`, including its typed halt
kind, height, ordered ancestry IDs, anchored finality state ID, and that same
ID from the signer stop. These identities are diagnostics of the returned
terminal result, not an alternate authorization interface. No winner is
selected. A same-proof pair reaches the existing consuming non-distinct error:
it reports `proof_failed` with `strict_restart_required`, not a continuing
rejection or an anchored halt. Other consuming failures retain the existing
fatal handling. Both terminal and consuming-error paths stop processing,
dispose of surviving independent runtime custody, and release journals before
the final `stopped` report. Already queued network work cannot be recalled.
Strict open alone distinguishes a durable paired halt from a healthy or
ambiguous persisted prefix; the command never retries, repairs, or rolls back.

Candidate-backed proofs, historical-sibling source lookup, recovery-bundle
installation, source-store ownership, inbox drains, acquisition, and serving
remain outside this process profile. These commands grant no automatic proof
collection, conflict invocation, evidence selection, or production-liveness
authority.

## Events, shutdown, and restart

The process fairly selects between commands, Unix SIGINT/SIGTERM, and runtime
events. It preserves the runtime's own retained-work and due-before-input rules.
It does not continuously retry blocked/rejected driver work or drain inboxes.
Unrelated network events are reported and dropped, without serving artifacts,
accepting recovery bundles, or selecting additional evidence.

Reports are bounded JSONL. They distinguish `proposal_authored` (anchored signing
completion), `publication_prepared` (runtime custody), `peer_completed` with
`received` (correlated transport receipt), per-route `admission` with explicit
caller/local-publication/peer provenance, and `finality` with selected head and
next position. A peer receipt is neither admission nor finality. A
`publication_complete` report includes failed/refused delivery states and any
released proposal-token custody being discarded; completion alone proves no
successful delivery.

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
reopens durable state into a fresh runtime with empty volatile custody and fresh
timers. It never reconstructs prior operator input, network sessions, peer
receipts, publications, or inboxes.

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
extra fields and object-form roles before source reads while preserving the
valid scalar-role/nil-target form. Separate throwaway anchored signers create
the adversarial conflicting proof fixtures. A distinct pair produces terminal
reopen refusal; an identical pair consumes the process's authority without
changing its journals and strictly reopens healthy. A real connected peer
paused with SIGSTOP holds a publication with a released proposal token in
flight: all positive commands remain busy, malformed pair rejection preserves
custody, and a valid pair durably halts while reporting that surviving custody
for disposal. These are bounded local Unix process observations, not general
multi-node liveness, production timing, or deployment evidence.
