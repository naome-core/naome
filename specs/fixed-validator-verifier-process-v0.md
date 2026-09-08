# Fixed-Validator Verifier Process V0

## Authority and scope

`SEC-003-001` defines the local Unix `naome-verifier` executable. It owns one
`FixedValidatorAnchoredFinalityJournalV0` and accepts complete caller-supplied
fixed-validator artifact-only V0 finality envelopes and artifact payloads.
It verifies every imported proof independently, retains successful finality,
and strictly reconstructs that history on restart. Its offline configuration
loads no private key or network transport. Every configuration creates no vote
journal and constructs no consensus signer, validator driver, or consensus
runtime. The optional `SEC-003-002`/`SEC-003-004`
[archive profile](fixed-validator-archive-v0.md) adds a separate Noise identity,
explicit bounded complete-proof synchronization, caller-configured continuous
following, and healthy-history serving.

The caller selects the exact chain definition, consensus context, fixed public
keys and agreement weights, finality directories, and local replay-round
ceiling. These are configuration authority. Verification does not establish
that this configuration is globally canonical. The executable composes the
existing [bounded envelope verifier](fixed-validator-artifact-consensus-envelope-v0.md),
[finality journal](fixed-validator-finality-journal-v0.md), and
[independent anchor](fixed-validator-external-anchor-v0.md) contracts; it adds
no quorum, signature, consensus-value, journal, or anchor encoding.

Without a `network` table this is the approved offline complete-proof consumer
profile. That configuration grants no
signing, automatic proof acquisition or assembly, peer trust, network
participation, history serving, checkpoint selection, dynamic validator,
economics, or automatic recovery authority. `SEC-003` remains `IN_PROGRESS`:
this bounded profile does not satisfy the broader full-node requirements in
`SYNC-001`, `SYNC-002`, and `SYNC-004`.

## Invocation and public configuration

The program takes exactly one configuration-file argument:

```text
naome-verifier /absolute/path/verifier.toml
```

The offline configuration is UTF-8 TOML with exactly these fields. Example identity
strings below are placeholders to be replaced with the caller's public values;
the executable chooses no deployment, validator set, or weight defaults.

```toml
version = 0
mode = "create"
deployment_discriminator = "<64 lowercase hexadecimal characters>"
genesis_id = "<64 lowercase hexadecimal characters>"
protocol_version = 7
finality_max_round = "8"

[[validators]]
consensus_key = "<64 lowercase hexadecimal characters>"
weight = "1"

[directories]
finality_journal = "finality-journal"
finality_anchor = "finality-anchor"
```

`version` must be zero. `mode` is explicitly `create` or `open` and has no
fallback. `protocol_version` is a TOML unsigned value fitting `u32`.
`weight` and `finality_max_round` are canonical unsigned decimal strings,
without signs, whitespace, or leading zeroes except the single string `0`.
Weights must fit `u128`; the positive replay-round ceiling must fit `u64`.
All 32-byte public identities use exactly 64 lowercase hexadecimal characters.
Unknown fields, including consensus-private-key or vote-journal fields, are
rejected. The archive profile specifies the sole optional `network` table;
omitting it preserves offline behavior.

Before opening any authority file, configuration reconstructs the exact
virtual-genesis branch and preflights round zero. This rejects an empty set as
well as the existing duplicate-key, zero-weight, overflow,
and active-set-size conditions. It validates the positive replay ceiling and
requires both caller-selected directories to exist. It does not create
directories or infer configuration from retained history.

Relative directory and command source paths resolve against the configuration
file's parent directory; absolute paths remain explicit absolute paths. The
configuration and proof inputs must be regular files. They are opened with
final-component no-follow and nonblocking flags before inspecting the same
descriptor, so a symlink is refused and a FIFO cannot block the regular-file
check. Parent-directory routing follows the caller's filesystem choices.
The program reads source bytes without modifying or locking those sources;
full verification applies to the exact bytes it obtained.

The configuration is bounded to 65,536 bytes. Envelope reads are bounded by
`VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH`, and an envelope below
its `MIN_BYTE_LENGTH` is refused. Payload reads are bounded by
`ARTIFACT_PAYLOAD_MAX_BYTES`. Each read probes at most one byte beyond its
limit to reject excess input.

## Creation and strict restart

`create` uses the existing create-new finality journal and independent anchor
sequence. Only completion returns a ready owner. Creation is not an atomic
transaction across those files: a later failure retains earlier durable work,
returns no ready owner, and neither deletes nor rolls it back.

`open` uses the exact configured public inputs and the independently stored
anchor. It rejects missing, locked, corrupt, foreign, behind, ahead, divergent,
or mismatched complete journal/anchor state. It never falls back to creation,
promotes a temporary anchor, or reconciles a complete unanchored suffix. The
journal's separately specified incomplete-final-frame recovery remains
available only under its exact matching anchored prefix; this process adds no
recovery rule. All retained complete envelopes and payloads are strictly
replayed through the existing verifier; their original source files are not
needed on restart.

The journal and anchor locks remain exclusive for the entire owner lifetime.
An independently running verifier needs its own caller-provisioned pair; it
cannot concurrently open the authority files held by a validator process.
The existing file protocol does not detect coordinated rollback of both files,
provide hardware monotonicity, or promise whole-record power-loss atomicity.

A strictly opened journal may already contain a terminal finality conflict.
The process then emits `halted` with the exact terminal diagnostic state and a
null head, followed by a failed `stopped` report after releasing ownership. It
never emits `ready`, exposes retained records as operable history, or accepts
another import from that halted owner.

## Commands and complete proof admission

Stdin accepts newline-terminated JSON objects of at most 65,536 bytes excluding
the newline. Unknown, duplicate, missing, or incorrectly typed fields and
non-object or trailing JSON values are rejected. `id` is a required JSON
unsigned integer fitting `u64`; it correlates a response and is not a durable
deduplication token. Reusing an ID does not suppress a command.

```json
{"command":"import","id":1,"envelope_file":"h1.envelope","payload_file":"h1.payload"}
{"command":"status","id":2}
{"command":"record","id":3,"height":1}
{"command":"shutdown","id":4}
```

Each `import` follows one path for new, duplicate, and historical proofs:

1. Read the complete bounded envelope and enforce its minimum width.
2. Decode only its `ConsensusValueV0` prefix for unauthenticated context and
   positive-height routing. Reject a foreign context or unavailable selected
   parent before payload work. The prefix establishes no validity or finality.
3. Read the complete bounded payload and invoke that exact retained parent's
   `decode_and_verify_envelope_with_round_limit` with the configured ceiling.
   The verifier derives the embedded round, scheduled proposer, fixed weighted
   snapshot, ancestry, artifact predecessor, and complete successor state. It
   verifies producer authorization, strict-greater-than-two-thirds non-nil
   precommit evidence, and the canonical mathematical artifact payload.
4. Pass only the returned owned sealed transition to `commit_verified`.
   A new selected direct child becomes durable before a `finalized` outcome.
   A fully verified same-value proof returns `already_finalized` without a
   write or replacement of the first retained evidence variant. A distinct
   verified sibling at any selected height durably anchors `halted` and ends
   process ownership. A missing parent is never fetched or invented.

An imported duplicate still runs complete verification, including signatures,
quorum, payload, and round bounds. The importer does not accept a corrupted
proof merely because its unauthenticated value was selected earlier. Local
round limits constrain work and persisted history; exceeding one does not
assert that the proof is invalid under the general protocol.

`status` returns the exact current chain/context, immutable fixed-set identity,
persisted round ceiling, journal-state identity, and healthy head height,
ancestry, artifact-block identity, and artifact-set root. Height zero denotes
virtual genesis. `record` requires a positive JSON `u64` height and returns
metadata for that exact retained selected record: height, first evidence
round, ancestry, envelope identity, artifact-block identity, record-state
identity, and retained envelope/payload byte lengths. Zero or an unavailable
height is rejected. This bounded metadata command does not export or serve
proof bytes. Reported heights and rounds use decimal strings.

## Failure and process lifetime

Configuration failures emit an `error` code and fail the process. A malformed
complete JSON frame emits `command_rejected` with null `id`; typed command,
source-file, routing, or complete-proof verification failures emit
`command_rejected` with the submitted ID. These pre-commit refusals do not
change authority files and leave a healthy owner available for another command.

Once commit is invoked, any error is fatal: `command_failed` reports
`strict_restart_required: true`, and the owner is dropped. It does not report
success, continue from a poisoned handle, or claim that the prior file images
are unchanged. For example, an anchor temporary-file collision can leave a
durable journal suffix with the prior anchor; strict reopen then refuses that
gap. Unexpected state-read errors also end ownership. Error codes do not
include configuration contents, proof bytes, parser details, or source paths.

Every successful import report follows successful anchored publication. Lost
stdout does not undo a completed commit. A later explicit strict reopen and
fully verified duplicate import can establish the retained outcome; command
IDs and missing acknowledgements do not authorize an automatic retry.

`shutdown`, complete-frame EOF, SIGINT, and SIGTERM end orderly ownership.
Truncated final input, an oversized line, input failure, a durable conflict,
or a commit failure ends with a failed status. Signals are handled between
synchronous operations; there is no wall-clock cancellation of a filesystem
operation, proof verification, or full-history replay.

A dedicated input thread owns no journal and sends through a one-frame channel;
it can hold one additional frame being read or waiting to send. Only the owner
task executes complete commands. A partial frame cannot prevent that task
from handling termination. Commands not executed before shutdown or a terminal
event are discarded without effect.

Output uses an authority-free writer, at most 32 queued frames, and a
16,384-byte per-frame limit excluding the newline. A full or disconnected
output queue ends ownership. A write or flush failure independently wakes the
owner through a single stored notification, including while stdin is open and
idle. The process reports `locks_released: true` only
after the journal owner has actually dropped, then allows one final flush of
at most two seconds. It never joins an indefinitely blocked input/output
thread or repeats a failed flush. These queue and frame limits are process
policy. Total replay time and retained-history memory still grow with history.

## Verification evidence and limits

The offline Unix process tests in `crates/naome-verifier/tests/process.rs` cover
keyless two-height imports, first-evidence retention under valid certificate
and round variants, exact strict reopen without source files, and a process
kill after acknowledged durable finality. Test keys remain outside the target
process; target layouts contain only public configuration, supplied proof
files, and the two finality directories. Independent post-exit storage opens
compare exact retained envelope and payload bytes, not just process reports.
An additional post-restart import depends on a proof reconstructed from the
selected history after its original source files have been removed.

Adversarial cases cover an exact-two-thirds weighted certificate, wrong role,
proposer and signer, invalid signatures, foreign context, false ancestry or
state commitment, wrong payload, missing parent, excessive round, corrupted
historical duplicates, strict input/schema/file bounds, and retry after refusal.
One canonically encoded but mathematically invalid inference carries otherwise
valid consensus signatures and must still fail artifact checking before any
authority write.
Historical sibling evidence after a later selected height must preserve the
selected journal prefix, append the exact halt, drop ownership, and reopen
without a head. Real anchor-install failure and behind/ahead/divergent reopen
cases must fail without repair. Partial-input signals, truncated input, and
stalled or closed stdout must release ownership and preserve prior finality,
including closed stdout with idle open stdin and no subsequent command.

This evidence is finite local process and restart coverage. It does not prove
general consensus safety or liveness, every crash/syscall outcome, power-loss
durability, live network following, full-node conformance, or deployment.
