# Operating the trusted research MVP

These commands operate a separate four-validator research genesis on Unix. The
current qualification target is four independent local processes with separate
keys, journals, anchors, and authenticated network connections. The [completed lab report](evidence/lab-acceptance.json) records actual
300/120/120-second windows, a real agent review, and four local processes.
Accelerated tests and fake-provider adapter tests remain supplementary evidence.
This qualification does not establish multi-machine operation or public-network
security. Track acceptance separately
in [requirements.md](requirements.md).

## Build and choose an immutable run

Use the Rust toolchain selected by `rust-toolchain.toml`:

```sh
cargo build -p naome-research-cli --bin naome-research --profile release --locked
BIN="$PWD/target/release/naome-research"
RUN=/tmp/naome-lab-001
"$BIN" setup "$RUN" lab 256 44100 compact
```

Run this from the repository root. `RUN` must name a new directory; setup never
overwrites an existing run. A short absolute path also leaves room for Unix
control-socket path limits. The four ports beginning at `44100` must be available.

Setup accepts `lab`, `research`, or `short-test`. `lab` uses 300-second voting,
120-second commitment, 120-second reveal, and 1,800-second queue windows.
`research` uses seven days of voting, one day for commitments, one day for
reveals, and a 30-day queue lifetime. That long-running profile is a separate
later qualification; the initial MVP acceptance uses `lab`. `short-test` uses
15/8/8/120 seconds and must be labeled accelerated testing. `compact` changes
resource limits before genesis, while preserving the selected timing windows and reward rules:

| Bound | Default, 8,192 records | Compact, 256 records |
|---|---:|---:|
| Complete record | 1 MiB | 128 KiB |
| Original/final package | 256 KiB each | 64 KiB each |
| Transport frame | 1,088 KiB | 192 KiB |
| Maximum consensus round index | 64, allowing 65 rounds | 8, allowing 9 rounds |
| Conservative storage floor per node | 3,453,995,466,906 bytes | 2,441,919,130 bytes |

The compact example requires 9,767,676,520 free bytes across its four node
reservations, approximately 9.10 GiB. The calculation includes worst-case
signing history, archives, staged reveals, metadata, and a safety margin; it is
not a measured storage-consumption or throughput claim. Different record counts
produce a different calculation. Setup prints the actual genesis/profile IDs
and required bytes and rejects insufficient space. Nodes also halt visibly if
free space later falls below their profile floor.

Setup creates six account keys, four consensus keys, four separate transport
keys, public `genesis.bin`, and `node-0` through `node-3` configurations. Accounts
0–3 are the fixed validator owners; accounts 4–5 are available for independent
research authors. Private files use owner-only permissions. Keep the entire run
directory, including retained commitment secrets, private and backed up.

Consensus retries also have a finite per-height round and journal budget. A
partition without a quorum cannot consume rounds merely through elapsed time.
Consensus phase timeouts double with each round, up to sixteen times their base
duration, to allow slower authenticated delivery and durable signing to finish.
This does not extend the voting, commitment, or reveal windows. The multiplier
comes from the durable round; duplicate messages do not reset the phase timer.
Repeated quorum-backed failed rounds can exhaust that budget, however, causing a
visible local halt. Restart does not reset the genesis-bound budget. This does
not expire or pay a protected attempt, and confirmed history remains intact, but
these bounded qualification runs do not establish recovery from every possible
sequence of delays or exhausted retry budgets. Preserve the failed run and its
anchors for diagnosis; never discard signing history to obtain fresh signatures.

Inspect every committed bound and preview exact question identity before use:

```sh
"$BIN" profile-info "$RUN/genesis.bin"
"$BIN" compile-question "$RUN/genesis.bin" examples/research-mvp/question-a.nao
```

The question preview shows its normalized statement, negation parity, and shared
resolution family. The submit command also displays its compiled preview.

## Start, inspect, and restart

```sh
C0="$RUN/node-0/node.json"
C1="$RUN/node-1/node.json"
C2="$RUN/node-2/node.json"
C3="$RUN/node-3/node.json"
"$BIN" start "$C0" >"$RUN/node-0.log" 2>&1 &
"$BIN" start "$C1" >"$RUN/node-1.log" 2>&1 &
"$BIN" start "$C2" >"$RUN/node-2.log" 2>&1 &
"$BIN" start "$C3" >"$RUN/node-3.log" 2>&1 &
"$BIN" status "$C0"
```

Status reports finalized height, head/state/library commitments, certified time,
active phase and deadline, account balances/nonces, claims, and remaining/reserved
record capacity. Pending operations are local intake, not finality. A submission
response of `transported` does not promise eventual admission. Query its operation
ID using `receipt`; responses distinguish `finalized`, `not_finalized`, and
`rejected` with a reason. Identical saved actions can be resent with `send`.

```sh
"$BIN" receipt "$C0" "$OPERATION_ID"
"$BIN" send "$C0" "$RUN/saved-action.bin"
"$BIN" shutdown "$C0"
"$BIN" start "$C0" >>"$RUN/node-0.log" 2>&1 &
```

Restart with the same configuration, keys, history, and independent anchors.
Incomplete final writes are recovered only when the complete prefix matches its
anchor. Complete corruption, missing/mismatched anchors, conflicting verified
finality, or uncertain live writes halt the affected path. Do not delete anchors
or regenerate keys to clear an error. Preserve the failed run for diagnosis;
`setup` at a different unused directory creates a new run with a new identity.

## Local research preferences and agent votes

Each node has its own editable agenda text. This changes operator preferences,
not the genesis profile, protocol parameters, mathematical checker, or voting
weight:

```sh
"$BIN" profile "$C0" /absolute/path/research-preferences.txt
```

An explicitly configured provider executable can supply an agenda decision:

```sh
"$BIN" agent-vote "$C0" "$RUN/accounts/account-0.key" \
  "$RUN/a-agent-vote-0.bin" "$RUN/a-agent-report-0.json" \
  "$PWD/tools/research_agent_codex.py"
```

The executable receives one JSON request on stdin containing `version`, `profile`,
`question`, `purpose`, `question_id`, `attempt`, `genesis`, `author`, and
`agent_budget` (the inference index, maximum attempts, and remaining tool calls).
It must return one JSON object
on stdout with exactly `decision` (`YES` or `NO`), nonempty `reason`, nonempty
`provider`, and integer `tool_calls`. The adapter allows at most two inference
attempts per node/question/attempt, 60 seconds per inference, 8,192 output bytes,
a 4,096-byte reason, a 128-byte provider label, and four reported tool calls
across those attempts. Exclusive durable reservations survive CLI restarts; a
crashed or malformed call consumes its reservation and the remaining tool budget.
Changing the local profile cannot reset a reservation for the same question
attempt. Accepted decisions and exact signed votes are retained for retries,
which do not invoke the provider again. Configure the actual provider to enforce its tool-use limit as well. Provider processes and remaining
descendants are terminated when an invocation finishes or times out. Malformed,
failed, excessive, or late decisions create no vote. The CLI rechecks the active
question/phase and local voting deadline before signing.

The supplied [Codex bridge](../../tools/research_agent_codex.py) requires an
independently logged-in `codex` command on PATH. It uses a strict structured
decision, an empty temporary working directory, no enabled tools, bounded event
output, and a 55-second inner timeout. It receives the public question and
operator profile, never account keys or commitment secrets. Its reported tool
count is zero, even when the outer allowance is positive. A missing login or
provider failure produces no vote. Operators can instead supply another
executable that implements the exact bounded contract.

The executable is an operator-selected integration, not an automatically selected
AI service. A provider label or JSON report is not proof that an AI service ran.
The test suite's fake executables qualify parsing, deadlines, retries, and process
cleanup only. Real-agent qualification must retain the actual provider invocation
and its report. These votes express agenda preferences; mathematical validity is
determined separately by the deterministic checker.

## Submit, approve, commit, and reveal A

The checked examples are described in
[the fixture notes](../../examples/research-mvp/fixtures.md). A publishes its root
and helper H together under account 4. Use a fresh output path for each distinct
action:

```sh
"$BIN" submit "$C0" "$RUN/accounts/account-4.key" \
  examples/research-mvp/question-a.nao 'Develop a reusable reflexivity helper' \
  "$RUN/a-submit.bin"
"$BIN" status "$C0"
```

Save the returned operation ID as `A_SUBMISSION`. Once the finalized phase is
`Voting`, three or four distinct validator owners may vote. These explicit votes
are a manual alternative to agent votes; an owner may vote only once per attempt.

```sh
"$BIN" vote "$C0" "$RUN/accounts/account-0.key" YES "$RUN/a-vote-0.bin"
"$BIN" vote "$C1" "$RUN/accounts/account-1.key" YES "$RUN/a-vote-1.bin"
"$BIN" vote "$C2" "$RUN/accounts/account-2.key" YES "$RUN/a-vote-2.bin"
"$BIN" question "$C0" "$A_SUBMISSION"
```

An early three-YES quorum does not shorten the voting window. Wait for a finalized
`Commit` phase, then use the unchanged original package:

```sh
"$BIN" package "$RUN/genesis.bin" "$RUN/accounts/account-4.key" \
  "$RUN/a.package" examples/research-mvp/solution-a.nao \
  --helper examples/research-mvp/helper-h.nao
"$BIN" commit "$C0" "$RUN/accounts/account-4.key" \
  "$RUN/a.package" "$RUN/a.secret" "$RUN/a-commit.bin"
```

The commit command durably stores the random secret, signed original, and exact
commit action before submitting. Keep `a.secret`: restarting `commit` with the
same package/secret paths resends that original commitment. Do not replace the
secret or original bytes. Wait for a finalized `Reveal` phase and reveal before
its deadline:

```sh
"$BIN" reveal "$C0" "$RUN/accounts/account-4.key" \
  "$RUN/a.secret" "$RUN/a-reveal.bin"
"$BIN" status "$C0"
"$BIN" question "$C0" "$A_SUBMISSION"
```

Receipt queries establish final admission. A locally sent reveal is not timely
merely because it reached a process before the deadline. `SettlementPending`
retains the active slot until the next finalized settlement; a finalized timely
reveal does not expire while settlement waits for quorum.

## Reuse H, normalize B, and recognize C

After A completes, H's fixed fixture ProofId is
`c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73`.
Stop node 0 to exercise retrieval from another provider. From node 1's
`status.validators`, set `PROVIDER_INDEX` to the genesis-sorted index whose
endpoint is node 2 (`127.0.0.1:44102` in this example):

```sh
"$BIN" shutdown "$C0"
H=c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73
"$BIN" status "$C1"
"$BIN" fetch-proof-from "$C1" "$PROVIDER_INDEX" "$H" "$RUN/h.proof"
"$BIN" check-proof "$RUN/genesis.bin" "$RUN/h.proof"
```

Submit `question-b.nao` using account 5 and node 1. Repeat the phase workflow with
fresh `b-*` action/secret paths and votes from the three live owners 1, 2, and 3.
To demonstrate duplicate-helper substitution, construct its original package as:

```sh
"$BIN" package "$RUN/genesis.bin" "$RUN/accounts/account-5.key" \
  "$RUN/b.package" examples/research-mvp/solution-b-original.nao \
  --helper examples/research-mvp/helper-h-duplicate.nao
```

The original duplicate helper remains subject to full checking. Settlement reuses
the earlier H, preserves H's original recipient, recomputes B's normalized proof
and citation payment, and reports `REFUTED` for B's submitted negative formula.
An alternative package using the already selected H directly uses
`solution-b.nao --reference "$RUN/h.proof"`.

After B settles, submit `question-c.nao`. Its target is exactly the selected H;
opening records `KnownUnpaid`, with no new completion payment or eligibility
claim. Query all three submitted questions and compare balances, claims, and
`paid_completions`. Manual execution of these commands is a procedure, not by
itself a recorded acceptance result.

## Independent verification and inspection

```sh
"$BIN" export "$C1" "$RUN/export-after-b"
"$BIN" verify "$RUN/genesis.bin" "$RUN/export-after-b"
"$BIN" inspect "$RUN/genesis.bin" "$RUN/export-after-b" \
  "$B_SUBMISSION" "$RUN/inspect-b"
```

Export verifies each selected finality while writing a new directory. Verification
requires no signing key and replays the complete history, mathematical checks,
balances, phases, claims, and resource budgets against the manifest. Inspection
also exposes formal targets, outcome, winning commitment coordinate, original
hash, substitutions, normalized root, citation payments, and eligibility claim.
For a completed question it writes the signed original, original and normalized
packages, canonical normalization receipt, and a JSON report. Full history
archives include finalized reveal material and are kept private.

`fetch-proof` saves a locally selected canonical certificate.
`fetch-proof-from` obtains and validates the requested certificate through the
named validator's authenticated network connection. To check a root that needs
older proofs offline, use `check-proof GENESIS ROOT_PROOF DEPENDENCY_PROOF...`,
listing dependencies before their dependents. Mathematical checking alone does
not establish authorship, payment, or finality; archive replay supplies those
additional checks.

## Simulation controls and qualification

`peer CONFIG VALIDATOR_INDEX on|off` changes one local simulated peer link. The
index is the **genesis-sorted index printed by `status.validators`**, not necessarily
the `node-N` directory number; match its endpoint before changing a link. A 2:2
partition requires disabling every cross-group link in both groups. Restore those
same links with `on`. Two validators must never finalize; no command reduces the
four-owner denominator. Shutdown/restart uses the existing durable state.

The process test is
`crates/naome-research-cli/tests/research_process.rs`. Its accelerated execution,
the normal lab-window run, real-provider agent evidence, full two-profile workspace
checks, and cross-platform CI are separate qualification states. Record the exact
genesis/profile, commit, executed commands, timing, outcomes, and retained reports
for each. No acceptance checkbox is completed by this operating guide.


## Reproduce the lab acceptance run

Build once, copy the executable outside Cargo's output directory, and run the
acceptance harness against that preserved executable. Concurrent later builds
must not replace this copy. The runner uses a new private directory and its own
available ports; it does not reuse the manual example above.

```sh
cargo build -p naome-research-cli --bin naome-research --profile release --locked
umask 077
QUALIFICATION=$(mktemp -d /tmp/naome-qualification.XXXXXX)
cp target/release/naome-research "$QUALIFICATION/naome-research"
chmod 500 "$QUALIFICATION/naome-research"
python3 tools/research_lab_acceptance.py \
  --binary "$QUALIFICATION/naome-research" \
  --provider "$PWD/tools/research_agent_codex.py" \
  >"$QUALIFICATION/progress.jsonl" 2>&1
```

This takes approximately three nine-minute research attempts, plus startup,
network recovery, checking and export. It uses actual 300/120/120-second lab
windows and a real agent invocation. The actual agent's YES or NO is retained;
separately signed manual YES votes from the other three owners exercise approval.
A successful inference is an agenda judgment, not mathematical evidence.

The runner records the executable hash, source manifest hash, Git head, provider
and runner hashes, immutable genesis/profile, commands, timings, outcomes and
resource observations. Follow `progress.jsonl` for the private run directory and
final report path. The process exit code and the report's `result` must both
indicate success before using the run as acceptance evidence. Source files may
include uncommitted changes; use the manifest as well as the Git head when
identifying the tested source. Keep the executable copy and manifest with the
run's local evidence.

Only `acceptance-report.json` is designated for publication. It intentionally
includes the fixture operator-profile text and the agent decision, reason,
provider label and request hash, alongside public protocol identifiers and
outcomes. The same agent review is also retained as a local report. Private
keys, commitment secrets, original reveals, node logs, exported histories and
source manifests stay in the private run directory. Any retained raw
provider/command diagnostics are also private. Do not publish that directory or
the progress log wholesale. The report records
local four-process evidence; it does not establish operation on two physical
machines or completion of the seven-day research profile.

The [recorded lab run](evidence/lab-acceptance.json) completed successfully.
Each new run supplies acceptance evidence only after it finishes successfully.
The [verification map](verification.md) separates component tests, process tests,
lab evidence, and repository/CI gates. A successful lab run does not replace the
complete pinned test/release workspace checks or required platform CI.
