# Canonical state devnet qualification

For trusted hosts on separate machines, use the [pilot runbook](../docs/mvp/pilot.md).
The local devnet and portable-bundle rehearsal remain single-machine evidence.

This harness starts four trusted operators in four stable slots, with fresh keys
at each sealed record, separate histories, signer and handoff journals, period
custody, independent anchor directories, and authenticated TCP sessions.
The operator uses `naome`, validators use `naome-validator start`, and exported
history is independently replayed by `naome-verifier verify`. No artifact-chain
publisher or alternate history authority is involved.

The default workload finalizes at least 100 complete state records. Two distinct
registered owners alternate authenticated question submissions. Each attempt must
open its full voting window and close as `NotApproved` only after the certified
deadline. The default `short-test` profile has a 15-second voting window;
`--timing ci-test` explicitly selects a 1-second window for the Docker CI run.
The qualifier sends no consensus commands. This is
accelerated state/transport qualification. Proof publication, helper retrieval,
citation payment, commitment/reveal and settlement remain mandatory in the
separate Rust four-process suite and real-window lab; the 100-record run does not
claim 100 proof publications.

## Build and run

Use the toolchain in `rust-toolchain.toml`. Compile all three process packages in
the same profile before executing tests. Linux can package these exact binaries:

```sh
CARGO_INCREMENTAL=0 cargo test -p naome-cli -p naome-validator -p naome-verifier --profile release --all-targets --all-features --locked --no-run
CARGO_INCREMENTAL=0 cargo test -p naome-cli -p naome-validator -p naome-verifier --profile release --all-targets --all-features --locked --no-fail-fast four_process_state_recovery_partition_and_independent_replay
python3 -B -m unittest discover -s devnet -p 'test_*.py'
python3 -B devnet/image.py --bin-dir target/release --tag naome-devnet:local
python3 -B devnet/qualify.py --backend docker --image naome-devnet:local --bin-dir target/release --directory /tmp/naome-devnet-run-1 --heights 100 --timing ci-test --delay-ms 50 --deadline-seconds 2400
```

The output directory must be new and should remain outside the repository.
`--heights` accepts 4–128; fault qualification requires at least 12. The target is
a minimum: a complete attempt can finish up to two records beyond it. Genesis
allows 256 records so the maximum requested height leaves the ledger's protected
attempt capacity intact. The `ci-test` profile is committed in fresh genesis;
existing profiles and all non-voting bounds are unchanged. A failed run is
retained for inspection and is never repaired or reset.

For native smoke testing on Unix without Docker:

```sh
python3 -B devnet/qualify.py --backend process --bin-dir target/release --directory /tmp/naome-devnet-process-1 --heights 12 --delay-ms 50
```

The native path uses the same workload and delay proxy. It disables authenticated
links through explicit simulation controls while leaving the isolated process
running. It does not establish container isolation or multi-machine operation.
Docker is qualified on Linux, where native binary hashes must match the pinned
image's three runtime binary hashes. A source image can also be built with
`docker build -f devnet/Dockerfile -t naome-devnet:local .`; cross-host Docker
Desktop operation is not established by the Linux CI result.

## Isolation, faults, and evidence

Each Docker container receives only its own node directory, a separate anchor
parent, and the read-only public genesis. It has no other validator's keys or
journals, no host port publication, a read-only root filesystem, no Linux
capabilities or additional privileges, and an internal bridge. Limits are 512 MiB
memory with no additional swap, two CPUs and 128 processes. The qualifier samples
per-role disk use against 512 MiB and records peak process/container memory. Native
memory samples are observations; Docker supplies memory enforcement.

A bounded proxy delays each TCP chunk by 50 ms in each direction by default.
It overlaps one prefetched chunk with the current chunk's wait. Each write is
gated by its own completed-read timestamp plus the full configured delay, with
FIFO order and drain backpressure. Application custody is bounded to two 32 KiB
chunks per direction; the existing connection and transport-buffer bounds remain.
Genesis binds the initial advertised endpoints; each sealed handoff binds the
next endpoints and identities. Two delay proxies per operator cover both sides
of every rotation. Local bind overrides direct those authenticated identities
through the proxies; they change no consensus or ledger rule. The fault schedule includes malformed operation intake, one validator's
30-second network isolation, SIGKILL and strict reopen, and graceful restart.
Healing occurs at a fixed deadline even if finality has stopped. The run fails
unless the isolated validator stays at its old head and the surviving quorum
finalizes fresh work before healing. The returning validator must catch up.

Every validator export must independently replay to the same height, record head,
full state commitment and consensus commitment. The record head binds the full
ancestry. Different valid finality certificates may contain different sufficient
signer subsets; their raw bytes need not match across validators. Each validator's
selected evidence must remain byte-identical across its own restart. Public
reports retain per-validator finality-frame hashes. Corrupted exported evidence
must be rejected by the actual verifier without modifying the input.

The report records exact binary and harness hashes, source commit, whether the
working tree was clean, genesis capacity, certified window times, fault results,
replay results and resource observations. `outcome: passed` and a zero process exit
are both required. Process logs, keys, signed actions and journals remain private.
Only `report.json` is intended for publication. Containers, their internal network,
probe containers and native process groups are owned by the run and cleaned up on
success, failure and handled interruption. Cleanup failures fail qualification.

Docker observations reuse one bounded read-only probe per container. Each sample
requests fresh status from the actual local control socket and reads current
cgroup memory; it does not cache progress. Probe failures, oversized responses,
restarts and cleanup close the owned pipe. Authenticated submissions, exports
and independent verification continue through the normal executables.

Voting observation starts immediately after authenticated submission. The harness
retains each participating node's actual finalized Voting state for the exact
submission and requires the same attempt and certified deadline before accepting
settlement. The opening time is derived from that deadline and the voting
duration read from genesis; observed heights and times are retained separately.
Nodes need not appear in Voting in the same polling pass.
Every node must still be observed, and timeout reports retain the current attempt
and bounded public node states for diagnosis.

The timed partition starts only after all four nodes agree on a selected state
with four available signers. If a rotation temporarily leaves a slot vacant,
the harness continues genuine workload within the normal height deadline until
that owner returns. Those extra heights and their elapsed time count toward the
qualification. Failure to restore four slots, or failure to progress with the
surviving three during the fixed partition, fails the run. SIGKILL and graceful
restart follow on separate completed attempts, each targeting a currently active signer.

## CI timing baseline

The exact-main [CI run 35863331752](https://github.com/naome-core/naome/actions/runs/35863331752)
at commit `132fccc2dadae5514f89a7d1aaae8154208a4d8e` finalized 102 heights in
34 attempts with the Docker backend and 50 ms delay. Its retained devnet report
recorded 1,103.819 seconds for the qualification step. Its 34 complete voting
windows required 510 certified seconds; opening through settlement spanned
592 certified seconds, including deadline overshoot. The same Ubuntu 24.04 qualification step must finish
within 551.909 seconds to establish a 2x speedup. Compare the generated report's
elapsed time, height, faults, replay results, and binary/harness hashes before
claiming the faster run preserves coverage.
The original [public baseline report](../docs/mvp/evidence/handoff-baseline-ci.json)
retains those checks and source identities.
The baseline GitHub job timestamps separately record 47 seconds for the release
build barrier, 87 seconds for the native publication/recovery scenario,
34 seconds for the portable rehearsal, and 17 seconds for image packaging.
Those steps are outside the 1,103.819-second Docker execution measurement;
the speedup claim concerns the complete Docker qualification, not compilation.
CI compares the complete elapsed times after qualification cleanup and fails
unless the ratio is at least two. Its uploaded report includes that comparison,
startup and observation time, per-attempt receipt/opening/settlement phases,
fault recovery, and each independent export and replay. Observation and certified
voting-window counters overlap the attempt phases; they must not be added to
those phases as separate elapsed time. Build time remains separate in the
preceding release compilation step.

The first sealed-handoff [measurement](../docs/mvp/evidence/handoff-initial-ci.json)
on `40546f7`, in [CI run 35893100165](https://github.com/naome-core/naome/actions/runs/35893100165),
passed all 102-height Docker correctness checks in 661.884 seconds (1.668x).
It failed the required 2x gate. Receipt, voting-open and settlement phases
accounted for 618.675 seconds; the nested observation counter was 152.253 seconds.
The following optimization removes redundant same-parent finality and healthy
history requests only after an authenticated peer accepts an exact-parent offer,
and reuses status probes. Unconfirmed peers and stalled heights retain repair.
The full CI speed gate remains mandatory.

The [observation and repair measurement](../docs/mvp/evidence/handoff-observation-ci.json)
on `e4ce11a`, in [CI run 35897139541](https://github.com/naome-core/naome/actions/runs/35897139541),
passed the same Docker checks in 614.499 seconds (1.796x), still below the required
speedup. It used the identical Ubuntu 24.04 runner image `20260907.300.1` as the
baseline. Observation fell to 64.937 seconds; receipt, opening and settlement
still accounted for 565.664 seconds. The next latency change overlaps at most
two ordinary consensus messages per configured peer within the existing global
request and byte caps. Outbound handoff, history, proof and user-action requests
remain serial per peer. Configured peers allow four combined protocol streams
for two sends and two receives; recovery retains its two-stream limit. Request
and response decoding each retain at most two events within the same global
frame and byte budgets. Observation polls every 0.2 seconds, recorded in the report, to reduce
delay between confirmed workload stages without shortening certified windows.

The [bounded-concurrency measurement](../docs/mvp/evidence/handoff-concurrency-ci.json)
on `f18fd2f`, in [CI run 35902219562](https://github.com/naome-core/naome/actions/runs/35902219562),
completed the Docker correctness checks in 598.632 seconds (1.844x), still below
the required speedup. Its Ubuntu 24.04 runner image was `20260920.314.1`, while
the baseline used `20260907.300.1`; the runner class and container CPU/memory
limits were unchanged. Receipt, opening and settlement totaled 543.334 seconds;
the overlapping observation counter was 128.411 seconds. The proxy now overlaps
bounded read ahead while preserving every chunk's full configured latency in
both directions. Its minimum-delay, FIFO, backpressure, EOF and cancellation
properties have direct tests. Final acceptance still requires the complete
Docker fault run and its 2x gate.

## Authority setup and supervision

Canonical setup creates fresh genesis and refuses existing output, invalid or
duplicate endpoints, symlinked endpoint files, and invalid profile limits. Keys
remain private. Setup initializes all four histories and signing stores at
genesis before publishing configuration; validator startup only reopens them.
Missing authority is a failure, never an initialization request.

The qualifier moves each fresh external-anchor directory intact to its separate
per-validator mount and syncs both parent directories. Supervision uses the
node's bounded local status interface, checks process liveness, rejects state
regression/conflict, and applies fixed deadlines.

Python tests cover concurrent probes, failed-role propagation, symlink-safe
durable reports, timer healing, memory/disk limits, exact delayed TCP transfer,
listener release, private mounts and process/probe cleanup. Malformed intake
must leave authority unchanged before valid work progresses. Protocol/runtime
suites separately cover authenticated framing and operation rejection.
