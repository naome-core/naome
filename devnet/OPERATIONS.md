# Canonical state devnet qualification

For trusted hosts on separate machines, use the [pilot runbook](../docs/mvp/pilot.md).
The local devnet and portable-bundle rehearsal remain single-machine evidence.

This harness starts four trusted fixed validators with separate keys, histories,
signer journals, independent anchor directories, and authenticated TCP sessions.
The operator uses `naome`, validators use `naome-validator start`, and exported
history is independently replayed by `naome-verifier verify`. No artifact-chain
publisher or alternate history authority is involved.

The default workload finalizes at least 100 complete state records. Two distinct
registered owners alternate authenticated question submissions. Each attempt must
open its full 15-second short-test voting window and close as `NotApproved` only
after the certified deadline. The qualifier sends no consensus commands. This is
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
python3 -B devnet/qualify.py --backend docker --image naome-devnet:local --bin-dir target/release --directory /tmp/naome-devnet-run-1 --heights 100 --delay-ms 50 --deadline-seconds 2400
```

The output directory must be new and should remain outside the repository.
`--heights` accepts 4–128; fault qualification requires at least 12. The target is
a minimum: a complete attempt can finish up to two records beyond it. Genesis
allows 256 records so the maximum requested height leaves the ledger's protected
attempt capacity intact. All other limits and short-test timing rules are
unchanged. A failed run is retained for inspection and is never repaired or reset.

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
Genesis binds each advertised endpoint. The local bind override directs the same
authenticated peer identity through the proxy; it changes no consensus or ledger
rule. The fault schedule includes malformed operation intake, one validator's
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
