# Trusted multi-machine pilot

This is the physical-host qualification for the four-slot authority-period MVP. Tooling is
prepared locally; a successful local rehearsal is not a multi-machine result.
Use four Linux/macOS hosts where possible, or at least two physical machines.
Two validators on one machine share its failure domain: losing that machine
removes the quorum. Windows supports independent archive verification, not the
Unix validator custody and control interface.

## Prepare one run

Build the same reviewed source on every target with the pinned Rust toolchain:

```sh
cargo test --workspace --profile release --all-targets --all-features --locked --no-run
cargo test --workspace --profile release --all-targets --all-features --locked --no-fail-fast
```

Use reachable, canonical literal IP addresses on a private network or VPN, with
two fixed TCP endpoints per operator, alternating with each signing period.
Hostnames, wildcard advertised addresses,
duplicate endpoints, and IPv4-mapped IPv6 addresses are rejected. Permit inbound
connections from the four participants to those ports. The local Unix control
socket must never be exposed over the network. Synchronize host clocks and
inspect `profile-info` for the committed clock-error and phase budgets.

Create `endpoints.json` with the real addresses, in node-bundle order:

```json
["10.77.0.11:4100", "10.77.0.12:4100", "10.77.0.13:4100", "10.77.0.14:4100"]
```

Create `handoff-endpoints.json` in the same order using a second reachable port
on each host, for example port 4104. Both sets must be reachable throughout the
run; fresh transport identities use the next endpoint before the old one retires.

On a trusted provisioning machine, choose a new unused output directory:

The retirement-order JSON must contain each generated node index exactly once,
in the chosen order, for example `[2,0,3,1]`. The provisioner commits the
corresponding validator IDs in genesis and the manifest. Review them with
`naome profile-info GENESIS` before distributing bundles; this does not retire
any validator or change the four active signers.

```sh
python3 -B devnet/pilot.py --bin-dir target/release prepare \
  --endpoints /absolute/path/endpoints.json \
  --handoff-endpoints /absolute/path/handoff-endpoints.json \
  --retirement-order /absolute/path/retirement-order.json --directory /private/pilot \
  --timing lab --records 128 --limits standard
```

`standard` preserves the standard work and signing limits except the explicitly
chosen finite record count. It reserves worst-case storage for all four nodes on
the provisioner and one complete run on each target. This can require hundreds
of gigabytes. If the intended pilot uses reduced bounds, select `--limits
compact` explicitly before genesis; do not describe that run as qualification of
standard limits. `lab` retains real 300/120/120-second voting/commitment/reveal
windows. `short-test` is an accelerated rehearsal only. `research` needs a
separate long-running qualification; no local rehearsal proves it.

The provisioner creates one shared genesis and fresh private keys. Each
`node-0` through `node-3` bundle contains only that node's account, consensus and
transport keys, its initialized history, signer, period-custody and handoff
stores, and four separate anchor
directories. `authors/` contains only the two independent research accounts
4 and 5 plus public genesis. Keep these accounts with the research participants;
do not distribute all roles to every validator. Provisioning is centrally trusted
for this pilot: the provisioner sees the initial keys. This is not distributed
key generation or permissionless enrollment.

Move each fresh node bundle to its one assigned operator before its first start,
using an authenticated private transfer and preserving owner-only permissions.
Run as the owning user. Use a short absolute path, such as `/srv/naome/node-0`
on Linux or a short directory under your home on macOS. Relative paths in
`node.json` resolve next to that file, independent of the working directory.
Binaries are not bundled: use native binaries built for the target OS/CPU.
Compare the public `pilot.json` genesis, profile, endpoints and source identity
out of band across operators. Record the source commit and any local changes
used to build each host's binaries; the tool records hashes but does not attest
which source produced an executable.

Retain only one active copy of each signing identity. Never start a coordinator
copy after transferring its bundle, clone a running signer to another host, or
restore an older signer/anchor snapshot to clear an error. Anchors must remain
outside the corresponding data directories; arrange their durable storage
against the rollback failures in your deployment. Separate directories
alone do not protect against whole-machine rollback. Retiring a managed key
does not erase external backups, snapshots, copied secrets or regenerating seeds.
The pilot requires operators to attest that no such signing capability remains.
A failed preparation leaves
its private directory for diagnosis and cannot be resumed by overwriting it.

## Preflight and start on each host

```sh
python3 -B devnet/pilot.py --bin-dir target/release check --bundle /srv/naome/node-0
python3 -B devnet/pilot.py --bin-dir target/release start --bundle /srv/naome/node-0
```

Preflight checks layout, ownership, permissions, initialized stores, genesis,
profile, path length and disk capacity. Native startup then checks registered key
roles, anchored replay and exclusive signing custody. Neither command initializes
missing authority. Simulation controls are disabled. No service is installed and
no automatic restart policy is added; keep the foreground process supervised.
For an explicit proxy/NAT arrangement, `listen_address` and
`handoff_listen_address` may name local bind addresses; both configured advertised
endpoints must still reach them. This pilot keeps both endpoints fixed for the
run. Startup after a sealed handoff uses anchored fresh period custody; initial
consensus and transport files have been durably removed and must not be restored.

Use `naome status`, `shutdown`, `profile`, `submit`, `vote`, `agent-vote`,
`package`, `commit`, `reveal`, `receipt` and library commands from the
[operating guide](operations.md). Substitute each host's local bundle path and
local `account.key` for validator-owner actions. Authors use their separately
held account key and connect to their local node control socket; there is no
remote public submission API. For the first pilot, let an author operate from a
validator host under the trusted operator account, or securely transfer a saved
signed action and use `send`. The author must retain commitment secrets locally
until reveal; never transfer account keys to all operators for convenience.

## Acceptance on real machines

Record host placement, OS/CPU, source and binary hashes, disk headroom, clock
synchronization and network topology before starting. Keep private keys, secrets,
raw histories and archive contents out of public reports. Run these scenarios
using actual wall-clock LAB windows:

1. All four nodes agree on genesis and profile; submit A and obtain an actual
   bounded agenda-agent review plus three owner YES votes. Keep the provider
   report and finalized receipts. Early votes must not shorten the window.
2. Complete A with its checked helper H. Have a different author complete B as a
   refutation using H, retrieve H from another peer with its original provider
   stopped, and verify the positive citation payment. A later question C for H
   must be known but unpaid. The examples and commands are in the operating guide.
3. Preserve the competition checks: reverse two timely reveals and verify the
   earlier commitment wins; separately omit the earlier reveal and verify the
   later eligible author can win. Record outcomes and once-only accounting.
4. Stop one validator during live work, demonstrate progress with three, restart
   it with its original stores and anchors, and verify catch-up and later
   preparation with fresh keys. Its unavailable slot retains quorum weight.
   For a 2:2 network
   split, neither side may finalize; restore connectivity and compare full state.
   Apply network faults at the hosts/VPN under operator control, not the disabled
   simulation interface. Record actual start/end times and affected links.
5. Stop all validators cleanly, restart them, and repeat the comparison. An abrupt
   process crash is a separate scenario; collect before/after evidence and do not
   claim that graceful shutdown demonstrates a settlement-crash boundary.
6. Stop new submissions, wait for the active attempt and queue to settle, then
   collect four exports at the same finalized tip. Check exact balances, reserve,
   library, claims, selected authority, admission order and paid-family count by
   independent replay.
7. Use an earned finalized claim and authenticated join intent to prepare an
   incoming operator with the `candidate-setup` command in the operating guide.
   Observe oldest-claim selection, three incoming READY signatures, three
   outgoing TERMINAL signatures, retirement and activation. Confirm the original
   open research attempt still accepts its frozen owner electorate, and that an
   old consensus or transport key cannot exercise new-period authority.

The milestone passes only with scenario evidence and at least two actual
machines, preferably four. Archive equality alone proves neither independent
placement nor agent use, fault execution, clock behavior, or research usefulness.
Use meaningful participant-authored tasks after reproducing the checked fixtures.
Finite record and consensus-round budgets still apply. A budget halt, unavailable
quorum or storage error is diagnostic evidence, not permission to reset custody.

## Collect and compare

While each validator is live at the final quiet tip:

```sh
python3 -B devnet/pilot.py --bin-dir target/release snapshot \
  --bundle /srv/naome/node-0 --host-label operator-host-a \
  --directory /private/snapshot-0
```

Use a fresh output directory each time. The snapshot includes a private export
and the independent verifier result. Host labels are operator assertions, not
attested machine identities. Transfer the four snapshots privately to the
observer, which needs native binaries and the independently agreed genesis, but
no signing keys:

```sh
python3 -B devnet/pilot.py --bin-dir target/release collect \
  --genesis /private/pilot/genesis.bin --report /private/pilot-agreement.json \
  /private/snapshot-0 /private/snapshot-1 /private/snapshot-2 /private/snapshot-3
```

The collector freshly replays all four archives, rejects genesis mismatches,
duplicate node indices, zero-height exports, incomplete results, and different
finalized tips or complete state. It requires at least two paid completions by
default. It never promotes a height mismatch to success by comparing hashes from
different heights. Recollect after convergence if needed. The resulting report
contains commitments, public account state and operator labels, not private keys
or raw reveal material; review host labels before sharing it.

## Rehearse locally

```sh
python3 -B -m unittest discover -s devnet -p 'test_*.py'
python3 -B devnet/rehearse_pilot.py --bin-dir target/release \
  --directory /private/tmp/naome-pilot-rehearsal
```

Use a fresh, short directory. This creates compact, accelerated bundles, moves
them to four separate directories, checks key isolation, settles a real proof
with one validator offline, catches it up, cold-restarts all four, replays four
exports, and rejects a corrupt archive and a missing anchor. It uses manual votes
and one physical machine. Only `rehearsal-report.json` is intended for sharing;
all other run files remain private. [Verification](verification.md) records the
actual tested snapshot and keeps real-machine qualification pending.
