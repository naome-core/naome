# Running a verified-membership node

The executable and durable membership journal run on Unix platforms. The
consensus and network libraries also run in the Windows test matrix; Windows
checks additionally verify that journal creation, opening and recovery refuse
before writing any files because durable directory synchronization is unavailable. Obtain the complete
trusted genesis organization list and deployment discriminator from the network
operators, and at least one reachable bootstrap peer/address. Compare the
resulting context with those operators before approving anything. The source
repository deliberately supplies no production validator identities.

## Build and create local identities

Use the repository-pinned Rust toolchain:

```sh
cargo test -p naome-validator -p naome-verifier --profile release --all-targets --all-features --locked --no-run
target/release/naome-validator --membership-init /absolute/path/my-node
```

Initialization requires a new directory. It generates three independent private
Ed25519 seeds with mode 0600, private journal/anchor/inbox directories, and a
public `identity.json`. Only public identity data is printed. The generated
organization label is an application identifier; it proves no organizational
independence. Keep the approval seed under separate operator custody after
setup; the daemon needs it only for explicit approval/exit commands. Back up
keys and state under the signing-custody rules below.

Create `membership.toml` inside that directory. Fill local identity fields from
`identity.json` and copy the trusted genesis records exactly. This template's
angle-bracket values are placeholders, not valid keys:

```toml
profile = "verified_membership"
mode = "create"
deployment_discriminator = "<trusted 64 lowercase hex characters>"
organization = "<local organization identifier>"
consensus_seed_file = "consensus.seed"
approval_seed_file = "approval.seed"
network_seed_file = "network.seed"
journal_directory = "journal"
anchor_directory = "anchor"
inbox_directory = "inbox"
listen = "/ip4/0.0.0.0/tcp/41000"

[[bootstraps]]
peer_id = "<bootstrap Noise PeerId>"
address = "/ip4/192.0.2.10/tcp/41000"

[[genesis_members]]
organization = "<first trusted organization identifier>"
consensus_key = "<its consensus public key>"
approval_key = "<its operator public key>"
network_key = "<its Noise public key>"
# Repeat genesis_members for the complete trusted set (at least four).

[limits]
maximum_round = 10000
maximum_records = 1000000
maximum_bytes = 10000000000

[timing]
phase_base_millis = 5000
round_increment_millis = 1000
tick_millis = 100
```

All paths resolve relative to the configuration. These example local capacities
and timers are operational choices, not network validity rules. Lifetime journal
limits are bound at creation and cannot be raised by silently editing an existing
configuration. Provision enough capacity for the intended run; reaching a bound
requires stopping and an explicitly designed storage lifecycle, not resetting a
signing key. Do not put a peer's own identity in its bootstrap list. A pure
observer may omit `consensus_seed_file` and `approval_seed_file`; an applicant
needs all three possession keys.

```sh
target/release/naome-validator --membership /absolute/path/my-node/membership.toml
```

The process accepts one JSON command per stdin line and emits bounded JSON lines
on stdout. It continues as a daemon on stdin EOF; SIGINT/SIGTERM stop it cleanly.
An `error` event and nonzero exit indicate a startup, storage or runtime failure.
After first creation, use `mode = "open"` for ordinary restarts.

## Apply and approve

```json
{"command":"status","id":1}
{"command":"apply","id":2}
{"command":"export_request","id":3,"request_id":"<returned ID>","file":"application.request"}
```

Applications gossip to connected nodes. `status` lists known request IDs and
approval counts. Each reviewing operator independently checks the organization
and its key custody, then inspects and explicitly approves that exact request:

```json
{"command":"request","id":4,"request_id":"<application ID>"}
{"command":"approve","id":5,"request_id":"<application ID>"}
{"command":"export_approval","id":6,"request_id":"<application ID>","file":"operator.approval"}
```

Offline transport is supported with `submit_request` and `submit_approval`, each
taking a `file` path. Explicit request imports can make room by replacing an
unapproved network request. Operators can block unwanted requests locally with
`reject` and undo that local block with `allow`, each taking `request_id`.
Rejection does not withdraw an approval already shared with other validators.
An inbox-save failure is fatal; resolve the filesystem problem and reopen before
continuing.

Approvals alone do not advance height or activate the applicant. A proposer must
include the approved request in an artifact block and the active consensus quorum
must finalize it. The pending change is then excluded for the remainder of its
epoch and all of the following epoch. With 8,192 heights per epoch, an H1 join
first votes at H16385. These are finalized-height rules, not a wall-clock promise.

`status.active`, `generation`, `membership`, `members` and `quorum` describe the
next height's signing snapshot. At selected H16384, a scheduled H16385 join may
therefore show `active: true`. `pending_activation` records the scheduled boundary
until the first block using the successor has finalized.

## Exit, remove, and supply artifacts

```json
{"command":"exit","id":10}
{"command":"remove","id":11,"organization":"<target organization>"}
{"command":"members","id":12,"offset":0,"limit":16}
```

Exit is signed by the departing operator. Removal needs no target signature.
Both still need explicit current-operator quorum approvals and a finalized
artifact block, then the same E+2 delay. Neither can reduce the active set below
four. With four members, add and activate another independent organization first.
If the existing consensus quorum is unavailable, membership changes cannot repair
that outage; there is no privileged bypass.

The proposer accepts complete candidate files through either command:

```json
{"command":"candidate","id":20,"block_file":"candidate.block","payload_file":"artifact.payload"}
{"command":"offer","id":21,"file":"framed-membership-candidate.bin"}
```

`candidate.block` is the unchanged canonical artifact block prepared against the
exact current artifact parent/root; `artifact.payload` is a complete canonical
proof or definition payload. `offer` uses `MembershipCandidate::to_bytes` framing.
Candidate bytes are reverified and gossiped. Candidates are ephemeral and require
resupply after restart; approved requests persist in the separate inbox.
Candidate construction APIs are in `naome-chain` and
`naome-node::verified_membership`. No command accepts a manually chosen finalized
height or treats an artifact ID as proof of validity.

## Catch-up and recovery

An observer automatically asks connected peers for successive complete finality
proofs. Peer status is only a hint, and unsuccessful sources rotate. The same
finality verifier and anchored journal are used for normal progress, catch-up,
explicit `import_proof`, and restart replay.

```json
{"command":"export_proof","id":30,"height":100,"file":"height100.proof"}
{"command":"import_proof","id":31,"file":"height101.proof"}
{"command":"shutdown","id":32}
```

For an offline history transfer, add top-level
`bootstrap_history_directory = "history"` and `bootstrap_history_count = 100`.
The directory contains `00000000000000000001.proof` through
`00000000000000000100.proof`. Every file is verified in order from the trusted
genesis or compared with the already retained prefix; no installed height is
trusted from metadata. Bootstrap progress is reported every 128 proofs and
responds to termination signals. The transport's admitted set is refreshed after
replay before live work.

Use `mode = "recover"` only for the same existing journal/anchor pair when normal
opening reports an incomplete anchor or pending signature. Recovery verifies all
complete records, advances a lagging anchor, and completes only the exact already
recorded signing intent. It does not repair altered records, accept an anchor
ahead of its journal, change the signer, replace genesis, or clear conflicting
finality. After successful recovery, return to `mode = "open"`.

Keep journal and anchor in independently retained storage under one live signer
owner. Never start two copies of the same key from separate directories, roll
back both files to a matching old backup, or discard a failed signing journal.
The local lock cannot protect a duplicated key on another machine. A verified
historical finality conflict stops signing permanently in that pair and requires
investigation; recovery deliberately cannot pick a winner.

## Qualification

Normal test/release matrices include fast core, storage, transport and five-process
tests. The required Linux membership qualification also runs the long real-epoch
test explicitly:

```sh
cargo test -p naome-runtime --profile release --all-targets --all-features --locked --no-run
cargo test -p naome-runtime --profile release --all-targets --all-features --locked full_epochs_join_removal_and_independent_durable_replay -- --ignored --nocapture
```

It uses five separate journal/anchor pairs, 32,770 verified finalized heights,
real network finalization at join/removal boundaries, a minority partition and
catch-up, rejected old-set votes, and independent full restart replay. The long
prefix is certificate-driven; this is not a 32,770-height network throughput
benchmark. Runtime measurements and locally observed process results do not
replace the six-platform/profile CI outcomes.
