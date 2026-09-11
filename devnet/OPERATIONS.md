# Operational fixed-validator devnet V0

This is a reproducible, bounded deployment of four equal-weight validators and
two independent, source-only publishers. Each role has its own private directory,
Noise identity, process, and container. Publishers have no signing key. Validator
candidate and payload stores begin empty; new synthetic proof candidates are
created after startup and arrive through authenticated network offers and source
acquisition. The qualifier never writes validator source files or sends consensus
commands. Existing durable-choice, proof-validation, signing and finality rules
remain the authority.

The supported qualification is 4–128 heights (at least eight with faults), with
100 heights by default. It is an operational V0 development profile, not a
production timeout policy, an indefinite network, a public admission service, or
evidence of geographically distributed performance. Local isolated containers
provide separate role mounts and network fault injection on one Docker host.
The process backend is a development smoke path with process suspension rather
than a network partition.

## Build and qualify

Run from the repository root with the toolchain in `rust-toolchain.toml`, Python
3.9 or later, and Docker Engine/Desktop with Compose v2. Linux native binaries
can be packaged without sending the repository or private role files to Docker:

```sh
cargo test -p naome-devnet -p naome-validator -p naome-verifier --profile release --all-targets --all-features --locked --no-run
cargo test -p naome-devnet -p naome-validator -p naome-verifier --profile release --all-targets --all-features --locked --no-fail-fast
python3 -B -m unittest discover -s devnet -p 'test_*.py'
python3 -B devnet/image.py --bin-dir target/release --tag naome-devnet:local
python3 -B devnet/qualify.py --backend docker --image naome-devnet:local --bin-dir target/release --directory /tmp/naome-devnet-run-1
```

On macOS, build the native helpers using the same Cargo commands, then build
Linux runtime binaries inside Docker instead of using `image.py`:

```sh
docker build -f devnet/Dockerfile -t naome-devnet:local .
python3 -B devnet/qualify.py --backend docker --image naome-devnet:local --bin-dir target/release --directory /tmp/naome-devnet-run-1
```

Both image paths pin their base image digests. The source Dockerfile uses its
own allowlisted build context; keep generated private deployments outside the
repository. The qualifier resolves the image to an immutable image ID and records
runtime binary hashes. On Linux those hashes must equal the native binary hashes.
On macOS the native provisioner and Linux runtime are different builds and their
hashes are recorded separately. No image is pushed to a registry.

Choose a new output directory each time. Existing output is refused. Use
`--subnet PRIVATE_IPv4/24` if the default `172.30.88.0/24` conflicts with another
local network. The generated `compose.json` mounts only each role's directory in
its respective container. Containers use a read-only root filesystem, no Linux
capabilities, no additional privileges, a private internal bridge, and bounds of
512 MiB memory, no swap, two CPUs and 128 processes. Health endpoints stay inside
the containers; the qualifier queries each role's loopback HTTP endpoint through
`docker exec`, since host port publication is not reliable on an internal-only
bridge. The qualifier owns and removes its uniquely named
containers/network on success, failure or a handled interrupt. It retains role
state and the report for inspection; it never resets a failed validator.

Without Docker, the following exercises the same native binaries, workload and
finality oracle, but does not supply container-isolation evidence:

```sh
python3 -B devnet/qualify.py --backend process --bin-dir target/release --directory /tmp/naome-devnet-process-1 --heights 8
```

## What the qualification checks

The workload is generated separately at each publisher, one requested height at
a time, with distinct, locally verified closed mathematical proofs. Each height
waits for the expected finalized head and exact durable offer receipts from the
participating validators before advancing. The default schedule includes:

- 50 ms delay in each direction for each forwarded TCP chunk of at most 32 KiB;
- a full 32-ID invalid offer from one publisher while the other offers valid work;
- a 30-second validator network disconnection after height three, healed by time
  independently of finality, followed by catch-up to the same head;
- a publisher SIGKILL and strict reopen halfway through the run;
- a graceful validator restart and strict reopen three quarters through the run.

The process smoke path substitutes SIGSTOP/SIGCONT of the validator child for
network disconnection. It does not claim liveness while a peer remains offline.
There is no unsafe signing-recovery test disguised as a restart: the validator
restart is graceful, and the killed publisher owns no consensus signing key.

After stopping all roles, `naome-devnet verify` independently opens each anchored
finality journal, validates its recorded finality, compares every block and proof
payload with the expected workload, and checks contiguous ancestry. All four
reports must agree on height, head and ancestry digest. A pass also requires
observed completed network acquisition, no unknown or regressing finalized heads,
no unexpected child exit, no reported errors, and completed cleanup.

`report.json` records each height, injected faults, replay results, source and
runtime binary provenance, sample counts, observed event totals, peak sampled
resident memory on Linux, peak sampled role disk use, and connection counts.
Sampling is every half-second; these are observations, not precise allocation
maxima. The role disk limit is a sampled 512 MiB stop threshold, not a filesystem
quota. macOS process RSS/CPU values are unavailable and remain null, not zero.
Logs rotate at 8 MiB with two backups; Docker logs have their own bounded rotation.
Failure reports also contain bounded wrapper error output and container exit,
health and OOM status. Only `report.json` is uploaded by CI. Never upload the
private role tree.

`--height-timeout` defaults to 180 seconds, `--deadline-seconds` to 3600, and
`--partition-seconds` to 30. `--interval-seconds` can add up to 60 seconds between
heights for a longer bounded observation, within an explicitly increased total
deadline (at most one day). The configured source stores allow 256 entries and
8 MiB of payloads; the fixture stops at 128 heights. Capacity saturation remains
a refusal. None of these parameters establishes production liveness.

## Run and inspect individual roles

For manual operation, create a public JSON plan with six distinct canonical
literal IP/TCP endpoints. Set `version` to zero and `heights` to 4–128. For example:

```json
{
  "version": 0,
  "heights": 100,
  "validator_addresses": [
    "/ip4/127.0.0.1/tcp/4101", "/ip4/127.0.0.1/tcp/4102",
    "/ip4/127.0.0.1/tcp/4103", "/ip4/127.0.0.1/tcp/4104"
  ],
  "publisher_addresses": [
    "/ip4/127.0.0.1/tcp/4105", "/ip4/127.0.0.1/tcp/4106"
  ]
}
```

Provision once, then start one agent per role in separate terminals, choosing
distinct health ports when roles share a host:

```sh
target/release/naome-devnet init /tmp/plan.json /tmp/naome-roles
python3 -B devnet/agent.py run --role /tmp/naome-roles/validator-0 --validator "$PWD/target/release/naome-validator" --port 8080
```

Repeat the agent command for `validator-1` through `validator-3` and `publisher-0`
through `publisher-1`, with ports 8081–8085. Wait for healthy startup, then create
fresh work on each publisher using its own directory:

```sh
target/release/naome-devnet publish /tmp/naome-roles/publisher-0 1
target/release/naome-devnet publish /tmp/naome-roles/publisher-1 1
curl --fail http://127.0.0.1:8080/health
curl --fail http://127.0.0.1:8080/status
curl --fail http://127.0.0.1:8080/metrics
python3 -B devnet/agent.py status --role /tmp/naome-roles/validator-0
```

Advance the height only after all validators report that finalized height and
head. `/status` is always diagnostic JSON; `/health` returns 503 before readiness,
after an error/exit, or when a validator exceeds its finality-stall threshold.
An idle completed workload eventually reports stalled until stopped. `/metrics`
exposes bounded Prometheus counters and gauges. These HTTP endpoints accept only
reads and provide no authentication, so keep them on loopback or a private,
operator-controlled network. They never grant consensus authority.

The plan optionally accepts `validator_listen_addresses` and
`publisher_listen_addresses`, each the same length as its advertised array. When
an advertised endpoint differs from its listener, the agent owns a bounded TCP
delay proxy on the advertised endpoint; both addresses must be bindable in that
role's network namespace. Omit these arrays for direct transport. Public role
configuration contains all peer identities, but each private role directory
contains only its own Noise seed and, for a validator, its own signing seed.
Provisioned directories are mode 0700 and files 0600.

To place roles on independently managed private hosts, provision actual reachable
endpoints and securely transfer only the respective role directory to each host;
run the same version of the binaries and agent there. The automated qualification
in this change covers one-host containers; it does not certify this multi-host
deployment, firewall policy, WAN behavior, or operator key distribution.

## Stop, reopen and recover

Use SIGTERM/Ctrl-C on the agent for a graceful shutdown. It stops its child and
waits for exit; a forced timeout is an error. For generated containers use the
exact `compose.json` and project name from that run. Re-running the same agent
against an initialized role uses `open.toml`, preserving identities, anchors,
journals, source custody and durable candidate choice. The agent binds startup
to hashes of `role.json`, `create.toml` and `open.toml`; changed configuration or
an interrupted first create is refused for operator inspection. There is no
automatic reset, key regeneration, image upgrade or journal repair.

After stopping the validators, independently verify their workload histories:

```sh
target/release/naome-devnet verify /tmp/naome-roles/validator-0 100
```

Run this for all four validators and compare `height`, `head` and
`ancestry_sha256`. A live journal remains exclusively owned and cannot be opened
by the verifier. This fixture-specific command requires the exact synthetic
workload; it is not a general application-chain explorer.

If a publisher workload build is interrupted, preserve its diagnostic
`producer/staging` directory for inspection. Once no `publish` process owns
`producer/owner.lock`, an operator may move that scratch directory aside and
retry the same height; existing immutable bundles must match exactly. A leftover
`offer.pending` may likewise be moved aside after confirming no producer is
running. These scratch files contain no signing authority. Never apply that
cleanup procedure to candidate/payload stores, anchors, journals or validator
choice state.

For actual source corruption, stop the role and use the explicit operator source
recovery procedure in `specs/fixed-validator-process-v0.md`. The agent deliberately
does not automate migration or rewrite its configuration binding: run a separately
reviewed recovery configuration directly with the native validator, preserving
the original stores and authority. Incomplete signing state remains a refusal;
this devnet supplies no repair or safe arbitrary validator SIGKILL-resume promise.

CI's `Devnet qualification` job performs the 100-height container run and is a
dependency of the required `Rust CI` result, alongside the full Linux, macOS and
Windows test/release matrices. The Docker configuration follows the documented
[Compose service controls](https://docs.docker.com/reference/compose-file/services/)
and [network reconnect behavior](https://docs.docker.com/reference/cli/docker/network/connect/).
