# Trusted research MVP verification

The current authority-period implementation uses canonical `state-v6` history through
`naome`, `naome-validator`, and `naome-verifier`. The checked artifact DAG is the
proof-library component of that complete state. The historical `state-v1`
qualification recorded source identities, commands, output hashes, the real-agent
lab, and CI. Raw evidence JSON is no longer versioned in the current tree;
the measured results and source/CI references remain below. Keep new raw
reports outside Git, such as in local storage or CI artifacts. The mappings
below identify executable test sources; a source pointer is not a passing run.
Every recorded run establishes evidence only for its named snapshot.

The older lab and CI reports below qualify only their named historical snapshots.
They do not qualify the current v6 implementation. There is one supported
prerelease model; fresh genesis and stores are required for it.

## Portable v6 pilot evidence on 2026-09-27

The portable pilot tooling at code commit
`63558f5a3deb515571bff3c0601cbe314dfe5a69` passed a fresh four-process
rehearsal on one macOS machine with pinned Rust 1.97.1 release binaries,
`compact` limits, `short-test` timing and manual agenda votes. The private raw
report is `/private/tmp/naome-v6-pilot-63558f5/rehearsal-report.json` (SHA-256
`e3e51df7ed0426e5282bec7afc1f81e3af8befa2dbbe1fe078305d8cf6244608`).
Its source digest is
`681a118178e08c2e42a49bb05195e3a8e7edf0fbbb43a5c7529e7723bc7e549d`.
The live comparison report SHA-256 is
`b1b973f4de6535ae7a4b2db12c37e667500eda14e6c04b51049538aff41eec02`;
the archive comparison report SHA-256 is
`4307d436086cac7228070af0858efaf131b345771c0906164334f2393c89d10f`.

| Gate | Local rehearsal | Physical pilot |
| --- | --- | --- |
| Bidirectional TCP | Twelve directed loopback connections passed. | Unverified; no second host was available. |
| Remote authentication and placement | Four private bundles moved to separate directories on one Mac. | Unverified; the previously used laptop timed out on SSH port 22, and no remote bundle was transferred. |
| Validator startup and finalized agreement | Four processes started; a proof with one validator offline finalized, then all four reached height 11 and matching live head and state. | Unverified. |
| Restart and catch-up | The offline validator caught up, then all four cold reopened on the same state. | Unverified. |
| Independent archive replay | Four exports replayed and agreed; corrupt archive, duplicate exports and missing signer anchor were rejected. | Unverified. |
| Participant submission | A locally held author key produced a submission with a finalized receipt. | Exact signed-action transfer and receipt return to a remote participant remain unverified. |

No new proxy-delay run was performed for this tooling patch. The rehearsal
does not qualify `lab` or `research` timing, a real agenda agent, independent
machines, network faults, or a 32-host capacity result. The 32-seat roster
ceiling is a protocol bound; performance at 32 physical hosts needs a separate
run. Python pilot tests passed 38 cases, and pinned release-profile process
tests passed for both `naome-validator` and `naome-verifier` after a matching
`--no-run` build barrier.

## Current state-v6 roster decision

The current v6 protocol installs four bootstrap validators and permits earned
admission through 32 installed slots. At 32, a valid new claimant replaces the
oldest installed unit. The installed-slot quorum is 22 at the ceiling. Genesis,
snapshot, handoff, vote, time and seal decoding enforce the same 32-slot bound.
This is a controlled testnet limit, not a production sizing result.

The optimized 32-process direct runs below converged at one common height-two
head and state in 27.103–36.653 seconds; the paired local proxy runs with
50 ms one-way delay converged in 36.852 and 36.919 seconds. Two clean
64-process direct runs on the later source commit
`9c8584992a954b2b698fccc2335ca5ec5b4954d6` also converged, but needed
156.068 and 179.642 seconds for all nodes. Their local raw report SHA-256
values are `40b19c2d2044826380c55e1b6003cfa050a57c2d946360a3bb15f37bcd8f9c71`
and `50fbc67b1c7d46e793faafac08f6aae93c6c41f0412ec81ec6a322e3a3ad8f27`.
The different source snapshots and polling intervals limit a direct timing
comparison. Earlier 256-process attempts did not finalize. All of these runs
shared one macOS host, so they do not establish behavior on separate machines.
The current ceiling keeps the successfully repeated local roster size while
physical multi-host, slow-node, network-fault and sustained-load qualification
remain open.

On clean capped-source commit `56c71774ad56f1af06ebac71ae61503217b5a3bf`,
a fresh 32-process direct run reached one common height-two head and state
across all validators in 21.500 seconds. Its quorum was 22. The local raw
report, kept outside Git at
`/private/tmp/naome-cap32-pr-smoke-20260927/report.json`, has SHA-256
`8a1bd5d397d120b7fca27d0231e1648718d335f325b1dd8326cc38330d399ade`.
The run used one macOS host, loopback TCP, accelerated `ci-test` timing and a
two-second status poll; it did not independently replay exported archives.

For that capped source, pinned Rust 1.97.1 completed the full-workspace
all-target, all-feature, locked build barriers in both `test` and `release`.
The ledger, consensus and CLI library suites passed 232 tests per profile,
and the focused stable-recovery test passed in both profiles. Workspace Clippy
with denied warnings, formatting, 36 devnet Python tests and both 20-page
PDF structural checks passed. Complete-workspace test execution and the
Linux, macOS and Windows CI matrix remain to be checked on the PR head.

## Earlier state-v6 variable-roster assessment

Earlier implementation commit `05101336477c7fded3790a578a79476a7434ede5` extended the
sealed electorate to 4–256 equal-weight units. A paid completion claim can add
one unit until 256 are installed; later admissions replace the oldest unit.
Those historical experiments and tests below describe their named commits,
before the current 32-slot limit.
The full workspace test-profile and release-profile build barriers and test
runs each passed 646 tests on pinned Rust 1.97.1, including the five-seat
admission, reward, archive replay and restart process scenario. A separate
256-seat vote, time-certificate and full handoff-plan boundary test passed in
both profiles. Formatting and workspace Clippy with `-D warnings` passed.

Final source validation at `9cbcc425ec428a578cabb934c833057c4845f7cd`
used pinned Rust 1.97.1 and `CARGO_INCREMENTAL=0`. Complete workspace,
all-target, all-feature, locked build barriers and test runs passed in both
`test` and `release`: 655 tests across 26 binaries in each profile, with zero
failures. With cached dependencies, the test-profile build barrier took 0.15
seconds and execution 884.29 seconds; the release barrier took 31.63 seconds
and execution 913.16 seconds.
Workspace Clippy with `-D warnings` and `cargo fmt --all --check` passed. The
variable-roster proposal PDF passed its structural check at 20 pages, and a
rendered-page review found no visible clipping or diagram overlap. The
accelerated `short-test` process fixture now has 45-second commitment and
reveal windows to tolerate full-suite scheduling; production and `ci-test`
timings are unchanged. Its deterministic chain and consensus vectors were
regenerated and passed replay tests in both complete profile runs.

The local comparison uses the same
two-height, one-question workload in three sequential runs per configuration.
All nodes ran on one macOS ARM64 host through zero-delay local TCP proxies.
Times below start after process launch; memory and disk are totals sampled at
convergence, rather than peaks or reserved capacity.

| Release binary | Installed units | Quorum | First quorum median | All nodes median (range) | Sampled memory median | Disk median |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| v5 baseline | 4 | 3 | 3.165 s | 3.409 s (3.165–4.030) | 115.3 MiB | 209.0 KiB |
| v6 | 4 | 3 | 3.177 s | 3.991 s (3.951–3.996) | 114.7 MiB | 208.9 KiB |
| v6 | 8 | 6 | 3.254 s | 5.562 s (5.213–6.116) | 239.8 MiB | 676.1 KiB |

The v5 baseline and v6 four-unit medians differ by 0.582 s in this small
sample. This is not a sustained-throughput estimate. The older
12-height baseline uses a different
workload and is not used for the timing comparison.

The former 16-process setup rejection used a full-run maximum as the startup
free-space floor and counted reveal staging that has no separate validator
file. The corrected 256-seat, 296-record compact profile checks 78,923,176
bytes of next-height headroom per node, or 20,204,333,056 bytes across 256
local nodes. Setup succeeded on this Mac and occupied about 39 MiB. Its
separately reported 23,364,931,136-byte per-node full-run allowance assumes
every bounded height reaches maximum usage; it is not reserved at startup.
The local scale diagnostics identify
each release binary and keep failed attempts separate from passing runs.

| Diagnostic v6 direct-process run | Installed units | Quorum | All nodes at common height 2 | Disk at convergence |
| --- | ---: | ---: | ---: | ---: |
| 16 | 16 | 11 | 21.492 s | 2.45 MiB |
| 32 | 32 | 22 | 100.210 s | 8.44 MiB |
| 64, hybrid relay | 64 | 43 | 623.035 s | 40.50 MiB |

These are single runs on changing, uncommitted binaries. The direct-process
harness differs from the earlier four- and eight-unit proxy comparison, so the
tables are not a controlled speedup series. The recorded 256-process attempts
have not finalized a record. Early runs exposed overloaded control and submit
paths. A cap on connection attempts stalled peer discovery and was removed.
An IPv4-only mesh then approached this Mac's ephemeral-port limit; mixed IPv4
and IPv6 loopback allowed nearly all peer links to form. Later runs exposed
repeated idle candidate preparation and repeated hashing of the full genesis
on outbound frames. The corresponding scheduling and immutable-context fixes
passed focused tests and smaller process runs. The cached-context 256 run
reached at least 237 question holders and 201 validators in round-two
precommit, but no record finalized before one validator exited with a
transport error. The runtime now keeps a listener alive after a libp2p
nonfatal listener error. A later clean-head run formed all 255 peer links per
validator and collected all 256 offers and signed time reports, but was stopped
at 540 seconds with no finalized height: the selected round-zero proposer had
not received the pending question. The runtime now gives that proposer the
first bounded action-delivery slot. In the next clean-head run, one proposer
authored early, but after 926 seconds no record had finalized and
only 11–23 prevotes were visible per responding node. A short CPU sample found
repeated hashing of large outgoing requests before send-capacity checks;
fingerprinting now follows those checks. The next clean-head run reached a
complete peer mesh but was stopped after 624 seconds at height zero, with at
most one observed proposal in the final responding range. A second CPU sample
found that the runtime rehashed the same publication for each peer before
checking its delivery cache. Broadcast now computes that wire identity once
and retains the existing peer-specific delivery and acknowledgement bounds;
a clean-head run of this change remained at height zero after 2,062 seconds.
One sampled validator reached 217 prevotes and 162 precommits in round zero,
then advanced to round one without a seal. A second CPU profile found that
network-driven retries still rehashed retained publications and scanned the
delivery queue separately for each peer. The runtime now caches the exact wire
identity of each retained publication and builds one peer lookup per broadcast.
A clean-head 256-process run of that change remained at height zero after 1,234
seconds. All 256 nodes responded in its final sweep, which saw at most 170
precommits, one short of the 171-signature quorum. A CPU sample then found
repeated full validation of an already retained proposal, including execution
of the 256-offer successor plan. A signing node now recognizes exact bytes of
a proposal it has already verified; changed bytes still take the full
verification path. A clean-head run with this change remained at height zero
after 870 seconds: 34 of 222 responding nodes held a prepared agreement, but
none had sealed a record. The sampled main thread was mostly waiting for
network events. The CI test profile now allows a longer phase interval for
large local rosters, reaching 12 minutes at 256 seats; signed quorum and round
limits are unchanged. A clean-head 256-process run with that interval reached
prepared agreement on all responding nodes, but remained at height zero after
3,862 seconds: READY counts were only 1–8, TERMINAL was absent, and old-lane
connections had fallen to 0–32 peers. One sampled node had 32 staged peers
and almost 500 READY deliveries queued. The host did not sleep; sampled memory
was about 4.0 GiB across the 256 validators. This run does not establish that
host port exhaustion alone caused the stall.

The staged handoff listener now defers outbound full-mesh dialing until old
transport retirement. Signed READY can travel over the existing old lane,
and each signer retries its own durable handoff signature instead of flooding
every collected signature through every peer. The affected network and runtime
tests pass. Dirty-tree local process runs reached a common height two with 4,
16, and 32 validators in 6.387, 13.225, and 78.180 seconds respectively;
these are diagnostic runs, not a controlled baseline comparison. This change
reached 69 prepared agreements in a clean-head 256-process run, but eight
validators exited while binding their staged handoff listeners. The process
harness had chosen those ports from the OS ephemeral range before thousands of
outbound old-lane sockets opened. A port collision is plausible, though the
transport error gave no OS cause. The direct-process harness now probes
listener ports below this host's ephemeral range. A clean-head run with 512
unique listener addresses in that range still lost validators during staged
listener binding after 495 seconds. Thus port allocation alone did not resolve
the failure. The pinned libp2p version prints an empty message for an
underlying transport I/O error; the listener error now preserves that cause
so a subsequent run can identify it. The next clean-head run found the cause:
42 validators logged macOS `No buffer space available` (OS error 55) while
binding staged listeners. It stopped after 547 seconds, with 128 of 225
respondents prepared for agreement and READY at 0–31. The staged listener now
uses a 16-slot TCP backlog while the old mesh remains open, down from 64 at
large rosters. A clean-head run of this change still failed after 540 seconds:
22 validator logs reported the same macOS buffer error while binding staged
listeners. The last saved poll had 169 of 204 respondents prepared for
agreement, READY at 0–5 and no TERMINAL signature. No height was sealed.

On the same clean commit, a 128-process run was invalidated by a four-second
macOS maintenance sleep on battery. All validators then stopped on the
two-second UTC-drift safety rule; this is not a roster-capacity result. A new
run with display and system wake assertions reached one common height-two head
and state on all 128 validators. Its first height-two quorum took 1,934.460
seconds and all-node convergence took 2,214.905 seconds. Run data occupied
113,882,534 bytes (about 108.6 MiB); one host sample found the 128 validator
processes at about 4.7 GiB resident memory and 944% CPU. The handoff's
fresh-key connections were sparse for late nodes, so this pass does not
establish practical throughput or reliability at 128. The 256-process
handoff remains unproven.
No physical multi-machine result is available.

### Repeated 32-validator resource profile

Two direct-process runs on 26 September 2026 used clean commit
`6c1c9f3fc25e01d41f66283e2062c0a81510c3d3`, release binaries built with
pinned Rust 1.97.1, 32 validators, quorum 22, one submitted question and two
finalized heights. Each run started in a fresh directory on the same macOS host
with ten logical CPUs, local IPv4 TCP, no inserted delay, and the `ci-test`
timing profile. The local raw reports for runs A and B retain binary and
runner hashes, the common finalized head and state for each run, per-validator
events and counters, and sampled queue history. Both passed with all 32 nodes
at a common height-two head and state. Times below start after all processes
were launched; submission followed about two seconds later.

| Measure | Run A | Run B |
| --- | ---: | ---: |
| First height-two quorum | 20.983 s | 18.609 s |
| All 32 at common height two | 83.607 s | 83.398 s |
| Tail after first quorum | 62.624 s | 64.789 s |
| Validator CPU time since submission, median | 3.971 s | 3.731 s |
| Canonical state-exchange egress per validator, median | 7.310 MB | 6.119 MB |
| Canonical state-exchange ingress per validator, median | 7.040 MB | 6.020 MB |
| Started requests per validator, median | 790 | 679 |
| Sampled queued deliveries per validator, median peak | 158 | 114 |
| Sampled total queued deliveries, highest | 4,749 | 3,271 |

At height two, median agreement-to-finalization time per validator was 6.087
seconds in A and 5.321 seconds in B. Two validators in each run took roughly
60–68 seconds after agreement and accounted for most of the all-node tail.
Several late validators have no recorded local TERMINAL quorum; finalization
can also arrive through catch-up. The data establish a recurring long tail,
but do not isolate its cause. The queue peaks use a nominal two-second poll
interval and may miss shorter spikes. CPU time covers all threads in one
validator process, measured from just before submission, not host-wide CPU
demand.
Canonical message bytes exclude Noise, libp2p and TCP framing, retransmission,
and connection setup. Process memory was not captured in these runs. Neither a
real network nor one machine per validator was measured.

The [scenario calculator](../../devnet/variable_roster_forecast.py) holds
round-trip time and link rate constant. Its 12–24 serial one-way message waves
over two heights are **assumptions**, not a measured critical path. At 50 ms
RTT they yield 0.3–0.6 seconds of propagation; at 100 ms, 0.6–1.2 seconds.
Serializing the largest observed canonical egress volume from one validator
would take 0.565–0.652 seconds at an assumed 100 Mbit/s, or 0.057–0.065 seconds
at 1 Gbit/s. These are separate sensitivity budgets that can overlap, not
terms to add to the local 83-second result. The measured runs cannot yet
support a total-runtime estimate or a production capacity claim for 32
separate machines. The delayed-proxy runs below add a local sensitivity check;
a separate-machine validation is still needed to calibrate that estimate.

The pinned-toolchain focused runtime/node build barrier, workspace Clippy,
format check, and Python syntax check passed for the instrumented source.
The `cold_terminal_server_serves_final_record_to_a_late_owner` runtime test
also hit its 60-second timeout on this branch. The identical isolated test
timed out on unmodified parent commit `5edf02425f2740f19c6a12be7d6a51f94722184b`
under the same local conditions, so this observation does not establish a
regression from profiling. The instrumented commit does not have a passing
complete-workspace two-profile run; the earlier complete-workspace results
above apply only to their named commits. The test passed in 39.90 seconds on
the later optimized branch, though its earlier timeout remains a reliability
caveat.

The v6 implementation still permits one active research attempt; more voters
do not make questions run in parallel. This evidence supports a controlled
small-roster testnet, not production use of the current 32-unit ceiling or the
larger historical experimental rosters. The
256-node listener failure calls for a transport design that avoids the current
full-mesh resource demand. Separate-machine rehearsals, sustained workloads
and network-fault measurement remain necessary before recommending larger
rosters for deployment.

### 32-validator handoff recovery and delayed-proxy follow-up

The per-validator timeline on clean commit `7595a796` confirmed a long
post-quorum tail: the baseline run reached its first height-two quorum in
30.933 seconds, but all 32 validators needed 83.542 seconds. Several late
nodes had at most three old-peer links,
no staged peers and too few READY signatures. Their recovery sweep tried the
selected keyed endpoints before stable fallback addresses. A selected listener
can close after handoff while its peer remains reachable through the stable
recovery address. With only two probes per interval, putting every selected
endpoint first could delay useful history requests for much of a full sweep.

Commit `063b8f40` interleaves selected and stable recovery addresses, without
changing authority, voting, the recovery request format or the transport's
two-connection limit. Three fresh direct-process runs with the same workload,
profile and measurement runner all passed with 32 validators at one common
height-two head and state within each run (runs A, B and C).

| Direct-process measure | Baseline | Optimized A | Optimized B | Optimized C |
| --- | ---: | ---: | ---: | ---: |
| First height-two quorum | 30.933 s | 25.083 s | 34.625 s | 23.431 s |
| All 32 at common height two | 83.542 s | 27.103 s | 36.653 s | 29.505 s |
| Tail after first quorum | 52.609 s | 2.020 s | 2.028 s | 6.074 s |

The later proxy harness used the same optimized Rust binary in every run.
It raises the proxy connection cap to 64 for this roster and exposes a
configurable one-way delay per forwarded TCP chunk. Two runs at each setting
passed with all 32 validators at one common height-two head and state within
each run. Local raw reports, kept outside Git, retain the code, runner and
binary hashes, timing events, traffic counters and sampled queue history.

| One-way proxy delay | Runs | First height-two quorum | All 32 at common height two | Tail after first quorum |
| --- | --- | ---: | ---: | ---: |
| 0 ms | A / B | 28.169 / 21.626 s | 34.215 / 29.692 s | 6.046 / 8.066 s |
| 25 ms | A / B | 25.323 / 29.341 s | 27.344 / 31.365 s | 2.021 / 2.024 s |
| 50 ms | A / B | 32.883 / 32.799 s | 36.919 / 36.852 s | 4.036 / 4.053 s |

Raw reports remain on the measurement host at
`/private/tmp/naome-profile-32-<run>-20260926/report.json`, outside Git.
The run names and SHA-256 values are:

| Run | SHA-256 |
| --- | --- |
| `timeline-baseline` | `a86411e07df448e8dd3ae8324617b89b8acd3dca8d7b56a16d1bbbf0b40b8f59` |
| `interleave-a` | `9b1af3a60fc391d0c3b13962985e79ed526e42c07b8cd47368261c0ac660e073` |
| `interleave-b` | `22f22cbab7e9f07a324a00df74c42f4fa154dd42ebb40d36e4446c4ae8e59d62` |
| `interleave-c` | `ecd810d6ff14d3d4c3f0f9889964ef27d5dbd1bb5cb933b7794230f15c0c95ad` |
| `proxy0-cap64` | `d8b3ae13f4eaa9d471d0938042eb4c2112e124709e83cc8c52b01377d27b43af` |
| `proxy0-cap64-b` | `de0088af8d9cc536e930ce0041bbb5d640629c638af455b7f6e2bcea23a63c74` |
| `proxy25-a` | `5888ce1d51c59b1b6eef4080412a291ee2b07fd41883b76537d42e4bdce6aae9` |
| `proxy25-b` | `2a2b29ed9afdd694580365c7c12c65fddea1882e914628e90a92b4e985899173` |
| `proxy50-a` | `fc9fd721882f4c9727322edd7c7dfb44566b7b0212d7e24099e3b8032d91f1a1` |
| `proxy50-b` | `6e5d3e354fc0c00f3f2516afcbd56d93be2ae81cf148c9a5df5f13f27b2433f5` |

Five earlier v6 reports cited by the comparisons above are also retained
outside Git at `/private/tmp/naome-branch-evidence-20260926/<filename>` on
the measurement host:

| Filename | SHA-256 |
| --- | --- |
| `variable-roster-baseline-4.json` | `3ccfdb93b75adb7b5dd066d226a218e2e0f4413b65d0128b990467e13697b6da` |
| `variable-roster-local.json` | `a51ba0877e9c777565bc18c997e5cb3b35a7c3faf649255fb83b581455e85b6d` |
| `variable-roster-profile-32-a.json` | `41208c56cf46c1f4649170965453371e60e64698987238e16ccef55252141f5f` |
| `variable-roster-profile-32-b.json` | `7909dd6f16b17a2703ab1840166d9e380b3b3de653752bb7a96f50e91794aac6` |
| `variable-roster-scale-local.json` | `478db1b9c672452c575dd35116d1f5750d84677b487d75f130b6c50bbb63b7ad` |

These temporary local paths are not a durable published artifact.

The 25 and 50 ms one-way delays approximate 50 and 100 ms round trips for
forwarded chunks. All processes and proxies still ran on one ten-logical-CPU
Mac with loopback TCP and a system wake assertion. The proxy does not model
separate-machine CPU, link bandwidth, packet loss, geographic routing or
sustained load. Two runs per delay do not isolate a precise latency cost from
host scheduling variability.
The data support a controlled 32-validator testnet rehearsal: all ten new
baseline, optimized and proxy runs converged, and every optimized run finished
within 37 seconds. They do not qualify 32 separate machines or production
deployment. Physical multi-host, loss and sustained-load runs remain open.

With pinned Rust 1.97.1 on macOS ARM64, complete-workspace `test` and
`release` build barriers and test executions passed on the optimized runtime
code: 26 targets and 656 passing tests in each profile. A test-only module was
then moved to the end of its file to satisfy Clippy. On that final source,
workspace Clippy with `-D warnings`, formatting, and the focused recovery
probe test in both profiles passed. Python syntax checks passed. This branch
has not run the Linux or Windows CI matrix or a physical multi-host pilot.

## Historical state-v5 authority-period qualification

The canonical implementation seals every record using outgoing agreement,
three incoming READY signatures and three outgoing TERMINAL signatures. The
same selected authority drives consensus, time reports, service accounting,
transport and replay. Research attempts retain their frozen owner electorate.
Four stable slots retain their quorum weight through unavailability; admission
consumes the oldest eligible claim only when its successor is sealed.

The 23 September 2026 qualification passed on clean implementation commit
`66b84bcfb3d3c6ecbcb82a3d54666dd487e0871c`. The local qualification record
captured the source fingerprint, commands, elapsed times, output hashes,
architecture review and separately identified paper checks. The recorded paper
revision is `3eb1100ef66553c9aa5297c2039e78ca42ba0854`; its hashes and review
were recorded separately from the qualified software snapshot. The qualified consensus
implementation and devnet fixtures remain unchanged. A later Kev cleanup fix is
qualified separately below. The workflow removes the recurring
historical speed assertion at the user's request. The final PR commit must pass
CI using the revised workflow and full correctness qualification. The measured comparison
below remains milestone evidence. The qualification runner checked out
`2f0609ada04d5969e55ca34a278c3b898a888ad5`; its tree was independently verified to match the
qualified source tree, rather than assuming that a synthetic merge SHA equals
the feature head.

An earlier [PR CI run](https://github.com/naome-core/naome/actions/runs/35907476236)
reported two macOS release process-test timeouts. Investigation made vacant-slot
reentry deterministic before the dependent question and reproduced a roster
that could receive three outgoing votes with only two live incoming signers.
A configured live node now requires its exact prepared offer before choosing a
fresh proposal vote, with the verified candidate-replacement and earlier-quorum
exceptions. It retains all verified proposal evidence and preserves the normal
locked-value fallback. The focused regression failed before that fix and passed
after it; the complete qualification below includes the fix.

A later [CI run](https://github.com/naome-core/naome/actions/runs/35912269549)
exposed a provider-outage fixture ordering error and a timeout in simultaneous
Voting observation. The fixture now establishes the outage at a quiet four-slot
tip before submitting its dependent question. The harness observes Voting from
immediately after submission and retains each node's actual finalized evidence
for the same operation, attempt and deadline. It reads the full voting duration
from genesis, requires every participating node's observation, and keeps the
settlement, fault, resource and independent replay checks. Timeout reports retain
bounded public diagnostics; no failed run is counted as qualification.

The later [PR quality run](https://github.com/naome-core/naome/actions/runs/35919639411)
exposed an interrupt race in Python's subprocess wait lock during Kev setup
cleanup. The fix uses bounded polling of exclusively owned children and retains
process-group termination and reaping. Regressions cover a poisoned wait lock,
an interrupt after the child was reaped, and a nonzero installation exit. On
clean commit `fd742b1b06b0df0b24e251def61032fa45b6f05c`, all 57 Kev tests passed under
Python 3.12.12; source and output hashes are recorded in the local qualification
record. [CI run 35921060926](https://github.com/naome-core/naome/actions/runs/35921060926)
then passed all 12 jobs on `90a5a0a`, including all six Rust profiles, 57 Kev tests,
and the full Docker qualification. Docker reached 102 matching heights in
524.657 seconds with four agreeing replays and the required faults; its Ubuntu
runner image matched the baseline. This follow-up does not change the consensus
or devnet qualification; later paper and evidence changes still require their
own final-head CI.

| Evidence | Current result |
|---|---|
| Complete local workspace | Rust 1.97.1, `CARGO_INCREMENTAL=0`; 642 tests in `test` and 642 in `release`, zero failures. Each complete all-target, all-feature, locked execution followed its own complete `--no-run` build barrier. Profiles ran sequentially. |
| Local timing | Test compilation 1.563 s and execution 493.323 s; release compilation 4.461 s and execution 482.275 s. |
| Quality | Formatting, Clippy and rustdoc with warnings denied, workspace doctest command, 36 devnet Python tests and 54 Kev Python tests passed. |
| Platform CI | [Run 35915474813](https://github.com/naome-core/naome/actions/runs/35915474813) passed both profiles on Linux x86_64, macOS ARM64 and Windows x86_64, plus quality, devnet and all aggregate gates. |
| Earned installation | The process scenario registers a new account, verifies its paid proof and claim, installs its prepared candidate, requires its signature in a later ordinary quorum with only two bootstrap signers online, verifies the future service payment, cold-restarts peers and independently replays four distinct stores. |
| Vacant-slot recovery | The four-process scenario starts with one owner offline, completes a genuine three-slot handoff, catches the owner up with a vacant slot, and requires a real reentry period before testing provider-offline proof retrieval and three approvals. |
| Delayed native network | Four-process run: 15 matching heights in 105.431 s with 50 ms delay in each direction, timed isolation with surviving-quorum progress, catch-up, SIGKILL, graceful restart, four replays and corrupt-export rejection. |
| Portable bundles | CI rehearsal: relocated private bundles, real proof/helper settlement with one node offline, catch-up, cold reopen and four agreeing archive replays; all nine checks passed. |
| Independent review | Selected authority, seal binding, signer custody, recovery, transport retention and priority, obsolete paths, operating commands, process evidence and the local readiness policy were reviewed. Substantive findings were fixed and no blocking findings remained. |
| Whitepaper | The updated source, diagrams and generated 20-page English PDF passed structural checks and rendered-page inspection. Hashes were captured in the historical qualification record. |

The final Docker run reached 102 matching
canonical heights in 34 attempts in **508.743 seconds**, compared with
**1103.819 seconds** in the baseline:
**2.170 times faster**. Both runs used the GitHub-hosted Ubuntu 24.04
x86_64 runner class and the same container CPU/memory limits. The baseline image
was `20260907.300.1`; the current image was `20260920.314.1`.
The authorized timing profile changed from 15-second to 1-second voting windows,
all committed in genesis and completed under certified time
(510 versus 34 required seconds).
The profile, proxy and observation changes are part of this measured end-to-end
result; their individual contributions are not apportioned. It is not a
protocol throughput claim. Separate signed-time tests preserve every complete
Lab, research, short-test and CI phase boundary.

The Docker run retained 50 ms bidirectional delay, alternating authenticated
owners, the timed partition with surviving-quorum progress and catch-up, active
signer SIGKILL and graceful restarts, post-restart progress, bounded resources,
four independent archive replays, 32 rejected malformed ingress attempts and
corrupted-export rejection. The CI job separately recorded 95 s for the release
build barrier, 201 s for the publication/recovery scenario, 66 s for the portable
rehearsal and 16 s for image packaging. Those steps are outside the Docker
qualification measurement. Observation and certified-window counters overlap
the attempt phases and must not be added to them.

These results accept MVP-36 through MVP-38 and AB-08 through AB-10 under the
explicit accelerated authority-period qualification. A new real-agent Lab run,
physical multi-machine acceptance and the complete seven-day research run remain
separate and unqualified. Operational handoff requires operator attestation that
external secret backups and regeneration seeds are destroyed; the implementation
retires managed local signing capability. Finite run and journal limits remain.

## Historical retirement-order qualification

The v4 genesis and profile are incompatible with v3. The new genesis field is an
exact four-validator-ID permutation selected through a required setup JSON plan;
`profile-info` exposes it. Ledger tests cover missing, duplicate and foreign IDs,
order identity, strict wire decoding and stable state replay. CLI setup tests
cover rejection before provisioning. The 22 September 2026 local check used
Rust 1.97.1 and `CARGO_INCREMENTAL=0`: both complete workspace profiles passed
585 tests with zero failures, each after its own
`--workspace --all-targets --all-features --locked --no-run` build barrier.
Formatting, Clippy with warnings denied, rustdoc with warnings denied,
doctests, 54 Kev Python tests, and 18 devnet Python tests passed. Release
binaries passed a one-host four-process relocated-bundle rehearsal through 12
heights, with offline catch-up, cold reopen, and four agreeing independent
archive replays. The tested `fb21c8e` tree is identical to the rebased v4
implementation `d91675a`. Platform CI, physical multi-machine qualification,
and the long research-window profile remain unverified for v4. At that v4
snapshot, the order had no effect on live authority.

## Historical join-intent qualification

The 22 September 2026 local v3 check on the merged v2 base used Rust 1.97.1 and
`CARGO_INCREMENTAL=0`. Both complete workspace profiles (`test` and `release`)
passed 583 tests with zero failures, each after its own
`--workspace --all-targets --all-features --locked --no-run` build barrier.
Formatting, Clippy with warnings denied, rustdoc with warnings denied, and
doctests passed. All 54 Kev and 18 devnet Python tests passed. The seven local
process scenarios include a four-validator join-intent case that passed in
35.46 s. Component tests cover
claim binding, candidate key possession, role and endpoint collisions, nonce
conflicts, replay, and direct rejection of candidate research votes, consensus
signing and votes, proposals, time reports, and transport identity. The
qualified implementation and test source is
`e236914`.
The [v3 CI run 35784893448](https://github.com/naome-core/naome/actions/runs/35784893448)
passed all required platform and quality checks, plus Devnet qualification, on
head `754bec4`; squash merge `92353ca` has the same feature tree. Physical
multi-machine qualification and the long research-window profile have not
run. The v3 four-process run used the accelerated short-test profile, so
Lab-profile extension acceptance remains pending. At that v3 snapshot, a join
intent neither activated a validator nor consumed its eligibility claim; activation was deferred to the handoff milestone.

## Historical account-admission qualification

The original 22 September 2026 local v2 check passed 564 tests per profile.
After integration with Kev, the merged v2 head `b5f0207` passed both complete
Rust 1.97.1 workspace profiles with 572 tests each, their separate
`--all-targets --all-features --locked --no-run` build barriers, formatting,
Clippy with warnings denied, rustdoc with warnings denied, doctests, and 54 Kev
Python tests. [CI run 35781130410](https://github.com/naome-core/naome/actions/runs/35781130410)
passed all six platform test/release jobs, quality, devnet, and the required
aggregate checks on that exact head. The squash merge `68e9f7d` has the same
feature tree. The seven local process scenarios include a fresh
researcher creating a key, registering with zero balance, earning a proof reward,
independently verifying its archive, and surviving all four validators' cold
restart. Registry exhaustion, fixed voting authority, protected intake, original
and citation rewards, and journal replay have separate component coverage below.
Physical multi-machine acceptance remains separate.

## Historical state-v1 qualification

| Evidence | Source and result |
|---|---|
| Implementation | `0bae7b0e61c576f9fc1edf2f465da90602a9645e`, the source qualified by the successful CI run below. |
| Complete local workspace | Rust 1.97.1 with `CARGO_INCREMENTAL=0`; separate build barriers and complete all-target/all-feature/locked executions; 533 tests passed in each of the test and release profiles. Commands and output hashes were captured in the historical qualification record. |
| Quality | Formatting, Clippy with warnings denied, documentation with warnings denied, and the workspace doctest command passed. The final crates define zero doctests. |
| Platform CI | [Run 35465126870](https://github.com/naome-core/naome/actions/runs/35465126870) on `0bae7b0`: all six Linux x86_64, macOS ARM64, and Windows x86_64 test/release jobs, quality, devnet, and aggregate gates passed. |
| CI devnet | Docker run: all four validators independently replayed 102 matching complete records on the same clean `0bae7b0` source, with 50 ms traffic delay, isolation/healing, SIGKILL, graceful restart, and corrupt-export rejection. This is accelerated control-record qualification, not 102 proof publications. |
| Real lab | Local lab run: passed in 1,665.669 seconds with real 300/120/120-second windows, actual bounded agenda review, reversed reveals, missing earlier reveal, helper retrieval while its original provider was offline, citation payment, no retrospective payment, 2:2 partition/healing, four-node cold restart, and independent replay. |
| Lab provenance | The lab ran clean source `7e43f2bc3c5e967b2a2f3aad54496c61eb064be2`. The later code change only gates two Unix test helpers. Rebuilt main executable hashes match the lab; source-manifest and binary hashes were captured in the historical qualification record. |
| Independent review | Read-only architecture and source/log/binary/evidence review was clear for that integration. It did not perform an independent Cargo run. |

The lab produced exactly three paid completions and three passive claims, with
3,000,000,000 atoms across balances and reserve. Claims activate no voting rights.
Component checks, injected storage faults, accelerated process tests, platform CI,
and the real-window lab establish different properties. Graceful shutdown is not
an abrupt settlement crash; the storage fault suite covers that boundary.

The evidence is bounded to trusted fixed membership and four local processes.
Finite consensus-round and journal limits remain. Two-machine operation and the
seven-day profile are still unqualified; these results do not establish public
permissionless-network security. Keys, secrets, raw histories and provider
diagnostics remain private. Public reports include the intentionally published
fixture profile and actual agent decision and reason.

## Pilot preparation

The next pilot's local preparation run, dated
20 September 2026, recorded an exact file manifest for the changes after
`6cdab88`. Both complete Rust profiles passed 535 tests with separate build
barriers; formatting, Clippy, rustdoc and the doctest command passed. All 18
devnet/Python tests passed. A release-binary rehearsal moved four private bundles,
settled one real proof and helper with one validator offline, restored it,
cold-restarted all four, and independently replayed 12 matching records. It also
rejected duplicate node exports, corrupt archive bytes, missing anchors and
simulation controls. The run took 36.979 seconds with compact short-test limits
and manual votes; cleanup completed.

The [pilot runbook](pilot.md) defines deployment and collection on real machines.
The rehearsal is one-host evidence. Standard-limit network execution, a new
real-agent or LAB-window run, Docker and CI for this patch, physical machine
independence, and the seven-day profile were not run. The revised 19-page
[paper](whitepaper-en.pdf) passed structural checks and rendered-page visual
review; that document review does not qualify the proposed public network.

## Local Kev voting prototype

Local validation on 2026-09-22 used an Apple M4 with 16 GiB RAM. Rust 1.97.1
passed 543 tests in each of the test and release profiles, plus formatting,
Clippy, rustdoc and doctests. After the Python-only lifecycle changes, all 54
offline tests passed; Rust sources were unchanged from that validation.

Actual model loading cancellation, termination cleanup, restart and process
reuse passed. Existing installation reuse was exercised directly; fresh-download
interruption and resumption used fixtures. Real Kev reviews produced unsigned
REVIEW and finalized YES/NO ballots. The final four-validator smoke reused
assessments without extra inference and replayed four archives to the same head.
This is one-machine evidence, not separate-machine or full research-lifecycle
acceptance. No CI or publication result is claimed.

The frozen benchmark scored 37/48 baseline questions across 60 calls including
repeat/order probes. A confident wrong answer to `17 mod 5` illustrates why this
is not a dependable mathematical authority. Scores and policy thresholds remain
uncalibrated. The benchmark script and question set are local research artifacts
under ignored `.local/kev/research/`; reports are under `.local/kev/evidence/`.
See the [Kev runbook](kev.md) for repeatable software and integration checks.

## Executable evidence locations

| Label | Source and scope |
|---|---|
| Profile | [Profile/genesis tests](../../crates/naome-ledger/src/profile/tests.rs) |
| Account admission | [Registration, capacity and authority](../../crates/naome-chain/src/state/tests/admission.rs), [protected intake](../../crates/naome-runtime/src/state/tests/intake_priority.rs), [four-process registration, reward and restart](../../crates/naome-cli/tests/cases/admission.rs) |
| Join intent | [Canonical intent and key possession](../../crates/naome-ledger/src/operations/join_intent/tests.rs), [claim and state admission](../../crates/naome-ledger/src/state/tests.rs), [candidate consensus exclusion](../../crates/naome-consensus/src/state/tests.rs), [candidate transport exclusion](../../crates/naome-network/src/transport/state_exchange/tests.rs), [CLI action custody](../../crates/naome-cli/src/app/actions/tests.rs), [four-process prepare, replay and restart](../../crates/naome-cli/tests/cases/admission.rs); an intent alone grants no authority, while the sealed handoff activates its selected claimant |
| Questions | [Question compilation tests](../../crates/naome-ledger/src/question/tests.rs) |
| State | [Canonical state transitions](../../crates/naome-chain/src/state/tests.rs), [wire/replay vectors](../../crates/naome-chain/src/state/tests/golden.rs), [default queue boundary](../../crates/naome-chain/src/state/tests/queue_boundary.rs), [all-sixteen-author reservation](../../crates/naome-chain/src/state/tests/capacity_sixteen.rs) |
| Library | [Mathematical normalization/reuse tests](../../crates/naome-ledger/src/library/tests.rs), [workload qualification](../../crates/naome-ledger/src/library/tests/qualification.rs), [older-depth boundary](../../crates/naome-ledger/src/library/tests/depth_boundary.rs) |
| Accounting | [Exact monetary distribution](../../crates/naome-ledger/src/accounting/tests.rs) |
| Receipts | [Settlement inspection and canonical receipt tests](../../crates/naome-chain/src/state/receipt_tests.rs) |
| Authentication/time | [Action authentication](../../crates/naome-ledger/src/authentication/tests.rs), [signed time](../../crates/naome-ledger/src/time/tests.rs) |
| Consensus/node | [Consensus kernel](../../crates/naome-consensus/src/state/tests.rs), [node recovery](../../crates/naome-node/src/state/tests.rs) |
| Safety model | [Bounded explorer and mutation controls](../../crates/naome-node/src/state/safety_model/model.rs), [real signer/reopen replay](../../crates/naome-node/src/state/safety_model/replay.rs), [weighted arithmetic oracle](../../crates/naome-consensus/src/weight_oracle.rs) |
| Storage | [State history/signer/settlement recovery](../../crates/naome-storage/src/state/tests.rs), [journal I/O faults](../../crates/naome-storage/src/state/log_tests.rs) |
| Transport/runtime | [Network exchange](../../crates/naome-network/src/transport/state_exchange/tests.rs), [exact frame limits](../../crates/naome-network/src/transport/state_exchange/tests/boundary.rs), [peer isolation and lifecycle](../../crates/naome-network/src/transport/state_exchange/tests/lifecycle.rs), [wire protocol](../../crates/naome-protocol/src/state_exchange/tests.rs), [runtime intake](../../crates/naome-runtime/src/state/tests.rs) |
| CLI | [Agent](../../crates/naome-cli/src/app/agent/tests.rs), [durable actions](../../crates/naome-cli/src/app/actions/tests.rs), [private files](../../crates/naome-cli/src/app/files/tests.rs), [setup/local profile](../../crates/naome-cli/src/app/setup/tests.rs) |
| Process | [four_process_state_recovery_partition_and_independent_replay](../../crates/naome-cli/tests/state_process.rs): accelerated independent processes |
| LAB | [state_lab_acceptance.py](../../tools/state_lab_acceptance.py): real windows, actual provider, separate four-process state; report required |

## Requirement mapping

Names below identify concrete test functions within those sources. LAB references
identify runner actions and fields in the recorded acceptance report.

| Requirement | Executable evidence and scope |
|---|---|
| MVP-01 | Profile: `genesis_identity_binds_all_configuration_and_keys`, `rejects_duplicate_keys_roles_and_owners`, strict codec tests. Network: `state_noise_peer_with_wrong_genesis_never_delivers_application_payload`. LAB: `independent_process_custody` and immutable profile. |
| MVP-02 | Process test and LAB start four executables with separate configured histories, anchors, signer stores and keys. LAB records custody and agreement. |
| MVP-03 | State: `complete_a_h_b_c_workflow_preserves_attribution_citation_and_once_only_issuance`; Consensus: `verified_control_record_finality_binds_full_state_and_preserves_empty_library`; LAB compares complete state/accounts/claims/library. |
| MVP-04 | Consensus control-record test above; Storage: `complete_control_history_reopens_and_observer_uses_same_full_state`; Process finalizes an unapproved question without a proof. |
| MVP-05 | State: `canonical_wire_and_identifier_vectors`, `streaming_state_commitment_matches_materialized_canonical_bytes`; Profile and Protocol golden vectors; Process/LAB observer agreement. Target-platform agreement also requires completed CI. |
| MVP-06 | Questions: `rejects_free_variables_assumptions_imports_and_bad_syntax`, `profile_smaller_bounds_are_enforced_for_both_targets`, canonical/orientation tests. Receipts: `rendered_closed_targets_round_trip_without_changing_canonical_formula`. CLI `compile-question` and submission preview are exercised through operating procedures/LAB submission. |
| MVP-07 | State: `actual_queue_limit_and_exact_expiry_preserve_state_on_rejection`, `default_queue_accepts_32_in_finalized_order_and_rejects_33_without_mutation`; Runtime: `queue_receipt_is_not_finality_and_duplicate_identity_is_idempotent`. |
| MVP-08 | State A/H/B/C workflow; Library: `real_a_group_then_b_refutation_preserves_h_attribution_and_known_c`; LAB `helper_normalization_citation_known`. |
| MVP-09 | State: `complete_real_proof_settlement_and_replay_are_atomic`, `minimum_66_record_run_protects_active_slots_and_settles_timely_reveal_after_pause`; Library: `stale_library_parent_prevents_whole_publication_without_mutation`. |
| MVP-10 | CLI: `changing_local_agenda_profile_cannot_change_genesis_or_reinitialize_history`; LAB `actual_agent_review` with provider hash and actual question. Fake-provider tests do not supply the actual-agent evidence. |
| MVP-11 | CLI: `fake_provider_accepts_only_bounded_complete_decisions`, `changed_or_expired_voting_context_never_creates_a_signed_action`, timeout/process cleanup and durable budget tests. State vote/nonce tests prevent replacement of finalized votes. Manual fallback is an operator CLI path. |
| MVP-12 | State helper `open_and_approve` asserts three early YES votes leave phase Voting; `absence_never_counts_yes_and_expiry_never_means_refutation` rejects two YES. Consensus: `two_votes_never_finalize_and_duplicate_signers_never_add_weight`. Chain `every_timing_profile_preserves_complete_certified_phase_windows` checks exact full voting, commitment and reveal deadlines for Lab, research, short-test and ci-test using signed time certificates and canonical record replay. LAB phase/deadline observations. |
| MVP-13 | Time: `lower_median_and_parent_time_are_exact`, `distinct_registered_quorum_and_context_required`; State: `phase_start_deadline_and_nonce_rejections_leave_parent_unchanged`, `reveal_at_exact_deadline_and_wrong_original_author_are_rejected`. Process partition demonstrates no finality from local timers alone. |
| MVP-14 | CLI: `commit_secret_precedes_transmission_and_missing_action_or_lost_ack_reuses_exact_intent`; private file no-overwrite/durability helpers. LAB creates retained commitments before transmission. |
| MVP-15 | CLI: `retained_reveal_after_lost_ack_resends_without_open_phase_or_new_nonce`, `mismatched_private_bundle_author_genesis_secret_or_retained_reveal_never_transmits`; State exact-deadline/author rejection; Storage actual settlement recovery. |
| MVP-16 | State: `commitment_order_wins_even_when_reveals_arrive_in_reverse_order`, `invalid_or_missing_earlier_reveal_does_not_block_later_eligible_commitment`. LAB `AB02_reverse_reveal` and `AB02_missing_earlier`. |
| MVP-17 | Library: `invalid_unused_original_and_noncanonical_original_are_not_repaired`, `cycles_unknown_dependencies_wrong_target_and_known_roots_fail`; A/H/B actual checker fixtures; LAB `check-proof` for downloaded normalized certificates. |
| MVP-18 | Library: `different_new_certificates_of_same_statement_include_root_collision`, `same_derivation_original_alias_is_verified_then_removed_before_publication`. |
| MVP-19 | Library: `parent_selection_orders_height_operation_then_raw_proof_id`, `duplicate_helper_substitution_prunes_its_only_dependency_and_recomputes_root`; LAB B substitution and unchanged H provenance/payment. |
| MVP-20 | Library duplicate substitution/pruning test above, `cycles_unknown_dependencies_wrong_target_and_known_roots_fail`; Receipts: `receipt_reads_actual_settlements_and_rejects_truncation_and_reward_mutations`; LAB offline inspection. |
| MVP-21 | State atomic A/H/B/C workflow; Accounting: `arithmetic_failure_keeps_all_balances_unchanged`; Storage: `actual_settlement_anchor_failures_never_expose_partial_proofs_rewards_or_claims` and actual crash-image test. |
| MVP-22 | State: `absence_never_counts_yes_and_expiry_never_means_refutation`, `signed_old_attempt_reveal_never_resolves_new_attempt`, minimum-66 capacity/pending-settlement test. |
| MVP-23 | Process and LAB `fetch-proof-from` use another authenticated peer with node 0 stopped; B actually references H and credits its original recipient. |
| MVP-24 | Library: `older_ancestors_are_checked_but_only_first_boundary_proof_is_cited`, `repeated_boundary_paths_count_once_and_new_helpers_are_not_citations`, pruning test; LAB B payment inspection. |
| MVP-25 | Accounting: `no_citations_preserves_exact_supply`, `division_precedes_shared_recipient_aggregation`, `duplicate_or_unknown_recipients_cannot_gain_payments`; State A/H/B/C account assertions. |
| MVP-26 | Accounting exact distribution/overflow tests; Consensus: `finality_evidence_subset_and_consensus_round_do_not_change_value_or_successor`; LAB total accounts plus reserve equals three billion atoms after three completions. |
| MVP-27 | Receipts tests; Process export/verify; LAB question queries, inspection outputs, network download and independent `check-proof` of A/B/D roots with dependencies. |
| MVP-28 | CLI tests and complete Process/LAB command paths. [Operating guide](operations.md) distinguishes transported, finalized and settled states. |
| MVP-29 | Authentication: `every_wire_byte_is_bound_or_strictly_rejected`, `exact_action_roundtrip_and_roles`; State old-attempt and nonce tests; CLI exact commitment/reveal/agent retry tests; Runtime duplicate receipt test. |
| MVP-30 | Node: `cold_restart_resends_identical_completed_precommit_and_retains_record`, `all_validators_restart_after_prevoting_and_recover_the_durable_proposal`, `asymmetric_nil_quorum_delivery_recovers_after_full_cold_restart`; Storage: `proposal_and_both_votes_replay_for_exact_resend_until_round_changes`; Process/LAB returning-node catch-up. |
| MVP-31 | Storage: `actual_settlement_journal_crash_images_recover_only_old_complete_or_halted_state`, actual anchor-fault test, `signing_anchor_faults_never_publish_and_preparation_faults_never_use_key`; journal scripted I/O faults. These are explicit crash/fault experiments, separate from graceful process restart. |
| MVP-32 | Node: `absent_proposer_advances_by_nil_quorums_then_three_nodes_finalize_and_fourth_catches_up`, `clean_two_two_partition_does_not_consume_round_budget_and_heals`, `asymmetric_nil_quorum_delivery_recovers_after_full_cold_restart`; Process/LAB three live validators, 2:2 partition, restored links and convergence. |
| MVP-33 | State queue/capacity tests, `minimum_run_reserves_all_sixteen_authors_through_delayed_atomic_settlement`, and `multiple_reveals_share_budget_before_any_additional_checker_call`; Library count/byte/step/depth tests; Transport exact bounds/retention; Storage: `exhausted_signing_bytes_or_frames_never_use_key_and_pending_intent_recovers`. |
| MVP-34 | Library `qualification_actual_4096_steps_and_near_64k_certificate`, `qualification_17_used_nodes_near_compact_and_default_package_bounds`, `qualification_64_verified_older_citations_and_65th_reject_before_checker`, `qualification_near_2mib_older_closure_sixteen_authenticated_candidates`; exact queue/depth/frame tests; minimum 65/66-record state tests; LAB resource/timing report. Preserve measured output from both pinned profiles. |
| MVP-35 | Storage observer/full cold replay, `historical_conflicting_finality_is_verified_and_persistently_halts`; journal complete-corruption rejection; Process/LAB independent replay and corrupted export rejection. |
| MVP-36 | Account-admission State `registration_is_zero_starting_nonce_bound_and_idempotent_without_validator_rights`, `full_registry_preserves_existing_research_and_rejects_new_keys_atomically`, `registration_cannot_ride_on_reserved_progress_or_automatic_opening`; Process `new_researcher_registers_proves_receives_reward_and_survives_replay_and_restart`. The current combined run is recorded above; historical v2/v3 runs remain separately identified. |
| MVP-37 | Join-intent format `exact_join_intent_roundtrip_and_context_bound_key_possession`, `all_join_intent_bytes_are_bound_or_rejected`, `possession_roles_and_claim_fields_cannot_be_exchanged`; State `only_earlier_paid_claim_author_can_finalize_an_intent`, `author_can_replace_current_intent_without_gaining_authority`, `another_pending_intent_reserves_its_keys_and_endpoint`; CLI `join_intent_requires_own_claim_and_saves_a_pending_action_for_send`, `join_keys_are_private_role_specific_and_never_overwritten`; Process researcher flow. An intent remains preparatory until the separately tested sealed installation. |
| MVP-38 | Ledger `selected_claim_handoff_replaces_oldest_slot_and_retires_old_keys`, `attempt_opening_at_handoff_freezes_outgoing_owners_for_later_ballots`; Consensus [handoff seal and stable-slot tests](../../crates/naome-consensus/src/state/tests/handoff.rs); Storage READY/TERMINAL fault, period custody and candidate retry tests; Runtime [rotation and recovery](../../crates/naome-runtime/src/state/tests/handoff_lifecycle.rs); Process earned-owner quorum signature, future service payment and restart. Current run evidence is recorded above. |

## Acceptance scenario mapping

| Scenario | Required combined evidence |
|---|---|
| AB-01 | LAB independent startup, zero-balance A author, actual profile/agent invocation, three owner YES votes, real voting window; CLI profile isolation and State full-window tests supplement the run. |
| AB-02 | LAB reverse reveal ordering with distinct checked A roots and earlier winner; separate D attempt with missing earlier reveal and later winner. State tests additionally cover invalid earlier reveal. |
| AB-03 | LAB A is PROVED and publishes the used H/root; State A/H/B/C test checks no separate helper completion/claim. |
| AB-04 | LAB original provider stopped; network H retrieval from a different validator; distinct author B is REFUTED; duplicate H substituted; provenance retained and positive citation payment checked. |
| AB-05 | LAB C ends KnownUnpaid without completion payment; State A/H/B/C verifies unchanged issuance/claim count. |
| AB-06 | Component negative matrix: unapproved/expired attempt and late/old reveal (State); wrong target/invalid original/new duplicate (Library); mutated final effects/receipt (State/Receipts); chain/signature/role mutation (Authentication/Transport); queue/operation/package/work overload (State/Library/Transport). These are not all injected over the LAB network. |
| AB-07 | Actual settlement journal/anchor fault tests, including crash images; Process/LAB one node unavailable, partition, reconnect, catch-up, all-node cold start and independent complete-state replay; exact issuance and claim counts. |
| AB-08 | The current Process researcher flow creates and registers a new account, checks its zero starting balance, completes an approved proof, verifies its reward and earned claim, exports independently replayable history and cold-restarts the participating nodes. Account admission and registry-capacity negatives remain separate component tests. |
| AB-09 | The Process researcher flow records an earned join intent before activation; format, Ledger, Consensus and transport tests reject foreign or absent claims, conflicting nonce, stale or reused keys, endpoint collisions, bad possession proofs and premature authority. A current intent can replace its advertised pair while preserving its claim and queue order. |
| AB-10 | The extended Process researcher flow installs an earned claimant, decodes a later ordinary quorum to verify its selected signature, checks the next service payment, exports independently verifiable history and cold-restarts peers. Consensus and Storage tests cover conflicting seals, old-key rejection, READY/TERMINAL crash boundaries, failed preparation, candidate retry and retired custody. Runtime tests cover no-join rotation, vacant slots and owner-authenticated recovery; Ledger tests preserve frozen ballots. |

## Measurement and reporting boundaries

The qualifier measures real checked certificates and reachable work. Near-byte
limits are reported as the actual byte counts, not rounded up to an exact cap.
The many-candidate qualifier authenticates envelopes and accumulates one shared
verification budget; it does not claim that those candidates were admitted and
finalized together in a maximum-size record. Exact transport-frame tests qualify
bounded envelope parsing and custody, not the validity of arbitrary payload
bytes. The older-depth and queue tests use actual default capacities before
rejecting the next item.

Retain the `MVP34` measurement lines with machine/toolchain/profile information.
Component elapsed time, build time, process elapsed time, disk reservation floor
and observed disk use are different measurements. No throughput guarantee follows
from them. A compact local LAB run does not claim default-limit end-to-end network
throughput or multi-machine performance.

Reports identify the exact source snapshot that was measured. Earlier successful
runs do not qualify later code changes. Local checks, CI, lab execution, and
multi-machine qualification remain separate evidence.
