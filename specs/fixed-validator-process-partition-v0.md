# Fixed-validator V0 process partition corpus

## Scope and authority

`SEC-012-003` tests a cold partition after a shared nonempty finalized prefix
using four actual Unix `naome-validator` processes. Each process retains its
original runtime, sole signing scope, and independent anchored journals for
the complete execution. The test supplies only ordinary configuration and two
explicit `author_fresh` commands for canonical artifact sources. The processes
create every proposal signature and vote, exchange bytes through authenticated
Noise/Yamux sessions, admit them through the runtime, and select finality through
the existing strict driver. No signature, quorum proof, selected history,
timeout ticket, driver event, or recovered signing scope is injected.

The transport's shared consensus request-response worker limit is two per
connection. A normal outbound request can therefore overlap an inbound request
whose response channel remains held. The workers are shared by both directions;
neither direction has a reservation. Per-peer outbound application requests
remain limited to one, retained inbound consensus events remain limited to one
per peer and eight globally, aggregate retained consensus body bytes remain
33,755,856, and total Yamux substreams remain eight. The individual exchange
limits, including the separately specified complete-finality-proof exchange,
sum to twelve and cannot all be saturated concurrently. This change adds
no retry, arbitration, fairness, reserved control capacity, or general progress
guarantee. The framing, signatures, receipts, ingress allocation checks, strict
quorum denominator, and durable formats are unchanged.

## Corpus and physical cut

Consensus keys are sorted by their actual raw key bytes before assigning
weights. An arithmetic-only proposer calculation predicts the two round-zero
authors; successful process authoring and actual H1 finality must establish the
corresponding authority. All four processes first establish the complete mesh,
finalize the same H1 artifact, complete every prepared publication with one
correlated received outcome from each of the other three peers, and report H2,
round zero, Proposal phase with no pending publication or driver command.

Each of the six undirected links has one test-only opaque TCP gate. Configured
peer addresses point exclusively to those gates. Only the child processes
terminate Noise and Yamux. Gate listeners are bound before process startup;
forwarding starts after the backend process reports its actual listening port.
The lower raw Noise PeerId owns dialing under the existing session policy.

A cut closes both directions of every registered cross-component socket and
rejects subsequent connections. Cut and stream registration share a mutex;
a connection established concurrently with a cut is checked again before any
forwarding. Every cross-component endpoint must report disconnection before
the only H2 proposal is authored. Internal links remain connected, and actual
redials must encounter the blocked gates. The partition is never healed.

| Case | Immutable weights | H2 components | Required result |
| --- | --- | --- | --- |
| Equal halves | `[1,1,1,1]` | `{0,1}` / `{2,3}` | Both `2/4` components retain H1 |
| Exact threshold | `[2,1,1,2]` | `{0}` / `{1,2,3}` | The three-key `4/6` component and isolated `2/6` owner retain H1 |
| Weighted quorum | `[3,2,1,1]` | `{0,1}` / `{2,3}` | Only the two-key `5/7` component finalizes H2 |

The H2 proposer is inside the tested three-key exact-threshold component and
the two-key weighted quorum. Each member of the proposer's component must
successfully admit its own and every other member's H2/R0 proposal prevote.
Non-proposers must admit the actual proposal through both voting and finality
routes and queue its receipt. Every internal peer also produces a received
completion. These requirements prevent a broken internal delivery path from
masquerading as threshold refusal. Other components have no H2 proposal.
Every owner that cannot finalize must admit real elapsed deadlines, publish
and admit a local nil precommit, and reach at least H2/R1 Proposal without H2
finality. No timeout lowers the immutable denominator or grants finality.

## Oracle, bounds, and shutdown

The independent small-integer component oracle requires
`3 * available_weight > 2 * immutable_total` exactly for the allowed winners.
Opaque TCP bytes and Noise peer labels are not treated as consensus signatures
or evidence of admitted weight. The no-cross-input assertions and exclusive
physical paths bound which honest signers can contribute after the cut; strict
finality replay separately verifies the retained real proofs.

The test observes JSONL events fairly across all four children. During the
partition milestone, every forbidden recipient's finality journal and anchor
must remain byte-identical to its drained H1 baseline. These finality files are
also compared after all children exit. Live vote-journal images are not used
as quiescent snapshots. For permitted H2 finality, the original H1 journal bytes
must remain an exact prefix.

Normal shutdown must report released locks and successful process exit. Only
after all four children exit does strict parent-owned finality-journal replay
check the exact record count, head, round-zero positions, artifact blocks,
canonical payloads, artifact-set root, and parent ancestry. Every common
consensus ancestry prefix is compared across owners. Full authority images
before and after replay must match, so successful replay cannot hide tail
repair. The parent uses the existing spawn/journal guard while it owns replay
handles. Assertion unwinding kills and reaps children before gate and directory
cleanup; gate shutdown interrupts its bounded copy workers.

Each phase uses the already-supported test-local duration of five seconds plus
one millisecond per round. A milestone has a 45-second wall-clock bound. Each
process transcript contains fewer than 4,096 events; each of its four inboxes
has 128 entries and 1 MiB without drain or reset. The driver/recovery round
ceilings are four, finality replay round ceiling eight, vote preparation bound
64, and proposal preparation bound eight. Each gate permits at most four
forwarded connections and 64 rejected redials; the successful corpus requires
exactly one forwarded connection per link. These are fixture bounds, not
production timing recommendations.

## Evidence limits

The three process cases are implemented in
`crates/naome-validator/tests/cases/partition.rs` and its `gated_tcp.rs` helper.
The separate transport regression holds both reciprocal inbound requests until
explicit acknowledgement, rejects an extra public outbound request to the
same peer with its original allocation, and completes both correlated receipts.
The separate `crates/naome-runtime/tests/cases/duplex.rs` regression drives two
equal-weight runtime owners only through ordinary `next_event`, requires their
actual local and remote precommit admissions, all five successful publication
receipts, and matching finality.

This is finite local Unix process and loopback partition evidence. Strict
finality-journal reopening here establishes healthy retained finality, not
process restart or complete vote-journal recovery. The corpus does not cover
arbitrary schedules, topologies, weights, Byzantine behavior, in-flight
precommit cuts, healing, crash faults, dynamic validators, general partition
safety or liveness, deployment, or production readiness. `SEC-012` remains
`IN_PROGRESS`. The independent driver and caller-input runtime corpora retain
their separately documented evidence boundaries.

The separate [process-kill restart corpus](fixed-validator-process-partition-restart-v0.md)
adds a proposer-centered star, a non-nil lock, and continued isolated voting
after one actual process kill and strict restart. Its bounded evidence does
not widen the three cold-partition cases above.
