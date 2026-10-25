# Node resource policy

`resources` is the single owner of native capacity selection, live work admission,
resource observations and conservative allocation custody. Mathematical validity,
protocol encoding, durable obligations and process ownership retain their existing
owners. Hardware observations never grant proof or publication authority.

## Capacity and configuration

Native startup observes the node's filesystem, usable CPU quota, memory limits and
available memory. `calibration.rs` derives one process capacity, provider lane
allocation, cache ceilings, queue capacities and local page sizes. The soft descriptor limit and already open files bound
provider lanes and socket capacity, while preserving a separate descriptor
reserve for control, SQLite generations, shutdown and recovery. Coupled values
are validated together before constructing a node. Arithmetic uses wide
intermediates, including on large-memory hosts. Hardware that cannot preserve
the checker allowance and existing replay reserves is rejected explicitly.

`NAOME_RESOURCE_CONFIG` is an explicit owner ceiling. `ResourceProfile::default()`
remains the deterministic reference for explicit profiles and library callers;
it is not the ordinary native node's hardware-selection algorithm. A configured
profile is never silently replaced. Child processes inherit the parent's exact
resolved capacity through `NAOME_EFFECTIVE_RESOURCES`; they do not independently
reload a mutable configuration file. Physical capacity remains immutable during
one process lifetime. Existing slot locks must drain before a restart changes
the physical lane allocation.

The default scheduling intervals in `autonomous::Intervals` use zero to select
automatic scheduling. Positive intervals remain explicit owner pacing. The
resource selection in `resource-profile.json` retains Light, Dynamic, Heavy and
Custom semantics; Custom values remain upper bounds. No command is needed to
run a benchmark or tune an individual queue.

## Live observation and calibration

`adaptive/observation.rs` reads bounded OS data. Resident memory records the state owner and a conservative sum of its live
descendants separately. The governor checks their combined consumption against
the installed capacity; an existing local work-memory target keeps its original
state-owner meaning. CPU time includes the live tree and reaped descendants. Unrelated processes contribute to host pressure and
available memory, not to the node's own charged tree. Linux cgroup ancestors and
process limits narrow the effective hardware ceiling. Linux PSI and the macOS
kernel memory-pressure level inform pressure handling.

`feedback.rs` records executed checker operations, compaction visits, request
latency, cache lookups and provider backlog at their existing owning boundaries.
These observations are process-local scheduling evidence, not durable proof
facts. `adaptive/governor.rs` combines fresh observations with this feedback.
Expensive work reduces the execution quantum; faster work permits gradual
growth. Cache growth requires observed reuse as well as misses; one-pass
streams do not cause unbounded growth.
Memory, disk, power-saving or thermal pressure closes computation admission.
Native CPU deltas subtract the node process tree over the same interval; load
average is diagnostic only. External host CPU above 85% for ten seconds pauses
computation; recovery requires CPU below 60% and thirty seconds of clear
conditions with memory and disk headroom. These are stability-policy starting
values, not measured optimal thresholds. Unsupported OS pressure, energy or thermal sensors
remain unknown; a previously asserted condition must be confirmed clear before
resumption. Linux uses firmware thermal trip points; macOS uses the OS warning.
A transient hardware observation failure closes new work using the last valid
snapshot and retries without stopping the network or fabricating a fresh sample.

Sampling frequency includes its own
observed cost and remains bounded by existing control/freshness deadlines. Native
subprocess probes have both output and wall-clock bounds and retain custody of
a timed-out child until reaping is confirmed. One unreaped probe prevents more
helpers from accumulating.

`operating.rs` projects the live budget onto local working sets. Caches share a
conservative capacity-weighted target, including retained generations and program
evaluators; mandatory small SQLite/codec buffers remain covered by the process
reserve. Page sizes, queue admission, role concurrency, compaction portions and
automatic scheduling follow the same projection. A cache reduction takes effect
at the owning operation boundary; it is not a synchronous RSS guarantee.

Already admitted memory and disk leases remain valid and drain. Control requests
and bounded publication readback retain their reserved paths during a work pause.
The existing `Computation` gate tracks draining work from this same live budget;
it owns no second pause flag. Compute concurrency and quanta become zero while
a single bounded network request remains possible. Memory leases still enforce
actual headroom and the immutable shared capacity.
Identify protocol/address vector bounds remain at their original protection
ceilings (32/16), independently of adaptive transport queues and stream counts.
In-flight responses are checked against the installed admitted format bounds,
not a newly reduced page size. The serialized state owner remains singular.

## Persisted data and restart

The current catalog commitment is streamed with one member/payload resident at a
time. Its digest bytes, membership, ordering and payload checks do not depend on
the current batch budget. A smaller replay page may return fewer records under
memory pressure; the ordinal cursor still visits the complete history. Changes
to SQLite cache size or busy timeout do not change schema or durability checks.

Completed research results that exceed a smaller resident working set remain in
the original journal and are recovered through its FIFO archive scan. Their
original IDs, outcomes, accounting and acknowledgements remain authoritative.
Active obligations that cannot fit the installed capacity produce explicit
resource overload; startup never discards them or creates fresh allowances.
Shrinking hardware does not extend an obligation's deadline or work-unit budget.

## Boundaries that calibration does not relax

The resource-policy table in `resources.rs` is the canonical inventory of
reference values and owner overrides. Do not copy those values into consumers.

| Contract | Owner and treatment |
| --- | --- |
| Canonical formulas, certificates, definitions and question targets | Foundation, proof and checker crates; unchanged format bounds |
| Program records and transfer chunks | `naome-proof::program`; unchanged record/chunk maxima, variable local portions |
| Checkpoint rows, headers and authenticated disk-map nodes | Owning persistence/checker codecs; unchanged current formats |
| Question assessment search and policy identity | Checker question policy; resource exhaustion remains inconclusive |
| Job horizons, work units and uncertain effects | Durable job/account owner; no refund, reset or automatic extension |
| Peer fairness, request rates, payload widths and relay allowances | Transport/discovery owners; calibration never removes validation or peer limits |
| Replay guard, startup custody and cleanup | Native lifecycle owner; existing ceilings and original deadlines remain binding |
| Disk reserve and pending reservations | Shared disk custody; completion/recovery reserve is preserved |

Throughput improvement requires comparable measurements on the relevant
hardware and workload. Correctness tests establish the exercised adaptation,
pressure, integrity and recovery behavior; they do not establish a universal
optimal setting or a measured performance gain.
