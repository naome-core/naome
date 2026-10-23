# Resource policy

`naome resources` prints effective limits and current allocation charges.
Defaults and validation have one owner: `crates/naome-knowledge/src/resources.rs`.
Set `NAOME_RESOURCE_CONFIG` before startup to override them:

```json
{
  "version": 1,
  "memory_bytes": 1073741824,
  "workers": [1, 2, 2, 2],
  "tuning": { "proof_bytes": 131072, "request_timeout_ms": 5000 }
}
```

Unknown fields, zeros, overflows and inconsistent allocations fail before startup.
The profile is immutable; children inherit its resolved snapshot. Library callers
use `resources::configure` before constructing a node. Allocation fields scale
with memory unless overridden; per-operation defaults and timers are independent.

The 512 MiB default reserves 256 MiB for one checker, plus caches, resident job
results and provider streams. Shared allocation leases charge retained proofs,
frames, closures, contacts and queued CLI source bytes. CLI parsing takes a
separate lease before expanding JSON; queue counts and payload sizes are
validated together. The four worker lanes default to `[1,2,2,2]` for
finding, solving, local interest and peer interest. Resident jobs derive from
these workers, four bounded role queues and a recovery page. Kernel slot locks
preserve physical worker custody across crashes; reconfiguration requires the
previous workers to drain. These are conservative defaults, not throughput optima.

Histories have no population or lifetime quota: budget accounts, job results,
original question sources, admission receipts and unresolved work stay on disk.
RAM holds bounded pages/caches; budget accounts follow retained jobs. A disposable
reverse dependency index wakes blocked proofs only when their missing dependencies
arrive; its ready FIFO cursor does not sync on idle ticks. Job/question history
keeps its durable FIFO cursors. Retries and restarts retain original allowances.
Missing established stores, corruption and uncertain cleanup fail closed.

Intake limits apply to new work. Existing current-format proofs, source records
and provider outputs are validated against canonical format limits during replay.
Changing assessment policy does not rewrite first-admission evidence. Role budget
defaults apply to new obligations; an existing obligation retains its original
settings, spent time, reserved units and deadline. Physical worker, memory and disk
limits still apply to execution. Insufficient replay resources fail explicitly;
valid history is never replaced with a fresh budget.

Disk preparation leases are shared by filesystem and survive staged batches.
They cover payload/journal overhead, checked-index writes and compaction mirrors;
compaction itself reserves its copy space before opening a successor. The separate
emergency reserve remains available for final accounting and recovery. These are
conservative admission reservations, not an operating-system disk quota.

A publication outbox precedes proof commit. The shared completion path persists
the original question before reporting success or acknowledging its job. Recovery
uses the mathematically replayed graph to finish committed publications and discard
uncommitted intents. Registry compaction copies only reachable authenticated nodes
in bounded quanta; old live snapshots retain their generations until release.

The remaining fixed bounds have specific purposes:

- Mathematical source, formula, certificate and assessment maxima preserve one
  deterministic codec/checker envelope. See [NAO limits](NAO_SKILL.md#finite-limits-and-complexity-discipline).
  Runtime budgets can narrow them; they do not cap graph depth or total history.
- SHA-256 widths, binary tags and integer widths define current framing. Patricia
  paths use 256 bits; 4 KiB nodes and 2 KiB inline values hold metadata, with large
  formulas stored separately. Exhaustion fails rather than wrapping counters.
- Checkpoints allow 1 MiB headers, 64 MiB rows, 16-byte kinds and 128-byte keys.
  Profiles allow 64 KiB; identity files allow 1 KiB. These bound malformed input
  before allocation. JSON/tree overhead factors reserve worst-case decoded data.
- Existing caller custody retains 80/192-byte pipe frames, the 180-second startup
  owner window and its original 10-second cleanup stages. Status replay keeps its
  30-minute window, two-second freshness and 384 MiB RSS ceiling plus two 64 MiB
  reserves. Configuration cannot widen those installed protection ceilings.
- One state/checker owner and one active peer closure serialize mathematical
  publication. DNS packet/record widths and vendored relay/DCUtR handshake limits
  bound protocol negotiation beneath the configured connection and relay budgets.

Overload rejects new work before allocation or leaves durable work queued.
Metadata can wait in the bounded transport handoff; state-dependent requests get
prompt busy responses. Transport-event overflow revokes publication and stops the
owner. Retryable commands retain their original deadline. Invalid proofs and
corruption never become ordinary retries or accepted knowledge.

Allocation accounting is per process, not an OS RSS limit for an external provider
process tree. `resource_workload` provides a fixed public-API commit/replay sample;
the normal tests separately cover 4,096 budget obligations, question histories,
restarts, row-write sizes, overload and control latency during a stalled write.
