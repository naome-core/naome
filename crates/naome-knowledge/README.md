# Node lifecycle and computation

See [networking and security](NETWORKING.md) for automatic Internet discovery,
encrypted transport, public graph visibility and trust boundaries.

`naome start` starts the node. `naome pause` closes admission for productive
computation while keeping gossip, discovery, peering and bounded delivery of
already checked proofs available. `naome resume` opens computation admission
again. Both commands require a running node and are idempotent.

`naome status` reports network readiness separately from computation:

- `running`: computation can proceed within the existing resource budgets.
- `pausing`: no new computation is admitted; an admitted step is still draining.
- `paused`: admitted computation has reached a safe boundary.
- `stopped`: the node is stopped.

Use `naome --json status` for the machine-readable `computation` field. A pause
request can return `pausing`; subsequent status reads show when it becomes
`paused`. Existing provider steps finish at their confirmed checkpoint boundary.
Providers retain their original deadlines, reservations and cancellation paths;
pause does not grant additional time or work. A non-cooperative step remains
`pausing` until it finishes or its existing deadline ends it.

During a pause, the node defers generation, solving, interest assessment,
mathematical intake, bulk fetching and background compaction. Incoming offers
receive a retryable protocol refusal; in-flight payloads can be requested again
after resume. No unchecked proof becomes accepted. Existing queues and transport
limits remain bounded.

Computation pause is independent of automatic memory and disk pressure. Serving
checked data still obeys all existing memory, disk, per-peer and transport limits;
resource pressure may therefore restrict delivery even while peering continues.
Network work still uses CPU, memory and bandwidth, and the host must remain awake.

The pause belongs to the current daemon. `start` on an already running paused
node preserves the pause. `stop` ends the daemon; a later start, including after
a crash, starts with computation enabled and revalidates persisted proofs through
the existing startup path. `interest` remains available during a pause.

Status also reports `proof_verification`. A live checked graph reports `checked`;
a stopped node reports `not_run` and its `accepted_proofs` count describes recorded
admissions without mathematical replay. Offline controls still check structural
storage integrity. Every startup independently rechecks all admitted proofs before
they can be used as checked knowledge.
