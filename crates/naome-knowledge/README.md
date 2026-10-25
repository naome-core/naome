# Node lifecycle and computation

See [networking and security](NETWORKING.md) for automatic Internet discovery,
encrypted transport, public graph visibility and trust boundaries.

`naome start` starts the node. The resource governor automatically pauses
productive computation when resources or operating-system policy require it,
and resumes it after a stable recovery window. `naome stop` ends the node.
`naome interest <text>` remains available while computation is paused.

`naome status` reports network readiness separately from computation:

- `running`: computation can proceed within the installed resource budgets.
- `pausing`: new computation is closed; an admitted step is still draining.
- `paused`: admitted computation has reached a safe boundary.
- `stopped`: the node is not running.

`naome --json status` exposes `computation` and `computation_reason`. The reason
is null while computation is running or the node is stopped. A pause may first
report `pausing`; existing provider steps finish at their confirmed checkpoint
boundary. Original deadlines, reservations and work-unit accounting continue to
apply during a pause. A non-cooperative step remains subject to its existing
process supervisor and cleanup limits.

During a pause, the node defers generation, solving, interest assessment,
new proof intake and expensive validation. Gossip, discovery, peering and bounded
delivery of already checked proofs remain active. No unchecked proof becomes
accepted. Existing queue, protocol, peer and transport limits remain binding.
A real memory shortage can still refuse a network allocation; network service
never bypasses the installed shared capacity.

The same governor decision controls ordinary work and provider boundaries.
There is no separately persisted manual pause state. Restart re-observes current
conditions and revalidates stored proofs through the existing startup path;
a restart does not grant new time or work to retained obligations.

See [the resource policy](src/resources/README.md) for capacity ownership,
pressure signals and recovery behavior. Native energy or CPU savings have not
been measured.
