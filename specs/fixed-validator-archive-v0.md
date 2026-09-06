# Fixed-Validator Archive V0

## Scope and authority

`SEC-003-002` extends the Unix `naome-verifier` executable with an optional
archive profile. It retains the [verifier process](fixed-validator-verifier-process-v0.md)
public configuration, complete-proof verification, independently anchored
finality journal, strict restart and bounded I/O lifetime. A separately loaded
Noise identity permits static authenticated sessions. It is not a consensus
signer; the process owns no consensus secret, vote journal, validator driver,
vote collection or consensus runtime.

An operator explicitly requests a bounded sequence of complete finality proofs
from one configured peer. Each exact next-height envelope and artifact must
independently pass the existing verifier before anchored publication. The same
process serves its healthy retained history to configured archive peers. An
archive seeded through local complete-proof imports can therefore supply
another archive, which can strictly reopen and serve the same first evidence
to a third archive without the original source files.

The separate `SEC-003-003` [validator provider](fixed-validator-proof-provider-v0.md)
can supply the same complete proofs from its live selected history when
explicitly enabled. The archive requires no new peer-role field or consensus
observation to use that source.

This archive profile does not itself own live-validator proof serving, continuous following,
proposal/vote observation or assembly, automatic peer/source choice, head or
checkpoint discovery, branch selection, data retries, persistent sync intent,
automatic repair, dynamic validators, economics, or general full-node
conformance. `SEC-003`, `SYNC-001`, `SYNC-002` and `SYNC-004` remain unfinished.
Configured peers grant transport access only; they cannot replace the public
configuration, expected context, selected parent or complete verifier.

## Optional network configuration

Omitting `network` preserves the offline profile, including no private key or
transport. To enable an archive, add this table to the public configuration:

```toml
[network]
identity_seed_file = "noise.seed"
listen = "/ip4/127.0.0.1/tcp/0"

[[network.peers]]
peer_id = "<explicit configured libp2p PeerId>"
address = "/ip4/127.0.0.1/tcp/9000"
```

All three network fields are required. Zero peers uses `peers = []` in the
`network` table; otherwise at most eight distinct nonlocal identities are
permitted. Addresses are exactly literal `/ip4/<address>/tcp/<u16>` or
`/ip6/<address>/tcp/<u16>`. Listener port zero is allowed; peer port zero is
rejected. DNS, peer discovery and learned-record authorization are absent.
The existing static session contract chooses the lower raw `PeerId` as the
sole dial owner and retains its bounded reconnect behavior. Sync does not
initiate a connection or modify routing.

The seed path resolves against the configuration directory. Before authority
provisioning, open its final component without following symlinks and with
nonblocking mode, inspect that same regular descriptor, require the current
effective owner and no group/other permission bits, and read exactly 32 bytes.
Temporary seed buffers are zeroizing. Derive the Ed25519 Noise identity and
reject equality with every configured consensus public key. This comparison
detects configured key reuse; it cannot establish the seed's use elsewhere.
No seed, public configuration or source proof is generated or rewritten.

All configuration and network preflight precede finality-file creation/open.
The listener is installed before provisioning, but no network event loop or
application serving runs until strict replay returns a healthy owner.
`ready` confirms that owner; `listening` and `peer_session` separately report
the actual bound address/local identity and observed session transitions.
A halted strict reopen emits `halted` and releases ownership without becoming
ready or serving history. Bind/listener errors terminate the owner.

## Explicit synchronization and reporting

```json
{"command":"sync","id":10,"peer_id":"<configured PeerId>","count":2}
{"command":"cancel_sync","id":11}
```

`count` is a JSON unsigned `u64` integer in 1..=16. Before any request, require
an inactive sync, parse the selected peer, read a healthy anchored head and
check `head_height + count` without overflow. The first address is exactly
`head_height + 1`; the last address is the checked sum. Start requires that
configured peer's established session and the existing shared request permit.
Disconnected, unknown or physically busy peers cause `sync_request_start`
without a logical sync. There is no queue or automatic start retry.

`sync_started`, returned as a normal `command_result`, records the exact peer,
first and last heights. One volatile sync owns the command ID, peer, last
height, acknowledged count, absolute deadline and one exact generation ticket.
While active, another `sync` and local `import` reject with `sync_busy` before
proof-file work. `status`, `record`, `cancel_sync` and `shutdown` remain usable;
the process may also serve healthy retained proofs. Local commands and network
events receive no permanent relative priority; signals and output failure
retain the outer termination gate.

The [complete-proof exchange](artifact-network-transport.md#complete-finality-proof-v0)
carries each exact context and positive height. A correlated complete response
must match its expected context and height and the current head's direct
successor. The untrusted envelope prefix is only routing. The common import
path verifies the full envelope, weighted certificate, round ceiling,
scheduled producer, selected ancestry and canonical artifact mathematics, then
consumes the sealed transition through the unchanged anchored commit.

After each anchored publication, `sync_progress` carries the original ID and
the existing import outcome. Only then may the next height be requested.
After the last publication, `sync_completed` reports `completed` and
`last_height`. Heights and counts in outcomes use decimal strings. No sync
report upgrades Noise authentication into proof validity or peer provenance.

Unavailable content, wrong address/context, invalid complete proof, transport
failure, expired deadline or failure to start a successor emits `sync_stopped`
with ID, reason, `completed` and `next_height`. No later request starts, and
only the already acknowledged anchored prefix is reported as completed. A
later explicit command starts from the then-current healthy head. No error
causes fallback to another peer, response, proof assembly or implicit retry.

A commit error emits `command_failed` with the original ID, `completed` and
`strict_restart_required: true`, then terminates ownership with an `error`
report. It never acknowledges the failed height or promises unchanged file
images. A synchronized journal suffix may remain ahead of the anchor; strict
restart refuses that complete gap without repair. State-read failures also
end ownership. Reports claim released locks only after ownership has dropped.

## Deadline, cancellation and serving lifetime

One 120-second monotonic deadline starts immediately before the first request
enqueue and is never reset by a later height. Expiry wins before admitting a
response, including equality, and is checked again before starting a successor.
It bounds network waiting; it cannot interrupt synchronous verification,
filesystem operations or replay. A commit already running may finish after
the deadline and be acknowledged. If it was the last requested height, sync
completes; otherwise it stops without issuing another request.

`cancel_sync` returns `sync_cancelled` with the original `sync_id`, `completed`
and `next_height`, and removes that volatile command intent. Without active
sync it rejects with `sync_inactive`. Cancellation, expiry and shutdown do not
roll back acknowledged finality. Dropping a ticket does not physically cancel
libp2p work: its peer slot and shared permit remain occupied until the terminal
event drains, so an immediate same-peer command can still reject. A late
terminal emits `sync_response_discarded`, drops any response custody, and
cannot commit, resume an old sync or complete a different generation.
Strict restart restores only anchored history, never sync intent.

Each inbound complete-proof request is explicitly routed to the healthy owned
anchored journal under the transport's channel, shared response-rate and
custody limits. The exact first retained envelope and matching artifact are
copied for that height. Foreign context or an absent height is unavailable.
Journal errors end ownership; channel, rate or response-capacity failures emit
`proof_response_failed`. `proof_response_queued` reports only local queueing,
including unavailable responses. It proves no remote receipt or storage.

There is no general artifact/block/head responder or consensus ingress in this
profile. Unsupported application events are dropped. EOF, signals, shutdown,
output failure, listener failure or a terminal journal outcome release the
network and journal owners. Already transmitted serving bytes cannot be
retracted by later cancellation or halt. Existing input/output bounds remain;
transport response limits do not bound all retained history or verifier memory.

## Evidence and limits

Transport tests cover exact wire bytes, both length checks before allocation,
every truncated prefix/body of a minimal response, exact EOF, minimum/maximum
bodies, shared response capacity, cross-instance/generation/peer tickets,
cancelled partial reads/writes and real timeout/reconnect request retention.

Actual Unix child-process tests cover three-archive transfer and strict relay
reopen with original source files removed, first-evidence retention, exact
retained envelopes/payloads and ancestry, unavailable heights, wrong address,
context, signature, payload and exact-two-thirds certificates, explicit retry,
busy/cancel/late-response behavior, disconnect and shutdown after an anchored
prefix, real anchor failure with unrepaired strict-restart refusal, halted
history refusal, and configuration rejection before authority creation.
Consensus test keys and proof construction remain in the parent fixture;
these are complete-proof archive tests, not live validator proof production.

This is finite transport/process/restart evidence. The real 120-second
whole-command deadline, every crash/syscall schedule, power-loss durability,
general consensus safety/liveness, and deployed operation are not established
by this corpus. No CI or deployment result is implied by these normative claims.
