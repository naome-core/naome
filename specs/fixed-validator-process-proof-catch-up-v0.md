# Fixed-Validator Process Proof Catch-Up V0

## Scope and authority

`PROD-020-060` adds one explicit bounded catch-up operation to the Unix
validator. A caller chooses one configured static peer and a count of 1–16
successive heights. The process requests complete finality envelopes and
artifact payloads through the existing [archive exchange](fixed-validator-archive-v0.md).
Each complete direct-child proof independently enters the live driver's strict
verification and existing anchored finality-to-signer handoff. An authenticated
peer supplies bytes, not a trusted head, checkpoint, branch or validator set.

This operation uses no candidate or payload source store. It does not discover
peers or heads, choose among peers or conflicting proofs, assemble raw votes,
invoke historical or paired conflict operations, change quorum rules, or grant
proposal or vote signing authority. It adds no background following, retries,
persistent job intent, source population, repair, dynamic validators, custody
integration or general distributed-liveness guarantee.

## Direct complete-envelope ingress

`FixedValidatorNodeDriverV0::commit_finality_envelope` consumes one supplied
complete envelope and owned payload. Pending driver-command custody precedes
all input work. Every non-fallthrough current-finality classification retains
its existing priority, including a complete retained pair after saturation.
The caller must return to ordinary driver processing or explicitly dispose of
inbox custody; a downloaded proof cannot supersede those gates.

Checked successor timer generation precedes scope transfer and proof work.
Existing signer/branch height coherence and persisted signer-round ceiling
checks remain fatal. Exceeding the driver's caller-local signer-round ceiling
is an unchanged-state rejection. Neither live phase, due state, lock nor
current signing readiness can veto otherwise eligible complete finality.

The branch's existing `decode_and_verify_envelope_with_round_limit` bounds and
canonically frames the complete envelope, derives its embedded evidence round,
and requires the live branch's exact next height. Evidence rounds below,
equal to or above the signer round are eligible only within both the driver's
construction-time and persisted finality ceilings. Routing fields remain
unauthenticated until complete producer authorization, fixed-set strict
supermajority, branch-state and canonical artifact verification succeeds.
The caller supplies no independent round, height, parent, root or winner.

Typed pre-effect rejection consumes the supplied bytes and returns the exact
unchanged driver. A verified owned transition enters the existing independently
anchored finality commit and signer-height handoff. Only completed handoff
returns a child round-zero Proposal driver, preserves all four inboxes and
queues exactly one successor arm. Fatal preflight, finality or signer errors
return no driver; strict anchored reopen determines the durable prefix. No
cross-journal atomicity or repair is added. Old-height or wrong-parent input
is rejected as ineligible for this direct-child route, never reclassified as
historical conflict evidence.

The runtime's matching method checks driver, pending-command, pending-arm and
publication custody before delegation. Refusal returns the original payload
allocation. Delegated rejection restores the driver without changing independent
queued input, timer or publication custody. Success uses the existing timer
handoff; fatal outcomes retain independent custody only for disposal.
`request_finality_proof` applies that same runtime custody gate before requesting
one exact address on the existing bounded transport. Starting or completing a
transport request alone performs no consensus verification or anchored effect.

## Commands and job lifetime

The existing strict JSON object framing admits:

```json
{"command":"sync_finality","id":10,"peer_id":"<configured PeerId>","count":2}
{"command":"sync_status","id":11}
{"command":"cancel_sync","id":12}
```

Count is a JSON unsigned integer in 1–16. Correlation IDs retain the full `u64`
range. There is no caller height or round, peer fallback list, checkpoint or
source file. Unknown, duplicate, missing and wrongly typed fields reject.
One catch-up job and the existing source acquisition phase are mutually
exclusive: a second start rejects before peer work and does not cancel the
first. Other operator commands, runtime work, configured proof serving,
publication recovery/retries, stdin/output monitoring and signals continue.

A start derives the live driver's next height, checks the inclusive last-height
addition, and captures one 120-second whole-job network deadline, matching the
bounded archive profile. A disconnected, unknown or physically busy peer or
runtime custody refusal rejects the start; no job, queue or retry is installed.
A successful `command_result` contains `sync_started` and the job's ID, peer,
next height, last height and completed count. `sync_status` returns that same
bounded job description or null. Heights and progress counts are decimal
strings; IDs remain JSON integers.

Only the exact ticket's network owner, request generation, authenticated peer,
context and height correlate a response. A mismatch or late response emits
`sync_response_discarded` and cannot revive a job or advance another one.
A correlated response must arrive before the job deadline and while the driver
still owns the captured next height. The selected history is append-only:
a change in that owned height invalidates the captured selected parent and
stops the job. Round or phase advancement at the same height does not by itself
invalidate a proof. Complete envelope verification still rechecks the actual
live branch and context at the moment of delegation.

`Unavailable`, transport failure, selected-head drift, runtime refusal or
continuing driver rejection ends the job and disposes the response. No busy
proof is retained for a later attempt. Driver diagnostic events distinguish
continuing rejection/priority from fatal loss of authority. Fatal outcomes
end the process through its existing teardown path.

After each completed anchored handoff, `sync_progress` reports the exact height
and completed count. Its ordinary `finality` event still reports the new driver
state. After the final requested height, `sync_completed` ends the job even
when the peer retains later history. Otherwise the job waits for ordinary
runtime scheduling to transfer the child Proposal arm before starting the next
request to the same peer. It does not step the driver or acknowledge timers
itself. A successor request refusal stops the job; it adds no automatic retry.
If synchronous verification or fsync outlasts the network budget, completed
anchored work remains committed; no further request begins. A final successful
height may complete after that budget. The deadline cannot interrupt synchronous
verification or persistence and grants no production timing guarantee.

`sync_stopped` identifies the reason and retained completed prefix. Explicit
cancellation returns `sync_cancelled` with the original job or null and ends
logical job ownership. It cannot retract anchored progress or release the
transport's physical per-peer request slot; the late terminal or lower timeout
still disposes that custody. A later explicit start may therefore refuse until
physical custody resolves. Shutdown and signals dispose the job through normal
teardown. Lost output cannot undo an acknowledged durable prefix.

Strict restart restores only the existing anchored signer/finality state and
independent publication lifecycle. It restores no sync ID, peer choice, ticket,
response, deadline or remaining count. A fresh explicit command begins from
the then-current healthy next height. Partial or ambiguous anchor writes retain
the existing strict refusal classifications; no job resumes through them.

## Evidence boundary

Driver tests exercise all signer-relative proof rounds, retained inbox and due
custody, malformed and foreign proof/payload input, bounded evidence rounds,
selected-height replay, priority before generation/proof work, timer exhaustion,
finality/signer anchor failures and strict child reopen. Runtime tests exercise
exact payload refunds, queued input allocations, due phases, anchored handoff,
consuming failure and driver-unavailable request refusal.

Actual process tests use a retained-proof provider and a validator consumer to
commit only a bounded prefix, retain that prefix when the next proof is absent,
and strictly reopen without input files or a resumed job. A separate controlled
Noise-only peer supplies already prepared proofs to exercise invalid responses,
cancellation and late replies, SIGKILL, concurrent head change, retained-finality
priority and a real outstanding consensus publication. Those prepared fixtures
are not attributed to honest live consensus production by the serving peer.
These vectors establish this bounded profile, not arbitrary network scheduling,
exhaustive I/O cuts or general partition/liveness guarantees.
