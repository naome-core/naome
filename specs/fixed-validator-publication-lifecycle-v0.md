# Fixed-Validator Publication Lifecycle V0

## Scope and authority

`PROD-020-058` makes crash-recoverable consensus publication mandatory in the
Unix validator executable. It covers signed proposals, prevotes and precommits,
their exact original completion identities, and separate per-peer transport
progress. The library's `FixedValidatorRuntimeV0::new` retains its volatile
profile; `with_publication_journal` enables this profile before runtime polling.
The executable always enables it before reporting ready.

`PROD-020-059` adds optional, explicitly configured periodic retries through
`with_publication_retry_interval`. It requires the durable profile and must be
enabled before runtime polling. The positive interval is caller-local scheduling
configuration; it does not change consensus timeouts or validity. Omitting it
retains restart/reconnection-triggered retries.

The outbox source is the existing externally anchored signer journal. There is
no second signing transaction or post-signing payload dependency: each new
proposal completion contains every byte needed to reconstruct its original
consensus-push message, and completed votes already contain their exact bytes.
Delivery progress never authorizes signing, consensus admission, finality,
branch selection, rollback or repair. A transport receipt proves only the
correlated authenticated exchange; it does not prove remote consensus admission,
persistence or finality. Duplicate delivery is permitted. Exactly-once delivery
and general distributed liveness are not provided.

## Durable publication source

The proposal session reserves the exact bounded artifact payload before durable
preparation and key use. After the unchanged producer transcript is signed and
strictly self-verified, new proposal completions use local storage tag `0x0c`:

```text
tag[1] || producer_authorization[212] || canonical_artifact_payload[0..=4194305]
```

The existing length-framed chained record and external completion anchor cover
the complete body. Control bytes reconstruct from the already retained canonical
proposal intent and authorization. The signed proposal retains the exact payload;
driver publication uses those original bytes for an idempotent completed request.
Vote completion, canonical consensus wire formats, signature transcripts,
same-slot halt rules and signing-state ordering remain unchanged.

The original completion state identity binds context, fixed set, signer, height,
round, role and signed message through the existing header and chained history.
It remains the publication identity after later votes, checkpoints or heights.
The runtime borrows history only through the live node driver's sealed anchored
signing session. Stopped or poisoned signing owners cannot issue this capability.
Proposal payloads are strictly validated against the exact historical parent
and artifact snapshot supplied by retained selected finality history. A checksum
or storage record alone is not artifact-proof validation.

This closes the completed-signature-to-runtime-transfer gap. A crash after a
completed record and matching anchor but before any runtime publication command
can recover the whole message. Existing strict refusal for incomplete preparation,
unanchored complete suffixes, invalid history and terminal signer/finality stops
remains in force. This profile does not authorize repeating key use in any such
ambiguous state.

## Separate delivery snapshot

The vote-journal directory holds
`fixed-validator-publication-<signer-hex>.deliveries` and its exclusive `.lock`
file. The lock is explicitly unlocked on owner drop. Regular-file access rejects
symlinks and nonregular sources. This is a delivery snapshot, separate from the
anchored signer and finality journals.

Its exact prefix is the NUL-terminated ASCII domain
`naome:fixed-validator-publication-deliveries:v0`, chain ID `[32]`, genesis ID
`[32]`, protocol version `u32be`, fixed-set ID `[32]`, signer `[32]`, target count
`u8`, then each ordered target's `u16be` byte length and canonical PeerId bytes.
After the prefix are a `u64be` record count and strictly ascending original
completion-ID records:

```text
completion_state_id[32] || attempt_counts[8 * u64be] || received_mask[u8]
```

Each record is 97 bytes. Unconfigured attempt positions and receipt bits must be
zero; an acknowledged peer must have a positive attempt count. The final `[32]`
is SHA-256 over NUL-terminated
`naome:fixed-validator-publication-deliveries-checksum:v0` followed by every
preceding snapshot byte. Decode bounds derive from the exact sealed completion
history and fixed target count, before reading or reserving the full snapshot.
Unknown, duplicate or unordered IDs, invalid counts/bits, wrong binding,
truncation, trailing bytes and checksum mismatch refuse startup.

Creation requires zero completed signed records and creates a new receipt file
without overwriting an existing one. Strict open requires the existing valid
snapshot. Missing receipt entries for real anchored completions are inserted as
unacknowledged: a process may have died before runtime transfer registered them.
Missing files and malformed snapshots are not silently recreated. Target identity
changes, including reordering, refuse open; peer addresses may change. Historical
legacy `0x09` proposal completions remain readable by the lower signer journal,
but this profile refuses them because their exact artifact payload is absent.
No implicit migration or external source-file reload is provided.

Registration and each attempt are synchronized before transport submission.
Attempt counters use checked increment. Only successful completion of the exact
owned in-flight ticket can set a receipt bit, which is synchronized before
`PeerCompleted { received: true }` is returned. Replacements write a fresh
exclusive temporary file, synchronize it, rename it over the snapshot, then
synchronize the directory. Creation synchronizes the new file and directory.
Ambiguous I/O poisons the receipt owner and consumes runtime signing authority;
no successful durable receipt report is returned. Strict restart classifies the
installed complete snapshot. An older complete snapshot may cause duplicates;
it cannot supply new signing authority. This snapshot is not independently
anchored against malicious replacement of the local storage.

## Recovery and scheduling

Strict startup queues every completion with an unacknowledged target, in height,
round and Proposal/Prevote/Precommit order. Current-height completions also get
fresh ordinary local admission even when all peers previously acknowledged.
Recovery retains original bytes and original completion IDs and performs no
signing or anchor write. Previously acknowledged peers are marked
`PreviouslyReceived`; only unacknowledged peers receive attempts. Local admission
is volatile and independently reverified; it is not restored as trusted evidence.

One publication still backpressures normal driver transitions until local
admission and its bounded attempt pass complete. Refusal or asynchronous failure
finishes that pass but leaves durable resend debt. A managed peer `Established`
event coalesces outstanding debt for that recipient. Once the current pass and
active publication release their tickets, ordinary driver work and any exact due
consensus timeout precede a new reconnect pass. Queued and active completion IDs
are deduplicated; reconnection during an active failed attempt still leaves that
completion eligible after its pass finishes. No reconnect retry repeats local
admission. Strict restart also retries this debt.

`PROD-020-068` gives ordinary runtime work one opportunity after each completed
live historical message, for both reconnect and periodic passes. Startup replay
retains whole-queue priority and does not open these opportunities. The live
opportunity uses ordinary ordering: pending arms and commands, one retained
driver step, then an exact due timeout before input. A command produced by that
step transfers before another historical message can take publication custody;
a newly prepared publication completes its existing attempt pass first.
Between calls, ordinary proposal authoring may use the same opportunity under
the existing busy and signing checks. An idle opportunity polls transport once
without waiting, retaining input if a due timeout wins, then immediately resumes
the historical queue if no ordinary event is ready. An active publication or
transport ticket is never preempted. This is bounded interleaving, not a deadline
or general fairness guarantee across all classes of work.

### Explicit periodic retry policy

The optional interval has no default. The library accepts a positive `Duration`
whose addition to the current monotonic Tokio `Instant` succeeds; the process
accepts `[network].publication_retry_millis` as a canonical positive unsigned
decimal `u64` string. Values are never narrowed to `u32`. Zero, malformed or
unrepresentable values fail before process authority provisioning. Library
installation rechecks deadline addition; later deadline overflow consumes the
runtime signing owner through the existing fatal publication path.

The first interval begins at policy installation. A due interval is observed
only outside an active publication or recovery pass, after ordinary retained
driver work, pending commands and timer arms. An exact due consensus timeout
wins a tie, including when transport polling crosses its deadline. Buffered
input remains owned. Each new periodic pass gives transport one nonblocking
poll opportunity, so even a very short interval cannot bypass every ready
network event; a continuous stream of network events cannot by itself prevent
the next retry pass. Caller-supplied input retains its existing precedence.

An observed expiration snapshots the currently unacknowledged completion IDs
from sealed anchored history, ordered by height, round and role. This finite
queue is bounded by the existing signer-history replay limits. It adds no
unbounded timer-tick queue, new stored message copy or configurable history
retention limit. Each message gets one existing ordered per-peer attempt pass;
only unacknowledged targets are attempted and original signed bytes are reused.
Periodic delivery skips local admission; diagnostics distinguish that skip from
an attempted admission. In-flight ticket custody, aggregate-capacity waits,
persist-before-attempt and receipt-before-success ordering remain unchanged.

The periodic timer is suspended while its finite queue and intervening active
publication drain, including ordinary opportunities between messages. Afterward the next
deadline is the current monotonic time plus the full configured interval.
An empty pass also starts a fresh interval and reports zero queued messages.
Missed intervals coalesce into one observation, including across long caller
pauses; there is no catch-up burst. Reconnect triggers coalesce separately and
cannot append indefinitely to the currently draining pass. Ordinary driver work
and exact due observation occur before another reconnect or periodic pass.
These bounded opportunities do not guarantee fairness against arbitrary caller
actions, connection churn, unavailable peers or remote worker saturation.

Dropping a borrowed runtime future preserves the timer, pass and pending input.
`into_parts` and process teardown discard this volatile schedule. Strict restart
retains original completion IDs, bytes, attempts and acknowledged peers, performs
its existing startup recovery, and creates a fresh interval if configured.
Changing or omitting the retry interval on strict restart does not change receipt
identity binding. There is no persisted timer, retry-count cap, debt expiration,
exactly-once delivery, new proposal selection, signing-based reconstruction,
source job, proof acquisition or general distributed-liveness guarantee.

The network profile reserves one of the existing eight aggregate outbound
permits for consensus: background archive/acquisition work can occupy at most
seven. Consensus can cross an existing background request to the same peer,
while remaining limited to one pending consensus request per peer. New
background requests still refuse any occupied peer slot. The runtime keeps the
next recipient unattempted while all aggregate slots are held, and rechecks on
later polls, so completion can make the reserved slot available to the next peer.
Total outbound capacity,
consensus worker counts, ingress bounds and authenticated identity checks retain
their existing limits. Reservations do not promise fairness or available remote
workers. Managed outbound dials allocate a new local ephemeral port so a strict
restart does not reuse the killed process's listening-port TCP tuples.

Dropping a borrowed runtime future retains live custody. `into_parts` explicitly
ends durable supervision and releases the receipt lock and volatile recovery
schedule; its returned parts do not resume that supervision. Process teardown
disposes volatile reports, input, inboxes, sessions and timers. Durable restart
reopens the publication source and progress; it does not reconstruct operator
commands, acquisition jobs or transport tickets. Process JSONL reports expose
original completion IDs, recovered status and SHA-256 fingerprints of message
sections as diagnostics, without granting consensus authority.

## Evidence and limits

`crates/naome-runtime/tests/cases/publication_lifecycle.rs` checks proposal
completion before runtime transfer and both completed vote forms after transfer
but before external delivery, with exact original bytes, original IDs and
unchanged signer/anchor images. Its authenticated
connection test forces a receipt snapshot replacement failure, observes fatal
authority release without a successful peer report, rejects changed recipients
and missing/truncated receipt state, then strictly recovers exact resend debt.
`publication_journal/tests.rs` covers bounded strict decoding, lock release and
snapshot create/write/file-sync/rename/directory-sync failures. Network vectors
cover background saturation, batch refund, retained terminal permits and
consensus crossing a same-peer archive request. Process acquisition contention
vectors exercise consensus progress while an actual artifact response is held.

`crates/naome-validator/tests/cases/publication_restart.rs` launches four actual
equal-weight Unix validator processes. It withholds one recipient before an H2
proposal receipt, observes the other two receipts, SIGKILLs the proposer, removes
its original input files, and strictly restarts it while the other three original
processes remain alive. It compares independent signed-journal bytes, original
completion IDs and section fingerprints with recovered publication and actual
receiver admission. Only the previously unacknowledged peer is retried. All four
then finalize H2 and H3 and strictly reopen at next height four; a persistent
signing oracle checks pre-crash slots remain exact and all retained signatures
verify. Quorum progress need not require every validator to sign every role.
The restarted sender enables periodic retries, retains the exact partial peer
acknowledgements through managed reconnection, and observes an empty periodic
pass after H2 before the existing H3 progression and strict signing-history check.

`crates/naome-runtime/tests/cases/publication_retry.rs` refuses the initial
proposal, prevote and precommit transport receipts on one continuously connected
authenticated peer, then accepts byte-identical periodic retries. It checks
unchanged authority images during retry, skipped local admission, receipt-based
suppression, strict acknowledged reopen, cancelled polls, missed-tick
coalescing, consensus-deadline precedence and intervening ordinary transitions.
A real receipt-file replacement failure during a periodic attempt consumes
signing authority without a successful receipt event; strict reopen retains the
exact original unacknowledged message. `timer.rs` checks zero, overflow and
full-width interval boundaries. The executable's `publication_retry.rs` covers
repeated unavailable-peer attempts, strict reopen without source files, exact
original fingerprints, unchanged stopped-owner authority images and configuration
rejection before provisioning. These tests do not simulate power loss.

These are bounded local runtime and actual Unix process regressions. They do
not establish deployment readiness, non-Unix executable support, power-loss
hardware guarantees, Byzantine local-filesystem resistance, production timeout
calibration, arbitrary partition liveness or exhaustive crash coverage.
