# Direct Candidate Offer Intake V0

## Scope and authority

`PROD-020-071` adds direct authenticated publisher offers to the optional local
fixed-validator supervisor. Publishers are explicitly configured Noise peers.
There is no automatic relay, gossip, discovery, peer addition, remote signing
service, or change to selected-history authority. An offer is a replaceable set
of untrusted candidate IDs, not an assertion of validity, availability, order,
finality, or agreement. Source acquisition and full local validation remain
required before the existing durable proposer preference can be established.

This is a bounded fixed-validator V0 profile. General admission, eviction,
retention, traffic and relay policies under `NET-008`, `NET-010`, `NET-011`,
`NET-015`, `NET-016` and `NET-021` remain unresolved outside this profile.

## Wire and receipt

The protocol identifier is `/naome/candidate-offer-v0`. A request consists of:

| Field | Bytes | Contract |
| --- | ---: | --- |
| Chain ID | 32 | Untrusted artifact-chain context |
| Candidate count | 1 | Unsigned count from 0 through 32 |
| Candidate IDs | 32 each | Strictly increasing canonical byte order, no duplicates |

The complete request is at most 1,057 bytes. The decoder checks count before
allocating the body and rejects truncation, extra bytes, duplicate IDs and
noncanonical ordering. An empty set withdraws only this publisher's hints.
A receipt is exactly the 32-byte SHA-256 of the complete canonical request;
truncated or extended receipts are invalid. The outbound ticket correlates the
network instance, authenticated peer, peer-local request generation, exact
request and digest. A mismatched terminal preserves both routable owners.
Transport failure or a wrong digest is never a success receipt.

The low-level acknowledgement method must be called only after the application
has durably accepted the complete offer. The validator implementation below
meets that obligation. A receipt reports that acceptance; it promises neither
permanent retention nor validation, candidate choice, source bytes or finality.
Lost receipts can be retried. A publisher may replace its own offer after a
receipt, so receiving a receipt does not pin that offer forever.

## Bounded authenticated transport

At most eight peers are configured in total, including consensus peers and
publishers. Each authenticated peer selects its own request-response behaviour
and codec before body allocation. That codec has two retained-request slots and
2,114 retained wire bytes. These bounds include requests being decoded, queued
in connection handling, or retained by an application; memory is reserved before
reading the variable body. Retaining an application handle across timeout or
reconnect continues to charge the same peer's account. No other peer can charge
it. Aggregate candidate-offer custody is at most sixteen requests and 16,912
wire bytes, plus fixed transport/request metadata and bounded decoded IDs.

Each connection admits at most one candidate-offer protocol stream at a time.
At most one decoded offer per peer is delivered into application custody;
peer binding rejects a second retained handle. Delivery is paced to at most one
per second per peer. Rejected, malformed and paced requests receive no success
receipt and create no per-request application diagnostic stream. Inner
behaviours are polled round-robin. The network event loop yields cooperatively
after at most 32 suppressed events, allowing the caller's timers and shutdown
futures to be polled even under a stream of refusals.

Candidate-offer requests use the existing bounded non-consensus outbound
permits, preserving the reserved outbound consensus slot. These application
bounds do not reserve Yamux substreams, bandwidth, kernel buffers, CPU time or
pre-authentication capacity. The unchanged static connection and authentication
limits still apply. They do not establish arbitrary Byzantine network liveness
or a byte-rate guarantee.

## Validator policy and durable intake

A supervisor must select exactly one mode: a nonempty finite `targets` list, a
local `candidate_inbox` path, or nonempty `candidate_publishers`. The latter is
an ordered list of at most eight distinct canonical configured peer identities,
all also present in the supervisor's explicit source peer list. Publisher and
consensus identities together must satisfy the existing eight-peer network cap.
These entries do not make publishers validators or proof authorities.

For example, the supervisor portion of an otherwise complete validator config
may be:

```toml
[supervisor]
candidate_publishers = ["<configured publisher PeerId>"]
peers = ["<configured publisher PeerId>", "<configured validator PeerId>"]
interval_millis = "1500"
acquisition_blocks = "16"
```

This policy is included in the existing immutable supervisor binding. Absent new
fields are omitted from serialization, preserving previous finite-plan and local
inbox policy bytes. Removing, changing or switching this policy on an existing
signer fails closed; no implicit migration is provided.

Under the exclusive signer owner, create writes and synchronizes an explicitly
empty offer for every configured publisher in
`vote_journal/candidate-offers-v0.json`, then synchronizes the directory. Its
encoding is canonical JSON `{chain,publishers:[{peer,candidates}]}`, followed by
a newline and lowercase SHA-256 of the JSON bytes. Publisher order is the bound
configuration order; each candidate list obeys the wire bounds. Strict reopen
requires this regular, no-follow bounded file, exact encoding and checksum,
expected chain and publisher list, and file/directory synchronization. A missing,
corrupt, differently bound or partially initialized file is an error, never a
new empty intake. At most 20,000 bytes are read.

An accepted request must come from a configured publisher and name the current
chain. It replaces only that publisher's complete offer. Replacement writes and
synchronizes a newly created `candidate-offers-v0.pending`, renames it over the
snapshot, and synchronizes the directory before exposing the new in-memory
state or sending the receipt. A stale temporary name may be unlinked under the
owner lock; its bytes are never used as authority. Any persistence failure stops
the owner without acknowledging acceptance. An identical offer is idempotent: it compares and synchronizes the existing
canonical snapshot and directory before acknowledging again. Live missing or
changed snapshot bytes stop the owner. Unknown publishers and wrong-chain
offers are silently refused.

“Latest” means the receiver's latest durably accepted offer from that publisher.
It is not a globally fresh sequence number, anti-rollback certificate or promise
that a sender will never re-offer older IDs. Per-publisher slots prevent one
publisher from evicting another's hints. The sorted, deduplicated union is at
most 256 IDs. No local inbox or finite target list is combined with this union.

The existing supervisor scans that union only with idle source ownership.
Candidates must extend the exact selected head and have complete, locally
validated candidate and payload bytes. Missing data enters the existing bounded
configured-peer acquisition path. Missing-source work takes publisher turns in
configured order, with a separate hint cursor per publisher and a complete
configured-source-peer cycle before advancing that publisher's hint and moving
to the next publisher. Empty or locally complete offers are skipped. Changing or
withdrawing an offer cannot reset the global publisher turn; switching away from
an empty publisher starts a fresh full peer cycle for the next one. Thus another
publisher's changing IDs cannot displace a stable publisher's acquisition turns.
These cursors are volatile and restart locally; this promises neither available
bytes, bounded wall-clock completion nor candidate selection. The sorted union
and lowest fully validated choice rule remain separate and unchanged.
Retained-value precedence, complete-proof
catch-up, the persisted lowest eligible local choice and all signing gates
remain unchanged. Offer replacement or withdrawal cannot overwrite a current
durable choice. Intake may be accepted while acquisition owns the source stores;
it does not mutate those stores or interrupt acquisition custody.

A crash can leave either the previous complete offer snapshot or the new complete
snapshot. Strict reopen stabilizes the surviving canonical file. Lost receipts
are retried. This adds no recovery of incomplete signing preparations: pending
vote/proposal startup states still refuse normal signing. Source corruption still
requires the separately specified explicit recovery path.

## Source-only publisher process

On supported Unix platforms, run:

```sh
naome-validator --publisher publisher.toml
```

This mode has a separate configuration schema and does not load a signing seed,
validator set, vote journal, finality proof authority or stdin command stream.
It uses the same bounded static TCP/Noise sessions and source stores:

```toml
version = 0
mode = "create"
deployment_discriminator = "<64 lowercase hexadecimal digits>"
identity_seed_file = "publisher.seed"
listen = "/ip4/127.0.0.1/tcp/4100"
journal_directory = "journal"
offer_file = "offer.json"

[[peers]]
peer_id = "<configured receiver PeerId>"
address = "/ip4/127.0.0.1/tcp/4200"

[sources]
mode = "create"
candidate_directory = "candidates"
payload_directory = "payloads"
candidate_entries = "128"
payload_entries = "128"
payload_bytes = "1048576"
```

Paths resolve against the configuration directory. Directories are provisioned
by the operator. Identity seeds use the validator's owner-only 32-byte regular
file rules. `mode = "open"` strictly reopens the publisher's empty artifact-chain
journal at virtual genesis; source mode likewise selects create or open. This
journal supplies a fixed genesis snapshot for checked source-bundle staging and
never advances or represents received consensus finality. Source-store limits
remain caller-selected and mandatory. Automatic source recovery is unavailable
in publisher mode.

The publisher's producer atomically replaces its own bounded local manifest:

```json
{"candidates":["<canonical block ID>"],"bundle_file":"new-source.bundle"}
```

The optional bundle path may be absent or null. It is local producer input, never
a remote path. The manifest is read through a no-follow, nonblocking regular
file descriptor, capped at 4,096 bytes, with unknown/duplicate fields rejected.
Candidates must already be strictly sorted and unique, at most 32. A new manifest
with a bundle stages its complete validated branch before advertising those IDs.
Staging uses the existing source-only bundle checks, at most 256 blocks,
8,388,608 payload bytes and 8,454,144 encoded bytes. A staging failure stops the
publisher; any durable prefix retains the lower store's existing semantics.
Only the latest successfully loaded manifest is cached, so memory does not grow
with the number of updates. Missing or unreadable manifests retain the previous
offer; a readable malformed manifest stops the process. Stores remain under the
publisher's sole ownership while running.

The publisher polls at 1.1-second intervals and retains at most one outstanding
offer generation per configured receiver. It retries after terminal failure or
receipt, including unchanged offers, so receiver restarts and lost receipts need
no shared filesystem or command input. It serves candidate and payload requests
from its own checked bounded archives. Source integrity failure stops it.
A receipt report is emitted only when that receiver acknowledges a different
exact offer digest; repeated retries do not cause unbounded periodic diagnostics.
SIGINT/SIGTERM stop the process and release its store/network owners before its
bounded final output flush. These signals do not imply receipt of an outstanding
offer.

## Evidence and limits

`crates/naome-protocol/src/candidate_offer.rs` tests canonical count/order and
all truncation boundaries. Network tests cover strict framing and custody,
receipt correlation, per-peer transport routing, retained custody across
reconnect and a pollable deadline under a finite paced-offer flood. Durable intake tests cover
full eight-publisher capacity, independent replacement/withdrawal, duplicate
acceptance, strict reopen, failed persistence and acquisition turns under moving
invalid hints.

`crates/naome-validator/tests/cases/network_intake.rs` uses real child processes
with independent directories. The 100-height and receipt/reopen fixtures use
closed stdin; the acquisition victim accepts one read-only source-status probe
as an output-order barrier after all responders are frozen, then closes stdin.
No fixture issues acquisition, proposal or signing commands. The 100-height fixture uses
preseeded source stores and post-startup network hints from two publishers,
including a full competing invalid-ID offer, a partition and healing. A separate
three-height fixture begins with empty validator source stores, publishes a
source bundle after startup, acquires bytes over the network and kills/reopens
an owner during acquisition. Receipt/reopen tests kill an owner after durable
intake and reject missing, corrupt or changed policy state. These are bounded
loopback process oracles, not WAN, separate-host, indefinite-soak or production
latency measurements. Existing signing and publication crash tests remain
separate evidence; intake does not broaden their recovery contract.
