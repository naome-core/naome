# Fixed-validator process artifact-source serving V0

## Scope and disclosure

`PROD-020-062` adds an explicitly enabled source service to the Unix
[`naome-validator` process](fixed-validator-process-v0.md). It connects the
existing runtime's exact candidate-store and payload-store responders to the
process-owned [source stores](fixed-validator-process-artifact-acquisition-v0.md).
The operator authorizes disclosure of every explicitly retained entry, including
unselected candidates and payloads, to every configured static Noise peer.
There is no selected-history filter, per-entry recipient list or provenance
claim. Noise authorization remains separate from consensus signing identity.

The component does not grant validation, signing, consensus admission, branch
selection or finality authority. A receiver must independently check structural
blocks and fully validate payloads against its own target state. Acquiring a
branch does not authorize its tip as a live proposal; authoring and finality
continue through their separate complete live signer gates.

## Configuration and ownership

The optional `[network].serve_artifact_sources` field is a TOML boolean with
default `false`. `true` requires `[sources]`; otherwise preparation fails with
`source_serving_requires_sources` before source opening or authority provision.
Incorrect types fail the existing strict schema. Source creation/opening,
limits, chain/Foundation binding and failure ordering retain their existing
contracts. The flag is not persisted and may be changed on explicit restart.
It is independent of `serve_finality_proofs` and publication targets.

When false or omitted, returned inbound block and artifact handles follow the
existing diagnostic disposal path, even when sources are configured and contain
the requested data. When true and sources are idle, block requests use only the
chain-scoped candidate store, and artifact requests use only the
Foundation-scoped payload archive. Neither request carries a store selector;
the configured process ownership supplies that routing decision. No request
falls back to selected journals, files, proposal custody or another peer.
No chain-head, inventory, bundle, announcement or new wire protocol is added.

While an ancestry or payload acquisition exclusively borrows sources, both
request kinds receive an explicit `Unavailable` through the existing transport
response gates without accessing either store. This is temporary local
unavailability, not a statement about absence, validation or remote storage.
After completion, failure or explicit cancellation releases the borrow,
subsequent requests use the stores again. There is no retained serving request,
deferred queue or automatic retry. A requester chooses whether and when to retry.

## Responses and failures

Healthy idle lookups return the exact retained canonical block or tagged payload
bytes, or the existing `Unavailable` encoding when the address is absent.
Serving never inserts, refreshes, deletes, promotes or otherwise modifies
source entries. File-backed authoring and received consensus messages do not
automatically populate sources, including after their artifacts finalize.
Explicit acquisition and offline staging remain separate population mechanisms.

Existing authenticated channel checks, shared inbound application budget and
response framing limits apply. Candidate lookup keeps its existing integrity
read before response gates. Payload lookup checks health and indexed presence
before gates, but reads a present payload body only after channel and rate
acceptance. Busy responses perform no lookup and use those same channel/rate
gates. Each response consumes its inbound handle once. Queuing owned response
bytes does not prove transmission, receipt or admission.

The process emits bounded `source_response_queued` reports containing `kind`
(`block` or `payload`), authenticated `peer`, requested hexadecimal `address`,
and `sources_busy`. The report does not distinguish found from absent data.
It emits `source_response_failed` with the same kind, peer and address plus a
reason: `candidate_store`, `payload_store`, `channel_closed`, `rate_limited`, or
`unsupported_response`. An integrity failure remains an error, never an
unavailability response; the affected store retains its poison-and-reopen
boundary. Independent source and signer owners retain their existing authority.
There is no repair, rollback or source-to-authority transaction.

## Scheduling, restart and evidence

The ordinary runtime poll returns each request under its existing command,
publication, consensus-input and deadline scheduling. The process handles one
returned request without spawning a task or acquiring another source owner.
Active acquisition advances only its exact correlated terminal; unrelated
inbound requests follow the serving rule above. Responses have no durable job
or receipt state. Shutdown, signals and output failure retain the existing
awaited ownership teardown; strict restart reopens retained source data and
does not recreate serving requests or acquisition intent.

Actual Unix process vectors in
`crates/naome-validator/tests/cases/artifact_acquisition/source_serving/` cover
offline-staged unselected data, exact bundle reconstruction at a network
receiver, unchanged authority before separate authoring, actual two-process
finality, strict reopen and serving to a fresh receiver, both busy acquisition
phases, cancellation and late-response disposal, SIGTERM and source reopen,
default-off and configuration boundaries, absent data, source corruption and
continued independent file-backed signing, and no automatic payload population
or selected-journal fallback. An actual held consensus receipt also proves
that serving preserves outstanding publication and driver state, followed by
ordinary finality and strict original signed-proposal replay. Network tests exercise explicit unavailability
through the real wire, exact block-ticket correlation, rate rejection and
closed payload-channel precedence. These are bounded local integration vectors;
they establish no production throughput, global availability, proactive publication,
discovery, retention/pruning policy, distributed liveness or dynamic-validator
support.
