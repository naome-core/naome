# NAOME Addressed Proof Exchange

## Status and scope

This document defines one bounded, transport-neutral request and response for
retrieving a complete proof by `ProofId` and admitting it without confusing the
requested address with a different valid proof. It is a prerelease protocol
contract and may change before the first stable protocol release.

The contract assumes that an outer transport already provides one exact
message boundary and distinguishes successful message completion from transport
failure. It defines neither sockets nor a complete peer-to-peer network.

The [authenticated proof transport](authenticated-proof-transport.md) defines
one concrete static TCP + Noise + Yamux binding for this exchange. This
transport-neutral contract remains authoritative for request-address binding
and journal admission.

## Request

A `ProofRequest` is exactly the 32 raw bytes of one `ProofId`:

```text
proof_id[32]
```

There is no request tag, version, length, or second identity. The enclosing
request-response protocol supplies the message kind and boundary. Any 32-byte
value is a syntactically valid address; decoding it does not prove existence,
validity, availability, or selection.

## Response

One already delimited response message has exactly one of two meanings:

```text
Unavailable = empty message
Found       = candidate_proof_bytes[1..=CERTIFICATE_MAX_BYTES]
```

The `Found` payload is byte-for-byte the proof-certificate candidate. It adds no
tag, length, echoed `ProofId`, `StatementId`, `DerivationId`, dependency list,
proof-set root, or wrapper encoding. A successfully completed empty message is
the sole `Unavailable` representation.

The outer transport must reject an announced response length above
`CERTIFICATE_MAX_BYTES` before allocating the body. A reset or timeout before
the declared outer message completes, a truncation, or an absent response must
remain a transport error and must never be converted to `Unavailable`. This
object codec can reject an already supplied oversized message but does not
itself provide network allocation limits, timeouts, or backpressure.

`Unavailable` reports only that one sender supplied no payload for this
request. It is not evidence of global absence, non-membership in a
`ProofSetRoot`, peer honesty, freshness, or finality. This contract defines no
permanent negative cache.

## Serving a response

A local responder looks up the exact requested `ProofId` in its healthy
`ProofDagJournal`:

- an accepted record yields its borrowed `canonical_proof_bytes` directly;
- a missing record yields `Unavailable`; and
- a poisoned or unreadable journal yields its existing `JournalError` rather
  than a response.

Serving does not re-encode the proof or duplicate identities. The
transport-neutral lookup itself borrows the retained bytes without allocating.
Transport-specific writing and buffer ownership remain outside this contract;
the authenticated libp2p binding documents its one required owned response
copy.

## Receiving and closure promotion

A nonempty response is untrusted candidate data. The immutable request
`ProofId` must remain coupled to the owned bytes; neither the response nor a
peer-supplied field may replace that request context. This transport-neutral
codec deliberately exposes no raw response-to-journal admission helper.

The concrete authenticated transport consumes responses through a bounded
single-peer closure acquisition. It decodes each response, requires exact
root-normal-form canonical bytes, and discovers only the normal form's direct
`ProofReference` addresses. It stops at selected dependencies, deduplicates
exact addresses, rejects cycles, and returns at most eight addresses observed
absent during discovery, in dependency-first order with the requested root
last. Selected state may grow before completion or promotion. These candidates
remain unselected and have not yet been mathematically checked or proven to
match their requested addresses.

The opaque completed closure has one consuming promotion operation through
`ProofDagJournal::apply_rooted_canonical_proof_batch`. The authoritative order
then remains:

1. journal health verification;
2. batch count, duplicate expected-address, and root-last preflight;
3. for each candidate in order: proof-certificate decoding, canonicality
   verification, deterministic mathematical checking against selected state
   plus earlier staged dependencies, checked `ProofId` comparison with its
   immutable request address, and staged state registration;
4. requested-root reachability validation over all staged records; and
5. atomic state merge followed by one durable rooted transaction commit.

Malformed or noncanonical responses fail during acquisition with a
`DependencyAcquisitionError` and never reach the journal. For a completed
closure, invalid, dependency-incomplete, wrong-address, and duplicate
candidates preserve the existing nested `JournalError` -> `ProofBatchError` ->
`LedgerError` precedence. Every ordinary pre-commit failure leaves the ledger,
authenticated proof set, proof-set root, retained records, and journal bytes
unchanged. A valid proof for a different requested ID therefore cannot become
locally visible as a side effect of rejecting its closure. Fetched dependencies
are not admitted incrementally.

An empty response terminates the current one-peer acquisition, discards its
quarantine, and performs no proof admission or journal write.

## Dependency boundary

Proof references remain dependency-first. This transport-neutral message codec
does not fetch them itself. The concrete static transport may acquire up to
eight root-reachable absent addresses sequentially from the same authenticated
peer, while holding received bytes in bounded in-memory quarantine. It performs
no raw unaddressed fallback and selects no dependency before the complete
closure is atomically validated.

This restriction is intentional. A malicious peer can send a wrong-address
candidate whose missing references are discovered before mathematical checking
can derive its actual `ProofId`. Fixed candidate and request limits bound that
work; retaining the complete closure unselected prevents such a response from
smuggling dependencies into selected state. Proof-request retries, multi-peer
fallback, rolling work budgets, and total-job deadlines remain later policy;
managed transport redial is specified separately by the authenticated binding.

## Explicit exclusions

This contract does not define:

- socket or stream I/O, transport encryption, peer identities, or handshakes;
- timeouts, backpressure, rate limits, connection limits, or worker pools;
- peer discovery, bootstrap seeds, address management, DHTs, gossip, scoring,
  bans, retries, or multi-peer selection;
- batch wire messages, multiplexed correlation IDs, announcements, negative
  caches, persistent orphan pools, or proof availability claims;
- proof-set checkpoint trust, signatures, fork choice, finality, reorgs, or
  consensus;
- economic transactions, rewards, fees, balances, or settlement; or
- compression, erasure coding, snapshots, pruning, or availability proofs.

The next networking layers must preserve this request-address binding and may
not expose raw unaddressed or incremental proof admission to peer-provided
response bytes.
