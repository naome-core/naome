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

## Receiving and admission

A nonempty response is untrusted candidate data. The receiver must pass its
owned bytes and the immutable request `ProofId` exclusively to
`ProofDagJournal::apply_canonical_proof_bytes_with_expected_id`. The resulting
order remains:

1. proof-certificate decoding;
2. root-normal-form canonicality verification;
3. deterministic mathematical checking and dependency resolution;
4. checked `ProofId` comparison with the request address;
5. state registration; and
6. durable journal commit.

Malformed, noncanonical, invalid, dependency-incomplete, wrong-address, and
duplicate candidates preserve the existing nested `JournalError` and
`LedgerError` precedence. Every such failure leaves the ledger, authenticated
proof set, proof-set root, retained records, and journal bytes unchanged. A
valid proof for a different requested ID therefore cannot become locally
visible as a side effect of rejecting the response.

An empty response performs no proof admission or journal write. The receiver
still requires a healthy journal handle before reporting the `Unavailable`
outcome.

## Dependency boundary

Proof references remain dependency-first. If a response cites a `ProofId` that
is absent from the selected local state, admission returns the existing
`UnknownProofReference` checker error. This exchange performs no recursive
fetch, retry, orphan retention, quarantine, or raw unaddressed fallback. The
same response may be retried only after a higher layer has separately admitted
the missing dependency.

This restriction is intentional. A malicious peer can otherwise use a wrong
or expensive candidate to trigger unbounded dependency work before its actual
`ProofId` is known. Per-peer and global dependency, byte, time, concurrency,
and checker-work budgets belong to the later network scheduler.

## Explicit exclusions

This contract does not define:

- socket or stream I/O, transport encryption, peer identities, or handshakes;
- timeouts, backpressure, rate limits, connection limits, or worker pools;
- peer discovery, bootstrap seeds, address management, DHTs, gossip, scoring,
  bans, retries, or multi-peer selection;
- batches, multiplexed correlation IDs, announcements, negative caches,
  automatic dependency fetching, or orphan pools;
- proof-set checkpoint trust, signatures, fork choice, finality, reorgs, or
  consensus;
- transactions, rewards, fees, balances, or economic settlement; or
- compression, erasure coding, snapshots, pruning, or availability proofs.

The next networking layers must preserve this request-address binding and may
not expose raw unaddressed proof admission to peer-provided response bytes.
