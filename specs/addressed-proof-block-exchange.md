# NAOME Addressed Proof Block Exchange

## Status and scope

This document defines one bounded, transport-neutral request and response for
retrieving a canonical [`ProofBlock`](proof-block.md) by exact `ProofBlockId`.
It is a prerelease protocol contract and may change before the first stable
protocol release.

The contract assumes that an outer transport already provides one exact message
boundary and distinguishes successful message completion from transport
failure. It defines no socket, stream framing, peer identity, authentication,
authorization, retry, announcement, or complete peer-to-peer network.

The separate
[Authenticated Proof Block Transport](authenticated-proof-block-transport.md)
binds this exact object exchange to statically authorized Noise peers over the
existing managed Yamux sessions. That binding does not change these canonical
request, response, or validation rules.

A found response is useful only as content addressed by an already known block
identity. The exchange does not discover that identity, determine whether the
block belongs to the caller's configured chain, acquire its proof payloads, or
authorize selection. Those facts remain separate from content retrieval.
The separate
[Caller-Selected Proof Block Import](caller-selected-proof-block-import.md)
may compose one exact response with existing proof acquisition and journal
application, but it does not change this exchange or let a peer choose the
requested identity.

## Public surface

The transport-neutral Rust surface is equivalent to:

```text
PROOF_BLOCK_REQUEST_BYTES = 32
PROOF_BLOCK_RESPONSE_MAX_BYTES = PROOF_BLOCK_MAX_BYTES = 353

ProofBlockRequest::new(block_id: ProofBlockId) -> ProofBlockRequest
ProofBlockRequest::block_id(self) -> ProofBlockId
ProofBlockRequest::to_wire_bytes(self) -> [u8; 32]
ProofBlockRequest::from_wire_bytes(bytes: &[u8])
    -> Result<ProofBlockRequest, ProofBlockExchangeWireError>

ProofBlockResponse::from_wire_bytes(
    request: ProofBlockRequest,
    bytes: &[u8],
) -> Result<ProofBlockResponse, ProofBlockExchangeWireError>
ProofBlockResponse::is_unavailable(&self) -> bool
ProofBlockResponse::into_block(self) -> Option<ProofBlock>
ProofBlockResponse::to_wire_bytes(&self) -> Vec<u8>

proof_block_response(
    journal: &ProofChainJournal,
    request: ProofBlockRequest,
) -> Result<Option<&ProofBlock>, ProofChainJournalError>
```

Response fields are private. A response can expose an owned decoded block only
after canonical decoding and exact requested-identity validation have both
succeeded.

## Request

A `ProofBlockRequest` is exactly the 32 raw bytes of one `ProofBlockId`:

```text
block_id[32]
```

There is no tag, version, length, chain identifier, height, parent, or second
identity. The enclosing transport supplies the message kind and boundary. Any
32-byte value is a syntactically valid address; decoding it does not establish
that the block exists, has valid ancestry, belongs to a configured chain, is
available from any peer, or was selected or finalized.

Every shorter or longer complete message fails with
`InvalidRequestLength { actual, expected: 32 }`.

## Response

One already delimited response message has exactly one of two meanings:

```text
Unavailable = empty message
Found       = canonical_proof_block[129..=353]
```

`Found` is byte-for-byte the canonical `ProofBlock`. It adds no tag, length,
echoed block identity, chain identifier, height, payload count, proof payload,
source, signature, or wrapper encoding. A successfully completed empty message
is the sole `Unavailable` representation.

The outer transport must reject an announced response length above 353 before
allocating its body. A reset, timeout, absent response, truncated outer message,
or failure before the declared message completes remains a transport error and
must never be converted to `Unavailable`. This object codec can reject an
already supplied oversized slice but does not itself provide network allocation
limits, timeouts, or backpressure.

`Unavailable` reports only that one local serving boundary supplied no block
for this exact request. It is not evidence of global absence, invalidity,
non-membership in an ancestry, or absence from another peer or journal. This
contract defines no negative cache.

## Receive validation and error precedence

The immutable `ProofBlockRequest` remains coupled to the complete response. A
nonempty response is processed in this exact order:

1. reject more than 353 bytes with `ResponseTooLong` before block decoding;
2. strictly decode the complete slice with
   `ProofBlock::from_canonical_bytes`, preserving any
   `ProofBlockDecodeError` as `BlockDecode { source }`;
3. compute the decoded block's canonical `ProofBlockId` exactly once;
4. compare it with the immutable request address; and
5. on inequality, return `BlockIdMismatch { expected, actual }` without
   exposing the decoded block.

An empty response becomes `Unavailable` before those found-response checks.
Every nonempty slice shorter than 129 bytes or otherwise malformed fails strict
block decoding rather than becoming unavailable. A canonical block for a
different request remains a typed identity mismatch even when its transition is
structurally valid.

On success, `ProofBlockResponse` retains the decoded `ProofBlock`, not a second
copy of its input bytes. `into_block` transfers it, and `to_wire_bytes`
reproduces its sole canonical representation. No API exposes raw nonempty
response bytes before identity matching.

## Golden message

For the canonical 161-byte block in the [Proof Block](proof-block.md) golden,
the exact request is its raw block identity:

```text
9b1dbade5300bbb36e1b126226dc940395d7ccd742a2bd7a8d6f7cbb9543237f
```

The matching found response is the canonical block itself:

```text
f47ee4acce1f5797ff773e7b620cfc66b101dfadb0b87cb4f83e3b94765c8b98
1111111111111111111111111111111111111111111111111111111111111111
2222222222222222222222222222222222222222222222222222222222222222
02
3333333333333333333333333333333333333333333333333333333333333333
4444444444444444444444444444444444444444444444444444444444444444
```

The line breaks above are presentation only. The wire response is their direct
concatenation with no whitespace or length field. The unavailable response is
zero bytes.

## Serving from selected storage

`proof_block_response` asks a healthy
[`ProofChainJournal`](proof-chain-journal.md) for the exact requested block:

- a committed selected block yields a borrowed `&ProofBlock`;
- an unknown identity or the virtual genesis anchor yields `None`; and
- a poisoned or otherwise failing journal yields its existing
  `ProofChainJournalError` rather than a response.

The helper performs no journal scan, block clone, canonical re-encoding, proof
lookup, or state mutation. The journal reconstructs its private committed-block
lookup only through strict entry replay and exposes no uncommitted or competing
block through this path.

The concrete authenticated transport may encode the borrowed result once into
an owned response buffer because libp2p owns it across the asynchronous write.
That transport-specific ownership does not change the zero-allocation local
lookup contract.

Serving a block from one local selected journal establishes only that this
healthy handle committed and replayed that exact block. The block remains
standalone, without a repeated `ProofChainId`; a receiver needs separately
configured chain context and an unbroken valid ancestry to classify it. Local
retention is not a signature, checkpoint, consensus receipt, finality proof, or
network availability guarantee.

## Payload and application boundary

A found block contains only its exact parent and `ProofTransition`. It contains
no proof-certificate payload. This exchange does not invoke proof acquisition,
construct `AddressedProofCandidate` values, prepare a block, inspect the
receiver's selected head, or call `ProofChainJournal::apply_block`.

A higher layer may use the block's ordered `ProofId` commitments with the
separate addressed proof exchange and may later supply the unchanged block and
a complete opaque closure to the existing atomic application boundary. This
contract neither performs nor authorizes that sequence. Successful retrieval is
content availability for one block commitment, not authority to select it.

## Resource and security boundary

The request is fixed at 32 bytes. A found response is at most 353 bytes and
strict decoding retains at most eight proof identities. Successful matching
performs one canonical block-ID hash. The response object does not retain its
input slice, while `to_wire_bytes` allocates at most one canonical block buffer.
The journal serving helper returns a shared reference and allocates no response
buffer; transport-specific ownership remains outside this contract.

Security relies on the existing canonical block decoder and the collision and
second-preimage resistance assumptions of `ProofBlockId`. Exact request binding
prevents a valid block for another address from being silently substituted.
Neither content identity nor canonical structure authenticates a sender,
establishes ancestry availability, or decides selection.

## Explicit exclusions

This contract defines no socket or stream I/O, transport framing,
authentication, peer authorization, learned-peer session, bootstrap policy,
retry, timeout, cancellation, rate limit, worker, batch request, range request,
height or parent query, head discovery, ancestry synchronization, orphan pool,
cache, announcement, subscription, gossip, DHT, proof-payload bundle,
compression, erasure coding, data-availability sampling, automatic proof
acquisition, block preparation, block application, competing-fork storage, fork
choice, rollback, reorganization, checkpoint trust, proposer, signature, proof
of work, proof of stake, validator set, voting, quorum, consensus, finality,
reward, fee, balance, novelty policy, issuance, or settlement.
