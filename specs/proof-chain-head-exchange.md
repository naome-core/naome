# NAOME Proof Chain Head Exchange

## Status and scope

This document defines one bounded, transport-neutral request and response for
observing the current head of one locally selected proof chain identified by an
exact `ProofChainId`. It is a prerelease protocol contract and may change before
the first stable protocol release.

[`ProofBlock`](proof-block.md) defines that configured chain context, its
domain-separated virtual genesis parent, and the exact `ProofBlockId` head type.

The contract assumes that an outer transport provides exact message boundaries
and distinguishes a successfully completed empty response from truncation,
reset, timeout, or absent response. It defines no socket, stream framing, peer
identity, authentication, authorization, retry, announcement, or complete
peer-to-peer network.

The separate
[Authenticated Proof Chain Head Pull](authenticated-proof-chain-head-pull.md)
binds this exchange to a statically authorized Noise peer over an existing
managed Yamux session. The separate
[Authenticated Proof Chain Head Announcement](authenticated-proof-chain-head-announcement.md)
carries a sender's exact chain context and current head in one fixed
receipt-bearing message; it does not reuse or change this pull request or
response. The separate
[Addressed Proof Block Exchange](addressed-proof-block-exchange.md) retrieves an
already known block by exact identity, and the separate
[Caller-Selected Proof Block Import](caller-selected-proof-block-import.md) may
import one caller-selected direct child. Neither operation is performed or
authorized by this head exchange.

A successful found response is only one serving boundary's untrusted
observation. It is not fresh, signed at the application layer, an ancestry
proof, a checkpoint, a selection decision, or evidence of consensus or
finality. The response must never be used as a trusted expected head for
`ProofChainJournal::open_verified` merely because it was received through this
exchange.

## Public surface

The transport-neutral Rust surface is equivalent to:

```text
PROOF_CHAIN_HEAD_REQUEST_BYTES = 32
PROOF_CHAIN_HEAD_RESPONSE_BYTES = 32

ProofChainHeadRequest::new(chain_id: ProofChainId) -> ProofChainHeadRequest
ProofChainHeadRequest::chain_id(self) -> ProofChainId
ProofChainHeadRequest::to_wire_bytes(self) -> [u8; 32]
ProofChainHeadRequest::from_wire_bytes(bytes: &[u8])
    -> Result<ProofChainHeadRequest, ProofChainHeadExchangeWireError>

ProofChainHeadResponse::from_wire_bytes(bytes: &[u8])
    -> Result<ProofChainHeadResponse, ProofChainHeadExchangeWireError>
ProofChainHeadResponse::is_unavailable(&self) -> bool
ProofChainHeadResponse::head_block_id(&self) -> Option<ProofBlockId>
ProofChainHeadResponse::to_wire_bytes(self) -> Option<[u8; 32]>

proof_chain_head_response(
    journal: &ProofChainJournal,
    request: ProofChainHeadRequest,
) -> Result<ProofChainHeadResponse, ProofChainJournalError>
```

Response state is private. No response type claims that its optional
`ProofBlockId` belongs to a valid, available, selected, or finalized remote
ancestry.

## Request

A `ProofChainHeadRequest` is exactly the raw configured chain context:

```text
proof_chain_id[32]
```

There is no tag, version, length, height, expected parent, block identity, or
second context. The enclosing transport supplies the message kind and boundary.
Any 32-byte value is a syntactically valid `ProofChainId`; decoding does not
establish that another node recognizes or serves that context.

Every shorter or longer complete message fails with
`InvalidRequestLength { actual, expected: 32 }`.

## Response

One already delimited response message has exactly one of two meanings:

```text
Unavailable = empty message
Found       = head_block_id[32]
```

`Unavailable` means only that this serving boundary did not expose a head for
the exact requested chain context. A healthy journal whose configured
`ProofChainId` differs from the request returns `Unavailable`. It is not proof
that the chain does not exist, that another peer lacks it, or that the requester
used an invalid identifier. This contract defines no negative cache.

`Found` is exactly one raw `ProofBlockId`. It has no tag, length, echoed
`ProofChainId`, height, timestamp, sequence, signature, state root, ancestry,
proof payload, or wrapper. Any 32-byte value is a syntactically valid found
value. A nonempty complete response with any other length fails with
`InvalidResponseLength { actual }`; it never becomes `Unavailable`.

The immutable request must remain coupled to the response by the outer
transport. The response itself does not repeat the chain context and cannot be
reinterpreted under another request.

## Golden messages

For the `ProofChainId` containing 32 bytes of `11`, the exact request is:

```text
1111111111111111111111111111111111111111111111111111111111111111
```

A matching empty journal returns the virtual genesis parent defined by the
[Proof Block](proof-block.md) contract:

```text
f47ee4acce1f5797ff773e7b620cfc66b101dfadb0b87cb4f83e3b94765c8b98
```

A healthy journal configured with any different `ProofChainId` returns the
zero-byte unavailable response.

## Serving from selected storage

`proof_chain_head_response` reads one
[`ProofChainJournal`](proof-chain-journal.md) in this exact order:

1. require the journal handle to be healthy, preserving every
   `ProofChainJournalError`, including `Poisoned`;
2. compare the request's `ProofChainId` with the journal's configured chain
   context;
3. return an unavailable `ProofChainHeadResponse` on a context mismatch; or
4. return a found response containing the journal's exact current head on a
   context match.

Journal health therefore precedes mismatch classification. A poisoned journal
must not be converted to `Unavailable` and must not expose a possibly ambiguous
in-memory head.

A matching empty journal returns its domain-separated virtual genesis parent as
`Found`. The virtual genesis value is the current expected parent, not an
admitted or retrievable `ProofBlock`; requesting it through the addressed block
exchange remains `Unavailable`. A matching nonempty journal returns the exact
identity of its latest durably acknowledged selected block.

The helper performs no journal scan, block lookup, block encoding, hash,
allocation, proof lookup, state mutation, disk write, or synchronization. It
does not retain or expose a second selected-state owner. Retaining the already
persisted configured `ProofChainId` for this comparison changes neither the
journal file format nor canonical block bytes.

## Use with block retrieval and import

A caller may treat a found value as a candidate address and later make a
separate exact request through the
[Authenticated Proof Block Transport](authenticated-proof-block-transport.md).
The caller may then explicitly choose to invoke the
[Caller-Selected Proof Block Import](caller-selected-proof-block-import.md).
This exchange performs neither step and exposes no combined pull-and-import
operation.

The existing importer still requires the retrieved block to directly extend
the receiver's current head, match its current proof-set roots, acquire every
committed proof payload, and pass strict journal application. A stale, unrelated,
lying, or more-than-one-block-ahead head observation therefore confers no
admission bypass. Conversely, a rejected import does not prove that the
observation was globally false; the peers may simply be on different histories
or at different positions.

`ProofChainJournal::open_verified` has a stronger trust boundary: its expected
head must come from a separately trusted source. A head exchange response,
including one received from an authenticated static peer, is not such a source
by itself and must never be promoted implicitly into that argument.

## Resource and security boundary

The request is fixed at 32 bytes and the response body is either zero or exactly
32 bytes. Request decoding, response decoding, chain-context comparison, and
head copying are constant-space operations. The local serving helper allocates
nothing and performs no hashing or proof validation.

The journal retains one additional immutable 32-byte in-memory `ProofChainId`
copied from its already synchronized or replay-verified prefix context. No
additional byte is written to disk, and no per-request state is added to the
journal.

The chain-scoped request prevents an honest serving boundary from accidentally
returning the head of a differently configured local journal. It does not make
the peer honest and does not prove that a returned head belongs to a complete or
valid remote ancestry. Security therefore relies on outer request/source
correlation and on the existing strict local block import boundary, not on
trusting the returned digest.

## Explicit exclusions

This contract defines no socket or stream I/O, authentication, peer
authorization, learned-peer session, chain-identifier discovery, bootstrap
policy, retry, timeout, cancellation, rate limit, polling scheduler, push,
announcement, subscription, gossip, DHT, freshness, timestamp, sequence,
height, parent query, child query, range query, ancestry walk, multi-block
synchronization, block or proof payload transport, automatic block retrieval,
automatic import, selected-state mutation, trusted `open_verified` anchor,
competing-fork storage, fork choice, rollback, reorganization, checkpoint trust,
proposer, signature, proof of work, proof of stake, validator set, voting,
quorum, consensus, finality, reward, fee, balance, novelty policy, issuance, or
settlement.

The separate authenticated head-announcement contract adds one explicit push
message without changing this pull exchange or granting either observation
selection authority.
