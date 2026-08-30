# Fixed-validator artifact consensus envelope V0

## Status and authority

This specification defines the prerelease artifact-only V0 consensus value,
its evidence-free proposal and ancestry identities, the complete
certificate-bearing envelope, and the typed fixed-validator branch boundary
that verifies one direct child.

Successful typed verification proves that one exact canonical value:

- names the branch's exact chain, final genesis, protocol version, direct child
  height, and required consensus parent;
- carries the complete fixed-validator artifact-only V0 branch-state projection
  derived from that parent, its exact artifact block, fixed validator set, and
  once-advanced proposer base;
- is authenticated by the deterministic proposer selected for the envelope's
  exact height and round;
- has a strict greater-than-two-thirds non-nil precommit certificate over the
  same internally derived immutable agreement snapshot; and
- contains an `ArtifactBlock` that strictly validates with the supplied
  canonical artifact bytes against the artifact snapshot coupled to the same
  consensus parent.

The public full-envelope constructor exists only on `FixedConsensusRoundV0`.
Callers supply the envelope bytes and canonical artifact payload bytes, not an
expected proposer, agreement snapshot, ancestry, state commitment, or artifact
parent. The lower-level independently parameterized composition helper is
crate-private so it cannot bypass the typed branch boundary.

Success publishes a separate immutable child branch. Consuming that proof into
`OwnedVerifiedFixedConsensusTransitionV0` seals its exact parent coordinate,
authenticated position, value, envelope identity, canonical envelope bytes,
canonical artifact payload, and verified child for transfer to the fixed-V0
finality journal. The owned proof alone still selects no sibling and mutates no
state.

This envelope component does not prove that the caller-selected genesis context
or fixed set is globally canonical, execute Tendermint locking or timeout
transitions, create signatures, provide signing safety, change validators,
provide data availability, gossip or fetch data, grant peer authority, or
execute economics. The separate fixed-validator proposal-control V0 contract
admits a complete proposal and provides only unsigned in-memory lock and
valid-value effects before reconstructing this unchanged final envelope from a
matching current-round precommit certificate. Only the separate
fixed-validator finality-journal contract may consume the sealed owned form to
install durable selection, retain the exact first envelope and payload, apply
same-value no-write idempotence, and commit a conflicting-certificate halt for
this exact V0 format. The owned proof itself remains non-authoritative. A
libp2p `PeerId` authenticates transport only and remains unrelated to a
consensus key.

## Primitive values

All integers are unsigned and big-endian unless explicitly identified as a
signed proposer priority. Every byte string has the exact width shown.

| Value | Canonical representation | Meaning |
| --- | ---: | --- |
| `ArtifactChainId` | 32 bytes | Exact artifact-chain and consensus-chain context |
| `ConsensusGenesisId` | 32 bytes | Opaque final genesis identity selected by the caller |
| `ConsensusProtocolVersion` | `u32` | Exact protocol version carried by value and evidence |
| `ConsensusHeight` | `u64` | Positive non-genesis height; zero is rejected |
| `ConsensusAncestryId` | 32 bytes | Value-derived ancestry address or virtual-genesis sentinel |
| `ArtifactBlock` | 128 bytes | Existing unchanged canonical artifact-block representation |
| `FixedAgreementSetId` | 32 bytes | Identity of the sorted fixed keys and weights |
| `ProposerPriorityStateId` | 32 bytes | Identity of the fixed set and exact signed priorities |
| `ConsensusStateCommitment` | 32 bytes | Complete fixed-validator artifact-only V0 branch-state projection |
| `ProposalSigningRoot` | 32 bytes | Evidence-free proposal target derived from the value |
| `ConsensusEnvelopeId` | 32 bytes | Evidence-variant address of one complete envelope |

Strict value decoding can represent every observed 32-byte state commitment,
including all zeroes. Typed branch verification accepts only the exact digest
derived by the fixed-validator proposer and branch-state V0 contract.

## Canonical artifact-only value

Every V0 value is exactly 268 bytes:

| Offset | Width | Field | Canonical rule |
| ---: | ---: | --- | --- |
| 0 | 32 | chain | exact `ArtifactChainId` bytes |
| 32 | 32 | genesis | exact `ConsensusGenesisId` bytes |
| 64 | 4 | version | `ConsensusProtocolVersion` as `u32` big-endian |
| 68 | 8 | height | `ConsensusHeight` as `u64` big-endian; zero is rejected |
| 76 | 32 | parent ancestry | exact required `ConsensusAncestryId` bytes |
| 108 | 128 | artifact block | exact existing canonical `ArtifactBlock` bytes |
| 236 | 32 | post-consensus state | exact derived `ConsensusStateCommitment` bytes |

The value carries no round and no producer or agreement evidence. The same
unchanged value may therefore be proposed again in a later sequential round
without changing its proposal root, ancestry identity, or post-height proposer
base. Producer authorization and every vote remain bound to one exact round.

### Parent semantics

Height one names a context-derived virtual-genesis parent. Its trailing-NUL
ASCII domain is:

```text
naome:consensus-ancestry-genesis:v0\0
```

The exact sentinel is:

```text
SHA256(
    genesis_ancestry_domain
    || ArtifactChainId[32]
    || ConsensusGenesisId[32]
    || ConsensusProtocolVersion_u32_be[4]
)
```

The only root branch constructor requires a matching-chain, internally empty
artifact virtual-genesis snapshot and retains this ancestry sentinel with no
positive verified height. Its first round cursor derives height one. Every
successor branch stores the verified value's ancestry and height; its next
cursor derives exactly `verified_height + 1`. There is no caller-supplied later
height or ancestry constructor.

### Fixed-validator artifact-only branch-state projection

The exact state-commitment domain and 300-byte preimage are specified in
`fixed-validator-proposer-state-v0.md`. The preimage is:

```text
ArtifactChainId[32]
|| ConsensusGenesisId[32]
|| ConsensusProtocolVersion_u32_be[4]
|| direct_child_ConsensusHeight_u64_be[8]
|| parent_ConsensusAncestryId[32]
|| exact_child_ArtifactBlock[128]
|| FixedAgreementSetId[32]
|| post_height_ProposerPriorityStateId[32]
```

The parent ancestry is included instead of the child ancestry to avoid a
self-referential digest: the child ancestry already hashes the complete value
containing this commitment. Round-local priorities and all evidence are
excluded. The post-height priority identity always comes from the first
proposer step for the height, even when later-round evidence authenticates the
value.

## Evidence-free identities

The trailing-NUL proposal-root domain is:

```text
naome:consensus-proposal-signing-root:v0\0
```

The exact proposal signing root is:

```text
SHA256(proposal_root_domain || canonical_value[268])
```

The trailing-NUL non-genesis ancestry domain is:

```text
naome:consensus-ancestry:v0\0
```

The exact evidence-invariant ancestry identity is:

```text
SHA256(consensus_ancestry_domain || canonical_value[268])
```

Both identities exclude round, producer authorization, and precommit evidence.
The proposal root is the exact target authenticated by both evidence objects.
Constructing either digest alone does not establish validity, availability,
selection, ancestry continuity, or finality.

## Canonical envelope and identity

One complete V0 envelope is the unambiguous concatenation:

```text
canonical_value[268]
|| producer_authorization[212]
|| non_nil_precommit_certificate[216..24696]
```

There is no additional version tag, count, or length prefix. The certificate's
embedded signer count must consume the exact remaining bytes. The complete
minimum is 696 bytes for one signer and the maximum is 25,176 bytes for 256
signers. Truncation, trailing bytes, and inputs above the maximum are rejected.
The proposal-control proof tag and any earlier-round prevote certificate are
never appended to this envelope; they are proposal-admission evidence only.

The trailing-NUL complete-envelope identity domain is:

```text
naome:consensus-envelope:v0\0
```

The exact evidence-variant identity is:

```text
SHA256(envelope_domain || complete_canonical_envelope_bytes)
```

Different valid rounds, signer subsets, or signature variants can produce
different `ConsensusEnvelopeId` values for one unchanged value, proposal root,
and ancestry identity. V0 does not select a preferred evidence variant or
define its durable retention.

## Typed verification

Verification is invoked on one sequential `FixedConsensusRoundV0`. The cursor
already owns or derives the exact branch context, direct child height, parent
ancestry, fixed set, active snapshot at its position, scheduled proposer,
post-height proposer base, and artifact parent. The caller supplies only the
complete envelope bytes and owned canonical artifact payload bytes.

All-or-nothing verification returns failures with this observable precedence:

1. Reject input above 25,176 bytes, then below 696 bytes.
2. Strictly decode the exact 268-byte value and reject reserved height zero.
3. Require exact chain, final-genesis, and protocol-version equality with the
   branch context, in that order.
4. Require the value height to equal the cursor's exact direct child height.
5. Require the embedded parent to equal the branch's exact ancestry; height one
   uses only its context-derived virtual-genesis sentinel.
6. Derive the complete fixed-validator artifact-only V0 branch-state projection
   from the branch, cursor, exact decoded artifact block, fixed-set identity,
   and post-height proposer state; require exact equality with the embedded
   bytes.
7. Require the branch's artifact snapshot chain to equal the context chain.
8. Strictly verify producer authorization against the cursor's scheduled
   proposer and internally derived active snapshot.
9. Require producer authorization to authenticate the value-derived proposal
   root.
10. Strictly verify the certificate-to-end-of-input as one non-nil precommit
    certificate against the same context and snapshot.
11. Require the certificate to authenticate the same proposal root.
12. Strictly validate the exact `ArtifactBlock` and supplied canonical artifact
    bytes as one child of the artifact snapshot coupled to the consensus parent.
13. Publish one verified transition only after every prior check succeeds.

Consuming the verified transition can return either a separate
`FixedConsensusBranchV0` or one sealed owned transition. The owned form retains
the exact verified byte inputs and the complete semantic parent coordinate;
callers cannot construct or retarget it from raw fields. Its child branch has
the value height and ancestry, the strict artifact successor, the unchanged
fixed set, and the height's once-advanced next-height proposer base. The
original branch, round cursor, and every journal remain unchanged on success or
failure.

This coupling closes the previous composition gap in which independent caller
inputs could name consensus ancestry from one branch and an artifact parent
from another. Explicit siblings remain constructible by verifying multiple
children from one immutable parent, but the API grants no sibling preference.

## Resource and compatibility boundary

The envelope decoder enforces its 25,176-byte bound before child allocation. It
verifies one producer signature and between one and 256 precommit signatures,
uses the fixed 256-validator bound, performs bounded exact proposer arithmetic,
and validates exactly one artifact child. Supplied artifact bytes remain subject
to the artifact decoder and checker resource contract.

This is deliberately the fixed-validator artifact-only V0 bridge. Its fixed
268-byte value cannot carry future economic or validator operations, a
prior-height settlement certificate, or definition supporting-proof proposal
input. Those fields require a newly specified successor or replacement format,
identity domains, and strict decoder; they must not be appended to or silently
reinterpreted as V0. This prerelease format has no production-data compatibility
promise.

The bounded unsigned in-memory fixed-validator lock and valid-value kernel is
specified separately in `fixed-validator-proposal-control-v0.md`; it does not
change this envelope or grant this component state-machine authority. Dynamic
validator selection and transitions, finite-window proposer-gap proofs,
durable locking, valid-value and anti-equivocation signing state, general
consensus-block formats, dynamic-set or multi-node finality,
checkpoint/bootstrap and external-anchor recovery, networking, peer trust,
data availability, and economics remain required product work outside this
component's authority. Fixed-artifact-V0 local durable installation,
caller-anchored strict replay, and conflict halt are specified separately in
`fixed-validator-finality-journal-v0.md`.
