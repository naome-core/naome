# Fixed-validator artifact consensus envelope V0

## Status and authority

This specification defines the prerelease artifact-only V0 consensus value,
its evidence-free proposal and ancestry identities, the complete
certificate-bearing envelope, and one stateless verification boundary that
joins the value to existing V0 producer authorization and precommit evidence.

Successful verification proves that one exact canonical value:

- names the caller-selected chain, final genesis, protocol version, positive
  height, and required consensus parent;
- carries the caller-expected opaque post-consensus-state commitment;
- is the exact proposal root authenticated by the caller-designated active
  producer and by a strict greater-than-two-thirds non-nil precommit
  certificate over one caller-supplied immutable agreement snapshot; and
- contains an `ArtifactBlock` that strictly validates with caller-supplied
  canonical artifact bytes against one caller-supplied immutable artifact
  branch snapshot.

The result owns the resulting immutable artifact successor. This verifier
passes the same agreement-snapshot reference into both child verifiers and
offers no public constructor that joins separately verified evidence.

Success does not prove that the supplied agreement snapshot, proposer,
expected prior ancestry, expected state commitment, artifact parent, or
artifact bytes came from canonical state. It does not derive consensus state,
select a proposal or chain, execute Tendermint locking or round transitions,
resolve conflicting certificates, install finality, mutate a selected journal,
persist a value or certificate, provide crash-atomic recovery, gossip or fetch
data, grant a peer consensus authority, create signatures, provide signing
safety, select validators, or establish an economic result. A libp2p `PeerId`
authenticates transport only and is unrelated to a consensus key.

## Primitive values

All integers are unsigned and big-endian. All byte strings have the exact
fixed width shown below.

| Value | Canonical representation | Meaning |
| --- | ---: | --- |
| `ArtifactChainId` | 32 bytes | Exact artifact-chain and consensus chain context |
| `ConsensusGenesisId` | 32 bytes | Opaque final genesis identity supplied by the caller |
| `ConsensusProtocolVersion` | `u32` | Exact protocol version carried by the value and evidence |
| `ConsensusHeight` | `u64` | Positive non-genesis height; zero is rejected |
| `ConsensusAncestryId` | 32 bytes | Value-derived ancestry address or context-derived virtual-genesis sentinel |
| `ArtifactBlock` | 128 bytes | Existing unchanged canonical artifact-block representation |
| `ConsensusStateCommitment` | 32 bytes | Opaque post-consensus-state commitment |
| `ProposalSigningRoot` | 32 bytes | Evidence-free proposal target derived from the value |
| `ConsensusEnvelopeId` | 32 bytes | Evidence-variant address of one complete envelope |

Every 32-byte state commitment, including all zero bytes, is representable.
The verifier accepts it only when it equals the exact caller-expected bytes.
Representability and equality do not prove derivation, execution, installation,
or availability of the committed state.

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
| 236 | 32 | post-consensus state | exact opaque `ConsensusStateCommitment` bytes |

The value carries no round and no producer or agreement evidence. The same
value may therefore be proposed again at another round without changing its
proposal signing root or ancestry identity. Producer authorization and every
vote still authenticate one exact round under their existing V0 contracts.

### Parent semantics

Consensus height one names a virtual-genesis parent. Its trailing-NUL ASCII
domain is:

```text
naome:consensus-ancestry-genesis:v0\0
```

The virtual-genesis identity is exactly:

```text
SHA256(
    genesis_ancestry_domain
    || ArtifactChainId[32]
    || ConsensusGenesisId[32]
    || ConsensusProtocolVersion_u32_be[4]
)
```

At height one the verifier requires the caller's expected-prior-ancestry input
to be absent and requires the embedded parent to equal this exact sentinel. At
every height greater than one the input must be present and the embedded parent
must equal that exact caller-expected `ConsensusAncestryId`. The verifier does
not fetch, select, or prove availability of that prior value.

## Evidence-free identities

The trailing-NUL ASCII proposal-root domain is:

```text
naome:consensus-proposal-signing-root:v0\0
```

The exact V0 proposal signing root is:

```text
SHA256(proposal_root_domain || canonical_value[268])
```

The trailing-NUL ASCII non-genesis ancestry domain is:

```text
naome:consensus-ancestry:v0\0
```

The exact evidence-invariant ancestry identity is:

```text
SHA256(consensus_ancestry_domain || canonical_value[268])
```

Both identities exclude round, producer authorization, and precommit evidence.
The proposal root is the exact target that both embedded evidence objects must
authenticate. Constructing either digest does not establish proposal validity,
selection, availability, ancestry continuity, or finality.

## Canonical envelope and identity

One complete V0 envelope is the unambiguous concatenation:

```text
canonical_value[268]
|| producer_authorization[212]
|| non_nil_precommit_certificate[216..24696]
```

There is no envelope version tag, count, or length prefix beyond fields already
inside these V0 children. The value and producer authorization are fixed width.
The remaining bytes are exactly one self-framed canonical precommit
certificate, whose embedded signer count determines and must consume its exact
length. The complete minimum is 696 bytes for one signer and the complete
maximum is 25,176 bytes for 256 signers. Truncation, trailing bytes, and input
above the maximum are rejected rather than ignored or normalized.

The trailing-NUL ASCII complete-envelope identity domain is:

```text
naome:consensus-envelope:v0\0
```

The exact evidence-variant identity is:

```text
SHA256(envelope_domain || complete_canonical_envelope_bytes)
```

Different valid rounds, signer subsets, or signature variants can produce
different `ConsensusEnvelopeId` values for one unchanged value, proposal root,
and `ConsensusAncestryId`. This V0 contract neither selects a preferred evidence
variant nor defines retention, deduplication, or durable storage policy.

## Verification

Verification receives the complete canonical envelope bytes, one exact
expected context, one caller-designated expected proposer, one borrowed
immutable active-agreement snapshot, an expected prior ancestry that is absent
exactly at height one and present at later heights, one exact expected opaque
post-consensus-state commitment, one immutable artifact parent snapshot, and
owned canonical artifact payload bytes. It proceeds all-or-nothing in this
order:

1. Reject input above 25,176 bytes, then reject input below 696 bytes.
2. Strictly decode the exact 268-byte value and reject reserved height zero.
3. Require exact chain, final-genesis, and protocol-version equality with the
   caller-selected context, in that order.
4. Require the value height to equal the borrowed agreement snapshot height.
5. Enforce the height-one virtual-genesis or later-height caller-expected parent
   rule.
6. Require the embedded state commitment to equal the caller-expected bytes.
7. Require the artifact parent snapshot's chain to equal the expected chain.
8. Strictly verify the embedded producer authorization under its existing V0
   contract against the same expected context, caller-designated proposer, and
   borrowed snapshot.
9. Require the producer authorization to authenticate the proposal root derived
   from the value.
10. Strictly verify the certificate-to-end-of-input as one non-nil precommit
    certificate under its existing V0 contract against the same expected
    context and borrowed snapshot.
11. Require the precommit certificate to authenticate the same derived proposal
    root.
12. Strictly validate the embedded `ArtifactBlock` and supplied canonical
    artifact bytes as one child of the immutable artifact parent snapshot.
13. Only after every prior check succeeds, publish one verified envelope with
    byte-identical re-encoding, the complete-envelope identity, both borrowed
    evidence objects, and the owned immutable artifact successor.

No selected predecessor is mutated on success or failure. Consuming the result
may transfer the immutable artifact successor, but does not install it as a
selected or finalized branch.

## Resource and compatibility boundary

The envelope decoder enforces its 25,176-byte bound before child allocation.
It verifies exactly one producer signature and between one and 256 precommit
signatures, uses the existing fixed 256-validator agreement bound, and validates
exactly one artifact child. The separately supplied canonical artifact bytes
remain subject to the artifact decoder and checker resource contract.

This is deliberately the **fixed-validator artifact-only V0** bridge. Its fixed
268-byte value cannot carry the already-decided future economic-operation or
validator-operation sequences, prior-height settlement certificate, or
definition supporting-proof proposal input. It therefore does not complete the
global consensus-block codec. Those fields require a newly specified successor
or replacement value and envelope with new identity/signing domains and a new
strict decoder; they must not be appended to or silently reinterpreted as this
V0 format. This prerelease format has no production-data compatibility promise.

Canonical snapshot and proposer derivation, finality installation, consensus
and artifact persistence, restart recovery, fork selection, evidence-variant
storage, networking, peer trust, and economics remain required product work,
but are outside this component's authority rather than outside the NAOME
roadmap.
