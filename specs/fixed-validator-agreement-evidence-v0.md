# Fixed-validator agreement evidence V0

## Status and authority

This specification defines the prerelease V0 canonical bytes and stateless
verification contract for separately signed Tendermint prevotes and
precommits, plus one bounded shared-body quorum-certificate layout reused for
prevote or precommit quorums over either nil or one opaque proposal signing
root.

Successful generic certificate verification proves only that distinct
Ed25519 keys in one exact caller-supplied immutable
`ActiveAgreementSnapshot` validly signed the certificate's exact embedded
prevote-or-precommit role and nil-or-proposal target at one exact
caller-supplied chain, final-genesis, protocol-version, height, and round
context, and that their exact weight is strictly greater than two thirds of
that snapshot's unchanged total active weight. Only a verified non-nil
precommit quorum can be published through the finality-facing
`VerifiedPrecommitCertificateV0` subtype; that subtype still proves agreement
evidence rather than a finality transition.

It does not prove that the supplied snapshot is canonical or correctly
derived; derive or validate the proposal signing root; prove that a proposal,
block, artifact, payload, or state transition exists, is valid, or is
available; select or finalize a block; mutate or persist selected state; run
Tendermint locking, timeouts, proposer selection, or round transitions; create
a signature; provide anti-equivocation durability; choose between conflicting
certificates; define evidence retention or preference; grant a network peer
validator authority; or establish any economic result. A libp2p `PeerId`
authenticates transport only and is unrelated to a consensus key.

## Primitive values

All integers are unsigned and big-endian. All byte strings have the exact
fixed width shown below.

| Value | Canonical representation | Meaning |
| --- | ---: | --- |
| `ArtifactChainId` | 32 bytes | Exact artifact-chain definition identity reused as the consensus chain-context field |
| `ConsensusGenesisId` | 32 bytes | Opaque final genesis identity supplied by the caller |
| `ConsensusProtocolVersion` | `u32` | Protocol version carried by this agreement evidence |
| `ConsensusHeight` | `u64` | Positive non-genesis height; zero is rejected |
| `ConsensusRound` | `u64` | Tendermint round, including round zero |
| `ProposalSigningRoot` | 32 bytes | Opaque evidence-free proposal target; derivation is outside this specification |
| `ConsensusKey` | 32 bytes | Raw RFC 8032 Ed25519 verifying-key bytes |
| `ConsensusSignature` | 64 bytes | Raw RFC 8032 Ed25519 signature bytes |

Constructing the opaque context values does not prove their derivation,
installation, or support. Protocol-version support and downgrade rejection are
caller responsibilities outside this stateless verifier.

## Canonical vote body

Every V0 prevote and precommit has one 118-byte canonical body:

| Offset | Width | Field | Canonical rule |
| ---: | ---: | --- | --- |
| 0 | 1 | role | `0x01` prevote; `0x02` precommit; every other value is rejected |
| 1 | 32 | chain | exact `ArtifactChainId` bytes |
| 33 | 32 | genesis | exact `ConsensusGenesisId` bytes |
| 65 | 4 | version | `ConsensusProtocolVersion` as `u32` big-endian |
| 69 | 8 | height | `ConsensusHeight` as `u64` big-endian; zero is rejected |
| 77 | 8 | round | `ConsensusRound` as `u64` big-endian |
| 85 | 1 | target tag | `0x00` nil; `0x01` proposal; every other value is rejected |
| 86 | 32 | target payload | all zero for nil; exact opaque `ProposalSigningRoot` bytes for proposal |

A proposal root containing 32 zero bytes is valid because the target tag keeps
it distinct from nil. A nil target with any nonzero target-payload byte is
noncanonical and rejected rather than normalized.

## Signing transcript and signed vote

The role-specific trailing-NUL ASCII signing domains are:

```text
prevote:   naome:consensus-prevote-signing:v0\0
precommit: naome:consensus-precommit-signing:v0\0
```

The exact unsigned signing transcript is:

```text
role_signing_domain || canonical_vote_body[118] || ConsensusKey[32]
```

The domain is reconstructed from the canonical role tag and is not duplicated
in the signed-vote wire bytes. The role tag remains inside the authenticated
body. Ed25519 signs this complete transcript directly according to RFC 8032.
There is no caller-visible SHA-256 prehash, Ed25519ph mode, double hash, remote
signer, or aggregate signature.

The complete signed-vote wire representation is exactly 214 bytes:

```text
canonical_vote_body[118] || ConsensusKey[32] || ConsensusSignature[64]
```

`ConsensusVoteId` is:

```text
SHA256(role_signing_domain || canonical_vote_body || ConsensusKey)
```

It excludes the signature. Valid signature variants over one exact semantic
vote therefore share one `ConsensusVoteId`; this specification does not select
or persist a preferred signature variant.

Standalone signed-vote verification requires one caller-selected expected
`ConsensusContextV0`. Verification rejects a chain, genesis, or protocol
version mismatch before public-key or signature work, then parses the raw
Ed25519 key and applies strict Ed25519 verification to the exact transcript.
Success authenticates the embedded position, role, signer, and target but does
not establish active-set membership or agreement.

## Canonical quorum certificate

The V0 certificate compresses multiple signatures over one shared vote body.
Its exact representation is:

```text
shared_vote_body[118]
signer_count u16 big-endian
signer_count * (
    ConsensusKey[32]
    ConsensusSignature[64]
)
```

The shared body admits exactly the four combinations formed by role `0x01`
prevote or `0x02` precommit and target tag `0x00` nil or `0x01` proposal:

```text
prevote   / proposal
prevote   / nil
precommit / proposal
precommit / nil
```

Every combination uses the identical representation, signer-count bound,
entry order, signature verification, and agreement-weight threshold. The
embedded role and target remain authenticated protocol values and are never
normalized or inferred from a consuming state-machine phase. Generic success
publishes `VerifiedQuorumCertificateV0`; only the precommit/proposal
combination may also publish `VerifiedPrecommitCertificateV0`. A verified
prevote or nil certificate does not itself lock, unlock, update a valid value,
advance a phase or round, or finalize anything.

`signer_count` is in `1..=256`. Entries are strictly ascending by the raw 32
consensus-key bytes. Equal keys are duplicates and rejected. Descending or
otherwise unsorted keys are noncanonical and rejected rather than reordered.
Each signature authenticates the role-specific signing transcript reconstructed
from the shared body and that entry's exact consensus key.

The complete length is:

```text
120 + 96 * signer_count bytes
```

The minimum is 216 bytes and the maximum is 24,696 bytes. The decoder rejects
input above the maximum before allocation, rejects a declared count above 256
before entry allocation, and requires the declared count to consume the input
exactly. Truncation and trailing bytes are errors.

`QuorumCertificateId` is exactly:

```text
SHA256(complete_canonical_certificate_bytes)
```

For a verified non-nil precommit, `PrecommitCertificateId` retains these same
32 digest bytes through the specialized compatibility boundary. Different
valid signer subsets or valid signature variants produce different certificate
evidence identities while retaining the same authenticated role and target.
Certificates with different authenticated roles or targets also have distinct
complete canonical bytes and therefore distinct identities. This identity
defines neither evidence preference nor consensus ancestry.

## Certificate verification

Verification receives the canonical certificate bytes, one exact expected
`ConsensusContextV0`, and one borrowed immutable `ActiveAgreementSnapshot`.
It proceeds all-or-nothing in this order:

1. Enforce the complete input-size bound, fixed body framing, supported role
   and target tags, canonical nil payload, positive height, signer-count bound,
   exact derived length, strict key order, and distinct keys.
2. Require exact equality between the embedded and expected chain, final
   genesis, and protocol version.
3. Require exact equality between the certificate height and round and the
   supplied snapshot position.
4. Require every listed key to be active in that snapshot and compute the exact
   sum of their stored agreement weights. Unlisted active weight remains in the
   denominator.
5. Parse every listed Ed25519 verifying key and strictly verify every signature
   in ascending key order.
6. Require the authenticated signer weight `S` to be strictly greater than two
   thirds of the unchanged total active snapshot weight `T`.
7. Only after every prior check succeeds, publish one borrowed
   `VerifiedQuorumCertificateV0` exposing the exact authenticated role and
   target.

The threshold is mathematically `3 * S > 2 * T`, but the reference verifier
uses the equivalent division-and-remainder comparison so the full `u128`
weight domain cannot overflow. Exact two-thirds equality fails. A snapshot's
offline validators remain in `T`; verification never renormalizes the
denominator.

The verified generic value borrows the supplied snapshot so it cannot silently
outlive its verification context. It exposes the authenticated role, target,
position, ascending signer keys, signed weight, unchanged total weight,
canonical bytes, and evidence identity. It has no public unchecked
constructor. The finality-facing `VerifiedPrecommitCertificateV0` boundary
accepts only an already fully verified certificate whose role is precommit and
whose target is one proposal signing root. The other three valid generic forms
cannot produce that subtype.

## Resource and compatibility boundary

One signed vote performs one strict Ed25519 verification. One quorum
certificate in any of the four supported role-target forms contains at most
256 keys and signatures, performs at most 256 active-set lookups and 256 strict
Ed25519 verifications, and allocates only after its count and exact byte length
pass the fixed bounds.

This is a prerelease V0 format with no production-data compatibility promise.
Any incompatible successor must use new role signing domains and a newly
specified canonical decoder. A future proposal-message codec, proposal-root
derivation, canonical consensus-block envelope, validator-snapshot derivation,
signing subsystem, Tendermint state machine, network protocol, or durable
finalized-state transition must not reinterpret these bytes silently.
