# Fixed-validator producer authorization V0

## Status and authority

This specification defines the prerelease V0 canonical bytes and stateless
verification contract for one validator producer authorization over one opaque
evidence-free proposal signing root.

Successful verification proves that the exact consensus key designated by the
caller is present in one exact caller-supplied immutable
`ActiveAgreementSnapshot` for the authorization's height and round and that
the same key directly signed the canonical producer-authorization transcript.
The borrowed snapshot is verification context, not proposer-selection or
canonical-state authority.

This contract does not derive or validate the proposal signing root; prove that
a proposal, consensus block, artifact, payload, or state transition exists, is
valid, or is available; derive the canonical active snapshot; run weighted
round-robin or prove that the caller designated the canonical proposer; create
a signature or provide anti-equivocation durability; select or finalize a
block; mutate or persist state; define a signed proposal control message or
consensus-block envelope by itself; grant a network peer validator authority;
or establish any economic result. The separately specified fixed-validator
proposal-control V0 wrapper reuses this complete authorization unchanged after
typed value and branch admission. A libp2p `PeerId` authenticates transport
only and is unrelated to a consensus key.

## Primitive values

All integers are unsigned and big-endian. All byte strings have the exact fixed
width shown below.

| Value | Canonical representation | Meaning |
| --- | ---: | --- |
| `ArtifactChainId` | 32 bytes | Exact artifact-chain context supplied by the caller |
| `ConsensusGenesisId` | 32 bytes | Opaque final genesis identity supplied by the caller |
| `ConsensusProtocolVersion` | `u32` | Protocol version carried by this authorization |
| `ConsensusHeight` | `u64` | Positive non-genesis height; zero is rejected |
| `ConsensusRound` | `u64` | Tendermint round, including round zero |
| `ProposalSigningRoot` | 32 bytes | Opaque evidence-free proposal target |
| `ConsensusKey` | 32 bytes | Raw RFC 8032 Ed25519 proposer verifying-key bytes |
| `ConsensusSignature` | 64 bytes | Raw RFC 8032 Ed25519 signature bytes |

Constructing the opaque context values, root, or consensus key does not prove
their derivation, installation, support, validity, or authority. Every 32-byte
proposal-root value, including all zero bytes, is representable because this
format does not interpret or derive the root.

## Canonical authorization body

Every V0 producer authorization has one 116-byte canonical body:

| Offset | Width | Field | Canonical rule |
| ---: | ---: | --- | --- |
| 0 | 32 | chain | exact `ArtifactChainId` bytes |
| 32 | 32 | genesis | exact `ConsensusGenesisId` bytes |
| 64 | 4 | version | `ConsensusProtocolVersion` as `u32` big-endian |
| 68 | 8 | height | `ConsensusHeight` as `u64` big-endian; zero is rejected |
| 76 | 8 | round | `ConsensusRound` as `u64` big-endian |
| 84 | 32 | proposal root | exact opaque `ProposalSigningRoot` bytes |

The body has no role tag. The producer-authorization signing domain supplies
the role binding, and another role's domain cannot be substituted.

## Signing transcript and complete proof

The trailing-NUL ASCII signing domain is:

```text
naome:consensus-producer-authorization:v0\0
```

The exact unsigned signing transcript is:

```text
producer_authorization_domain || canonical_body[116] || ConsensusKey[32]
```

Ed25519 signs this complete transcript directly according to RFC 8032. There is
no caller-visible SHA-256 prehash, Ed25519ph mode, remote-signer variant, or
aggregate signature.

The complete canonical producer authorization is exactly 212 bytes:

```text
canonical_body[116] || ConsensusKey[32] || ConsensusSignature[64]
```

This V0 verifier publishes no producer-authorization semantic identity.
Accepted bytes can be re-encoded byte-identically, while evidence identity,
variant retention, and preference remain outside this contract and undecided.

## Verification

Verification receives the canonical authorization bytes, one exact expected
`ConsensusContextV0`, one caller-designated expected proposer key, and one
borrowed immutable `ActiveAgreementSnapshot`. It proceeds all-or-nothing in
this order:

1. Require exactly 212 input bytes and reject height zero.
2. Require exact chain, final-genesis, and protocol-version equality with the
   caller-selected expected context, in that order.
3. Require exact equality between the authorization height and round and the
   borrowed snapshot position.
4. Require the embedded proposer key to equal the caller-designated expected
   proposer key.
5. Require that exact proposer key to be active in the borrowed snapshot. No
   weight threshold, rank, or proposer-selection calculation is performed.
6. Parse the raw proposer key as an RFC 8032 Ed25519 verifying key.
7. Apply strict Ed25519 verification to the exact direct signing transcript.
8. Only after every prior check succeeds, publish one
   `VerifiedProducerAuthorizationV0` borrowing that snapshot.

The verified value exposes the embedded context, position, opaque proposal
root, proposer key, signature, and byte-identical canonical re-encoding. It has
no public unchecked constructor. The snapshot borrow prevents position-scoped
active-membership verification from being laundered into a timeless value.

## Resource and compatibility boundary

One verification processes exactly 212 input bytes, performs one active-set
membership lookup over at most 256 entries, parses one Ed25519 key, and performs
one strict Ed25519 verification. It allocates only the fixed-size signing
transcript used by the verification library.

This is a prerelease V0 format with no production-data compatibility promise.
Any incompatible successor must use a new signing domain and a newly specified
canonical decoder. The proposal-control wrapper specified in
`fixed-validator-proposal-control-v0.md` adds no new producer signature or
signing domain and does not reinterpret these bytes. Any successor
proposal-root derivation or proposal codec, proposer-selection algorithm,
canonical consensus-block envelope, snapshot derivation, signing subsystem,
network protocol, or durable consensus or finalized-state transition must not
reinterpret these bytes silently.
