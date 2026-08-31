# Fixed-validator proposal-control and lock state V0

## Status and authority

This specification defines the prerelease fixed-validator artifact-only V0
proposal-control bytes, their typed admission before an unsigned prevote
decision, and one bounded in-memory Tendermint lock-and-valid-value kernel. It
reuses the existing evidence-free 268-byte value, 212-byte producer
authorization, and generic prevote/precommit quorum-certificate formats. It
adds no new signature role, signing domain, proposal scalar, or final envelope
format.

Successful proposal admission proves that one complete artifact-only value and
canonical artifact payload strictly form the exact direct child expected by one
typed `FixedConsensusRoundV0`; that the round's deterministic proposer
authenticated the value-derived `ProposalSigningRoot`; and, when earlier-round
proof is present, that a strict-greater-than-two-thirds prevote/proposal
certificate authenticated the same root in one exact earlier round of the same
context and height. Only the sealed `VerifiedFixedConsensusProposalV0` result
may enter the lock kernel's proposal path.

The lock kernel produces unsigned local vote effects and bounded memory state.
It does not create, request, persist, or release a signature; prevent a caller
from asking another signer to equivocate; provide anti-equivocation durability
or rollback protection; survive restart; schedule a timeout; receive, buffer,
gossip, or fetch a proposal or vote; authenticate or trust a peer; select a
global branch; or finalize or persist a block. A libp2p `PeerId` remains only a
transport identity and cannot supply validator or consensus authority.

The separately specified `fixed-validator-vote-safety-journal-v0.md` may issue
one signing session that privately owns this kernel, derives its canonical
post-effect state-and-vote intents internally, and provides local per-key
prepare-before-sign, explicit external-anchor acknowledgement, complete-before-
release, and caller-anchored restart safety. The key-owning public path does not
accept a caller-created intent or mutable replacement kernel. That signer
boundary does not make a separate volatile kernel or unsigned effect
independently durable or signable.

## Canonical proposal-control bytes

One fixed-validator proposal-control V0 value is exactly:

```text
canonical_value[268]
|| producer_authorization[212]
|| proof_tag u8
|| proof
```

The two proof tags have these sole canonical meanings:

| Tag | Proof bytes | Complete length | Meaning |
| ---: | --- | ---: | --- |
| `0x00` | empty and immediate end of input | 481 bytes | no earlier-round valid-value proof |
| `0x01` | one complete canonical prevote/proposal quorum certificate consuming the remainder | 697..25,177 bytes | proof round is the certificate's authenticated round |

Every other tag is rejected. Tag `0x00` with any trailing byte is rejected.
Tag `0x01` with fewer than the certificate minimum, a certificate that does not
consume the remainder exactly, or total input above 25,177 bytes is rejected.
The certificate retains its existing 216..24,696-byte and 1..=256 signer
bounds. Decoding enforces the total-input cap before proof allocation.

The canonical value determines the sole `ProposalSigningRoot` exactly as
specified by `fixed-validator-artifact-consensus-envelope-v0.md`. The producer
authorization authenticates that root at the current round `R`. A present
certificate must have role prevote and target proposal, and its authenticated
round is the sole proof round `P`. The wrapper carries no independent
`validRound` scalar and no duplicated proof position. It is valid only when:

```text
certificate.context == producer_authorization.context
certificate.height  == producer_authorization.height
certificate.target  == ProposalSigningRoot(canonical_value)
P < R
```

The producer authorization must authenticate that same derived proposal root.
The typed verifier also requires both evidence objects to match the round
cursor's exact chain, final genesis, protocol version, height, and fixed
agreement set. The present certificate is verified against the immutable
snapshot at `(height, P)`; the producer authorization is verified against the
cursor's immutable snapshot at `(height, R)`. Absence means there is no proof
round. No sentinel integer represents absence.

The wrapper has no new signing transcript or signature. Producer authorization
continues to use only its existing current-round domain, and every certificate
signature continues to use only the existing prevote domain and embedded
earlier-round body. The `proof_tag` is framing rather than a separately signed
field: changing `0x01` to `0x00` while retaining proof bytes creates forbidden
trailing bytes, while removing a proof yields only the strictly weaker
no-proof proposal and cannot satisfy a conflicting-lock unlock condition.

The proposal-control verifier publishes no separate semantic identity or
semantic evidence preference. The value-derived `ProposalSigningRoot` remains
the semantic target of producer authorization and votes; the complete optional
certificate retains its existing `QuorumCertificateId` as evidence identity
only. The volatile lock state's later first-proof retention for the same value
and round is bounded local storage behavior, not a validity ordering.

## Typed sealed proposal admission

Proposal admission is invoked through one exact sequential
`FixedConsensusRoundV0`. The caller supplies canonical proposal-control bytes
and the owned canonical artifact payload; it does not supply an expected
proposer, height, ancestry, state commitment, artifact parent, agreement
snapshot, proposal root, or proof round.

Admission is all-or-nothing and requires:

1. exact bounded proposal-control framing and strict 268-byte value decoding;
2. the cursor's exact chain, final genesis, protocol version, direct-child
   height, consensus ancestry, fixed agreement set, and complete derived
   artifact-only branch-state commitment;
3. producer authorization by the cursor's deterministic current-round
   proposer over the exact value-derived proposal root;
4. strict validation of the embedded `ArtifactBlock` and supplied canonical
   payload as one child of the artifact snapshot coupled to the same consensus
   parent;
5. when tag `0x01` is present, one strictly verified prevote/proposal quorum
   over that same root and context at the exact derived earlier round `P < R`;
   and
6. publication of `VerifiedFixedConsensusProposalV0` only after every prior
   requirement succeeds.

The sealed result retains the exact current position, canonical value,
value-derived proposal root, producer authorization, optional proof-derived
round and certificate, canonical artifact payload, and verified immutable
child needed by later phases. It has no public unchecked or retargeting
constructor. Failure publishes neither a reusable partial validation token nor
an unsigned vote effect and changes no branch, artifact snapshot, journal, or
lock state.

Admission proves complete local proposal validity before voting, but admission
itself is not a vote. Multiple independently admitted siblings establish no
preference and must not be treated as anti-equivocation protection.

## In-memory lock and valid-value state

`FixedValidatorLockStateV0` holds at most one exact locked
`ConsensusValueV0` and its lock round `L`, plus at most one exact valid value,
its valid round `V`, and the canonical prevote certificate and evidence identity
that established it. The volatile state does not retain artifact payload bytes.
A later reproposal must re-supply and strictly revalidate the complete payload
and obtain new current-round producer authorization; round-specific producer
authorization is never reused.

The empty state can be constructed only from the exact branch-derived round-zero
cursor for one context and positive height. Its `FixedValidatorLockPhaseV0`
ordinary sequential-round path advances only from exact round `R` to `R + 1`
after a local precommit effect. Separately, one canonical current-round
precommit/nil quorum strictly verified against that cursor's private positioned
fixed-set snapshot may preempt the local Proposal, Prevote, or Precommit phase.
That evidence-bound path derives the same-branch `R + 1` cursor internally,
rather than accepting a caller-selected destination, and finalizes no value.
Both paths fail closed on round overflow, preserve the exact lock and complete
valid-value proof, reset only the consumed round-local phase, and make any
previously issued unsigned effect stale. There is no random-access round
constructor, attacker-sized fast-forward loop, or certificate-triggered jump to
an arbitrary higher round. Timeout expiry and scheduling are separate authority
and are not inferred from a nil certificate.

Every reachable nonempty lock has a valid value and `V >= L`. Proposal-quorum
effects create or replace both slots at the same current round, optional proof
can advance the valid slot, and either a nil quorum or a proof-authorized
conflicting proposal may clear the lock while preserving a valid value.

### Unsigned prevote effect

For one sealed proposal admitted at the current round `R`, the kernel derives
exactly one unsigned prevote target:

- with no lock, prevote the admitted proposal root;
- when the lock already names the same proposal root, retain the lock and
  prevote that root;
- when the lock names a different root and the admitted proposal carries proof
  round `P` satisfying `L < P < R`, clear the in-memory lock and prevote the
  admitted proposal root; or
- otherwise retain the lock and prevote its locked proposal root.

The proof comparison consumes only the round authenticated by the strictly
verified embedded certificate. A caller-supplied round, a no-proof proposal,
a proof round equal to or older than `L`, a current-round proof, or a proof for
another context, height, role, nil target, or proposal root cannot unlock a
different locked proposal. Clearing the lock does not clear or replace the
independently retained valid value.

Independently of the lock comparison, a proposal carrying proof round `P` newer
than the stored valid round replaces the bounded in-memory valid value and
certificate with that exact proposal value, `P`, and proof. Older proof is
ignored. Equal-round proof for the same exact value retains the first proof
variant, but equal-round proof for a different exact value returns a typed
local safety-conflict error before any unsigned vote effect or state mutation.
The error does not durably halt the node or retain the conflicting evidence.
Under the reachable `V >= L` invariant, newer proof for a different locked
value necessarily also satisfies `P > L`; newer proof for the same value may
advance the valid slot without clearing that matching lock.

The effect names what a separate signing subsystem may consider; it contains
no signature and grants no permission to sign or release one.

When the caller explicitly closes the proposal phase without an admitted
proposal, the kernel preserves both state slots and yields the locked proposal
root when locked or nil when unlocked. It does not schedule or infer the
propose timeout that caused the caller to choose this path.

### Current-round prevote-certificate effects

The current-round prevote phase accepts canonical certificate bytes only
together with the state's exact branch-derived `FixedConsensusRoundV0`. It
strictly verifies those bytes against that cursor's private immutable fixed-set
snapshot before any state change; a generic certificate verified against an
independently caller-supplied snapshot cannot provide this authority. The
result must belong to the state's exact context, height, and round `R`:

- a prevote/proposal quorum matching one sealed current-round proposal locks or
  relocks that exact proposal value at `R`, replaces the valid value, proof, and
  valid round with that value, current certificate, and `R`, and yields an
  unsigned precommit-proposal effect for its root;
- a prevote/nil quorum clears the lock, preserves the valid value, proof, and
  valid round unchanged, and yields an unsigned precommit-nil effect; and
- closing the phase without either current-round quorum preserves both lock
  and valid-value state unchanged and yields an unsigned precommit-nil effect.

An older-round certificate, a later-round certificate, a precommit certificate
at this phase, or a proposal certificate without the matching sealed admitted
proposal cannot mutate either slot. Nil evidence and phase close never clear a
valid value. Consuming a round-local phase prevents a second conflicting
effect from being published by the same in-memory state object, but this
process-local linearity is not durable signing safety.

## Matching precommit and unchanged final envelope

The sealed `VerifiedFixedConsensusProposalV0` may later accept one separately
verified non-nil precommit certificate only when its context, height, round
`R`, and proposal root exactly match that admitted current-round proposal. Nil,
another root, another round, or another context fails without publishing a
transition.

Success constructs the pre-existing final envelope without reinterpretation:

```text
canonical_value[268]
|| current_round_producer_authorization[212]
|| matching_current_round_non_nil_precommit_certificate[216..24696]
```

The proposal-control `proof_tag` and any earlier-round prevote certificate are
not present in that final envelope. Its canonical length remains 696..25,176
bytes, its `ConsensusEnvelopeId` remains defined by the existing envelope
domain, and its verification result remains the same sealed
`OwnedVerifiedFixedConsensusTransitionV0` accepted by the fixed-validator
finality journal. This step seals verified evidence; it does not itself select,
persist, or finalize the transition. Sealing deliberately does not require
that this process's volatile lock kernel previously emitted a matching
precommit effect: an externally obtained valid strict-supermajority precommit
certificate remains independently verifiable finality evidence.

## Resource and compatibility boundary

Proposal-control decoding processes exactly 481 bytes without proof or at most
25,177 bytes with proof. Admission verifies exactly one producer signature and
zero to 256 earlier-round prevote signatures, performs only fixed-set-bounded
snapshot and proposer work, and validates exactly one artifact child. The
state retains at most one lock and one valid value and performs constant
round comparisons; its valid slot retains at most one bounded 24,696-byte
prevote certificate and it does not accumulate proposals, rounds, payloads, or
peer data. Matching final-envelope sealing verifies at most 256 additional
current-round precommit signatures and retains the unchanged 25,176-byte final
envelope cap. Artifact payload bytes remain governed by the existing artifact
decoder and checker resource contract.

This prerelease V0 format has no production-data compatibility promise. An
incompatible successor must use a newly specified canonical decoder and any
new signature role must use a separately specified signing domain. Durable
lock, valid-value, phase, and anti-equivocation state plus conditional rollback
detection are supplied only when the separate vote-safety journal's single
issued session synchronizes the complete sealed post-effect intent under its
exact external-anchor contract. That session may move to a child height only by
consuming a matching branch-relative verified transition; it neither selects a
sibling nor durably installs finality. Timeout and arbitrary higher-round
advancement, external-anchor storage and recovery, networking, availability,
peer trust, global branch selection, dynamic-validator consensus, and durable
global-finality recovery remain required components whose authority is not
granted by this in-memory kernel or inferred from the signing journal.
