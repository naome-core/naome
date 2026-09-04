# Fixed-Validator Vote-Safety Journal V0

## Status and authority

This document normatively defines one local, per-consensus-key durable signing
boundary for fixed-validator artifact-only V0 proposals, prevotes, and
precommits. Its
public key-owning path never accepts a caller-created proposal or
`FixedValidatorVoteIntentV0`. Instead, the journal issues one sealed signing
session whose private `FixedValidatorLockStateV0` alone may prepare an intent;
it does not accept caller-assembled lock, valid-value, phase, position, role,
target, proposal value, signing transcript, or predecessor-lineage fields.

`FixedValidatorVoteSafetyJournalV0` retains the original caller-anchored state-
identity acknowledgements. `FixedValidatorAnchoredVoteSafetyJournalV0` owns the
canonical per-key file-backed anchor defined by
`fixed-validator-external-anchor-v0.md`, exposes no raw journal escape hatch,
and advances that anchor before publishing any state-changing outcome, live
height or round effect, key-use authority, terminal stop, or signed proposal or
vote bytes.

The journal owns one `ed25519_dalek::SigningKey` in memory, exposes no secret
key getter or export path, and creates only the existing V0 producer-
authorization, prevote, and precommit signatures for its matching
`ConsensusKey`. It has no remote-signer protocol. The journal file never stores
the secret seed. The reference build enables the signing key's `zeroize` drop
behavior; this is best-effort process-memory cleanup rather than hardware
custody, swap exclusion, or proof that no other seed copy exists.

Moving a Rust `SigningKey` into this handle does not prove that no copy of the
seed exists elsewhere. The local anti-equivocation guarantee therefore requires
the journal signer to be the sole operational use path for that key. A copied
key, another process, another directory, or an unsupported signer can violate
that deployment condition without changing these bytes.

This is local signing safety rather than consensus authority. The journal does
not prove that its chain, final genesis, protocol version, fixed agreement set,
branch, lock state, valid value, or vote target is globally canonical. Those
values enter only through the typed fixed-validator branch and lock kernel.
After a session is issued, its lineage advances to a new height only through an
externally acknowledged transition reconstructed by a caller-selected local
finality journal from retained selected history. Before the first session, the
caller-selected round-zero bootstrap coordinate is itself persisted as an exact
signing-lineage record and externally anchored. The caller retains authority for
selecting and attesting that initial coordinate; a later reopen no longer has
authority to replace it. An exact anchored reopen may instead issue one opaque
signer-recovery capability whose fields are derived entirely from the retained
lineage and latest durable current-lineage state: round zero, the latest
completed proposal or vote, or the latest higher-round checkpoint. A finality
journal may consume that capability to recover only the matching branch
retained by the configured finality journal; callers cannot supply its height,
coordinate, signer, fixed set, or round. At initial height one this is the
journal's configured virtual-genesis branch, accepted only when its complete
coordinate reproduces the already persisted lineage digest. Recovery therefore
reproduces the exact bootstrap binding and cannot replace, reselect, or
independently attest it.

## Journal-issued signing lineage

One successfully created or strictly reopened key-owning handle may issue at
most one non-clone signing session. The issuance latch is monotonic for that
handle and is not released by dropping or forgetting the session. A failed
attempt using a wrong external state identity or mismatching typed round does
not consume the latch, but once a session has been returned there is no second
session, raw-intent preparation, or direct key-signing path through that handle.

A header-only journal is provisioning state, not signing authority. Proposal
authoring must first be activated exactly once with a positive, independent
prepared-proposal ceiling. That additive activation is synchronized and
externally anchored before a fresh or recovered signing session may be issued.
Exact repeat activation is no-write; another ceiling fails typed.
`bind_signing_lineage` first strictly derives or restores the supplied typed
round, then appends and synchronizes one exact lineage record when none exists.
An exact existing binding is no-write idempotence; a different branch or height
cannot replace it. The caller must externally persist the returned exact current
journal-state identity. `issue_signing_session` accepts only that exact current
identity and a typed round whose parent coordinate, signing height, context,
fixed set, and signer reproduce the retained lineage binding.

The anchored wrapper's lineage bind advances its paired anchor before returning,
and its session-issuance method accepts no caller state identity. It derives the
same check only from the still-live journal-and-anchor pair.

At the current retained lineage height, a healthy completed journal strictly
restores only its latest durable current-lineage state against the supplied
exact typed round. A completed proposal or vote is reconstructed from its exact
complete-state intent. A higher-round checkpoint is reconstructed only after its retained
certificate is fully reverified against that typed target round's private fixed-
set snapshot. When the latest durable state belongs to an older lineage, the
exact retained current branch starts at round zero. Historical states are not
selectable. A pending proposal or vote, halted, poisoned, header-mismatching,
unbound, wrongly anchored, or lineage-mismatching journal issues no session.

`acknowledge_signer_recovery_is_externally_durable` is the branch-independent
restart path. It requires the exact complete current vote-journal state identity,
the same healthy recoverable state required for ordinary session issuance, one
retained lineage, and an unused handle issuance latch. Success returns one
non-clone `FixedValidatorAnchoredSignerRecoveryV0` that immutably borrows the
issuing journal. The capability privately binds the complete lineage digest,
signer, required latest position, exact vote state, and live-handle provenance;
it has no public constructor, serialization, or raw lineage accessor.

One finality journal may consume that capability and return an opaque
`FixedValidatorRecoveredSignerBranchV0` only when its replay-retained branch at
exactly `signing_height - 1` reproduces the complete lineage digest. The vote
journal then consumes that value through `issue_recovered_signing_session`,
rechecks the exact current external vote anchor and pointer-identical handle
provenance, derives round zero from the recovered branch, and advances
sequentially to the position of the latest same-lineage completed proposal,
vote, or higher-round checkpoint. A caller-local inclusive
`FixedValidatorSignerRecoveryRoundLimitV0` is checked before that loop; it bounds
restart work without changing protocol validity or either journal's durable
identity. Only after exact typed proposal or vote-intent replay or complete
checkpoint-state and certificate reverification succeeds does the handle consume its sole
session latch and release the branch paired with the session.

The session exclusively owns the recoverable lock state. It exposes the current
position, phase, lock, and valid value read-only and delegates only the fixed
kernel's proposal authoring, prevote, precommit, sequential-round, bounded
authenticated higher-round, and durable-finality transition operations. It exposes no mutable
state reference, unchecked state replacement, generic mutation closure, raw-
intent submission, secret key, raw verified-child height transition, or raw or
unacknowledged signing method. A caller may calculate with a separate fresh lock
kernel, but its effects cannot enter this journal's key-owning path: session
preparation recomputes the hidden state binding and requires the effect's private
volatile lineage seal to be pointer-identical to the session's exact lock-state
instance.

Moving the key-owning lineage to the next height starts with one non-clone
`FixedValidatorDurableFinalityTransitionV0<'journal>`. Only the finality journal's
`acknowledge_signer_height_transition_is_externally_durable` may produce that
token after matching its exact current state identity and strictly
reconstructing an operable retained selected child. The token immutably borrows
that journal through lineage persistence, external vote-journal acknowledgement,
and successful consumption. The signing session has no public raw
`OwnedVerifiedFixedConsensusTransitionV0` height path. The non-key-owning
consensus lock kernel may still consume that proof as a branch-relative
transition; doing so creates no signing authority.

`prepare_height_with_durable_finality` first requires the transition's exact
parent coordinate and height to match the private current state and derives only
the sealed child's round zero. Before changing signer memory, it appends and
synchronizes a `0x04` record for that exact child lineage and returns an opaque
`FixedValidatorPreparedHeightAdvanceV0` carrying the still-live finality token,
the new vote-journal state identity, and private signing-session provenance.
Every proposal, vote, round, higher-round checkpoint, or second height
transition is blocked while this live height advance awaits acknowledgement.

The caller next advances its separate vote-journal anchor to that exact state
identity. For the current live session,
`acknowledge_prepared_height_is_externally_durable` rechecks the identity,
session provenance, current record, and live finality token before it consumes
the verified transition, derives the same child round zero, clears the old-height
lock and valid value, and returns that exact child branch. It never accepts a
separately supplied or cloned child branch. A wrong acknowledgement returns no
child and consumes the one-shot capability; the anchored journal must be
reopened to resume the already persisted child lineage.

On the anchored signing-session wrapper, preparation has already synchronized
the child-lineage anchor before returning the capability. Its
`acknowledge_prepared_height` therefore accepts no caller state identity and
publishes only that internally anchored exact child.

The handoff is ordered rather than cross-file atomic: finality and its external
anchor complete first, then the child signing-lineage record and vote anchor,
then volatile signer-memory advancement. The exact external child-lineage anchor
is the durable signer-authorization boundary. A crash or token drop after that
boundary but before live acknowledgement may reopen without reissuing the
consumed height-transition token or repeating bootstrap selection. Real process
restart reconstructs the missing branch only by combining the vote journal's
opaque anchored recovery capability with matching replay-retained finality
history. An old anchor rejects a complete child-lineage suffix; an anchor ahead
of durable bytes also fails closed. Once a child proposal or vote is prepared,
the ordinary pending-message recovery rule applies. Neither journal rolls the
other back or repairs an external-anchor gap.

Finality authorization is point-in-time. Once the exact child-lineage state is
externally anchored, a later finality-journal conflict halt alone does not
retroactively revoke that durable signer lineage or its subsequent proposals or
votes. This
holds whether the same live session successfully consumes the token or the
token is dropped and an exact reopen recovers the anchored child. Revocation becomes
durable only when the caller externally anchors that exact conflict and
explicitly routes the separate proof-backed stop capability below into this
signer journal. The vote lineage does not otherwise persist a finality state
identity or clock, so the pre-stop exception proves semantic branch agreement
under the caller's point-in-time contract, not objective chronology, unique
finality provenance, or cross-journal atomicity.

## Explicit proof-backed finality-conflict stop

After a finality journal durably records either a selected-sibling conflict or
a neutral paired-preselection conflict and the caller separately anchors its
exact terminal state identity,
`acknowledge_signer_stop_is_externally_durable` may issue one non-clone
`FixedValidatorDurableFinalityConflictV0`. Private fields bind the still-live
halted journal, exact consensus context and fixed set, conflict height, both
ancestry and envelope identities, halt kind, and exact terminal finality state.
The public copyable halt summary and raw constructible state IDs are diagnostics
and cannot substitute for this capability.

The caller must explicitly consume one capability into every local signer that
must stop. `stop_after_durable_finality_conflict` accepts it on either the
key-owning journal or its already-issued live session, requires exact context and
fixed-set equality. A selected-sibling halt appends and synchronizes terminal
tag `0x05`; a neutral paired-preselection halt appends and synchronizes terminal
tag `0x0b`. Both use the same fixed-width evidence-address fields, but their
distinct tags and halt kinds are never interchangeable for replay or exact-repeat
idempotence. The conflict applies at any height to every signer in that fixed
set; the destination does not compare it with one signer height or bind it to
one key. Equivalent strictly verified finality histories may supply the same
semantic authority. The handoff selects neither sibling and grants no rollback,
fork-choice, peer, path, or device provenance authority.

The stop preempts a pending preparation, pending height transition, or pending
higher-round checkpoint and blocks all later session transitions, key use,
retained-vote release, session issuance, and recovery. It cannot retract signed
bytes already returned to a caller. Exact repeat evidence is no-write
idempotence; another finality conflict or an existing same-slot terminal halt
cannot replace the first stop. State and stop diagnostics remain readable. The
required order is finality-conflict sync, external finality anchor, borrowed
capability, vote-stop sync, then external vote anchor. Neither journal can prove
the caller's anchor persistence, update all configured signers automatically, or
make these files and anchors one atomic transaction.

When both sides use anchored wrappers, each applicable anchor update is internal
to its own append boundary. `acknowledge_signer_stop` and the anchored vote stop
still form an explicitly routed ordered handoff; they do not make the finality
journal, finality anchor, vote journal, and vote anchor one transaction.

## Canonical post-effect vote intent

`FixedValidatorVoteIntentV0` seals one complete post-effect lock snapshot and
one vote effect for the same fixed-validator branch position. All integers are
unsigned big-endian. Its canonical variable-length bytes are:

| Offset | Width | Field | Canonical rule |
| ---: | ---: | --- | --- |
| 0 | 37 | intent header | exact `naome:fixed-validator-vote-intent:v0\0` |
| 37 | 32 | chain | exact `ArtifactChainId` |
| 69 | 32 | final genesis | exact opaque `ConsensusGenesisId` |
| 101 | 4 | protocol version | exact `ConsensusProtocolVersion` |
| 105 | 1 | parent-height tag | `0x00` absent or `0x01` present |
| 106 | 8 | parent verified height | zero when absent; positive `ConsensusHeight` when present |
| 114 | 32 | parent ancestry | exact `ConsensusAncestryId` |
| 146 | 32 | parent artifact head | exact `ArtifactBlockId` |
| 178 | 32 | parent artifact-set root | exact `ArtifactSetRoot` |
| 210 | 32 | fixed set | exact `FixedAgreementSetId` |
| 242 | 32 | parent proposer state | exact parent `ProposerPriorityStateId` |
| 274 | 32 | post-height proposer state | exact round cursor `ProposerPriorityStateId` |
| 306 | 8 | height | positive current `ConsensusHeight` |
| 314 | 8 | round | current `ConsensusRound` |
| 322 | 1 | post-effect phase | `0x01` prevote or `0x02` precommit; proposal-phase tag `0x00` cannot form a vote intent |
| 323 | 1 | lock tag | `0x00` absent or `0x01` present |
| 324 | 0 or 276 | lock payload | when present, `ConsensusValueV0[268] || lock_round_u64_be[8]` |
| variable | 1 | valid-value tag | `0x00` absent or `0x01` present |
| variable | 0 or `312 + certificate_length` | valid-value payload | when present, `ConsensusValueV0[268] || valid_round_u64_be[8] || QuorumCertificateId[32] || certificate_length_u32_be[4] || canonical_prevote_certificate[216..=24,696]` |
| variable | 1 | vote role | `0x01` prevote or `0x02` precommit |
| variable | 33 | vote target | `0x00 || zero[32]` for nil or `0x01 || ProposalSigningRoot[32]` for proposal |
| variable | 32 | signer | exact active `ConsensusKey` |

The complete canonical intent is 391 bytes with no lock or valid value. A lock
adds exactly 276 bytes. A valid value adds 312 bytes plus one complete canonical
216..=24,696-byte prevote certificate. The maximum with both present and a
256-signer certificate is therefore exactly 25,675 bytes. Every other tag,
nonzero absent-height payload, zero present height, noncanonical nil target,
shorter or trailing input, oversized certificate, or derived-length mismatch
is rejected.

The snapshot is the state after the in-memory kernel has decided the unsigned
effect. A prevote effect therefore retains phase `Prevote`; a precommit effect
retains phase `Precommit`. The effect position must equal the state position,
the journal-selected intent signer must be active in the round cursor's
immutable fixed set, and all branch, fixed-set, phase, lock, valid-value,
certificate, role, and target invariants are checked before a sealed intent is
published. There is no public unchecked constructor or retargeting method.

Each live `FixedValidatorUnsignedVoteEffectV0` privately carries a state binding
derived as SHA-256 of the exact trailing-NUL domain
`naome:fixed-validator-vote-effect-state-binding:v0\0` followed by the canonical
state fields from context through the optional valid-value certificate. The
binding excludes role, target, signer, and the intent header because those are
checked separately. `prepare_vote_intent` recomputes it from the current lock
state and rejects a stale or cross-state effect before canonical bytes are
published. In addition, every live lock-state instance owns one private
process-local `Arc` seal and clones only its pointer identity into effects it
emits. `prepare_vote_intent` requires pointer equality with that exact state;
therefore another fresh kernel cannot substitute a different target even when
both decisions converge to identical post-state fields. Structural decoding
creates only an unsealed observed effect, and typed replay reconstructs a new
state with a new seal, never a live signing effect. Neither the digest nor the
seal is serialized, secret, a consensus identity, a signature domain, or a
restart capability.

The intent reconstructs the existing 118-byte canonical vote body and the
existing role-specific signing transcript:

```text
prevote:   "naome:consensus-prevote-signing:v0\0"
           || canonical_vote_body[118] || ConsensusKey[32]
precommit: "naome:consensus-precommit-signing:v0\0"
           || canonical_vote_body[118] || ConsensusKey[32]
```

The durable snapshot introduces no new wire signature domain and is not
appended to the signed vote. Completing an intent with one
`ConsensusSignature` first applies the existing strict Ed25519 verification and
then publishes the unchanged 214-byte signed-vote representation:

```text
canonical_vote_body[118] || ConsensusKey[32] || ConsensusSignature[64]
```

Header-bound `ObservedFixedValidatorVoteIntentV0` decoding checks exact framing,
context, fixed-set identity, signer, internal state/effect consistency, and
bounded certificate structure but grants no signing transcript or completion
method. Verification against the exact matching `FixedConsensusRoundV0`
rechecks the parent branch, both proposer-state identities, position, active
signer membership, complete retained certificate signatures and weight, phase,
lock, valid value, role, and target before reconstructing a
`VerifiedReplayFixedValidatorVoteIntentV0`. That replay result remains
non-signable. Only the live in-memory lock kernel's `prepare_vote_intent`
operation may publish `FixedValidatorVoteIntentV0` with a signing transcript and
strict signature-completion method. Stored bytes never self-authorize a branch
cursor or recreate live signing authority.

## Canonical durable higher-round checkpoint

The canonical higher-round checkpoint representation retains one complete
phase-only jump prepared by the live lock kernel. All integers are unsigned
big-endian. Its variable-length bytes are:

| Offset | Width | Field | Canonical rule |
| ---: | ---: | --- | --- |
| 0 | 49 | checkpoint header | exact `naome:fixed-validator-higher-round-checkpoint:v0\0` |
| 49 | 8 | source height | positive current `ConsensusHeight` |
| 57 | 8 | source round | exact pre-jump `ConsensusRound` |
| 65 | 1 | source phase | `0x00` Proposal, `0x01` Prevote, or `0x02` Precommit |
| 66 | 32 | source-state binding | digest defined below |
| 98 | `288..=25,572` | target state snapshot | exact branch, target position and phase, lock, and valid-value fields defined below |
| variable | 4 | triggering-certificate length | canonical `u32`; exactly the remaining certificate width |
| variable | `216..=24,696` | triggering certificate | one exact canonical generic prevote or precommit quorum certificate |

The target state snapshot is the vote-intent state encoding from exact chain
through optional valid-value certificate, without the 37-byte intent header,
vote role, vote target, or signer. Its fixed 288 bytes encode context, parent-
height tag and value, all six 32-byte branch and proposer-state bindings, target
height and round, target phase, and absent lock and valid-value tags. A present
lock adds exactly 276 bytes. A present valid value adds exactly 312 bytes plus
its exact `216..=24,696`-byte retained prevote certificate.

The source snapshot is exactly the target snapshot with only position and phase
replaced by the separately encoded source position and phase. The binding is:

```text
SHA256(
  "naome:fixed-validator-higher-round-source-state-binding:v0\0"
  || exact_source_state_snapshot
)
```

The target height must equal the source height, its round must be strictly
higher, and its phase must be `Prevote` for either prevote target or `Precommit`
for either precommit target. Lock and complete valid-value fields are therefore
byte-identical across source and target. The triggering certificate header must
match the journal context, target position, and role-corresponding target phase.
Nil and proposal targets are retained only inside that exact certificate and do
not change the state snapshot.

The complete checkpoint is exactly `606..=50,370` bytes. The minimum is an
empty state plus one one-signer certificate. The maximum permits a lock, one
valid value with a 256-signer retained certificate, and a separate 256-signer
triggering certificate. Structural decoding enforces this complete bound before
allocation, every tag and derived width, source binding, state invariant,
certificate framing, context and position, and canonical re-encoding.
Structural decoding cannot authenticate triggering-certificate signatures,
membership, or weight because the journal header stores only the fixed-set
identity, not the private positioned set. It also cannot fully authenticate a
retained valid-value proof. Both certificates obtain authority only when exact
typed target-round replay rechecks them against that cursor's private fixed-set
snapshot before a signing session is issued.

For a healthy signing session with no pending proposal or vote, height
transition, or higher-round checkpoint,
`prepare_higher_round_quorum_advance` first obtains the non-mutating verified
kernel transition under its positive caller-local inclusive round ceiling. It
then appends and synchronizes one exact `0x06` checkpoint frame and chained
footer before returning a session-bound one-shot capability and its state
identity. Live position, phase, lock, valid value, and key use remain unchanged.
While acknowledgement is pending, every other mutable session path is blocked
except the explicit proof-backed finality-conflict stop, which may preempt the
checkpoint.

The caller must advance its separately protected monotonic anchor to that exact
checkpoint state identity. `acknowledge_prepared_higher_round_is_externally_durable`
rechecks the exact identity, same-session provenance, current journal state,
latest retained checkpoint, and unchanged live source state before it publishes
only the target position and phase. A wrong, stale, or foreign acknowledgement
publishes nothing and leaves exact anchored reopen as the recovery path. A crash
or token loss after the complete frame became durable is recoverable because no
signature or key authority was used: strict reopen at that exact anchor derives
the exact target cursor and fully reverifies the checkpoint before issuing a
session. An older typed cursor fails; no historical checkpoint is selectable.
Any append ambiguity poisons the live handle, and the existing proof-backed
finality-conflict stop may preempt a pending checkpoint.

On the anchored session wrapper, checkpoint preparation advances the paired
anchor before returning. `acknowledge_prepared_higher_round` accepts no caller
state identity and can publish only the exact internally anchored capability.

## Separate per-key files and header

The journal uses a namespace separate from the selected finality journal. For
the signer's 32 raw public-key bytes encoded as exactly 64 lowercase hexadecimal
characters, the files are:

```text
fixed-validator-vote-safety-<64-lowercase-hex-key>.lock
fixed-validator-vote-safety-<64-lowercase-hex-key>.journal
```

The exact 185-byte journal prefix is:

```text
"naome:fixed-validator-vote-safety-journal:v0\0"[45]
ArtifactChainId[32]
ConsensusGenesisId[32]
ConsensusProtocolVersion_u32_be[4]
FixedAgreementSetId[32]
ConsensusKey[32]
positive_max_prepared_votes_u64_be[8]
```

Creation derives the signer key from the consumed `SigningKey` and accepts one
caller-supplied `ConsensusContextV0` and opaque `FixedAgreementSetId`. The later
sealed live intent must carry those same values from its typed round cursor, but
the journal header does not prove how either caller input was selected or
derived. `max_prepared_votes` is a positive caller-local resource ceiling on
distinct prepared vote slots retained by this append-only journal. It is not a
protocol-wide height, round, liveness, or vote-validity rule. Zero is invalid.

Creation uses create-new semantics, takes the per-key lock exclusively and
nonblockingly, writes the complete header, and synchronizes it before success.
It never replaces another key's journal or either fixed-validator finality file.
Portable durability of the parent-directory entry remains caller
responsibility.

Anchored creation additionally synchronizes the journal parent directory, then
creates and synchronizes the independent per-key anchor before returning. The
anchor filename, exclusive lock, 256-byte codec, exact signer binding, and
platform durability requirement are defined by
`fixed-validator-external-anchor-v0.md`. Paired construction and open acquire
the journal lock before the anchor lock.

Strict reopen requires the same key-owning `SigningKey`, context, fixed set,
and local preparation ceiling. A wrong key selects a different filename and
cannot acquire signing authority from another key's file; any mismatch in a
located file's complete header fails before replayed state is exposed.

## Record framing

Every committed record is:

```text
body_length_u32_be[4]
record_body[body_length]
FixedValidatorVoteSafetyJournalStateIdV0[32]
```

The first body byte is the record tag and has exactly these meanings:

| Tag | Remaining body bytes | Meaning |
| ---: | --- | --- |
| `0x01` | one exact canonical `FixedValidatorVoteIntentV0` | prepared post-effect state and vote intent |
| `0x02` | one exact canonical signed vote `[214]` | completed signature for the immediately pending prepared intent |
| `0x03` | one exact canonical `FixedValidatorVoteIntentV0` | observed non-identical intent for an already retained vote slot; terminal local halt |
| `0x04` | `signing_height_u64_be[8] || SigningLineageIdV0[32]` | exact initial or sequential child signing-lineage binding |
| `0x05` | `finality_state_id[32] || conflict_height_u64_be[8] || selected_ancestry[32] || selected_envelope[32] || conflicting_ancestry[32] || conflicting_envelope[32]` | terminal local signer stop transferred from one exact externally anchored selected-sibling finality conflict |
| `0x06` | one exact canonical higher-round checkpoint `[606..=50,370]` | externally anchorable phase-only higher-round state |
| `0x07` | positive proposal replay limit as `u64` big-endian | one-time proposal-authoring activation |
| `0x08` | one exact canonical proposal intent `[629..=25,913]` | prepared complete Proposal-phase state and producer intent |
| `0x09` | one exact producer authorization `[212]` | completed producer signature for the immediately pending proposal intent |
| `0x0a` | one non-identical canonical proposal intent `[629..=25,913]` | terminal local halt for an occupied proposal position |
| `0x0b` | `finality_state_id[32] || positive_conflict_height_u64_be[8] || first_ancestry[32] || first_envelope[32] || second_ancestry[32] || second_envelope[32]` | terminal local signer stop transferred from one exact externally anchored neutral paired-preselection halt |

A completion body is exactly 215 bytes and its complete frame is 251 bytes.
One signing-lineage body is exactly 41 bytes and its complete frame is 77 bytes.
Each selected-sibling or neutral paired-preselection finality-conflict stop body
is exactly 169 bytes and its complete frame is 205 bytes. Equal-width tags
retain distinct semantics and exact-repeat identities.
Prepare and halt bodies are 392..=25,676 bytes and their complete frames are
428..=25,712 bytes. Higher-round checkpoint bodies are 607..=50,371 bytes and
their complete frames are 643..=50,407 bytes. Proposal activation body/frame is
9/45 bytes, proposal completion body/frame is 213/249 bytes, and proposal
prepare or halt bodies/frames are 630..=25,914/666..=25,950 bytes. Before allocation, every
`body_length` must be in the bounded union of those admitted widths. After the
bounded body is read, its tag-specific width and canonical framing are checked
during tag dispatch before admission.

`SigningLineageIdV0` is the exact SHA-256 result:

```text
SHA256(
  "naome:fixed-validator-vote-safety-signing-lineage:v0\0"
  || ArtifactChainId[32]
  || ConsensusGenesisId[32]
  || ConsensusProtocolVersion_u32_be[4]
  || parent_verified_height_tag_u8[1]
  || parent_verified_height_u64_be[8]
  || ConsensusAncestryId[32]
  || parent_ArtifactBlockId[32]
  || parent_ArtifactSetRoot[32]
  || FixedAgreementSetId[32]
  || parent_ProposerPriorityStateId[32]
  || signing_height_u64_be[8]
  || ConsensusKey[32]
)
```

The parent-height tag is `0x00` with a zero height for virtual genesis and
`0x01` with a positive height otherwise. The committed coordinate is the exact
parent coordinate from which the signing height's round zero is derived; the
round is therefore implicitly zero and is not a separately caller-supplied
field.

The first lineage record may appear only with no pending proposal or vote. If
completed legacy V0 vote records precede it, its height must equal the latest
retained vote height. Every later lineage record must be exactly one height
greater than the previous lineage and may appear only with no pending proposal
or vote. When a lineage exists,
every prepare record must be at its current height. A duplicate, replacement,
skipped or exhausted lineage height, lineage while pending, vote at another
height, malformed payload, or any record after either terminal cause fails
strict replay. Lineage
records do not consume the header's distinct-prepared-vote ceiling.

A higher-round checkpoint requires an existing current signing lineage and no
pending proposal or vote. Its target height must equal that lineage height. Its
source coordinate may equal or be ahead of the latest durable current-lineage
coordinate, accounting for supported volatile phase and sequential-round work,
but it may never be behind it. Its target round is strictly greater than its
source round. Replay retains only the latest current-lineage state in memory
while every historical frame remains chained and structurally checked. A later
checkpoint source may not move behind that retained state. A later vote-state
snapshot must be strictly greater under `(height, round, Proposal < Prevote <
Precommit)`; the vote slot's role-corresponding phase cannot equal or precede
the checkpoint. These persistence-order checks grant no protocol authority to
skip a round or phase; the same journal-issued session and verified kernel
transition supply that authority live.

File replay checks checkpoint framing, context, fixed-set identity, source
binding, state invariants, certificate header and position, and role-to-phase
mapping. It deliberately does not treat raw file parsing as certificate
signature, membership, weight, retained-proof, branch, or signing authority.
The latest checkpoint is fully reverified only during exact typed ordinary
session issuance or capability-gated signer recovery.

Proposal authoring must be activated by exactly one `0x07` record before any
session or recovery issuance. Activation has its own positive preparation
ceiling and does not reinterpret the unchanged journal header or existing vote
limit. Every new `0x08` position must be strictly greater than the latest
retained proposal position, belong to the current signing-lineage height, retain
Proposal phase, and not equal or precede the latest vote position. Conversely,
a later vote position may not precede the latest proposal. Proposal and vote
preparations share one pending-effect boundary. Byte-identical proposal replay
is no-write; an exact `0x09` completion reconstructs and verifies the existing
producer authorization against its pending intent before proposal-control bytes
may be released.

One non-identical proposal intent for an already occupied position appends
`0x0a` before key use and terminally stops this local signer. The retained
preparation plus the conflicting record preserve both exact intents. Their
roots and intent digests are local diagnostics rather than objective
equivocation proof, signer attribution, peer evidence, branch selection, or
finality authority. A conflict halt may close the matching pending slot or a
previously completed slot. Replay rejects it while the other message kind or a
different slot of the same kind is pending, preserving the live serial
boundary.

A tag-`05` or tag-`0b` finality-conflict stop is the sole record that may
intentionally preempt an unrelated pending preparation. A same-slot conflict
halt may instead follow only the matching pending proposal or vote. The
finality stop's kind, positive conflict height, and exact fixed width are
validated under the context and fixed set already bound by the journal header;
the compact record is a durable enforcement and audit marker, not an independent
reverification of either full finality proof. It invalidates any held live
prepare, height, or higher-round authority and consumes no prepared-vote
capacity. No record may follow it.

A completion is valid only when strict verification proves that its signer,
context, position, role, target, and transcript exactly match the one pending
prepared intent. A halt body retains the newly observed conflicting intent; the
earlier prepare record retains the already accepted intent. No completion may
appear without exactly one pending prepare, no second distinct completion may
replace the retained signed bytes, and no record may follow either terminal
cause.
At most one prepared intent may be incomplete at a time. Byte-identical
re-preparation through the same uninterrupted live handle is idempotent,
but no later slot, role, or round may be prepared until the pending intent is
completed. A process restart with an incomplete preparation never reconstructs
signing authority from those bytes, even when their state identity matches the
external anchor. This serializes the state transitions the external anchor must
protect and fails closed across the prepare-to-completion crash gap.

Replay checks every field and trailing byte of every complete record. At most
one incomplete final frame is handled, and only under the separately anchored
recovery rule below. The journal never normalizes, reorders, or synthesizes an
intent or signed vote from partial persisted fields.

## Chained state identity and external anchor

`FixedValidatorVoteSafetyJournalStateIdV0` is an exact 32-byte identity for one
complete local per-key history. The empty state is:

```text
SHA256(
  "naome:fixed-validator-vote-safety-state-genesis:v0\0"
  || complete_header[185]
)
```

Every accepted proposal activation, proposal or vote prepare, completion or
same-slot halt, signing-lineage binding, finality-conflict stop, or higher-round
checkpoint record derives its footer as:

```text
SHA256(
  "naome:fixed-validator-vote-safety-state-step:v0\0"
  || prior_state_id[32]
  || body_length_u32_be[4]
  || complete_record_body[body_length]
)
```

The resulting identity is stored as the record's 32-byte footer and becomes the
prior identity for the next record. The footer is excluded from its own
preimage. An exact repeated proposal activation, byte-identical idempotent
preparation, completed proposal or vote replay, exact current-lineage binding,
or exact repeated same-kind finality-conflict stop writes no record and leaves
the state identity unchanged. Equal fields under the other finality-stop tag are
not interchangeable.

This unkeyed digest detects history changes relative to an independently
trusted expected identity; it is not a secret authenticator and cannot make the
file its own trust anchor. It is not a `ConsensusVoteId`, proposal root,
consensus ancestry, finality proof, globally trusted checkpoint, or global
rollback-prevention mechanism.

The caller must retain the genesis identity and every later identity it accepts
in a separately protected monotonic anchor, advancing only to an identity
returned after that record's footer synchronization. It must never resume this
key from an older accepted identity. The exact initial signing-lineage identity
and proposal-activation identities must be anchored before session issuance;
every child signing-lineage identity must be anchored before volatile height
advancement; every prepared proposal or vote identity must be anchored before
the corresponding private-key use; each proposal or vote completion identity
must be anchored before signed bytes are released; every higher-round
checkpoint identity must be anchored before its position or phase is published
live; and a same-slot or finality-conflict stop identity must be anchored before
treating that local key as durably stopped. Each corresponding API requires
explicit acknowledgement of that exact still-current identity. A wrong or
stale identity is rejected before session publication, height or higher-round
publication, key use, or a completion append. The journal verifies identity and
ordering, but each acknowledgement is a caller assertion: the journal cannot
prove that the external store is durable, monotonic, honest, or unavailable to
an attacker. A false acknowledgement violates this signing contract.

The anchored wrapper removes these caller assertions. Every state-changing
frame advances the private paired anchor after the footer synchronization and
before returning. Its activation, lineage, proposal or vote preparation and
completion, height, checkpoint, and stop acknowledgement methods accept no
caller state identity; raw state IDs remain diagnostics and cannot construct
the private journal-to-anchor transition.

Operational reopen requires the exact separately trusted expected terminal
state identity. Replay validates the header, framing, every chained footer,
lineage sequence, proposal activation and ceiling, proposal and vote intents,
completed messages, preparation/completion relations, vote ceiling, and
terminality before exposing any journal state. It returns a key-owning handle
only when the final recomputed identity equals that external expectation. When
its current complete final record is an exact child-lineage binding, the handle
can authorize reconstruction without recreating the consumed height-transition
token. It still needs either the exact caller-held typed branch through ordinary
issuance or the capability-gated matching branch from retained finality history;
the 41-byte lineage record does not encode the branch itself. A final higher-
round checkpoint is recoverable only at its exact typed target and after full
checkpoint and certificate verification; no live acknowledgement token is
reconstructed. If the final state is either terminal cause or a prepared-but-
uncompleted proposal or vote intent, the handle is diagnostic only: every
signing and signer-recovery capability path remains fail-closed and no live
prepared capability is reconstructed.

`FixedValidatorAnchoredVoteSafetyJournalV0::open` instead loads the exact per-key
file-backed anchor under journal-then-anchor exclusive locking and requires both
the complete frame count and state identity to match replay. Anchor behind,
anchor ahead, and equal-sequence divergence fail separately without choosing or
changing a complete side. Only after equality, the existing incomplete-tail
rule, and synchronization of the anchor file and parent directory may the
key-owning wrapper be published.

At most one framing-incomplete final record may be truncated only after the
strictly replayed complete prefix already equals the expected identity. A
complete suffix beyond an older anchor is never rolled back or adopted; an
anchor ahead of the complete file is never repaired. Thus deletion,
reordering, substitution, or rollback fails closed when the caller preserves a
monotonic trusted anchor. Persisting and protecting that anchor, resolving an
anchor/file crash gap, backup, restore, and operator recovery policy remain
outside this journal.

## Prepare, sign, complete, release

Preparation and signing are separate signing-session operations connected by
one opaque `FixedValidatorPreparedVoteV0` and one private-field durability-
acknowledgement capability. This gives the caller the prepare state identity
needed to monotonically advance its separate anchor before it may ask the key
to sign. For a new admissible vote slot, the key-owning path performs this
order:

1. Derive the sealed intent internally from the session's exact lock state,
   typed round, unsigned effect, and journal signer, then validate it against
   the header, resource ceiling, retained slot history, and healthy non-halted
   state.
2. Append and synchronize `body_length || prepare_body`, append the derived
   state-ID footer, synchronize again, and return only the opaque live prepared
   capability and prepare state identity.
3. Require the caller to advance its separate durable anchor to that exact
   prepared state identity and explicitly acknowledge the same identity through
   a capability bound to that live preparation.
4. Only after validating that acknowledgement in the same uninterrupted
   signing session, use the private local key to sign the retained sealed
   intent's exact existing role-specific transcript.
5. Strictly verify that signature by completing the sealed intent, obtaining
   the canonical 214-byte signed vote.
6. Append and synchronize `body_length || completion_body`, append the derived
   state-ID footer, and synchronize again.
7. Only after the complete completion footer is synchronized, publish the
   signed-vote bytes and resulting state identity to the caller.

For the anchored session, step 2 also replaces and synchronizes the prepare
anchor before returning. Its acknowledgement accepts only the opaque prepared
capability. Step 6 likewise replaces and synchronizes the completion anchor;
only then may step 7 release signed bytes. An anchor-update error poisons the
pair and returns no signed vote even when the completion footer became durable.

While a vote preparation is pending, the session admits no lock-state, round,
higher-round checkpoint, or height mutation. An acknowledgement cannot be
manufactured through safe public API fields and carries the exact live prepared
capability; signing revalidates the current pending slot and prepared state
identity before key use. The type does not cryptographically attest the external
store and is never serialized or treated as consensus evidence.

The two synchronization points per frame define a durable framed boundary;
they do not claim whole-frame atomic filesystem writes. Any append seek, write,
or synchronization failure poisons the live handle because durability may be
ambiguous. A poisoned handle returns no signed bytes and has no further signing
authority. A reopen read, truncation, or stabilization failure returns no
handle. Both paths require a later fresh strict anchored reopen.

A crash after durable preparation but before completion permanently closes this
V0 operational signer path, even if the exact prepare-state identity was safely
anchored. Reopen may diagnose the pending slot summary and identity but cannot
sign, complete, skip, truncate, or replace it. This deliberately avoids turning
a disk decoder into post-restart signing authority. Separately authorized
operator recovery or key replacement is outside V0.

A crash after durable completion but before delivery permits only
byte-identical re-release of the retained strictly verified signed vote. The
implementation does not infer delivery, broadcast, certificate inclusion, or
finality from either case.

A complete externally anchored higher-round checkpoint has different recovery
semantics from a pending vote because it used no key and released no signature.
A crash before live acknowledgement may strictly reopen only at that exact
state identity, derive the checkpoint's exact typed target under the caller-
local recovery ceiling, fully reverify the triggering certificate and retained
valid proof, and resume no lower than the checkpoint. A complete checkpoint
suffix beyond an older anchor still fails closed; the journal does not adopt or
roll it back.

On a healthy non-halted reopened journal with no pending proposal or vote,
session issuance first matches the exact current lineage and external state
identity. If the latest durable current-lineage state is a completed proposal or
vote, issuance internally retrieves only its exact canonical complete-state
intent, requires its durable completion, and strictly restores that state
against the exact typed round. If it is a higher-round checkpoint, issuance
retains only the latest checkpoint, requires its exact target cursor, and fully
reverifies its complete state and certificate. If the current lineage is newer
than any retained state, issuance instead requires its exact caller-supplied
child round zero and carries no older-height lock or valid state forward. No
public coordinate-based, raw-state, or historical-state lookup exists: recovery
cannot resume an older lock state and then advance past newer retained state.
Only strict proposal-intent replay,
`VerifiedReplayFixedValidatorVoteIntentV0`, or
`VerifiedReplayFixedValidatorHigherRoundCheckpointV0` verification may
reconstruct a same-lineage lock, valid value, proof, and phase inside the
returned session. These replay values are non-signing. Ordinary issuance
verifies a caller-held exact typed cursor. Capability-gated restart instead
obtains the sole matching branch from retained finality history and internally
derives the exact cursor under the caller-local round-work ceiling. Neither path
grants global branch authority or permits historical state choice.

While such a session is healthy and has no pending proposal or vote
preparation, height transition, or higher-round checkpoint, the node may apply
either one exact context-and-position-bound Precommit close or one canonical
current-round precommit/nil quorum through the kernel's sequential-round path.
The explicit close additionally requires the current phase to be Precommit and
accepts no caller cursor. The evidence-bound path verifies the certificate
against the exact current cursor, derives the same-branch `R + 1` cursor
internally, and may preempt any local round phase. Both paths preserve the exact
lock and complete valid-value proof. This volatile advancement appends no
journal record, changes no journal state identity, and releases no signature.
Any later proposal or vote at `R + 1` must still pass through its ordinary
prepare, external-anchor acknowledgement, private-key use, completion, and
release sequence above. The volatile advance itself is never recovered. If the
process restarts without a later durable node or signer action, strict reopen
reconstructs only the prior durable current-lineage state; the caller must
resupply the exact close identity or re-observe and resupply the quorum to apply
the volatile advance again. Otherwise restart follows that later durable ready,
pending, or terminal state, including the existing non-signable
pending-preparation rule. The journal retains neither the close event nor
current-round quorum and infers no timeout expiry, scheduling, finality,
networking, peer trust, or branch selection from either.

While the same session also has no pending higher-round checkpoint, it may use
the separate bounded higher-round path. Unlike the current-round nil transition,
that path must synchronize and externally anchor the exact `0x06` checkpoint
before publishing the new live position and phase. It retains the triggering
certificate precisely so exact anchored restart can reproduce the higher floor.
Neither path emits a vote; every later signature remains behind the ordinary
prepare, vote-anchor acknowledgement, completion, and release sequence.

An incomplete preparation surviving restart exposes only its position,
prepare-state identity, message-kind-specific proposal root or vote role and
target, and the fact that it is non-signable. Its full intent bytes are not
exposed through the operational API, so a caller cannot advance consensus state
from an unresolved prepare boundary. Terminal halt denies completed-state
retrieval as well as signing and message release.

If a complete prepare or completion became durable but the caller crashed
before monotonically advancing its separate anchor, reopen with the old anchor
fails closed. If the caller advanced the anchor before the corresponding footer
became durable, reopen with the new anchor also fails closed. The journal does
not select between those ambiguous states or weaken the expected identity so
that signing can continue.

## Exact replay and terminal local stops

A vote slot is the exact `(context, height, round, role)` for the journal's
fixed signer key. Only a byte-identical complete prepared intent is idempotent
inside the uninterrupted signing operation. Once the slot has a durable
completion, exact replay returns only the retained signed bytes and changes
neither journal bytes nor state identity. An incomplete preparation surviving
restart is diagnostic only and cannot be resumed.

Distinct new slots are ordered lexicographically by height, round, and role,
using `Prevote < Precommit` only as the role comparison. Each new slot must be
strictly greater than the latest retained vote slot and, when a higher-round
checkpoint is latest, its complete post-effect phase must be strictly later than
that checkpoint's `(height, round, phase)`. An unrecorded earlier or equal slot
fails without a write or signature. The sequence need not contain every
role: a validator may abstain from a signature and later sign a session-
authorized higher slot, but it cannot return to fill the skipped slot afterward.
This persistence order does not itself authorize a skipped round, higher-round
jump, or new height. The same journal-issued session must carry every supported
lock transition. Advancing the current live session to a new height requires the
consumed externally acknowledged durable-finality transition defined above;
after the exact child lineage is externally anchored, an exact reopen may resume
that already persisted height without recreating or consuming the token.

Any non-identical canonical intent for an already retained slot is rejected
before the private key signs it. The handle first durably appends the `0x03`
halt record and its chained footer, then enters a permanent local halt. A
different target at the same slot is a conflicting local signing intent, not
objective equivocation evidence, because the second intent is never signed.
Objective equivocation remains the separate signed-conflicting-message contract
defined by `PROD-015`. The same target with a different lock, valid-value,
phase, branch, or intent byte is not a second objective vote target, but it is
still a local restart-safety inconsistency and halts rather than silently
replacing the state that authorized the first vote.

After either same-slot halt or finality-conflict stop, no proposal or vote may
be prepared, signed, completed, or released. The applicable summary and exact
state identity remain diagnostic. A vote same-slot halt identifies retained and
observed targets; a proposal same-slot halt identifies retained and conflicting
roots and domain-separated intent digests. Neither chooses a valid branch,
claims that a message was broadcast, nor converts the unsigned observed intent
into public equivocation evidence. A finality-conflict stop identifies only the
compact evidence address transferred by the live capability and is not a
standalone proof. Recovery, key replacement, evidence publication, and fleet
coordination require separately specified authority.

## Resource and compatibility boundary

Each intent retains at most one bounded canonical lock snapshot and one bounded
valid-value certificate. A vote intent additionally retains one 118-byte vote
body and one 214-byte completed vote; a proposal intent retains one 268-byte
value and completes one 212-byte producer authorization. Signature work is one
local Ed25519 signature plus one strict verification.
The positive header ceiling bounds distinct prepared votes admitted to one
journal; exact replays do not consume another slot. Completion through the same
uninterrupted live handle and either terminal record remain permitted for already
admitted state so the cap cannot prevent fail-closed conflict recording.
Signing-lineage records do not consume this vote-preparation ceiling; their
strict positive sequential-height rule is the separate bound. Higher-round
checkpoints also do not consume prepared-vote capacity: each is independently
bounded to 50,370 payload bytes, only the latest current-lineage state is kept
in memory, and its target round must strictly increase from its source under the
positive caller-local inclusive work ceiling. The header ceiling remains
vote-only and does not bound the cumulative number of checkpoints or total
append-only file size if callers later raise their per-call round ceiling. A
separate positive activation ceiling bounds distinct proposal preparations;
exact replay, completion, and fail-closed same-slot conflict consume no extra
proposal capacity. A process crash may intentionally strand an incomplete
proposal or vote preparation because
V0 prefers loss of liveness to reconstructed signing authority.

The journal is append-only and retains its complete accepted signing history.
It provides no pruning, compaction, automatic or incompatible-format migration,
cross-key transaction, automatic rotation, or backup policy. This prerelease V0
has no production-data compatibility promise. Any incompatible successor must
use new filenames,
header and state-ID domains, strict decoder, and—if the existing signed-vote
meaning changes—new role signing domains rather than reinterpreting these
bytes.

The `0x04` record is a backward-readable extension of the existing V0 header and
state chain: the current implementation strictly opens older header-only and
prepare/complete histories that contain no lineage record. Such a history has no
new signing session authority until `bind_signing_lineage` appends one exact
current binding. For a legacy completed history, the supplied typed round must
strictly replay its latest completed intent and the first binding height must
equal that latest vote height. After the first lineage record, every later
binding is sequential and the legacy no-lineage path is permanently closed.
The additive `0x05` selected-sibling stop, `0x06` higher-round checkpoint,
`0x07` through `0x0a` proposal records, and `0x0b` neutral paired-preselection
stop are likewise readable by the current decoder but
intentionally rejected by older binaries that do not recognize them. A healthy
older journal must append and anchor `0x07` before any current implementation
session or recovery issuance. Older binaries are not forward compatible with
newly extended journals; this prerelease format makes no such promise.

The journal does not implement timeout scheduling, unauthenticated or unbounded
higher-round progression, proposal or certificate buffering and routing,
dynamic validator sets, selection among verified sibling branches, durable
installation or recovery of global finality, global safety or liveness,
networking, peer discovery or trust, artifact availability,
hardware-backed or adversarially rollback-resistant anchor attestation,
coordinated journal-and-anchor rollback detection, automatic crash-gap repair,
key-seed exclusivity proof, hardware-backed custody, economics, slashing
evidence, or cross-journal atomicity. The anchored wrapper supplies only the
bounded file-backed persistence contract in
`fixed-validator-external-anchor-v0.md`. It
consumes only the separate finality journal's externally acknowledged exact
selected-child transition to keep the local signing lineage continuous, and uses
only its capability-gated exact retained branch for real restart reconstruction.
It also consumes explicitly routed proof-backed stop authority from an exact
externally anchored finality conflict, but it does not
discover that conflict, route it across a signer fleet, or choose a sibling. It
supplies the explicit local fixed-validator V0
journal-issued lineage, mandatory durable-finality lineage-advancement gate,
bounded source-bound higher-round checkpoint and acknowledgement gate,
complete proposal authoring from one explicit caller input, prepare-before-
sign, vote-anchor acknowledgement, complete-before-release, exact replay, and
anchored restart boundary described above.
