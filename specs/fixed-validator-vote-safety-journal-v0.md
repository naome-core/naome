# Fixed-Validator Vote-Safety Journal V0

## Status and authority

This document normatively defines one local, per-consensus-key durable signing
boundary for fixed-validator artifact-only V0 prevotes and precommits. Its
public key-owning path never accepts a caller-created
`FixedValidatorVoteIntentV0`. Instead, the journal issues one sealed signing
session whose private `FixedValidatorLockStateV0` alone may prepare an intent;
it does not accept caller-assembled lock, valid-value, phase, position, role,
target, signing-transcript, or predecessor-lineage fields.

The journal owns one `ed25519_dalek::SigningKey` in memory, exposes no secret
key getter or export path, and creates only the existing V0 prevote and
precommit signatures for its matching `ConsensusKey`. It cannot create a
producer authorization and has no remote-signer protocol. The journal file
never stores the secret seed. The reference build enables the signing key's
`zeroize` drop behavior; this is best-effort process-memory cleanup rather than
hardware custody, swap exclusion, or proof that no other seed copy exists.

Moving a Rust `SigningKey` into this handle does not prove that no copy of the
seed exists elsewhere. The local anti-equivocation guarantee therefore requires
the journal signer to be the sole operational use path for that key. A copied
key, another process, another directory, or an unsupported signer can violate
that deployment condition without changing these bytes.

This is local signing safety rather than consensus authority. The journal does
not prove that its chain, final genesis, protocol version, fixed agreement set,
branch, lock state, valid value, or vote target is globally canonical. Those
values enter only through the typed fixed-validator branch and lock kernel.

## Journal-issued signing lineage

One successfully created or strictly reopened key-owning handle may issue at
most one non-clone signing session. The issuance latch is monotonic for that
handle and is not released by dropping or forgetting the session. A failed
attempt using a mismatching typed round does not consume the latch, but once a
session has been returned there is no second session, raw-intent preparation,
or direct key-signing path through that handle.

An empty journal issues its first session only from an exact branch-derived
round-zero cursor whose context and fixed agreement-set identity match the
journal header. A healthy completed journal issues a session only by strictly
decoding the latest completed post-effect intent against the caller-supplied
exact typed round and reconstructing that one state. Historical completed
states are not selectable. A pending, halted, poisoned, or header-mismatching
journal issues no session.

The session exclusively owns the recoverable lock state. It exposes the current
position, phase, lock, and valid value read-only and delegates only the fixed
kernel's proposal, prevote, precommit, sequential-round, and verified-child
transition operations. It exposes no mutable state reference, unchecked state
replacement, generic mutation closure, raw-intent submission, secret key, or
raw or unacknowledged signing method. A caller may calculate with a separate
fresh lock kernel, but its effects cannot enter this journal's key-owning path: session
preparation recomputes the hidden state binding and requires the effect's
private volatile lineage seal to be pointer-identical to the session's exact
lock-state instance.

Moving to the next height consumes one
`OwnedVerifiedFixedConsensusTransitionV0`. The session requires the
transition's exact parent coordinate to equal its current parent and the
transition height to equal its current height, consumes the proof, derives
round zero only from the proof's internally sealed child branch, clears the
old-height lock and valid value, and returns that exact child branch for later
typed cursors. It never accepts a separately supplied or cloned child branch.
This operation binds the one local signing lineage to a caller-selected,
branch-relative non-nil precommit-quorum transition; it neither chooses that
transition among siblings nor claims that the caller durably installed global
finality. A crash before the first completed child vote reconstructs the older
completed state and requires the transition to be verified and consumed again.
After a child vote completes, its canonical intent binds the child coordinate
and only that exact typed round may restore the session.

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

A completion body is exactly 215 bytes and its complete frame is 251 bytes.
Prepare and halt bodies are 392..=25,676 bytes and their complete frames are
428..=25,712 bytes. Every `body_length` outside the exact range for its tag is
rejected before payload allocation.

A completion is valid only when strict verification proves that its signer,
context, position, role, target, and transcript exactly match the one pending
prepared intent. A halt body retains the newly observed conflicting intent; the
earlier prepare record retains the already accepted intent. No completion may
appear without exactly one pending prepare, no second distinct completion may
replace the retained signed bytes, and no record may follow a terminal halt.
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

Each prepare, completion, or halt record derives its footer as:

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
preimage. A byte-identical idempotent preparation or completed replay writes no
record and leaves the state identity unchanged.

This unkeyed digest detects history changes relative to an independently
trusted expected identity; it is not a secret authenticator and cannot make the
file its own trust anchor. It is not a `ConsensusVoteId`, proposal root,
consensus ancestry, finality proof, checkpoint, or global rollback-prevention
mechanism.

The caller must retain the genesis identity and every later identity it accepts
in a separately protected monotonic anchor, advancing only to an identity
returned after that record's footer synchronization. It must never resume this
key from an older accepted identity. Before any private-key operation, the
caller must separately persist the exact prepared state identity and explicitly
acknowledge that exact identity as externally durable through the session's
prepare-bound acknowledgement capability. A wrong or stale identity is rejected
before key use or a completion append. The journal verifies identity and
ordering, but the acknowledgement is a caller assertion: the journal cannot
prove that the external store is durable, monotonic, honest, or unavailable to
an attacker. A false acknowledgement violates this signing contract.

Operational reopen requires the exact separately trusted expected terminal
state identity. Replay validates the header, framing, every chained footer,
intent, signed vote, preparation/completion relation, preparation ceiling, and
terminality before exposing any journal state. It returns a key-owning handle
only when the final recomputed identity equals that external expectation. If
the final state is a terminal halt or prepared-but-uncompleted intent, that
handle is diagnostic only: every signing operation remains fail-closed and no
live prepared capability is reconstructed.

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

While a preparation is pending, the session admits no lock-state, round, or
height mutation. An acknowledgement cannot be manufactured through safe public
API fields and carries the exact live prepared capability; signing revalidates
the current pending slot and prepared state identity before key use. The type
does not cryptographically attest the external store and is never serialized
or treated as consensus evidence.

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

On a healthy non-halted reopened journal with no pending preparation, session
issuance internally retrieves the exact canonical state-and-intent bytes only
for the latest retained slot, which must have its durable completion. No public
coordinate-based, raw-state, or historical completed-state lookup exists:
recovery cannot resume an older lock state and then advance to a greater slot
past newer retained state. The caller supplies the exact typed
`FixedConsensusRoundV0`; only strict
`VerifiedReplayFixedValidatorVoteIntentV0` verification may reconstruct the
retained lock, valid value, proof, and phase inside the returned session. The
replay value exposes no signing transcript or completion method. Replay fixes
the latest slot; storage does not choose the round cursor or grant global branch
authority.

An incomplete preparation surviving restart exposes only its position, role,
target, prepare-state identity, and the fact that it is non-signable. Its full
intent bytes are not exposed through the operational API, so a caller cannot
advance consensus state from an unresolved prepare boundary. Terminal halt
denies completed-state retrieval as well as signing and vote release.

If a complete prepare or completion became durable but the caller crashed
before monotonically advancing its separate anchor, reopen with the old anchor
fails closed. If the caller advanced the anchor before the corresponding footer
became durable, reopen with the new anchor also fails closed. The journal does
not select between those ambiguous states or weaken the expected identity so
that signing can continue.

## Exact replay and terminal local halt

A vote slot is the exact `(context, height, round, role)` for the journal's
fixed signer key. Only a byte-identical complete prepared intent is idempotent
inside the uninterrupted signing operation. Once the slot has a durable
completion, exact replay returns only the retained signed bytes and changes
neither journal bytes nor state identity. An incomplete preparation surviving
restart is diagnostic only and cannot be resumed.

Distinct new slots are ordered lexicographically by height, round, and role,
using `Prevote < Precommit` only as the role comparison. Each new slot must be
strictly greater than the latest retained slot; an unrecorded earlier or equal
slot fails without a write or signature. The sequence need not contain every
role: a validator may abstain from a signature and later sign a session-
authorized higher slot, but it cannot return to fill the skipped slot afterward.
This persistence order does not itself authorize a skipped round, higher-round
jump, or new height. The same journal-issued session must carry every supported
lock transition; a new height additionally requires the consumed verified-
child transition defined above.

Any non-identical canonical intent for an already retained slot is rejected
before the private key signs it. The handle first durably appends the `0x03`
halt record and its chained footer, then enters a permanent local halt. A
different target at the same slot is the objective equivocation conflict
defined by `PROD-015`. The same target with a different lock, valid-value,
phase, branch, or intent byte is not a second objective vote target, but it is
still a local restart-safety inconsistency and halts rather than silently
replacing the state that authorized the first vote.

After halt, no vote may be prepared, signed, completed, or released. The halt
summary and exact state identity remain diagnostic; they identify the retained
and observed slots and targets without choosing a valid branch, claiming that
either vote was broadcast, or converting the unsigned observed intent into
public equivocation evidence. Recovery, key replacement, evidence publication,
and operator policy require separately specified authority.

## Resource and compatibility boundary

Each intent retains at most one bounded canonical lock snapshot, one bounded
valid-value certificate, one 118-byte vote body, and one 214-byte completed
vote. Signature work is one local Ed25519 signature plus one strict verification.
The positive header ceiling bounds distinct prepared votes admitted to one
journal; exact replays do not consume another slot. Completion through the same
uninterrupted live handle and a terminal halt remain permitted for already
admitted state so the cap cannot prevent fail-closed conflict recording. A
process crash may intentionally strand an incomplete preparation because V0
prefers loss of liveness to reconstructed signing authority.

The journal is append-only and retains its complete accepted signing history.
It provides no pruning, compaction, migration, cross-key transaction, automatic
rotation, or backup policy. This prerelease V0 has no production-data
compatibility promise. Any incompatible successor must use new filenames,
header and state-ID domains, strict decoder, and—if the existing signed-vote
meaning changes—new role signing domains rather than reinterpreting these
bytes.

The journal does not implement timeout scheduling, arbitrary higher-round
certificate jumps, dynamic validator sets, selection among verified sibling
branches, durable installation or recovery of global finality, global safety or
liveness, networking, peer discovery or trust, proposal production, artifact
availability, external-anchor storage, key-seed exclusivity proof, hardware-
backed custody, economics, slashing evidence, or a durable receipt handoff from
the separate finality journal. It consumes the caller-selected verified child
transition only to keep the local signing lineage continuous. It supplies the
explicit local fixed-validator V0 journal-issued lineage, prepare-before-sign,
external-anchor acknowledgement, complete-before-release, exact replay, and
anchored restart boundary described above.
