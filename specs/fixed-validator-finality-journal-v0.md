# Fixed-Validator Finality Journal V0

This document normatively defines the local durable-selection boundary for the
fixed-validator artifact-only V0 consensus format. It consumes only a sealed
`OwnedVerifiedFixedConsensusTransitionV0` produced by the typed verifier. It
does not accept raw caller-assembled consensus, artifact, or provenance fields.

The journal makes one already verified direct child operable only after its
exact consensus envelope and exact canonical artifact payload are durably
committed together. `FixedValidatorFinalityJournalV0` retains the original
caller-anchored contract. `FixedValidatorAnchoredFinalityJournalV0` additionally
owns the canonical file-backed anchor defined by
`fixed-validator-external-anchor-v0.md` and advances it before publishing any
state-changing outcome. Neither path establishes that the supplied genesis
context or agreement set is globally canonical.

The same durable history is the only source for advancing an already-issued
key-owning signing lineage to a child height. The caller first persists the
journal's exact current state identity in its separate monotonic finality
anchor. Only
`acknowledge_signer_height_transition_is_externally_durable` with that exact
identity may strictly reconstruct an opaque
`FixedValidatorDurableFinalityTransitionV0<'journal>` for the vote-safety
signing session. After that child lineage is separately anchored, the vote
journal may instead issue an opaque signer-recovery capability. This journal
can consume it to recover only the exact retained branch that reproduces the
anchored lineage, including after a later terminal conflict halt when no
explicit conflict stop has been applied to that signer.

## Authority and clean replacement

`FixedValidatorFinalityJournalV0` is the sole selected/finalized artifact-state
authority in its directory. It reuses the artifact journal's exact file and
lock names:

```text
artifact-chain.lock
artifact-chain.journal
```

The anchored wrapper does not create a second finality authority. It owns this
same journal handle plus one separately locked finality anchor and exposes no
raw journal reference, mutable escape hatch, or caller-constructible anchor
transition. It acquires the journal lock before the anchor lock.

The joint V0 format cleanly replaces the artifact-only journal format in that
directory. Creation uses create-new semantics and never replaces either
format. The exclusive nonblocking lock prevents simultaneous old and new
owners. An artifact-only journal remains usable only in a separately
provisioned directory and grants no consensus or finality authority.

This prerelease cutover has no legacy reader, migration, parallel journal, or
automatic upgrade. Old artifact-only bytes fail the joint header check. Local
data that must move to the joint format is recreated or explicitly reimported
through a separately specified caller workflow; it is never reinterpreted.

Issuing a signer-height transition does not add a second selection path. The
journal derives it only from its already retained first finalized record and
coupled child branch. The caller still chooses which sealed verified transition
to submit to `commit_verified`; the transition capability neither chooses among
siblings nor turns this local selection into globally canonical finality.

## Header and caller anchors

The exact 150-byte prefix is:

```text
"naome:fixed-validator-finality-journal:v0\0"[42]
ArtifactChainId[32]
ConsensusGenesisId[32]
ConsensusProtocolVersion_u32_be[4]
FixedAgreementSetId[32]
positive_max_round_u64_be[8]
```

Creation derives the empty typed branch from the complete caller-supplied
artifact definition, consensus context, and fixed agreement entries. The
header stores their derived chain, context, and fixed-set identities, not raw
caller assertions. `max_round` is an inclusive positive caller-selected local
admission and replay bound. Zero is invalid. A certificate above the bound is
rejected by this journal without asserting that it is cryptographically invalid
under a wider configuration or defining a protocol-wide maximum round.

Raw creation synchronizes the complete prefix before success. Portable
durability of its parent-directory entry and storage of every trusted
journal-state anchor remain caller responsibilities. Anchored creation instead
synchronizes the journal parent directory and then creates and synchronizes the
independent typed genesis anchor before returning; its exact format, locks, and
platform requirement are defined by `fixed-validator-external-anchor-v0.md`.

## Record framing

Each committed record is:

```text
body_length_u32_be[4]
record_tag_u8[1]                 # 01 finalized, 02 terminal conflict halt
round_u64_be[8]
envelope_length_u32_be[4]
payload_length_u32_be[4]
canonical_envelope[696..=25,176]
canonical_artifact_payload[1..=4,194,305]
FixedValidatorFinalityJournalStateIdV0[32]
```

`body_length` covers the 17-byte body header and the exact envelope and payload,
but not its own four bytes or the 32-byte footer. It is in
`714..=4,219,498`; a complete framed record occupies `750..=4,219,534` bytes.
The envelope and payload are the exact canonical bytes retained by the sealed
verified transition. Both finalized and halt records retain both byte strings.

Every field and trailing byte of every complete record is checked during replay.
At most one incomplete final frame is handled only by the anchored recovery rule
below. Persisted metadata never constructs an accepted branch directly or
bypasses envelope verification, strict artifact application, parent matching,
proposer state, or state-commitment validation.

## Chained journal-state identity

`FixedValidatorFinalityJournalStateIdV0` is an exact 32-byte local durable-state
identity. The empty state is:

```text
SHA256(
  "naome:fixed-validator-finality-journal-state-genesis:v0\0"
  || complete_header[150]
)
```

Each finalized or halt record derives its footer as:

```text
SHA256(
  "naome:fixed-validator-finality-journal-state-step:v0\0"
  || prior_journal_state_id[32]
  || body_length_u32_be[4]
  || complete_record_body[body_length]
)
```

The resulting ID is stored as that record's footer and becomes the prior ID for
the next record. The footer is excluded from its own preimage. A same-value
idempotent submission writes no record and does not advance the ID.

This identity commits one exact local journal history. It is not a
`ConsensusAncestryId`, `ConsensusEnvelopeId`, `ArtifactBlockId`, consensus-block
identity, checkpoint, global finality proof, or external trust anchor by itself.

## Durable finalization

`commit_verified` accepts only one sealed owned transition. Before writing it
requires a healthy, non-halted handle, a round not above the header ceiling,
and the exact retained selected parent coordinate for the transition height.

For a new direct height, the journal appends and synchronizes
`body_length || body`, appends the derived state-ID footer, and synchronizes
again. Only after the footer synchronization succeeds does it publish the new
finality record, coupled consensus-and-artifact child branch, and state ID in
memory. The outcome returns the exact position, ancestry, envelope identity,
and new journal-state identity so a raw caller can update its separate trusted
anchor. On the anchored wrapper, the journal-issued exact prior-to-next anchor
transition is synchronously consumed before the same outcome is returned. No
signer-height capability is usable until the applicable raw acknowledgement or
internal anchor update has completed.

The two synchronization points define a framed durable commit boundary; they do
not claim that one whole variable-length record is written atomically by the
filesystem. Any append I/O failure poisons the handle and returns the proposed
state ID only as ambiguity information, not as proof that the record committed.
No journal-state or history read and no commit is authoritative until strict
reopen; the immutable context and replay-limit configuration remain inspectable.

## Candidate-backed direct-child finalization

`commit_candidate_backed_finality_v0` is a narrow composition boundary for one
caller-selected, locally retained candidate. The caller supplies an operable
fixed-validator journal, one same-chain `ArtifactBlockCandidateStore`, one
Foundation-scoped `CanonicalArtifactPayloadStore`, the exact expected
`ArtifactBlockId`, one complete canonical finality envelope, and an inclusive
caller-local round-work ceiling no greater than the journal's persisted replay
ceiling. The expected target and store presence are routing and availability
inputs only; neither grants selection, preference, or finality authority.

The operation first requires the journal to be healthy and non-halted and the
caller-local work ceiling to fit the journal ceiling. It strictly bounds and
decodes the envelope value, requires its context and next height to match the
exact current journal head, and requires its embedded artifact block address to
equal the expected target before reading either source entry. It then requires
the candidate store's exact chain, integrity-reads that exact retained block,
requires byte equality with the envelope block, and integrity-reads the exact
payload committed by that block.

The envelope's canonically framed precommit certificate supplies its sole
claimed height and round only to route bounded sequential proposer derivation.
The claimed height must again equal the current head's next height, and the
claimed round must not exceed the caller-local ceiling before round work begins.
This preliminary position is not authenticated authority. The complete
envelope is then verified once against the derived exact fixed-set round,
including producer authorization, non-nil strict-supermajority precommit
evidence, ancestry, state commitment, artifact parent and roots, and the loaded
canonical payload. Only the resulting
`OwnedVerifiedFixedConsensusTransitionV0` reaches `commit_verified`.

One successful call installs exactly one current-head direct child and changes
only the finality journal. Candidate and payload log bytes, entries, order, and
retention remain unchanged. A source integrity/read failure can poison only
that source's live handle under its existing contract; it does not write the
source or finality journal. Every rejection before the journal append leaves
the finality bytes and state unchanged. An ambiguous finality append poisons
only the live finality handle and retains the existing exact-anchor reopen
classification; it is not a transaction across the three stores.

This boundary does not discover or rank candidates, promote a suffix, accept
an already selected historical value, admit sibling-conflict evidence, choose
a fork, roll back or reorganize history, prune source data, retain peer
provenance, establish network or global availability, or define peer trust.
Multiple staged heights require one independently certified successful call per
height in selected order. The existing raw sealed-transition `commit_verified`
path remains the separate boundary for authenticated sibling-conflict handling.

`commit_candidate_backed_anchored_finality_v0` applies the same verification,
source-store, caller-selection, and one-height boundaries to
`FixedValidatorAnchoredFinalityJournalV0`. Its successful finality frame also
advances the paired anchor before the candidate-backed outcome is published.

## Mandatory durable signer-height advancement

After a finality footer synchronizes, the caller reads the healthy journal's
current state identity and persists it in a separately protected monotonic
anchor. It then calls
`acknowledge_signer_height_transition_is_externally_durable(height,
exact_state_id)`. The journal first requires a healthy non-halted handle and
exact equality between `exact_state_id` and its still-current state. A wrong or
stale identity fails before retained evidence is reconstructed.

On `FixedValidatorAnchoredFinalityJournalV0`, the successful finality append has
already advanced the live paired anchor. Its
`acknowledge_signer_height_transition(height)` accepts no state identity and
derives the same capability only from that internally anchored current state.

For an exact positive retained height, the method then strictly re-verifies the
first retained envelope and artifact payload against their selected parent and
reconstructs the replay-coupled child. The current acknowledged identity may be
from a later healthy height because its chained history commits every earlier
retained child. A same-value evidence variant never replaces the first retained
envelope used by this reconstruction. Height zero, unknown height, poison,
terminal halt, ambiguous commit, reconstruction failure, or any non-operable
state returns no capability.

Success returns one opaque non-clone
`FixedValidatorDurableFinalityTransitionV0<'journal>` that immutably borrows the
issuing journal. Safe code therefore cannot commit another child or append a
conflict halt while the key-owning session validates the child, persists its
exact vote-journal signing-lineage record, waits for acknowledgement of that
record's externally durable state identity, and retains the token. The token
carries only the strictly reconstructed transition; it accepts no caller-
supplied child fields. `prepare_height_with_durable_finality` checks the exact
direct parent and height before persisting the child lineage, while advancing
the current live session requires
`acknowledge_prepared_height_is_externally_durable` to consume the token only
after the exact vote-journal anchor acknowledgement and then clear old-height
lock and valid-value state. Dropping the token after that exact anchor does not
erase the durable child binding: strict reopen resumes it without a new token.
No raw `OwnedVerifiedFixedConsensusTransitionV0` enters the public key-owning
height-advance path.

This requirement governs advancement of an already-issued signing lineage. A
header-only vote journal still receives its first branch-derived round-zero
cursor under explicit caller provisioning authority, but it persists and
externally anchors that exact initial lineage before issuing a session.
Selecting and attesting the initial branch remains outside this finality
handoff; replacing it after a crash is not permitted.

The caller also selects which healthy finality-journal handle supplies the
token. The signer checks the reconstructed semantic parent and height, not a
unique directory or device identity; independently opened journals with the
same acknowledged retained history are content-equivalent for this local
handoff. Requiring one uniquely attested journal source would be a separate
provenance policy and is not inferred here.

This is an ordered two-journal protocol, not a cross-file transaction. Finality
and its external anchor complete first; the vote journal then synchronizes the
exact child signing-lineage record and its caller-controlled anchor; only then
does signer memory advance. The exact external child-lineage anchor is the
durable signer-authorization boundary. A crash or token drop after that boundary
but before live acknowledgement needs no fresh height-transition token. A real
process restart that no longer holds the branch combines the exact vote-issued
recovery capability with this replay-retained history. A complete child record
beyond an older vote anchor fails closed, as does an anchor ahead of durable
bytes. The live code cannot detect a caller that falsely claims external
durability; such a lie violates this contract and may leave live advancement
unprotected. Neither journal rolls the other back, repairs an anchor gap, or
claims atomic durability across the two files.

The token's borrow ends after successful consumption or drop. Once the exact
child lineage is externally anchored, a distinct sibling may then durably halt
the finality journal before or after live acknowledgement, but that halt alone
does not retroactively revoke the anchored signer lineage. Exact reopen may
therefore resume the child through the capability-gated path after a post-anchor,
pre-acknowledgement halt unless a separate proof-backed signer stop has already
been applied to the vote journal. The lineage does not commit a finality state
identity or chronology, so the caller's point-in-time assertion remains a
deployment condition rather than a cross-journal temporal proof.

## Capability-gated signer restart

`recover_anchored_signer_branch` accepts only one non-clone
`FixedValidatorAnchoredSignerRecoveryV0` issued by an exact externally anchored,
healthy, recoverable vote journal. It accepts no separate height, branch,
coordinate, signer, fixed set, head, or history selector. The capability
immutably borrows its vote-journal handle until consumption and privately binds
the complete retained lineage digest, latest required position, exact current
vote state, signer, and live-handle provenance.

The finality journal requires healthy replay state but deliberately does not
require operability for this one method. It indexes exactly the retained branch
at `signing_height - 1`, recomputes the full signing-lineage digest from that
branch's complete coordinate, the anchored height, and the capability signer,
and requires exact equality. Unknown or unindexable height, missing history,
lineage mismatch, or poison returns no branch. There is no fallback to the head,
nearest height, another branch, or either conflict value.

At signing height one the indexed branch is the journal's configured virtual
genesis. It is accepted only when its complete coordinate and the capability
signer reproduce the already persisted lineage digest. This recovers the exact
bootstrap binding; it does not let the journal select, replace, or independently
attest bootstrap configuration.

Success returns only an opaque `FixedValidatorRecoveredSignerBranchV0`. The
originating vote-journal handle must consume it, recheck the exact external vote
anchor and pointer-identical handle provenance, derive the exact required round
under its caller-local work ceiling, strictly replay the latest completed intent,
and consume its sole session latch before the branch becomes visible beside the
session. The recovery operation writes neither journal and changes no state ID,
halt, retained history, or external anchor. Content-equivalent replayed finality
histories remain valid semantic sources; unique directory, device, evidence
variant, and chronology provenance are not inferred.

## Evidence variants and terminal conflict

If a later sealed transition at an already selected height carries the exact
same `ConsensusValueV0`, the journal reports it as already finalized. It retains
the first exact envelope, returns that retained envelope identity and the
unchanged state ID, and writes nothing. A later valid signer, signature, or
round evidence variant therefore cannot replace or accumulate beside the first
committing envelope or become the evidence identity in a signer-height
transition.

If the transition instead carries a distinct valid value at that same height,
the journal appends and synchronizes a terminal conflict-halt record containing
the exact conflicting envelope and payload. After its footer becomes durable,
there is no operable selected head. Future commits fail until separately
specified recovery tooling is explicitly invoked.

On a healthy halted handle, `halt()` and `state_id()` remain the general
history-state diagnostics; immutable `context()` and
`replay_limit()` bindings also remain inspectable. `head()`,
`parent_for_height()`, `finality_record()`, `finalized_len()`, and
`commit_verified()` all return the terminal-halt error. Two narrow non-operable
operations remain: capability-gated exact signer-branch reconstruction above,
and `acknowledge_signer_stop_is_externally_durable`. The latter requires the
exact current terminal state identity to be separately anchored and returns a
non-clone `FixedValidatorDurableFinalityConflictV0` binding this live journal,
its context and fixed set, and the complete halt summary. A matching vote journal
or live signing session must explicitly consume that capability before one local
signer is durably stopped. Fresh one-use capabilities may be issued for other
local signers in the same fixed set. Neither operation exposes caller-selectable
history or revives operability. The halt summary
names the height, both distinct ancestry identities, both envelope identities,
and the halt state ID; it does not choose a winner or expose either sibling as
the operable chain.

The anchored wrapper's `acknowledge_signer_stop()` accepts no caller identity;
the halt frame and exact terminal anchor replacement must both have synchronized
before `commit_verified` could have published the halt used by that method.

## Strict operational reopen

`open_verified` requires the complete expected definition, context, fixed
agreement entries, local round ceiling, and an exact separately trusted
expected `FixedValidatorFinalityJournalStateIdV0`. There is no unverified or
disk-self-authorizing operational open.

Replay validates the exact header, bounded framing, chained footer, canonical
envelope and payload, direct selected-parent sequence, fixed proposer state,
first-value retention, conflict-halt terminality, and end of file. It returns a
handle only if the final recomputed state ID equals the separately supplied
expected ID. A complete mismatch or corruption exposes no state.

Because a successful strict reopen already proves equality to the separately
supplied expected identity, the caller may acknowledge that exact current
operable identity and reconstruct a fresh transition for a retained finalized
child when starting a not-yet-persisted signer handoff. The caller supplies no
child fields, and the signing session repeats its direct-parent and direct-height
checks. If the exact reopened state is instead terminal, the caller may reissue
only the signer-stop capability bound to that conflict. Reissuance changes
neither finality-journal bytes nor state identity and cannot revive the journal.
When the vote journal has already anchored a child lineage, its exact reopen does
not require transition-token reissuance; if no branch object survived process
restart, the separate recovery path derives only the matching retained branch,
including through an otherwise halted journal, unless the vote journal itself
already carries a finality-conflict stop.

At most one framing-incomplete final record may be removed, and only after the
strictly replayed committed prefix already equals the trusted expected ID.
Comparison precedes truncation, so a wrong anchor preserves the file unchanged.

The external anchor is caller authority. If the journal commit becomes durable
but the caller crashes before updating its anchor, reopening with the old ID
fails closed. If the caller advances its anchor before a commit is durable,
reopening with the new ID also fails closed. The journal never adopts its own
latest footer as trust, rolls back a committed suffix, repairs an anchor,
selects a checkpoint, or automatically recovers either crash gap.

`FixedValidatorAnchoredFinalityJournalV0::open` replaces that raw expected-ID
input with the exact file-backed pair defined by
`fixed-validator-external-anchor-v0.md`. Under journal-then-anchor exclusive
locking, it requires the complete frame count and final state identity to match.
Anchor behind, anchor ahead, and equal-sequence divergence are distinct errors;
none chooses a winner or changes a complete file. After equality and the
existing incomplete-tail rule, reopen synchronizes the anchor file and parent
directory before publishing the wrapper.

## Read-only selected-artifact history

The journal retains the immutable artifact snapshot coupled to virtual genesis
and to every locally finalized fixed-validator V0 branch. Creation, strict
replay, and each successful `commit_verified` step maintain an in-memory exact
`ArtifactBlockId` lookup over those snapshots. An unknown address returns no
snapshot. A returned `ArtifactChainBranchSnapshot` is an owned artifact-state
view only; it does not expose or reconstruct a candidate consensus envelope,
value, certificate, or ancestry.

The sealed `SelectedArtifactHistory` capability on both raw and anchored
journals exposes the already bound
`ArtifactChainId` as immutable chain context so a caller can reject a mismatched
candidate store before an operable selected-state read. Its selected artifact
head, artifact-set root, and exact-position snapshot reads require a healthy,
non-halted journal. Terminal halt and poison deny those reads before selected
history is inspected, both on the live handle and after strict reopen; the
immutable journal context and the existing halt and state-ID diagnostics retain
their separately defined availability.

One caller may use this capability to reconstruct one exact caller-selected
retained candidate target from a virtual-genesis, historical, or current local
finality anchor. Reconstruction integrity-reads the caller-routed candidate and
payload stores under a positive caller-local block limit, strictly revalidates
the artifact children forward, and publishes only a complete memory-resident
snapshot. The journal is read-only throughout. Candidate ancestry fill may
separately durably insert an exact missing candidate block, and candidate-branch
payload fill may separately durably insert a strictly validated payload into
the payload archive; neither flow changes this journal. This journal advances
only through `commit_verified`.

The same capability may also be supplied to strict recovery-bundle staging.
That operation requires one exact retained selected anchor and unselected
target, repeats complete bundle validation from the returned immutable
snapshot, and may then write only to caller-routed candidate and payload stores.
A terminally halted or poisoned journal denies the first selected-history read,
so staging returns before either store writes. The journal is borrowed only as
sealed read-only history; successful or failed staging therefore cannot change
its bytes, state identity, selected head, root, finalized length, or halt
diagnostics.

The target, selected anchor, peer or peer order, and whether to start or restart
either network flow remain caller choices. The view grants no consensus-branch
or fork selection, global finality, provenance, payload availability, peer-truth,
external-anchor persistence, rollback, checkpoint, bootstrap, migration,
backup, or cross-store atomicity claim. Candidate-block ancestry fill checks
identity and structural parent/root continuity only; payload validity is
established later by strict artifact replay, not by block retrieval.

## Product boundary

This V0 supplies local fixed-validator artifact-only durable selection, exact
first-evidence retention, strict caller-anchored replay, and terminal conflict
halt. It also supplies the mandatory, externally acknowledged transition for
advancing the sole vote-safety signing lineage from one exact retained local-
finality child and the narrow capability-gated reconstruction of that exact
already anchored branch after process restart. An exact externally anchored
terminal conflict may additionally issue explicit one-signer-at-a-time stop
authority; the finality journal does not route it automatically, choose a
conflicting sibling, or coordinate a signer fleet. Its sealed read-only selected-
artifact history can anchor the existing caller-driven candidate reconstruction
and bounded network fill workflows, but the journal itself does not choose or
start them. It does not supply a general consensus-block format, Tendermint
locking or valid-value transitions, timeout progression, dynamic validator
selection or changes, signature creation or anti-equivocation signing state,
multi-node or global finality, automatic networking or recovery policy, data
availability, peer truth or trust, checkpoint/bootstrap, hardware-backed or
adversarially rollback-resistant anchor attestation, coordinated journal-and-
anchor rollback detection, automatic crash-gap repair, cross-journal atomicity,
provenance authority, economics, pruning, compaction, migration, or backup
policy. The anchored wrapper supplies only the bounded file-backed persistence
contract defined by `fixed-validator-external-anchor-v0.md`.
