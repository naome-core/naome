# Fixed-Validator Finality Journal V0

This document normatively defines the local durable-selection boundary for the
fixed-validator artifact-only V0 consensus format. It consumes only a sealed
`OwnedVerifiedFixedConsensusTransitionV0` produced by the typed verifier. It
does not accept raw caller-assembled consensus, artifact, or provenance fields.

The journal makes one already verified direct child operable only after its
exact consensus envelope and exact canonical artifact payload are durably
committed together. This is a fixed-set, caller-anchored local V0 boundary. It
does not establish that the supplied genesis context or agreement set is
globally canonical.

## Authority and clean replacement

`FixedValidatorFinalityJournalV0` is the sole selected/finalized artifact-state
authority in its directory. It reuses the artifact journal's exact file and
lock names:

```text
artifact-chain.lock
artifact-chain.journal
```

The joint V0 format cleanly replaces the artifact-only journal format in that
directory. Creation uses create-new semantics and never replaces either
format. The exclusive nonblocking lock prevents simultaneous old and new
owners. An artifact-only journal remains usable only in a separately
provisioned directory and grants no consensus or finality authority.

This prerelease cutover has no legacy reader, migration, parallel journal, or
automatic upgrade. Old artifact-only bytes fail the joint header check. Local
data that must move to the joint format is recreated or explicitly reimported
through a separately specified caller workflow; it is never reinterpreted.

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

Creation synchronizes the complete prefix before success. Portable durability
of the parent-directory entry and storage of every trusted journal-state anchor
remain caller responsibilities.

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
and new journal-state identity so the caller can update its separate trusted
anchor.

The two synchronization points define a framed durable commit boundary; they do
not claim that one whole variable-length record is written atomically by the
filesystem. Any append I/O failure poisons the handle and returns the proposed
state ID only as ambiguity information, not as proof that the record committed.
No journal-state or history read and no commit is authoritative until strict
reopen; the immutable context and replay-limit configuration remain inspectable.

## Evidence variants and terminal conflict

If a later sealed transition at an already selected height carries the exact
same `ConsensusValueV0`, the journal reports it as already finalized. It retains
the first exact envelope, returns that retained envelope identity and the
unchanged state ID, and writes nothing. A later valid signer, signature, or
round evidence variant therefore cannot replace or accumulate beside the first
committing envelope.

If the transition instead carries a distinct valid value at that same height,
the journal appends and synchronizes a terminal conflict-halt record containing
the exact conflicting envelope and payload. After its footer becomes durable,
there is no operable selected head. Future commits fail until separately
specified recovery tooling is explicitly invoked.

On a healthy halted handle, `halt()` and `state_id()` remain the only operational
or history-state diagnostics; immutable `context()` and `replay_limit()` bindings
also remain inspectable. `head()`, `parent_for_height()`, `finality_record()`,
`finalized_len()`, and `commit_verified()` all return the terminal-halt error.
The halt summary names the height, both distinct ancestry identities, both
envelope identities, and the halt state ID; it does not choose a winner or
expose either sibling as the operable chain.

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

At most one framing-incomplete final record may be removed, and only after the
strictly replayed committed prefix already equals the trusted expected ID.
Comparison precedes truncation, so a wrong anchor preserves the file unchanged.

The external anchor is caller authority. If the journal commit becomes durable
but the caller crashes before updating its anchor, reopening with the old ID
fails closed. If the caller advances its anchor before a commit is durable,
reopening with the new ID also fails closed. The journal never adopts its own
latest footer as trust, rolls back a committed suffix, repairs an anchor,
selects a checkpoint, or automatically recovers either crash gap.

## Read-only selected-artifact history

The journal retains the immutable artifact snapshot coupled to virtual genesis
and to every locally finalized fixed-validator V0 branch. Creation, strict
replay, and each successful `commit_verified` step maintain an in-memory exact
`ArtifactBlockId` lookup over those snapshots. An unknown address returns no
snapshot. A returned `ArtifactChainBranchSnapshot` is an owned artifact-state
view only; it does not expose or reconstruct a candidate consensus envelope,
value, certificate, or ancestry.

The sealed `SelectedArtifactHistory` capability exposes the already bound
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
halt. Its sealed read-only selected-artifact history can anchor the existing
caller-driven candidate reconstruction and bounded network fill workflows, but
the journal itself does not choose or start them. It does not supply a general
consensus-block format, Tendermint locking or valid-value transitions, timeout
progression, dynamic validator selection or changes, signature creation or
anti-equivocation signing state, multi-node finality, automatic networking or
recovery policy, data availability, peer truth or trust, checkpoint/bootstrap,
external-anchor persistence, rollback, provenance authority, economics,
pruning, compaction, migration, or backup policy.
