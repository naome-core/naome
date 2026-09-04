# Fixed-Validator External Anchor V0

## Scope and authority

This document normatively defines the reference file-backed anchor used by the
fixed-validator V0 finality and per-key vote-safety journals. The anchor closes
the caller-asserted persistence gap for the new
`FixedValidatorAnchoredFinalityJournalV0` and
`FixedValidatorAnchoredVoteSafetyJournalV0` APIs. Their underlying legacy
journal types retain their explicit caller-supplied expected-state contract.

An anchor names exactly one complete journal prefix through both its complete
frame sequence and chained journal-state identity. It never creates consensus,
finality, branch-selection, signer, peer, provenance, or checkpoint authority.
Only a private transition issued inside the live paired journal after its footer
synchronizes may advance it. Raw state identities and public commit outcomes are
diagnostics, not anchor-update capabilities.

The finality anchor is one file per configured finality journal:

```text
fixed-validator-finality.anchor
fixed-validator-finality.anchor.lock
```

The vote anchor is one file per consensus key, where `signer_hex` is the exact
lowercase two-digit hexadecimal encoding of all 32 public-key bytes:

```text
fixed-validator-vote-safety-{signer_hex}.anchor
fixed-validator-vote-safety-{signer_hex}.anchor.lock
```

Finality and distinct signer anchors have independent exclusive locks and may be
open concurrently. The same anchor file cannot be paired with two live journal
handles, including handles whose journals are in different directories. Paired
construction and open always acquire the journal lock before the anchor lock.

## Canonical finality anchor

The finality anchor is exactly 221 bytes:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 41 | `"naome:fixed-validator-finality-anchor:v0\0"` |
| 41 | 32 | exact `ArtifactChainId` |
| 73 | 32 | exact `ConsensusGenesisId` |
| 105 | 4 | exact `ConsensusProtocolVersion_u32_be` |
| 109 | 32 | exact `FixedAgreementSetId` |
| 141 | 8 | positive finality `max_round_u64_be` |
| 149 | 8 | complete journal-frame `sequence_u64_be` |
| 157 | 32 | exact `FixedValidatorFinalityJournalStateIdV0` |
| 189 | 32 | checksum |

The checksum is:

```text
SHA256(
  "naome:fixed-validator-finality-anchor-checksum:v0\0"
  || bytes[0..189]
)
```

## Canonical vote-safety anchor

The per-key vote anchor is exactly 256 bytes:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 44 | `"naome:fixed-validator-vote-safety-anchor:v0\0"` |
| 44 | 32 | exact `ArtifactChainId` |
| 76 | 32 | exact `ConsensusGenesisId` |
| 108 | 4 | exact `ConsensusProtocolVersion_u32_be` |
| 112 | 32 | exact `FixedAgreementSetId` |
| 144 | 32 | exact signer `ConsensusKey` |
| 176 | 8 | positive `max_prepared_votes_u64_be` |
| 184 | 8 | complete journal-frame `sequence_u64_be` |
| 192 | 32 | exact `FixedValidatorVoteSafetyJournalStateIdV0` |
| 224 | 32 | checksum |

The checksum is:

```text
SHA256(
  "naome:fixed-validator-vote-safety-anchor-checksum:v0\0"
  || bytes[0..224]
)
```

Both decoders require the exact length, header, checksum, context, fixed set,
local replay ceiling, and, for vote safety, signer. Extensions, truncation,
another anchor kind or version, and any binding mismatch fail strictly. The
unkeyed checksum detects accidental corruption only. It is not authentication
and does not protect against a party able to rewrite and rehash anchor bytes.

## Sequence and transition contract

Sequence zero names the synchronized journal header and genesis journal-state
identity. Every complete state-changing journal frame increments the sequence
exactly once. Finality frames include finalized children, selected-sibling
conflict halts, and one-frame paired-preselection halts. A tag-`03` finality
pair therefore advances `N` to `N + 1`; its two embedded transitions never
name separate anchor positions.
Vote-safety frames include lineage bindings, vote prepares, vote completions,
same-slot conflict halts, proposal-authoring activation, proposal prepares,
proposal completions, proposal same-slot conflict halts, higher-round
checkpoints, selected-sibling finality-conflict stops, and neutral paired-
preselection stops. No-write idempotence advances neither sequence nor state
identity.

The paired journal creates a private prior-to-next transition only after it has
synchronized the complete frame body and chained state-ID footer. The transition
contains a live pairing seal, exact prior sequence and state identity, and exact
next sequence and state identity. The anchor rejects a foreign seal, a stale or
skipped prior position, sequence exhaustion, or use after an ambiguous anchor
replacement. Neither callers nor sibling journals can construct this update
authority.

For every state-changing call, the order is:

1. append and synchronize the journal body;
2. append and synchronize its chained state-ID footer;
3. write the exact next anchor image to a create-new temporary file and
   synchronize that file;
4. atomically rename the temporary file over the authoritative anchor and
   synchronize the anchor directory;
5. only then update live journal state and publish the outcome, height or round
   effect, stop, signing acknowledgement, proposal-control bytes, or signed
   vote bytes.

Any error from steps 1 through 4 poisons the live paired journal. The operation
returns no success value and no signed proposal or vote bytes. Because the journal footer
may already be durable, the error does not claim that the prior pair remains
operable. The handle must be dropped and both files strictly reopened.

## Creation and strict reopen

Paired creation uses create-new semantics for both authority files. It
synchronizes the new journal header and its parent directory before creating the
anchor, then synchronizes the complete anchor and its parent directory before
returning a wrapper. It never replaces a pre-existing authority file. Failure
may leave provisioning remnants; it returns no operational wrapper and does not
infer which remnant the operator intended.

Strict reopen acquires the journal lock and then the exact anchor lock, decodes
the anchor, and replays every complete journal frame while counting the same
sequence. The pair is accepted only when both sequence and state identity match:

- journal sequence greater than anchor sequence is `AnchorBehind`;
- journal sequence less than anchor sequence is `AnchorAhead`;
- equal sequence with different state identity is `AnchorStateMismatch`.

The comparison happens before incomplete-tail truncation. After exact equality,
the journal applies its existing at-most-one incomplete-frame recovery and
synchronization rule. The anchor file and parent directory are then synchronized
again before the wrapper is published, so a prior post-rename directory-sync
failure cannot be silently accepted as stable merely because the bytes are
currently visible.

No mismatch chooses a winner, promotes a temporary file, truncates a complete
suffix, rolls either side back, or automatically repairs the pair. Temporary
files are non-authoritative and never accepted on reopen.

The reference V0 implementation requires durable parent-directory
synchronization and atomic same-directory rename replacement. Non-Unix targets
fail with the typed unsupported-platform error. On Unix, a filesystem that
rejects file or directory synchronization fails closed through the applicable
typed write or stabilization error. The implementation never substitutes a
silent directory-sync no-op.

## Product and security boundary

The finality anchor and each vote anchor are separate commit units. Finality-to-
vote height handoff and proof-backed signer stop remain ordered multi-file
protocols, not atomic transactions. This V0 supplies no automatic crash-gap
repair, operator recovery decision, backup protocol, migration, compaction, key
rotation, dynamic-validator anchor, remote or hardware signer integration, or
cross-anchor transaction.

The caller may place anchors in a separately protected directory, but ordinary
file storage is not hardware monotonicity. Coordinated rollback or replacement
of both a journal and its matching anchor, rollback of the whole filesystem,
malicious rehashing, and loss of the underlying device are outside this format's
detection guarantee. Deployments that require adversarial rollback resistance
must protect the anchor with an independently administered monotonic or
authenticated storage boundary. Rust ownership also cannot prove that another
copy of a signing key does not exist.

Networking, peer order, provenance, candidate discovery, branch preference,
fork choice, consensus selection, global finality, validator-set provenance,
checkpoint choice, and peer trust remain in their separately specified
components. Excluding them here is an authority boundary, not a statement that
the complete NAOME product does not need them.
