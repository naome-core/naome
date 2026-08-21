# NAOME Candidate-Branch Recovery Bundle V0

## Authority and scope

`CandidateBranchRecoveryBundleV0` is a caller-owned prerelease offline transfer
artifact for one exact caller-selected candidate target. It carries a bounded
candidate path and its exact canonical payloads without making them selected.

The bundle is not the node's durable competing-branch representation under
`FORK-002`. The node does not discover, retain, index, prune, exchange, or act on
bundles automatically. Caller-managed bundle files do not become a candidate
pool, fork choice, recovery queue, or source of consensus authority.

The current-head export binds the anchor to the source journal's exact current
head. A separate candidate-only export may instead bind the same V0 format to
the source chain's virtual genesis and include the replay-verified selected
prefix required to reach one unselected target. Import accepts either anchor
only at the destination's current head or behind an exact already-selected
bundle prefix, and can only append the remaining suffix. It cannot begin at an
arbitrary historical position, roll back, replace, or reorganize selected
history.

## Limits

`CandidateBranchRecoveryBundleLimits::new` requires positive caller-local
`max_blocks`, `max_payload_bytes`, and `max_bundle_bytes`. The first two bound
the block count and sum of logical tagged payload bytes; the third bounds the
complete canonical byte string before that string is hashed or allocated.
Checked arithmetic and fallible reservations precede growth.

These are per-operation local limits, not persisted identity or protocol rules
for branch depth, block size, validation work, retention, or networking.
For a virtual-genesis export they apply to the complete combined selected
prefix and candidate suffix: no selected-prefix block, payload byte, or encoded
byte is exempt from the caller's limits.

## Canonical bytes

The sole representation uses unsigned big-endian integers:

```text
header                    "naome:candidate-branch-recovery-bundle:v0\0"
artifact_chain_id         ArtifactChainId[32]
anchor_block_id           ArtifactBlockId[32]
anchor_artifact_set_root  ArtifactSetRoot[32]
target_block_id           ArtifactBlockId[32]
block_count               u32
total_payload_bytes       u64

repeated block_count times in forward ancestry order:
  artifact_block          ArtifactBlock[128]
  payload_length          u32
  artifact_payload        u8[payload_length]

bundle_digest             SHA256[32]
```

`block_count` and every `payload_length` are positive. Each payload length is
within the proof protocol maximum, their checked sum equals
`total_payload_bytes`, and the framing ends at the digest without truncation or
trailing bytes.

```text
bundle_digest = SHA256(
  "naome:candidate-branch-recovery-bundle-digest:v0\0"
  || every preceding bundle byte
)
```

The digest covers the exact header, chain, anchor, anchor root, target, path,
payloads, counts, and lengths. Any caller can recompute it; it detects corruption
or changes not accompanied by a new digest but is not a signature, MAC,
authorization proof, peer identity, availability certificate, consensus vote,
or finality certificate. Import always treats the bytes as untrusted.

This prerelease `v0` has no compatibility alias, legacy decoder, or migration.
Unsupported bundles must be re-exported from supported local stores.

## Current-head export

`ArtifactChainJournal::export_candidate_branch_recovery_bundle_v0` accepts one
exact target, the selected journal, a caller-routed candidate store with the same
`ArtifactChainId`, a caller-routed Foundation-scoped payload archive, and one
limit value.

It captures the healthy journal's exact current head and root, rejects a selected
target, and integrity-walks the retained candidate path backward to that head
within `max_blocks`. Missing candidates, repetition, broken parent or root
continuity, or encountering virtual genesis or selected history before the exact
captured head fail. Store integrity failures keep the existing poison-and-reopen
rules.

In forward order, export integrity-reads each exact archived payload, applies the
payload and complete-byte bounds before retaining it, and repeats the full
immutable branch validation defined by
[Artifact Chain Journal](artifact-chain-journal.md): canonical decoding,
identity, dependencies, mathematics, novelty, parent, and roots.

Only complete validation may publish one owned canonical bundle. Failure returns
no bundle or partial validation result. Export does not mutate the journal,
candidate store, or payload archive; caller-managed transport and durable file
placement remain outside this contract.

## Virtual-genesis candidate-only export

`ArtifactChainJournal::export_genesis_anchored_candidate_branch_recovery_bundle_v0`
is a separate mode that accepts the same caller-routed stores, exact target, and
limits. It rejects virtual genesis and every target already present in the
selected journal. It is therefore not a selected-history backup entry point.

The mode integrity-walks the target's retained candidate suffix backward to its
nearest retained selected ancestor under the same identity, repetition, parent,
root-continuity, and candidate-store failure checks as current-head export. It
then prepends every replay-verified selected block from the virtual-genesis
direct child through that ancestor. When the nearest selected ancestor is
virtual genesis, that selected prefix is empty. Later source-selected blocks are
never included.

Selected-prefix payloads come from each replay-accepted journal record's exact
canonical artifact bytes. The external payload archive is consulted only for
the candidate suffix. Starting from the journal's replay-built virtual-genesis
snapshot, export repeats immutable child validation over every selected-prefix
and candidate-suffix block and exact payload in forward order. Selected bytes
are therefore replay input, not trusted serialized state or a reusable
validation result.

The published object uses the existing V0 bytes without another header, mode,
or provenance field. Its anchor is the journal chain's exact virtual-genesis
`ArtifactBlockId`, and its anchor root is that replay-built snapshot's exact
`ArtifactSetRoot`. `max_blocks`, `max_payload_bytes`, and `max_bundle_bytes`
bound the whole combined path and final encoding before publication. A selected
prefix encoded in this bundle states neither that the target was selected at
the source nor that any entry is canonical, final, preferred, or trusted at the
destination.

The exporter performs no durable mutation. It does not make bundles a
node-managed candidate pool or durable competing-branch representation, and it
does not extend the current-head export to selected targets.

## Decode and import preflight

`CandidateBranchRecoveryBundleV0::from_canonical_bytes` checks the minimum fixed
frame, header, positive declarations, all three limits, digest, exact entry
count, canonical block bytes, payload lengths and total, and terminal framing.
It derives block identities from their canonical bytes. `canonical_bytes` and
`into_canonical_bytes` expose only the accepted representation; metadata getters
grant no validation or selection authority.

`ArtifactChainJournal::import_candidate_branch_recovery_bundle_v0` accepts one
bundle, a mutable selected journal, and destination limits. It re-decodes the
canonical bytes under those exact limits, so earlier decoding under wider limits
cannot bypass destination policy. It accepts no candidate or payload store.

Before the first append, import requires:

1. the exact bundle and journal chain IDs match;
2. the current journal head is the bundle anchor or one exact contiguous bundle
   prefix selected from that anchor;
3. the encoded anchor root and every selected-prefix block/root match the
   journal's replay-checked history;
4. the first block extends the anchor, every later block extends its predecessor,
   identities do not repeat, and the final identity equals the target; and
5. every payload passes the existing complete branch-child validation in its
   exact derived state.

Import strictly replays every bundle payload from the immutable snapshot at the
original anchor, including an already-selected prefix, and privately prepares
only the remaining suffix for commit. Framing, limit, digest, allocation, chain,
anchor, prefix, path, or artifact-validation failure returns before the first
new append and exposes no partial snapshot or reusable validation token.

## Sequential commit and exact-prefix restart

After complete preflight, import passes each remaining block and owned payload
through ordinary `ArtifactChainJournal::apply_block` in forward order. That gate
repeats full admission and its synchronized one-entry append. Success leaves the
declared target as head.

`CandidateBranchRecoveryBundleImportOutcome` reports the original anchor, the
head from which this call resumed, target, already-selected bundle count, newly
acknowledged commit count, and total payload bytes. A commit error reports the
exact acknowledged new prefix; an ambiguous current commit is excluded and
requires ordinary journal reopen to determine its durable outcome. Earlier
acknowledged blocks are never rolled back.

A retry may reuse the same bundle only when the reopened journal ends at an
exact contiguous bundle prefix. Import verifies that prefix and fully preflights
the remaining suffix before another append. A divergent, longer, or unrelated
head is an error. A fully selected bundle succeeds without a new commit.

## Non-goals

This API does not choose a target or branch; export an already-selected target
as a backup or attest selected provenance; persist or resume caller intent;
create node-managed competing-branch state; mutate candidate or payload stores;
fetch, relay, gossip, authenticate, or define a network protocol; import from an
arbitrary historical anchor; make the whole branch one crash-atomic transaction;
or establish availability, preference, fork choice, consensus, finality, peer
trust, or economic authority.
