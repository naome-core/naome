# Single-artifact block and linear chain state

An `ArtifactBlock` is the sole canonical selected-state transition. It commits:

```text
parent_block_id:            ArtifactBlockId
previous_artifact_set_root: ArtifactSetRoot
resulting_artifact_set_root: ArtifactSetRoot
artifact_id:                ArtifactId
```

There is no subordinate change object, artifact list, count, or dependency
closure. Each block selects exactly one proof or one definition. Every proof
reference and definition application used by a proof, and every
function-obligation statement required by a definition, must already be
available from earlier selected blocks in the same ancestry.

### Chain definition and virtual genesis

`ArtifactChainDefinition` binds one caller-supplied 32-byte deployment
discriminator, the exact Foundation identifier, and the empty artifact-set root:

```text
deployment_discriminator[32]
foundation_id[9]           = "naome:zfc"
genesis_artifact_root[32]  =
  976e576ec6145d57b5e192d1c37a0938bb5c76663532d0354fcd98ba3fbf597a
```

The canonical definition is exactly 73 bytes. Decoding first requires that
length, then the compiled Foundation bytes, then the executable empty root. It
accepts no caller-supplied Foundation or genesis semantics.

```text
ArtifactChainId = SHA256(
  "naome:artifact-chain-definition:canonical-definition-v1\0"
  || canonical_definition[73]
)

virtual_genesis = SHA256(
  "naome:artifact-chain-genesis:v0\0" || ArtifactChainId[32]
)
```

For a deployment discriminator of 32 bytes `11`:

```text
ArtifactChainId = 72ba0843747f3fdd503c77827c726f5bf428258ac7eec0fe57716e400cd54c40
virtual_genesis = 9754a99788a5a44e8d4e2fd6e385970d3ce0120c624de04e3250a9e8d0f64c2e
```

The deployment discriminator separates intentional deployments; it is not a
secret, signer, authorization token, or consensus parameter. The virtual
genesis is an anchor, not an admitted block, and has no payload or height.
Blocks omit `ArtifactChainId`; their context comes from a supported definition
and unbroken exact-parent ancestry.

### Block encoding and identity

Canonical block bytes are exactly:

```text
parent_block_id[32]
previous_artifact_set_root[32]
resulting_artifact_set_root[32]
artifact_id[32]
```

The block is fixed at 128 bytes. It contains no version, type tag, chain ID,
height, timestamp, count, length, payload, padding, or checksum. The separately
supplied tagged payload reveals whether the opaque `ArtifactId` addresses a
proof or definition.

```text
ArtifactBlockId = SHA256(
  "naome:artifact-block:v0\0" || canonical_block[128]
)
```

For the preceding `11` definition, its virtual genesis parent, previous root
`22` repeated 32 bytes, resulting root `33` repeated 32 bytes, and `ArtifactId`
`44` repeated 32 bytes, the block ID is:

```text
2d5b1570acc98fd873426f4f5148f8aa4c625997324c69cf96a108cc1b2e076d
```

Changing any committed byte changes the block identity under SHA-256 collision
resistance. Identity alone establishes neither valid ancestry nor selection.

### Preparation, validation, and application

Chain state begins from one supported definition with an empty private artifact
DAG and its virtual genesis head. It accepts no arbitrary chain ID, initial
head, or pre-populated DAG.

Preparation takes one `ArtifactId`, rejects it if already selected, binds the
current head and root, and projects the one-key resulting root. It does not read
or check payload bytes and does not mutate state.

Read-only validation and application each take one block and exactly one owned
canonical tagged payload. Before payload work they execute in this order:

1. require the block parent to equal the exact current head;
2. require its previous root to equal the current `ArtifactSetRoot`;
3. reject an already selected `ArtifactId`; and
4. project insertion and require the committed resulting root.

Preflight failure precedes payload decoding. After preflight, strict artifact
admission decodes and checks the one typed payload against unchanged selected
state, derives its typed `ArtifactId`, compares the block address, and registers
it atomically. Application computes the next `ArtifactBlockId` before mutation
and assigns it only after registration. No fallible operation follows selected
state commit.

Read-only validation runs the same checks in discarded state and returns no
authority token. Application always repeats validation against its then-current
state. Every failure preserves head, records, resolver maps, authenticated-set
topology and root, and existing witnesses. Success adds exactly one artifact and
advances the head exactly once.

Two siblings may be prepared from one head, but after one applies the other
fails at parent comparison before payload work. This defines one local selected
line; it does not define fork choice, rollback, reorganization, consensus, or
finality.

### Persistent candidate-branch snapshots

`ArtifactChainState::branch_snapshot` returns an opaque owned
`ArtifactChainBranchSnapshot` at that state's exact current head. The snapshot
contains the same checked resolver, accepted records, authenticated artifact-set
root, and block head as its source, represented by immutable structurally shared
identity-map and authenticated-set nodes. Cloning a snapshot shares those
immutable nodes; it does not copy accepted payloads or grant selected-state
authority.

`ArtifactChainBranchSnapshot::validate_child` takes one exact-child
`ArtifactBlock` and one owned canonical tagged payload. It applies the same
parent, previous-root, already-selected, projected-root, decode, canonicality,
content-identity, dependency, mathematical, and novelty checks as selected
application. Success returns a new snapshot whose changed resolver and
authenticated-set paths are persistently path-copied. The predecessor remains
unchanged and may independently produce another child. Failure returns no
successor and likewise preserves the predecessor.

Proof and definition resolution uses exactly one snapshot's ancestry. An
artifact admitted only to one sibling cannot satisfy a dependency or function
obligation in another sibling derived from the same predecessor. The selected
state can advance after a snapshot is created without changing that snapshot.
Authenticated-set roots and proof bytes remain the canonical values defined
above; structural sharing is an in-memory representation and contributes no new
identity bytes.

A Foundation-scoped payload archive may use
`validate_and_insert_branch_payload` to validate and retain one exact child
against a caller-held branch snapshot. The archive returns the successor only
after strict snapshot validation and durable insertion or idempotent
confirmation of that exact payload. The predecessor never changes; a validation
or archive failure returns no successor. Archive retention is not a checked
record or branch-state cache, so every later use repeats complete validation in
its target ancestry.

`ArtifactChainJournal::reconstruct_candidate_branch` may start from one
caller-selected retained candidate tip, walk its exact parent and root links
backward to the first selected ancestor, and replay its archived payloads
forward from that ancestor's replay-built snapshot. The caller supplies a
`CandidateBranchReconstructionLimits` with a positive maximum candidate-block
count for that one operation. Only a completely validated target returns a
`ReconstructedCandidateBranch` containing its memory-only snapshot; missing,
corrupt, over-limit, or invalid input returns no partial result. Reconstruction
performs no durable or selected-state mutation; corrupt store reads retain
their typed poison-and-reopen behavior.

This boundary evaluates caller-supplied artifact ancestry only. It does not
persist a candidate snapshot, map consensus ancestry to artifact ancestry,
choose or retain a consensus branch, define a branch-count, depth, byte, or work
limit, fetch missing content, treat local absence as global absence, mutate
canonical selected state, or establish availability, consensus, finality, or
economic authority. A caller-local reconstruction bound is not a protocol-wide
branch limit.

### Payload and trust boundaries

Block bytes contain an `ArtifactId` but no typed payload. Possessing a block
does not establish payload availability. Exact import requests only that
artifact payload and never fetches a dependency implicitly. If application
finds an unselected proof or definition application, or a missing
function-obligation statement, it rejects the block; catch-up must apply the
required earlier block first.

Only successful application or verified journal replay supplies selected
resolver authority. Candidate stores, payload archives, fetched responses,
peer-reported heads, ancestry pulls, membership witnesses, and successful
read-only validation remain non-authoritative observations.

Domains separate proof identity, definition identity, typed artifact identity,
artifact-set nodes, chain definitions, genesis anchors, and blocks. These
commitments assume SHA-256 collision and second-preimage resistance. They do
not establish proposer identity, data availability, mathematical novelty,
reward, fee, consensus selection, or finality.

This is a clean prerelease cutover to `canonical-definition-v1`. There is no
legacy reader, compatibility alias, or local migration. Earlier definition
payloads, journals, candidate stores, payload archives, and network protocol
data must be removed and recreated. Existing primitive canonical proof
certificates and their `ProofId`, `DerivationId`, and `StatementId` values remain
byte-identical.
