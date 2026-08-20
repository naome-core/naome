# NAOME Proof Protocol

This document normatively defines NAOME's canonical proof certificate, proof
identities, typed artifact admission, authenticated artifact set, and linear
single-artifact block. The [ZFC Foundation](foundation.md) owns the primitive
language and rules; [Mathematical Definitions](mathematical-definitions.md)
owns conservative definition artifacts and expansion. The
[Artifact Chain Journal](artifact-chain-journal.md) owns durable selected-state
recovery.

The protocol pipeline is:

```text
canonical typed artifact
  -> deterministic proof or definition checking
  -> immutable accepted record
  -> authenticated selected artifact set
  -> exact-parent single-artifact block
```

Mathematical checking decides Foundation-relative proof validity. State roots,
blocks, ancestry, persistence, and later consensus may
commit ordering, inclusion, and provenance; none can make an invalid proof
valid or establish mathematical truth independently of checking.

## Proof certificate

A certificate is a finite, assumption-free derivation relative to Foundation.
Structural validity does not imply mathematical validity. Admission derives the
root-proof normal form, requires canonical bytes where applicable, and checks
that normal form exactly once.

### Integers and formulas

Counts, lengths, free-variable identifiers, and step indices are unsigned
big-endian `u32` values with exactly one four-byte representation. Tags are
single `u8` values. Canonical bytes contain no variable-length integers,
strings, maps, floats, padding, or implicit Rust enum layouts. Tag literals and
byte dumps below are hexadecimal.

Formulas use prefix order:

| Tag | Node | Payload |
| --- | --- | --- |
| `00` | equality | two variables |
| `01` | membership | two variables |
| `02` | negation | one formula |
| `03` | implication | antecedent, consequent |
| `04` | universal quantifier | one formula |
| `05` | selected graph relation | `DefinitionId`, argument count, variables |

Variables are:

| Tag | Variable | Payload |
| --- | --- | --- |
| `00` | free | identifier as `u32` |
| `01` | bound | De Bruijn index as `u32` |

Binder names are absent. A bound index must be smaller than the number of
enclosing universal quantifiers. Derived connectives and existential
quantification are encoded only after expansion to Foundation primitives. Tag
`05` is permitted only in definition-aware proof formula fields and has the
exact codec and selected-resolution semantics in
[Mathematical Definitions](mathematical-definitions.md). A primitive formula
has no extra envelope and retains its exact Foundation bytes.

The standalone formula codec admits at most 65,536 nodes, nesting depth 256,
and 393,216 bytes in one formula. These processing limits do not restrict the
abstract Foundation language.

### Certificate envelope and steps

```text
step_count  u32
steps       step_count consecutive steps
EOF         no trailing bytes
```

A certificate contains at least one step. Steps are zero-indexed; encoded order
is part of the concrete certificate, and the final step is the claimed
conclusion.

The codec admits at most 4,194,304 certificate bytes, 65,536 steps, and 65,536
cumulative nodes across all explicitly encoded formula fields. Formula nodes
are charged in step and field order, including repeated equal occurrences,
before the next node is decoded or allocated. Fixed ZFC expansions, resolved
reference conclusions, and checker-derived results are excluded from this
payload budget and remain subject to the checker work budget.

Every formula-valued field is:

```text
formula_length  u32
formula_bytes   formula_length canonical formula bytes
```

A schema parameter list is a `u32` count followed by that many free-variable
identifiers in quantifier order. Each step begins with one tag:

| Tag | Step | Payload order |
| --- | --- | --- |
| `00` | L1 simplification | antecedent formula, consequent formula |
| `01` | L2 Frege | first formula, second formula, third formula |
| `02` | L3 classical contraposition | antecedent formula, consequent formula |
| `03` | Q1 universal distribution | variable, antecedent formula, consequent formula |
| `04` | Q2 vacuous universal | formula |
| `05` | Q3 universal instantiation | variable, replacement variable, body formula |
| `06` | E1 equality reflexivity | variable |
| `07` | E2 equality substitution | from variable, to variable, body formula |
| `10` | fixed ZFC axiom | one ZFC axiom tag |
| `11` | Separation | predicate formula, element, source, result, parameters |
| `12` | Replacement | predicate formula, input, output, uniqueness witness, source, result, parameters |
| `20` | modus ponens | premise step index, implication step index |
| `21` | generalization | premise step index, variable |
| `30` | proof reference | one 32-byte `ProofId` |

Fixed ZFC axiom tags are:

| Tag | Axiom |
| --- | --- |
| `00` | Extensionality |
| `01` | Pairing |
| `02` | Union |
| `03` | Power Set |
| `04` | Infinity |
| `05` | Foundation |
| `06` | Choice |

No result formula is encoded beside a step; the checker reconstructs it from
the tag, payload, and earlier results. Q2 encodes no quantified-variable
identifier: the locally nameless representation constructs the nameless
vacuous binder directly, satisfying the abstract freshness condition without
redundant bytes.

### Structural decoding

The decoder accepts bytes exactly when:

- every tag is known;
- all fixed-width values and formula payloads are complete;
- the certificate is non-empty and within the byte, step, formula, and
  cumulative-node limits;
- every modus-ponens or generalization reference is strictly smaller than the
  referencing step index;
- every canonical formula is well formed;
- every count fits `u32`; and
- no bytes remain after the declared steps.

These rules make local references finite and acyclic. Duplicate and unused
steps are structurally valid. Structural decoding does not check proof or
definition reference existence, definition arity or expansion, axiom-schema
side conditions, inference rules, or final closure.

### Mathematical checking

Checking executes every supplied step in encoded order and accepts exactly when
each operation succeeds and the final formula is closed. The first failure in
that order reports the zero-based step index. Admission checks the normal-form
certificate, not presentation-only steps removed by normalization. The
dependency-free entry point uses an empty artifact state and therefore rejects
every proof reference and reachable definition application; reference-aware
checking uses explicit immutable selected artifact state.

Every definition-aware formula field is conservatively expanded before its
primitive operation. Expansion failure is attributed to that normal-form step.
Each result is then reconstructed only through its Foundation operation:

- L1 through L3, Q1, Q3, E1, and E2 instantiate their logical axioms;
- Q2 constructs nameless vacuous universal quantification;
- fixed ZFC steps expand their selected axiom;
- Separation and Replacement expand their predicates, then validate schema side
  conditions while constructing the primitive axiom instance;
- proof references reuse the primitive closed conclusion registered for the exact
  selected `ProofId`;
- modus ponens consumes its referenced premise and implication; and
- generalization universally quantifies its referenced premise.

Every reconstructed result must satisfy the formula depth, node, and byte
limits before it can be referenced. A Separation or Replacement step with at
least 256 parameters fails with the formula depth-limit error before expansion,
because those binders alone cannot fit the limit.

Each definition-aware field has a separate 65,536-node, depth-256 expansion
bound. Checker admits at most 4,194,304 bytes of cumulative canonical primitive
formula work. It
charges both operand lengths before modus ponens, the premise length before
generalization, every reconstructed result, a resolved reference result before
cloning, and the conclusion once more before closure checking. An operand
charge that exceeds the remaining budget rejects before execution. A derived
formula codec error precedes its result charge; the final closure traversal is
charged before the conclusion is classified open or closed. Checker never
inserts implicit universal quantifiers.

### Canonical proof normal form

Every structurally valid certificate has one proof normal form. This is the
canonical input to proof identity, not an inference rule or validity claim.
Starting from the final step as root:

1. Traverse only root-reachable steps with an explicit stack. Modus-ponens
   dependencies retain premise-then-implication order; generalization visits
   its premise. Dependency roles are never sorted.
2. Emit each step after its dependencies, producing dependency-first postorder
   and backward-only remapped references.
3. During emission, map each first-seen free-variable identifier to the smallest
   unused `u32` from zero. Step fields retain wire order, formulas retain prefix
   order, and bound De Bruijn indices are unchanged.
4. Replace local references with emitted output indices.
5. Merge a step only when its normalized tag, complete payload, and ordered
   local references have byte-identical canonical encodings.

The normal form uses the existing envelope and step codec. Normalization is
idempotent, cannot increase byte length or step count, and is invariant under
presentation topological order, systematic free-variable renaming, unreachable
steps, and exact duplicate nodes. It does not merge equal derived formulas from
different rules or dependency structures and performs no theorem rewriting,
commutative or associative sorting, proof minimization, or mathematical-
equivalence search.

A proof reference is a leaf. It contributes no local dependency or free
variable; exact duplicate reference leaves merge byte-for-byte, while different
`ProofId` values never merge even if they resolve to one statement. A
`DefinitionId` application remains compact, participates in formula bytes and
free-variable normalization, and is expanded only during checking.

Encoded input follows this order:

```text
structurally decode the complete input certificate
derive its proof normal form
mathematically check every normal-form step exactly once, resolving every
  reachable ProofId and DefinitionId from selected state
require a closed conclusion
```

Decoding validates all input framing and limits before pruning. Mathematical
validity belongs to the root-reachable normal form: unreachable invalid schema
or inference steps have no admission effect, while reachable invalid steps are
rejected. Mathematical errors identify normal-form indices and normalized free
variables. Strict external admission additionally compares submitted bytes with
normal-form bytes before checking; mismatch is rejected, never repaired.

#### Normal-form golden vector

These structurally valid certificates differ in order, free-variable names, an
unused fixed-ZFC step, and duplicate equality/generalization nodes.

Input A:

```text
00000006
10 01
06 00000007
06 00000007
21 00000001 00000007
21 00000002 00000007
20 00000003 00000004
```

Input B:

```text
00000006
06 0000002a
10 06
21 00000000 0000002a
06 0000002a
21 00000003 0000002a
20 00000002 00000004
```

Both normalize to:

```text
00000003
06 00000000
21 00000000 00000000
20 00000001 00000001
```

The unused step is removed, duplicate nodes share one output index, free
variable `7` or `42` becomes `0`, and both modus-ponens references become `1`.
The final modus-ponens step is intentionally invalid; this vector isolates
structural normalization and must not be admitted as a checked proof.

### External proof references

A `ProofReference` is exactly one raw 32-byte `ProofId`; it repeats no statement
identity, conclusion, proof bytes, or Foundation identifier. Structural decoding
accepts any 32-byte value without asserting existence.

Checking resolves each reachable reference from immutable selected state that
can contain only checked proofs. The state maps `ProofId` through `DerivationId`
to `StatementId` and stores one closed canonical conclusion and its length per
statement. Different derivations remain separately citable without duplicating
the conclusion.

Resolution requires the exact `ProofId` to exist. Absence fails at the
normalized reference step before dependent inference. The conclusion is charged
before cloning, the referenced certificate is not executed again, and
unreachable references removed by normalization are never resolved.

A reference may be the checked root. Its `DerivationId` equals the referenced
derivation. Registration rejects an existing `ProofId`, an existing
`DerivationId`, or a missing cited dependency rather than replacing state.
Changing only an inline/reference boundary changes `ProofId` but not
`DerivationId`; citing a genuinely different derivation changes the dependent
derivation and artifact identities.

For the checked proof in the identity golden below, the reference-only
certificate is:

```text
00000001
30 c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73
```

Its conclusion retains the golden `StatementId`, while the citation proof has:

```text
DerivationId = 59219d63c7c2353dcb6ffd1e604153143380ae6602e04215703bc0ea043243fb
ProofId      = bfd427b447e1514686cfa31b0b5aa1dd5036464cd8c5d73d0c3112cb46b0519b
```

Registering this alias beside the cited proof fails as a duplicate derivation.

### Content identity

Successful checking produces three distinct 32-byte identities:

- `StatementId` identifies the closed conclusion independently of derivation;
- `DerivationId` identifies the inference DAG independently of inline/citation
  packaging; and
- `ProofId` identifies the concrete checked normal form, including citation
  boundaries and cited `ProofId` values.

All use SHA-256 as specified by FIPS 180-4 and bind the exact UTF-8 Foundation
identifier `naome:zfc`. This identifier is a protocol namespace, not a hash
of Foundation source. Exact domain and Foundation bytes are:

```text
statement_domain = 6e616f6d653a73746174656d656e7400
proof_domain     = 6e616f6d653a70726f6f6600
derivation_node_domain = 6e616f6d653a64657269766174696f6e2d6e6f646500
foundation       = 6e616f6d653a7a6663
```

Variable fields have four-byte big-endian lengths. The fixed 32-byte
`StatementId` has no length prefix:

```text
StatementId = SHA256(
    statement_domain
    || u32be(length(foundation))
    || foundation
    || u32be(length(statement_bytes))
    || statement_bytes
)

ProofId = SHA256(
    proof_domain
    || u32be(length(foundation))
    || foundation
    || StatementId
    || u32be(length(normal_proof_bytes))
    || normal_proof_bytes
)
```

`DerivationId` is computed compositionally during checking. For each local,
non-reference step, `result_bytes` are the reconstructed formula bytes after
renumbering that result's free variables to `0, 1, ...` by canonical-prefix
first occurrence. Bound indices are unchanged. This makes the result formula
the node's canonical variable interface across inline/reference boundaries.

```text
node_derivation = SHA256(
    derivation_node_domain
    || u32be(length(foundation))
    || foundation
    || rule_tag
    || u32be(length(result_bytes))
    || result_bytes
    || ordered_parent_derivation_ids
)
```

`rule_tag` is the certificate step tag. Primitive axioms and schemas have no
parents. Modus ponens appends two raw 32-byte parent identities in premise-then-
implication order; generalization appends one premise identity. The tag fixes
arity, so no parent count is encoded. A proof reference creates no node and
returns the registered derivation identity unchanged. The final step's value is
the checked proof's `DerivationId`.

Any added rule whose result and ordered parent identities do not preserve its
complete variable wiring must define additional canonical witness bytes or a
distinct derivation domain; it cannot reuse this transcript silently.

`statement_bytes` are the fully expanded checked conclusion's canonical
primitive formula bytes; `normal_proof_bytes` are the compact checked
normal-form certificate bytes, never the unnormalized submission. Definition
applications therefore remain identity-bearing in `ProofId` while derivation
nodes and `StatementId` use their primitive expansions. Presentation order,
systematic free-variable renaming, unreachable steps, and duplicate nodes
change no identity. Inlining
versus citing can change `ProofId` but not `DerivationId`. Different inference
DAGs of one conclusion share `StatementId` but normally differ in the other two
identities. No logical-equivalence or proof-minimization search occurs.

An identity is an address, not evidence that content exists or is valid.
Admission still requires normalization and mathematical checking. Statement-
novelty policy must use `StatementId`, not counts of proof or derivation
artifacts.

#### Content-identity golden vector

For `E1(x); Generalization(0,x)`, normalization maps `x` to free-variable `0`:

```text
statement_bytes   = 040001000000000100000000
normal_proof_bytes = 000000020600000000210000000000000000

StatementId  = f902f799c24f064ea98bf7fa33c12c5178f1722fdfd94b223c64ea1aa9ae3d19
DerivationId = 59219d63c7c2353dcb6ffd1e604153143380ae6602e04215703bc0ea043243fb
ProofId      = c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73
```

#### Certificate golden vector

Equality reflexivity for free variable `0x01020304` is:

```text
00 00 00 01           one step
06                    equality-reflexivity step
01 02 03 04           free-variable identifier
```

Canonical bytes are:

```text
00 00 00 01 06 01 02 03 04
```

## Selected artifact state and admission

Selected in-memory `ArtifactState` contains:

- `ProofId -> DerivationId` for every selected concrete proof;
- `DerivationId -> StatementId` for every selected inference DAG;
- one canonical primitive conclusion and encoded length for every selected
  statement; and
- one exact checked, primitive, self-contained graph for every selected
  `DefinitionId`.

Only strict proof or definition admission may add entries. Existing identities
are never replaced. State grows monotonically but is not an order-free CRDT:
dependency availability and duplicate derivation rules make admission depend on
the selected prefix.

### Typed payload and strict admission

One externally admitted payload is:

```text
artifact = type_tag u8 | typed_payload

00 | canonical proof certificate
01 | canonical definition certificate
```

The envelope has no inner length, is at most 4,194,305 bytes, and must end with
its typed payload. Exact definition encoding and semantics are specified in
[Mathematical Definitions](mathematical-definitions.md).

Strict addressed admission executes:

1. decode one complete tagged payload;
2. for a proof, derive root-proof normal form and require the submitted inner
   bytes to equal it; for a definition, require exact canonical re-encoding;
3. check the proof or conservative definition against unchanged selected
   artifact state;
4. derive `ArtifactId` from the resulting `ProofId` or `DefinitionId`;
5. require it to equal the immutable expected `ArtifactId`;
6. revalidate duplicates and every direct selected dependency; and
7. atomically register one accepted record.

Decode errors precede canonicality errors; canonicality precedes mathematical
checking; checking precedes expected-address comparison; address mismatch
precedes registration failure. The expected address is request context, never a
trusted payload field. Every failure leaves all selected state unchanged.

The owned-certificate authoring path may normalize a proof before checking and
registration. It is not an external byte-admission substitute. Definitions
have one canonical encoding and are never normalized from another form.

### Accepted records and artifact DAG

An accepted proof record contains the exact tagged canonical payload; its
`ArtifactId`, `ProofId`, `DerivationId`, and `StatementId`; directly cited
`ProofId` values in normal-form step order; and unique direct `DefinitionId`
values in canonical occurrence order. An accepted definition record contains
the exact tagged payload; its `ArtifactId` and `DefinitionId`; and its optional
derived obligation `StatementId`. Definition certificates contain no selected
definition or proof address.

Dependencies are direct, not transitive. Accepted bytes and dependency lists are
immutable. Callers cannot insert unchecked records, identities, edges, or set
leaves. Registration rechecks direct dependencies so a checked value cannot be
moved from a different selected context. The
[Artifact Chain Journal](artifact-chain-journal.md) is the sole durable selected
state owner and reconstructs records only through strict block replay.

Duplicate concrete proofs, derivations, and definitions are rejected. Multiple
different checked derivations may establish one `StatementId`, but selecting a
second packaging of an already selected derivation is rejected. Identity
collision checks are fail-closed.

## Authenticated artifact set

The selected exact `ArtifactId` set is a compressed binary Merkle-Patricia tree.
It has one insertion-order-independent `ArtifactSetRoot` and compact membership
and non-membership proofs. Its sole key is the complete 32-byte `ArtifactId`.
Typed payloads, `ProofId`, `DefinitionId`, statement and derivation identities,
conclusions, and dependency indexes are not separately hashed into this set.

### Key bits and topology

Bits are read most-significant first:

```text
bit(key, d) = (key[d / 8] >> (7 - (d mod 8))) & 1
```

For `d` in `0..=255` and finite key set `S`:

```text
Tree(empty) = Empty
Tree({key}) = Leaf(key)
Tree(S)     = Branch(d, Tree(S0), Tree(S1))
```

For more than one key, `d` is the first differing bit; `S0` and `S1` are the
nonempty zero- and one-bit subsets. Every branch therefore has two nonempty
children, branch bits increase strictly from root to leaf, and a nonempty
`n`-key tree has `n` leaves and `n - 1` branches. There are no empty, unary, or
extension nodes. Lookup, insertion, projection, and one proof path traverse at
most 256 branches.

### Hash transcript

Every digest is SHA-256 under the exact trailing-NUL domain:

```text
artifact_set_domain = "naome:artifact-set:v0\0"

E = SHA256(artifact_set_domain || 00)
L(key) = SHA256(artifact_set_domain || 01 || key[32])
B(d, left, right) = SHA256(
  artifact_set_domain || 02 || d_u8 || left[32] || right[32]
)
```

`E` is the empty root. Branch children are ordered with zero left and one right;
the discriminating bit is authenticated content.

### Compact set proofs

A proof has an empty-tree, membership, or non-membership terminal. A non-member
terminal contains the different leaf reached by the query. The root-to-terminal
path stores only the branch bit and sibling digest because direction derives
from the queried `ArtifactId`.

```text
Empty     = 00
Member    = 01 | Path
NonMember = 02 | terminal_artifact_id[32] | Path

Path = Step*
Step = branch_bit u8 | sibling_digest[32]
```

The complete input boundary determines the count. A membership proof can cover
all 256 bit positions and is at most 8,449 bytes. A non-membership proof can
cover at most 255 positions and is at most 8,448 bytes because its terminal key
must differ at another bit.

Decoding rejects oversize input before allocation, unknown or incomplete
terminals, partial 33-byte steps, excessive paths, non-increasing branch bits,
empty siblings, and a path after an empty terminal. This establishes structure
only. Verification additionally requires the non-member key to differ from the
query and follow the same authenticated path, folds the terminal digest back to
the root using query directions, and returns membership only after equality with
the trusted expected root.

The empty-set root is:

```text
976e576ec6145d57b5e192d1c37a0938bb5c76663532d0354fcd98ba3fbf597a
```

For all-zero `ArtifactId`, the singleton root is:

```text
f8d94326ff427a5311fd43c28524588f5fa955cb1b1be096a34b1b724c103963
```

For all-zero plus `80` followed by 31 zero bytes, the root is:

```text
f89fb7c7336af38296e54143f3111c23dc352f8795ed76742549767ea42880a5
```

Adding 31 zero bytes followed by `01` produces:

```text
c8ecb7085200b45d99f505bd00fa791d0fdd2bbfc3d65014b89aa9491095d768
```

An `ArtifactSetRoot` or verified witness authenticates set membership relative
to a caller-trusted root only. It does not check payloads, establish ancestry,
prove availability, select a fork, or establish finality.

### Integration and projection

Strict typed admission, dependency resolution, expected-address comparison,
and registration all succeed before tree insertion. Duplicate rules then make
insertion logically infallible. Failed admission changes neither record count,
topology, root, nor existing witnesses.

Block preparation and preflight project the root produced by one `ArtifactId`
without mutating records or topology. Projection performs no payload decode,
checking, dependency resolution, or registry admission and must not clone or
scan the selected set. Journal replay stores no Merkle nodes; it reconstructs
and verifies the set through strict block application.

## Single-artifact block and linear chain state

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

This boundary evaluates caller-supplied artifact ancestry only. It does not
persist a candidate snapshot, map consensus ancestry to artifact ancestry,
choose or retain a consensus branch, define a branch-count, depth, byte, or work
limit, mutate canonical selected state, or establish availability, consensus,
finality, or economic authority.

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
