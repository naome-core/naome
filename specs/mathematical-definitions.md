# NAOME Mathematical Definitions

This document normatively defines canonical conservative definitions, their
identities, and their use inside proof formulas. The [ZFC Foundation](foundation.md)
remains the only primitive mathematical language. Definitions are selected
artifacts that abbreviate formulas; they add no axiom and no inference rule.

## Definition-aware formulas

A `DefinedFormula` extends the canonical Foundation formula codec with exactly
one node. Existing primitive formulas retain byte-for-byte their Foundation
encoding.

| Tag | Node | Payload |
| --- | --- | --- |
| `00` | equality | two variables |
| `01` | membership | two variables |
| `02` | negation | one formula |
| `03` | implication | antecedent, consequent |
| `04` | universal quantifier | one formula |
| `05` | selected graph relation | `DefinitionId`, argument count, arguments |

The new node is encoded as:

```text
05
definition_id  32 raw bytes
arg_count      u32 big-endian
arguments      arg_count consecutive variables
```

Each argument is one existing canonical variable: tag `00` plus a free-variable
`u32`, or tag `01` plus a De Bruijn `u32`. A defined application accepts only
variables. It does not introduce a primitive constant, function term, string,
name, or nested term tree.

The decoder consumes exactly one complete formula, rejects unknown tags,
dangling bound variables, truncation, and trailing bytes, and applies the same
limits as the primitive codec: 393,216 bytes, 65,536 visited nodes, and nesting
depth 256. A proof formula is decoded through the primitive codec first. Only a
primitive `UnknownFormulaTag(05)` restarts through the definition-aware codec.
Consequently, every proof that contains no definition application retains its
exact prior bytes and identities.

## Canonical graph definitions

A `DefinitionCertificate` has one kind and one primitive Foundation body. Its
free variables are positional formal parameters; presentation names and
definition applications are absent. Source authoring may use selected
definition aliases, but must fully expand them before constructing these bytes.

| Kind | Tag | Formal graph interface | Proof obligation |
| --- | --- | --- | --- |
| relation | `00` | arguments `0 .. arity - 1` | none |
| function | `02` | inputs `0 .. input_arity - 1`, output `input_arity` | total unique existence |

The exact certificate encodings are:

```text
relation =
  00 | arity u32 | body_length u32 | body

function =
  02 | input_arity u32 | body_length u32 | body
```

All integers are unsigned big-endian. `body_length` covers only `body`; the
decoder requires exact end-of-input. Tag `01`, formerly used by prerelease
constant certificates, is invalid and is not reinterpreted. One certificate is
at most 393,225 bytes: a nine-byte header plus one maximum Foundation formula.

Relation graph arity is `1..=256`. Function input arity is `1..=255`, so its
input-plus-output graph arity is at most 256. The body's free-variable set must
equal the complete positional interface `{0, ..., graph_arity - 1}`. A missing,
unused, or undeclared formal is rejected by certificate construction; duplicate
source parameter names are rejected earlier by authoring. These rules prevent
identity variation through empty or unused interfaces and make the encoded
interface minimal.

## Conservative expansion

Resolving `R(a0, ..., an)` first requires the exact `DefinitionId` to be selected.
Expansion consumes the selected certificate's already primitive graph body.
It requires the graph arity to equal the argument count and capture-safely
substitutes each formal free variable with the corresponding argument. Bound
variables are shifted when substitution crosses a quantifier. The result
contains only Foundation nodes.

Expansion is deterministic and fail-closed. It rejects:

- a definition absent from immutable selected state;
- an arity mismatch;
- an out-of-range formal that cannot occur in an admitted selected
  certificate; or
- work beyond 65,536 visited compact nodes or depth 256.

The node budget charges each compact definition-application node and each
visited graph-body node once, before recursion or allocation. Selected state
retains one exact self-contained certificate for both identity and graph
resolution; there is no second expansion cache or canonical
definition-dependency edge. Alias boundaries are authoring presentation only.

## Exact proof obligations

Let `P` be the fully expanded primitive graph body, let `o` be the output formal,
and let `w` be the fresh uniqueness witness. NAOME derives:

```text
unique(P, o, w) = ∀w (P[o := w] → w = o)
exists_unique(P, o, w) = ∃o (P ∧ unique(P, o, w))
```

`and` and `exists` above are expanded to the Foundation abbreviations in
[Foundation](foundation.md); no new logical constructor is introduced.

- A relation definition has no proof obligation because it is only an
  eliminable formula abbreviation.
- A function with inputs `0 .. n - 1`, output `n`, and witness `n + 1` requires
  an already selected statement whose checked conclusion is exactly:

```text
∀0 ∀1 ... ∀(n - 1) exists_unique(P, n, n + 1)
```

The checker constructs this obligation from the primitive body, derives its
exact `StatementId`, resolves that statement from earlier selected state, and
compares the complete primitive conclusion structurally. A theorem that is
merely equivalent, a candidate or archived proof, or a statement unavailable
from selected state does not satisfy the obligation. The particular proof and
derivation that selected the statement are neither serialized nor
definition-identity-bearing.

Before duplicating the graph body, the checker enforces the exact derived work
bounds `2 * body_nodes + input_arity + 9 <= 65,536` and
`body_depth + input_arity + 8 < 256`. The fixed additions are the primitive
expansions of uniqueness, conjunction, existence, and their deepest branch.
Oversized obligations therefore fail before allocating their derived formula
trees.

## Definition identity

`DefinitionId` is the SHA-256 digest of the complete minimal interface and
fully expanded primitive graph under the exact Foundation context:

```text
definition_domain = "naome:definition:v1\0"
foundation        = "naome:zfc"

DefinitionId = SHA256(
  definition_domain
  || u32be(length(foundation)) || foundation
  || u32be(length(canonical_definition)) || canonical_definition
)
```

The golden `DefinitionId` for the relation of arity one with body
`free(0) = free(0)` is
`0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035`.

Source aliases are fully expanded and parameter names are absent before this
identity is computed. Therefore an alias-authored graph and its direct
canonical graph have the same `DefinitionId` and typed `ArtifactId`; selected
state rejects the second occurrence as a duplicate. This is exact canonical
graph deduplication, not logical-equivalence search: structurally different but
provably equivalent formulas remain different definitions.

Constructing an identity from 32 bytes creates an address only. It does not
establish that the definition exists, is selected, or has a selected function
obligation statement.

## Use inside proofs

Every formula-valued proof-step field may contain selected definition
applications. Before the primitive axiom, schema, or inference operation runs,
the checker expands that field through immutable selected state. A missing
definition, wrong arity, or expansion-limit failure rejects the proof at that
step. The generic resolver also rejects cycles defensively, although admitted
canonical definitions contain no definition references and therefore cannot
form a selected-state cycle. Primitive formula fields take the zero-conversion
path.

Proof normal form retains the compact `DefinitionId` applications. Therefore
`ProofId` identifies the concrete compact certificate and its exact definition
references. `StatementId`, derived step results, and `DerivationId` use fully
expanded primitive formulas. This gives the intended split:

- changing a definition boundary may change `ProofId`;
- the same primitive conclusion retains its `StatementId`; and
- the same primitive inference DAG retains its `DerivationId` when the rule and
  ordered primitive dependencies are unchanged.

Proofs can cite earlier selected `ProofId` values and use earlier selected
`DefinitionId` values in the same certificate. Definitions are self-contained;
source aliases used to author them are expanded before identity and admission.

## Typed artifact envelope

Proofs and definitions share one canonical artifact envelope:

| Tag | Artifact | Payload |
| --- | --- | --- |
| `00` | proof | one complete canonical proof certificate |
| `01` | definition | one complete canonical definition certificate |

The tag is one `u8` followed immediately by the typed payload, with no length
inside the envelope and no trailing bytes. The maximum envelope is 4,194,305
bytes. Empty input, an unknown tag, or a payload invalid for the selected tag is
rejected.

Blocks use a single opaque `ArtifactId`, not a 33-byte tagged reference and not
parallel proof and definition roots:

```text
proof_artifact_domain      = "naome:artifact:proof:v0\0"
definition_artifact_domain = "naome:artifact:definition:v1\0"

ArtifactId(proof)      = SHA256(proof_artifact_domain || ProofId)
ArtifactId(definition) = SHA256(definition_artifact_domain || DefinitionId)
```

The domains prevent the same 32 input bytes from aliasing across artifact
kinds. The payload tag supplies the type during strict admission; the derived
typed identity must equal the block's expected `ArtifactId` before state can
change.

## Admission and authority

Strict artifact admission is:

```text
decode exact tagged payload
  -> require canonical typed bytes
  -> check proof or conservative definition against immutable selected state
  -> derive typed ArtifactId
  -> compare the expected ArtifactId
  -> revalidate dependencies and duplicates
  -> atomically register
```

Proof canonicality means root-proof normal form. Definition canonicality means
the sole certificate encoding above. Every failure leaves proof, definition,
authenticated-set, and chain-head state unchanged.

Only a successfully applied block or verified journal replay adds resolver
authority. Merely hashing, decoding, checking locally, archiving, downloading,
or validating a candidate does not select an artifact and does not make its
dependencies available.

## Non-goals

This version does not define:

- consensus, fork choice, finality, incentives, or theorem importance;
- recursive or mutually recursive definitions;
- standalone constants, zero-input functions, zero-arity relations, primitive
  function symbols, or native Foundation term trees;
- implicit dependency discovery, fetching, or same-block dependency batches;
- logical-equivalence search or automatic search/construction of an obligation
  proof; or
- a claim that Foundation is consistent or every mathematical truth is
  decidable.
