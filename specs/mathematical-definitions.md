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

A `DefinitionCertificate` has one kind and one definition-aware body. Its free
variables are positional formal parameters; presentation names are absent.

| Kind | Tag | Formal graph interface | Proof obligation |
| --- | --- | --- | --- |
| relation | `00` | arguments `0 .. arity - 1` | none |
| constant | `01` | output `0` | unique existence |
| function | `02` | inputs `0 .. input_arity - 1`, output `input_arity` | total unique existence |

The exact certificate encodings are:

```text
relation =
  00 | arity u32 | body_length u32 | body

constant =
  01 | body_length u32 | body | unique_existence_proof ProofId[32]

function =
  02 | input_arity u32 | body_length u32 | body
     | total_unique_proof ProofId[32]
```

All integers are unsigned big-endian. `body_length` covers only `body`; the
decoder requires exact end-of-input after the kind-specific suffix. One
certificate is at most 4,194,304 bytes.

Relation arity may be zero. Function input arity must be positive because a
zero-input graph is canonically a constant. `input_arity + 1` must fit `u32`.
Every body free-variable identifier must be smaller than the graph arity: the
declared relation arity, `1` for a constant, or `input_arity + 1` for a
function. An unused formal is permitted; an undeclared formal is rejected.

## Conservative expansion

Resolving `R(a0, ..., an)` first requires the exact `DefinitionId` to be selected.
Expansion then consumes only a non-identity-bearing graph view: its arity and a
cached expanded body. That view exposes neither a `DefinitionId` nor canonical
certificate bytes, so it cannot masquerade as the selected artifact whose ID
authorized the lookup. Expansion requires the graph arity to equal the argument
count and capture-safely substitutes each formal free variable with the
corresponding argument. Bound variables are shifted when substitution crosses a
quantifier. The result contains only Foundation nodes.

Expansion is deterministic and fail-closed. It rejects:

- a definition absent from immutable selected state;
- an arity mismatch;
- an undeclared formal variable;
- a dependency cycle exposed by a resolver; or
- work beyond 65,536 visited compact nodes or depth 256.

The node budget includes compact nodes visited inside cited definition bodies,
including definition-application nodes that disappear from the primitive
result. Selected state retains the exact certificate separately for identity,
kind, dependency, and obligation checks, and stores a definition-free expanded
body for graph resolution. This avoids repeated transitive traversal while
preserving the same primitive result without assigning the cache a second
artifact identity.

Definition dependencies are resolved only from earlier selected blocks in the
same artifact chain. A local definition, same-block definition, forward
reference, candidate block, payload archive, network response, or unselected
fork cannot satisfy resolution. This selected-prior-block rule makes recursive
and mutually recursive definitions unavailable in this protocol version.

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
- A constant with body `P(0)` must name an already selected `ProofId` whose
  checked conclusion is exactly `exists_unique(P, 0, 1)`.
- A function with inputs `0 .. n - 1`, output `n`, and witness `n + 1` must name
  an already selected `ProofId` whose checked conclusion is exactly:

```text
∀0 ∀1 ... ∀(n - 1) exists_unique(P, n, n + 1)
```

The checker expands direct definition dependencies first, then requires the
named proof, constructs the expected obligation, and compares the complete
primitive conclusion structurally. A theorem that is merely equivalent, a
different proof address, or a proof unavailable from selected state does not
satisfy the declared obligation. The obligation `ProofId` is part of definition
identity.

## Definition identity

`DefinitionId` is the SHA-256 digest of the complete kind, arity, body, and
obligation reference under the exact Foundation context:

```text
definition_domain = "naome:definition:v0\0"
foundation        = "naome:zfc"

DefinitionId = SHA256(
  definition_domain
  || u32be(length(foundation)) || foundation
  || u32be(length(canonical_definition)) || canonical_definition
)
```

The relation definition of arity one with body `free(0) = free(0)` has:

```text
DefinitionId = 8f4506222901bb6e087615063e7d1db49be6842d96e7e1adfbcd01c84ff28018
```

Constructing an identity from 32 bytes creates an address only. It does not
establish that the definition exists, is selected, expands, or satisfies its
proof obligation.

## Use inside proofs

Every formula-valued proof-step field may contain selected definition
applications. Before the primitive axiom, schema, or inference operation runs,
the checker expands that field through immutable selected state. A missing
definition, wrong arity, cycle, or expansion-limit failure rejects the proof at
that step. Primitive formula fields take the zero-conversion path.

Proof normal form retains the compact `DefinitionId` applications. Therefore
`ProofId` identifies the concrete compact certificate and its exact definition
references. `StatementId`, derived step results, and `DerivationId` use fully
expanded primitive formulas. This gives the intended split:

- changing a definition boundary may change `ProofId`;
- the same primitive conclusion retains its `StatementId`; and
- the same primitive inference DAG retains its `DerivationId` when the rule and
  ordered primitive dependencies are unchanged.

Definitions can themselves cite earlier selected definitions in their bodies.
Proofs can cite earlier selected `ProofId` values and use earlier selected
`DefinitionId` values in the same certificate. All direct dependencies are
recorded on admission and revalidated before registration.

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
definition_artifact_domain = "naome:artifact:definition:v0\0"

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
- primitive constants, function symbols, or native Foundation term trees;
- implicit dependency discovery, fetching, or same-block dependency batches;
- logical-equivalence search or automatic proof-obligation synthesis; or
- a claim that Foundation is consistent or every mathematical truth is
  decidable.
