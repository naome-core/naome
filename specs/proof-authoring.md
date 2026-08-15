# NAOME Artifact Authoring

## Scope and authority

This document normatively defines the prerelease `.nao` source language for
one proof or one conservative definition. Source is non-authoritative
presentation data. Compilation lowers it to the canonical contracts in
[Proof Protocol](proof-protocol.md) and
[Mathematical Definitions](mathematical-definitions.md), then invokes the same
deterministic checker used by admission.

Names, comments, whitespace, indentation, optional trailing commas, formula
bindings, and term-shaped calls do not become protocol fields. Successful
output is still unselected. Compilation never fetches, registers, selects, or
mutates an artifact and establishes no authorship, chain inclusion, consensus,
or finality.

The syntax is prerelease and may be replaced without a compatibility parser
while no stable source-format commitment exists.

## File shape

One file contains the fixed Foundation, optional selected-definition aliases,
and exactly one artifact:

```text
source := foundation selected-definitions? (definition | proof)

foundation := "foundation" "=" '"naome:zfc"'

selected-definitions := "definitions" ":" selected-definition+
selected-definition  := alias "=" quoted-definition-id

definition := relation-definition
            | function-definition

relation-definition :=
  "definition" name "=" "relation" "(" parameter-list ")" ":" formula EOF

function-definition :=
  "definition" name "=" "function" "(" input-list "," output ")" ":" formula EOF

input-list := input ("," input)*
parameter-list := name ("," name)*
term-list := term ("," term)*

proof := formula-bindings?
         "statement" "=" formula
         "proof" ":" step+ "return" step-name EOF

formula-bindings := "formulas" ":" formula-binding+
formula-binding  := binding-name "=" formula
```

The function production means one or more inputs followed by one output. A
relation has 1 through 256 parameters; a function has 1 through 255 inputs and
one output. Every parameter must be unique and must occur in the graph body.
A source contains only one definition or one proof, never both and never a
batch. A `formulas:` block is proof-only and follows `definitions:` when both
are present.

`quoted-proof-id` and `quoted-definition-id` contain exactly 64 lowercase
hexadecimal characters. Strings have no escape syntax. Names begin with an
ASCII letter or underscore and continue with ASCII letters, digits, or
underscores. Keywords and operators are case-sensitive.

ASCII space, tab, carriage return, and line feed may occur between tokens. `#`
outside a quoted string starts a comment through line end. Indentation and line
boundaries are presentation-only. Commas between operands are mandatory; one
comma immediately before `)` or `]` is optional. The complete source must end
after its one artifact.

Selected-definition aliases and formula-binding names may not reuse any
keyword, formula operator, or proof-expression name shown by this grammar, nor
the schema field name `parameters`. A definition declaration name is
presentation-only, but it may not collide with a selected-definition alias in
the same file.

## Formula and term grammar

```text
formula := "equal" "(" term "," term ")"
         | "member" "(" term "," term ")"
         | "not_" "(" formula ")"
         | "implies" "(" formula "," formula ")"
         | "forall" "(" name "," formula ")"
         | "and_" "(" formula "," formula ")"
         | "or_" "(" formula "," formula ")"
         | "iff" "(" formula "," formula ")"
         | "exists" "(" name "," formula ")"
         | "not_equal" "(" term "," term ")"
         | relation-alias "(" term-list? ")"
         | formula-binding-name

term := name
      | function-alias "(" term-list ")"
```

An alias is declared only in `definitions:`. The compiler immediately resolves
its exact `DefinitionId` from immutable selected state and retains its checked
kind and arity. Therefore every declared alias, even an unused one, must already
be selected. Alias names are source-only. Proof certificates retain the exact
`DefinitionId` in canonical formula bytes; definition compilation instead
expands aliases into the certificate's self-contained primitive graph.

A relation alias is valid only in formula position and receives its graph
arity. A function alias is valid only in a term operand and receives its
declared input arity. Kind or arity mismatch is rejected. The name
being defined is not an alias, so a definition cannot cite itself; forward and
same-file definition references are unavailable by construction.

Primitive terms remain variables. A function call is source sugar for an
existential graph witness. For an atom `A(t1, ..., tk)`, nested term calls are
traversed left-to-right. Each call allocates one fresh witness and appends its
selected graph application. If traversal yields witnesses
`w1 ... wn` and graph constraints `G1 ... Gn`, lowering is exactly:

```text
exists(w1, exists(w2, ... exists(wn,
  and_(G1, and_(G2, ... and_(Gn, A(v1, ..., vk)) ...)))
...)))
```

Each `vi` is the variable or witness representing the corresponding term. This
is bounded, capture-safe formula construction, not a native Foundation term and
not a new checker rule. Calls may nest. Fresh witness allocation and all
expanded conjunction/existential nodes count toward source formula limits.

Derived forms lower one way:

| Source | Definition-aware formula |
| --- | --- |
| `and_(A, B)` | `not_(implies(A, not_(B)))` |
| `or_(A, B)` | `implies(not_(A), B)` |
| `iff(A, B)` | `and_(implies(A, B), implies(B, A))` |
| `exists(x, A)` | `not_(forall(x, not_(A)))` |
| `not_equal(x, y)` | `not_(equal(x, y))` |

They create no proof step or independent identity. Formula bindings resolve
left-to-right and may use only earlier bindings. They expand exactly as if their
right-hand sides were written inline. Binder capture follows the same locally
nameless, capture-safe rules as inline source.

## Definition source

Definition parameters map by declared order to canonical formal free variables:

```python
definition self_equal = relation(value):
    equal(value, value)

definition identity = function(
    input,
    output,
):
    equal(output, input)
```

The declaration name is presentation-only. A relation requires no proof
obligation. For a function, the checker derives the exact total-and-unique
existence statement from its graph. Selected state must already contain that
`StatementId`; no particular `ProofId` is part of the definition or its
identity. Definition bodies may call only earlier selected aliases from the
optional `definitions:` block.

Compilation fully expands selected aliases within deterministic limits, then
constructs and validates one canonical `DefinitionCertificate` from the
resulting primitive graph. It checks the exact function obligation where
required and returns `DefinitionId`, typed `ArtifactId`, and canonical
definition bytes. Therefore an alias-written body and the same inline graph
have exactly the same bytes and identity. Compilation does not admit the result
or make its source name available to another file.

## Proof construction

Proof source expressions are:

```text
simplification(A, B)
frege(A, B, C)
classical_contraposition(A, B)
universal_distribution(x, A, B)
vacuous_universal(A)
universal_instantiation(x, y, A)
modus_ponens(premise, implication)
equality_reflexivity(x)
equality_substitution(from, to, A)
zfc_axiom("extensionality" | "pairing" | "union" | "power_set" |
          "infinity" | "foundation" | "choice")
separation(P, element, source, result, parameters=[...])
replacement(P, input, output, witness, source, result, parameters=[...])
cite("<ProofId>")
generalization(premise, x)
```

Each step is `name = expression`; names are unique. Modus-ponens and
generalization step references must be backward-only. `return` must name the
final declared step. Earlier unreachable steps are permitted and removed by
root-proof normalization.

Formula-valued rule slots may use relation aliases and term sugar. Rule slots
that are semantically Foundation variables remain variables: E1's variable,
E2's `from` and `to`, Q3's variable and replacement, generalization's variable,
and every Separation or Replacement role and parameter. This preserves the
primitive rule contract; term-shaped convenience never changes a rule's
signature.

Schema parameter lists are mandatory and may be empty. The compiler does not
infer them. Their order is the schema's quantifier order and is identity-bearing.
The checker remains authoritative for every distinctness and free-variable side
condition.

`cite` names one exact selected `ProofId`, not a theorem name, statement, local
file, or payload. A reachable citation resolves its stored primitive conclusion
and derivation identity without re-executing the cited certificate. An
unreachable citation removed by normal form is not resolved. Compilation never
searches candidates, archives, network content, or other locally checked
outputs.

The declared statement may use selected definitions and term sugar. It is fully
expanded through selected state before comparison with the checked primitive
conclusion. Canonical proof bytes retain compact `DefinitionId` applications,
so source alias spelling is neutral but selected definition identity is not.

## Compilation order and limits

Compilation executes:

1. require at most 4,194,304 UTF-8 source bytes;
2. require exact Foundation `naome:zfc`;
3. resolve every optional definition alias from immutable selected state;
4. for a definition, parse its one kind and body, fully expand every selected
   alias, build the canonical self-contained certificate, check the exact
   function obligation where required, and return typed output;
5. for a proof, expand optional formula bindings left-to-right, parse and fully
   expand the declared statement, lower proof steps in source order, require
   final `return` and EOF, and construct one certificate;
6. normalize and check the proof once against the same selected state;
7. require its checked primitive conclusion to equal the expanded declared
   statement; and
8. return canonical bytes and identities without registration.

The source, formula, certificate, definition, expansion, and checker limits are
the corresponding protocol limits. Formula bindings have one cumulative
65,536-node budget; the statement has 65,536 nodes; all explicit certificate
formula fields share 65,536 nodes; formula depth is 256. Limits are checked
before unbounded allocation or recursive expansion and fail closed.

Systematically renaming source variables, steps, bindings, declaration names,
or selected aliases together with their uses changes no canonical identity.
Comments, whitespace, indentation, line breaks, optional trailing commas, an
exact formula binding inline/out-of-line boundary, and exact derived-form
expansion are likewise presentation-neutral. Changing a selected `ProofId`,
schema parameter order, proof rule, or proof dependency structure is not
neutral. Changing a proof's selected `DefinitionId` is not neutral even if two
definitions expand alike. In definition source, replacing an alias with another
alias that has the exact same expanded primitive graph is neutral because only
that graph enters the certificate.

## Public API and CLI

`compile_artifact(&str)` compiles one proof or definition against empty
`ArtifactState`. It can compile a dependency-free relation definition or proof,
but it cannot authorize a definition alias, proof citation, or function
obligation statement.

`compile_artifact_against_selected_chain(&str, &ArtifactChainJournal)` first
borrows the healthy journal's immutable selected state and then compiles. Journal
failure precedes every source failure. The borrow prevents mutation through the
same handle during compilation. No candidate, archive, network, or arbitrary
caller-built state is accepted.

`CompiledArtifact` is either `Proof(CompiledProof)` or
`Definition(CompiledDefinition)`. It exposes the complete tagged
`canonical_artifact_bytes` and typed `artifact_id`. A definition result also
exposes `canonical_definition_bytes`, owned-byte conversion, `definition_id`,
and `artifact_id`. The proof-only `compile` and
`compile_against_selected_chain` APIs remain convenience compatibility entry
points and reject definition source; they do not weaken resolver authority.

The only command is:

```sh
naome proof <proof.nao>
```

There is deliberately no separate `definition`, `compile`, state-file,
dependency-file, or network command. The standalone command uses empty state.
Proof success prints exactly:

```text
statement_id <32-byte lowercase hex>
derivation_id <32-byte lowercase hex>
proof_id <32-byte lowercase hex>
artifact_id <32-byte lowercase hex>
canonical_proof <lowercase hex bytes>
```

Definition success prints exactly:

```text
definition_id <32-byte lowercase hex>
artifact_id <32-byte lowercase hex>
canonical_definition <lowercase hex bytes>
```

Usage errors exit `2`; file, UTF-8, compilation, and output errors exit `1`;
success exits `0`. The command reads at most the source limit plus one byte and
never echoes an unbounded source line.

Diagnostics use these stable classes:

| Code | Class | Code | Class |
| --- | --- | --- | --- |
| `NAO0001` | source too long | `NAO0013` | unknown formula binding |
| `NAO0002` | syntax | `NAO0014` | formula-binding node limit |
| `NAO0003` | Foundation mismatch | `NAO0015` | expected proof |
| `NAO0004` | duplicate step | `NAO0016` | duplicate definition alias |
| `NAO0005` | unknown step | `NAO0017` | unknown definition alias |
| `NAO0006` | return not final | `NAO0018` | definition not selected |
| `NAO0007` | formula depth limit | `NAO0019` | definition arity mismatch |
| `NAO0008` | statement | `NAO0020` | definition structure |
| `NAO0009` | certificate | `NAO0021` | definition check |
| `NAO0010` | proof check | `NAO0022` | definition formula |
| `NAO0011` | statement mismatch | `NAO0023` | definition expansion |
| `NAO0012` | duplicate formula binding |  |  |

Source-local failures carry half-open UTF-8 byte spans and derived one-based
line and column positions. Diagnostic names are bounded for rendering. Codes
and spans are authoring metadata and never canonical artifact content.

## Selected-state example

Assume the relation below was selected in an earlier block:

```python
foundation = "naome:zfc"

definition self_equal = relation(value):
    equal(value, value)
```

Its `DefinitionId` is:

```text
0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035
```

A later proof can give it a short source-only name while retaining the exact
chain identity:

```python
foundation = "naome:zfc"

definitions:
    self_equal = "0196e76ee0ecabbe9e863a19f191ded87b599a4b158c52f75d8ece35ba796035"

statement = forall(
    x,
    implies(equal(x, x), implies(self_equal(x), self_equal(x))),
)

proof:
    p0 = equality_substitution(x, x, self_equal(x))
    p1 = generalization(p0, x)
    return p1
```

The definition application in the E2 body remains compact and identity-bearing
in canonical proof bytes. The declared statement and checked result expand it
to primitive equality before comparison and statement/derivation identity.
This file must be compiled through the selected-journal API, not the empty-state
CLI.

## Non-goals

The source language does not provide hypotheses, tactic search, implicit
inference, automatic obligation proofs, dependency fetching, multiple artifacts
per file or block, recursion, standalone constants, zero-input functions,
zero-arity relations, native Foundation constant/function terms,
arbitrary user-defined macros, modules, imports, filesystem citation lookup,
admission, chain selection, consensus, or finality.
