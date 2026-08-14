# NAOME Proof Authoring

## Scope and trust boundary

This document defines the prerelease `.nao` source accepted by
`naome_authoring::compile`,
`naome_authoring::compile_against_selected_chain`, and the `naome proof`
command. The source is a non-authoritative presentation of one assumption-free
Foundation proof.
Compilation lowers names to a `ProofCertificate`, derives its canonical proof
normal form, checks that proof through `naome-checker`, and requires its checked
conclusion to equal the source statement.

Every source formula lowers to the existing primitive Foundation formula
language, and every proof expression lowers to an existing Proof Protocol step.
The authoring grammar adds no canonical encoding, checker rule, resolver
abstraction, or mutation path. The selected-chain adapter only supplies the
checker with the immutable proof state already owned by a healthy
`ProofChainJournal`.

Source text is not a canonical protocol object. Its theorem, step, and variable
names, comments, and whitespace are absent from canonical proof bytes and all
content identities. The checked canonical proof remains governed by the
[Proof Protocol](proof-protocol.md); the source file grants no admission,
selected-state membership, chain inclusion, authorship, or consensus authority.

The source syntax is prerelease presentation syntax. It may be replaced without
a compatibility parser while no stable authoring-format commitment exists.

## Complete source grammar

One file contains exactly one Foundation declaration and one theorem:

```text
source      := "foundation" foundation-id ";"
               "theorem" name "{"
                 "statement" formula ";"
                 "proof" "{" step+ result "}"
               "}" EOF

foundation-id := '"naome:zfc"'

formula     := "(" "equal" name name ")"
             | "(" "member" name name ")"
             | "(" "not" formula ")"
             | "(" "implies" formula formula ")"
             | "(" "forall" name formula ")"
             | "(" "and" formula formula ")"
             | "(" "or" formula formula ")"
             | "(" "iff" formula formula ")"
             | "(" "exists" name formula ")"
             | "(" "not-equal" name name ")"

step        := "step" name "=" proof-expression ";"

proof-expression
            := "(" "simplification" formula formula ")"
             | "(" "frege" formula formula formula ")"
             | "(" "classical-contraposition" formula formula ")"
             | "(" "universal-distribution" name formula formula ")"
             | "(" "vacuous-universal" formula ")"
             | "(" "universal-instantiation" name name formula ")"
             | "(" "modus-ponens" name name ")"
             | "(" "equality-reflexivity" name ")"
             | "(" "equality-substitution" name name formula ")"
             | "(" "zfc-axiom" zfc-axiom-name ")"
             | "(" "separation" formula name name name
                   schema-parameters ")"
             | "(" "replacement" formula name name name name name
                   schema-parameters ")"
             | "(" "proof-reference" proof-id ")"
             | "(" "generalization" name name ")"

schema-parameters
            := "(" "parameters" name* ")"

zfc-axiom-name
            := "extensionality" | "pairing" | "union" | "power-set"
             | "infinity" | "foundation" | "choice"

result      := "result" name ";"

name        := name-start name-continue*
name-start  := ASCII letter | "_"
name-continue
            := name-start | ASCII digit | "-"

proof-id    := lowercase-hex-digit{64}
lowercase-hex-digit
            := ASCII digit | "a" | "b" | "c" | "d" | "e" | "f"
```

ASCII space, tab, carriage return, and line feed may occur between tokens. `#`
outside the Foundation string starts a comment extending to the next line feed
or end of file. Comments and whitespace cannot split a name or the fixed
Foundation string. No string escape or other comment form exists.

Keywords and rule names are case-sensitive. The complete input must match the
grammar; trailing tokens are rejected. The theorem name is presentation data.
The 64 characters of a `proof-id` form one indivisible token: whitespace and
comments cannot occur within it, and uppercase hexadecimal is rejected.
`and`, `or`, `iff`, `exists`, and `not-equal` are the Foundation's exact
eliminable abbreviations, not additional primitive formulas. No alternate
spelling exists. Formula syntax alone does not make a statement derivable.
Proof expressions instantiate L1-L3, Q1-Q3, E1-E2, Separation, or Replacement;
select one of the seven fixed ZFC axioms; cite one exact checked proof; or apply
explicit modus ponens or generalization. The checker still determines whether
those steps derive the declared statement.

## Names and proof construction

Variable names identify presentation variables throughout the theorem. The
compiler assigns internal free-variable identifiers deterministically and
`forall x A` binds occurrences of `x` in `A`. Formula operands of
`simplification`, `frege`, and `classical-contraposition` instantiate the
corresponding Foundation schema in source order. An `equality-substitution from
to A` step constructs `from = to -> (A -> A[from := to])` using capture-free
substitution. A `modus-ponens premise implication` step derives the consequent
of the earlier implication step when its antecedent equals the earlier premise
step. A `generalization premise x` step applies Foundation generalization to the
earlier step named by `premise` and binds the same presentation variable.

Derived formula forms recursively lower before certificate construction:

| Source | Primitive Foundation formula |
| --- | --- |
| `(and A B)` | `(not (implies A (not B)))` |
| `(or A B)` | `(implies (not A) B)` |
| `(iff A B)` | `(and (implies A B) (implies B A))` |
| `(exists x A)` | `(not (forall x (not A)))` |
| `(not-equal x y)` | `(not (equal x y))` |

These are one-way source expansions. They create no proof step, new primitive
node, alternate canonical formula, or independent identity. In particular,
`iff` duplicates both operands exactly as its Foundation definition requires,
and `exists` binds the named variable capture-freely through the same locally
nameless representation as `forall`.

Step names must be unique. Both modus-ponens operands and a generalization
premise must name previously declared steps, so source dependencies are finite
and backward-only. Modus-ponens operand order is significant: the first name is
the premise and the second is the implication. `result` must name the final
declared step. At least one step is required.
Earlier steps may be unreachable from that result; the Proof Protocol's normal
form removes them before checking and identity derivation.

`proof-reference` takes one exact `ProofId`, not a theorem name or
`StatementId`. `compile_against_selected_chain` resolves that address only from
the immutable checked state of a healthy selected-chain journal. A
candidate-store block, archived payload, fetched proof, peer response, or
otherwise checked local proof is not a reference source unless block
application has committed it into that journal. Resolution reuses the cited
proof's closed conclusion and derivation identity without executing its
certificate again. Compilation neither inserts a missing proof, fetches
dependencies, mutates the journal, nor registers its output. Later ledger or
chain admission must resolve the reference again against its own then-current
selected state.

Normalization removes an unreachable reference step before checking, so a
well-formed but absent `ProofId` in such a step is not resolved. A reachable
absent reference fails closed with `CheckError::UnknownProofReference` before
any dependent inference. Exact `ProofId` selection is intentional: different
proof artifacts of one statement remain different citations.

Quantifier expressions refer to presentation variables, not binders already
present in their formula operands. `universal-distribution x A B` instantiates
Q1 with `x`, `A`, and `B`. `universal-instantiation x y A` instantiates Q3 by
binding the free occurrences of `x` in `A`, then capture-freely substituting
free `y` into the conclusion. Q2 has no source binder operand:
`vacuous-universal A` constructs a fresh nameless binder internally, so its
freshness side condition cannot depend on a presentation name.

`zfc-axiom` takes one fixed, case-sensitive selector. It allocates no source
variable and carries no source formula: the checker reconstructs the axiom's
normative primitive Foundation formula from the existing protocol step.

`separation P element source result (parameters p q)` and `replacement P
input output witness source result (parameters p q)` preserve exactly that
predicate, role order, and parameter order in the existing Proof Protocol
steps. The `(parameters ...)` list is mandatory and may be empty; the compiler
does not infer parameters from `P`. Its order is the schema's universal
quantifier order, so reordering it is not presentation-only renaming.

For Separation, every role and parameter must be distinct; every free variable
of `P` must be `element`, `source`, or a declared parameter; and `result` must
not occur free in `P`. For Replacement, every role and parameter must be
distinct; every free variable of `P` must be `input`, `output`, `source`, or a
declared parameter; and neither `witness` nor `result` may occur free in `P`.
These are checker-enforced Foundation side conditions, not parser authority.

The fourteen proof-expression forms lower exactly as follows:

| Source | Proof certificate step |
| --- | --- |
| `(simplification A B)` | Foundation L1 instantiated as `A -> (B -> A)` |
| `(frege A B C)` | Foundation L2 instantiated as `(A -> (B -> C)) -> ((A -> B) -> (A -> C))` |
| `(classical-contraposition A B)` | Foundation L3 instantiated as `(not B -> not A) -> (A -> B)` |
| `(universal-distribution x A B)` | Foundation Q1 instantiated as `forall x (A -> B) -> (forall x A -> forall x B)` |
| `(vacuous-universal A)` | Foundation Q2 instantiated as `A -> forall _ A` with a fresh nameless binder |
| `(universal-instantiation x y A)` | Foundation Q3 instantiated as `forall x A -> A[x := y]` with capture-free substitution |
| `(modus-ponens premise implication)` | modus ponens with the two earlier steps in premise-then-implication order |
| `(equality-reflexivity x)` | Foundation E1 for `x` |
| `(equality-substitution from to A)` | Foundation E2 instantiated as `from = to -> (A -> A[from := to])` with capture-free substitution |
| `(zfc-axiom name)` | the fixed ZFC axiom selected by `extensionality`, `pairing`, `union`, `power-set`, `infinity`, `foundation`, or `choice` |
| `(separation P element source result (parameters p q))` | Separation with predicate `P`, the three roles in source order, and parameters in quantifier order |
| `(replacement P input output witness source result (parameters p q))` | Replacement with predicate `P`, the five roles in source order, and parameters in quantifier order |
| `(proof-reference id)` | `ProofReference { proof_id: id }` for the exact 32-byte `ProofId` |
| `(generalization premise x)` | generalization of the earlier `premise` step over `x` |

No source construct adds an implicit proof step. Q2's nameless binder is the
only universal quantifier introduced without a presentation-variable operand.

## Compilation

Compilation proceeds in this order:

1. require the source byte length to be at most
   `AUTHORING_SOURCE_MAX_BYTES` (`4_194_304` bytes);
2. parse the Foundation declaration and require the exact identifier
   `naome:zfc`;
3. parse and recursively expand the declared statement, then require the
   resulting primitive formula to satisfy the canonical Foundation limits;
4. parse the proof in source order, resolving variables and backward-only step
   names, enforcing the cumulative certificate formula-node budget, and
   lowering each expression;
5. require one final result, both closing braces, and end of source;
6. construct one structurally valid `ProofCertificate`;
7. normalize and check that certificate against either the empty state used by
   `compile` or the immutable selected journal state obtained by
   `compile_against_selected_chain`;
8. require the checked closed conclusion to equal the declared statement; and
9. return the checked canonical proof bytes with its `StatementId`,
   `DerivationId`, and `ProofId`.

The checker is authoritative for mathematical validity, reference resolution,
and closure. `compile` supplies an empty `ProofState`;
`compile_against_selected_chain` supplies only the exact state borrowed from
its journal. A declared statement does not override or supply the proof result.
Statement mismatch is checked only after a proof has passed structural and
mathematical checking.

Normalization removes presentation-only proof structure and canonicalizes
free-variable identifiers according to the Proof Protocol. Systematically
renaming theorem, step, or variable names, or changing only comments and
whitespace, therefore preserves the canonical proof bytes and all three IDs.
Replacing a derived formula with its exact primitive expansion also preserves
the canonical proof bytes and identities.

Derivation identity is reference-transparent: a referenced subproof contributes
its already checked `DerivationId`, so replacing that same derivation's inline
steps with the exact citation preserves the enclosing `DerivationId`. Concrete
proof identity is not reference-transparent: canonical proof bytes contain the
cited `ProofId`, so changing an inline/citation boundary or selecting another
proof artifact changes the enclosing `ProofId`. A certificate consisting only
of a reference consequently has the cited derivation and statement identities
but a distinct concrete proof identity; ordinary selected-state registration
rejects that alias as a duplicate derivation.

## Public API and command

`compile(&str) -> Result<CompiledProof, CompileError>` compiles one complete
source value against an empty checked-proof state. `CompiledProof` exposes
`canonical_proof_bytes`, `statement_id`,
`derivation_id`, and `proof_id`; `into_canonical_proof_bytes` consumes it and
returns the owned canonical bytes. It is not an accepted ledger record, carries
no selected proof state, and conveys no authority from the state used during
compilation.

`compile_against_selected_chain(&str, &ProofChainJournal) ->
Result<CompiledProof, SelectedChainCompileError>` is the protocol-facing
reference-authoring adapter. It first requests the journal's healthy state built
by strict block application or replay and only then compiles the source. A
journal failure is `SelectedState` and takes precedence over every source or
checking failure; a later authoring failure is `Compilation`. The state borrow
remains live for the compilation call, so the journal cannot be mutated
concurrently through that handle. The adapter performs no journal I/O,
candidate or payload lookup, network request, state clone, or mutation.

This selected-journal entry point intentionally replaces the prerelease public
`compile_with_state` API. Arbitrary caller-assembled `ProofState` values are not
a supported dependency source, and no compatibility alias is retained.

The command:

```sh
naome proof proof.nao
```

The path is the second and final argument and is treated as an opaque path;
`compile` is a valid filename in that position. The prerelease
`naome proof compile proof.nao` spelling is rejected as a usage error rather
than retained as a compatibility alias. The command reads one UTF-8 file and,
on success, writes exactly four space-separated lines of lowercase hexadecimal
data:

```text
statement_id <32-byte StatementId>
derivation_id <32-byte DerivationId>
proof_id <32-byte ProofId>
canonical_proof <canonical proof bytes>
```

The command uses `compile` and therefore has an empty proof state. A source
with a reachable `proof-reference` fails as an unknown reference. The command
has no state, journal, dependency-file, network, or implicit discovery option.
Protocol applications that own an opened selected-chain journal use
`compile_against_selected_chain`.

Usage errors exit with status `2`. File, compilation, and output errors exit
with status `1`; success exits with status `0`. File and compilation failures
occur before identity output begins. As with any streamed command output, an
I/O failure while writing successful output may leave a partial byte stream.

## Resource and error contract

`AUTHORING_SOURCE_MAX_BYTES` equals the Proof Protocol's
`CERTIFICATE_MAX_BYTES`: `4_194_304`. Source length is measured in UTF-8 bytes
and rejected before parsing when it exceeds that inclusive limit. Names
and token count have no separate arbitrary cap; their total representation is
already bounded by source bytes, while the number that can reach a compiled
proof is bounded by the existing formula, schema-depth, step, and
certificate-byte limits.
Formula node and depth limits apply to the recursively expanded primitive
formula, not to the shorter source spelling. If `A` and `B` expand to `nA` and
`nB` primitive nodes with root-to-leaf depths `dA` and `dB`, respectively, the
derived roots have these exact costs:

| Source | Primitive nodes | Primitive depth |
| --- | ---: | ---: |
| `(and A B)` | `3 + nA + nB` | `max(dA + 2, dB + 3)` |
| `(or A B)` | `2 + nA + nB` | `max(dA + 2, dB + 1)` |
| `(iff A B)` | `5 + 2*nA + 2*nB` | `max(dA, dB) + 4` |
| `(exists x A)` | `3 + nA` | `dA + 3` |
| `(not-equal x y)` | `2` | `2` |

`iff` therefore charges both copied occurrences of each operand; source sugar
cannot bypass a formula or certificate budget.
Every formula occurrence in a formula-bearing proof expression is charged
independently against `CERTIFICATE_MAX_FORMULA_NODES`, including textually equal
operands. This covers both operands of `simplification`,
`classical-contraposition`, and `universal-distribution`, all three operands of
`frege`, and the single operand of `vacuous-universal`,
`universal-instantiation`, `equality-substitution`, `separation`, or
`replacement`. A schema predicate is encoded and charged once even though
schema expansion can reuse it; the reconstructed result is separately governed
by the checker formula and work limits. A `zfc-axiom` expression contributes
one certificate step but zero encoded certificate formula nodes. Its complete
canonical step encoding is the fixed-ZFC step tag plus one axiom tag. The
declared statement has its separate standalone formula budget.
A `proof-reference` likewise contributes one certificate step and zero encoded
formula nodes. Its canonical step is exactly one tag plus the 32-byte
`ProofId`, or 33 bytes; the certificate still carries its separate four-byte
step count. During checking, the resolved conclusion is charged to the formula
work budget before it is cloned, and the referenced certificate is not
re-executed.
The CLI reads at most the limit plus one byte before decoding UTF-8. Its
over-limit diagnostic therefore states only that the limit was exceeded; it
does not misreport that bounded observation as the complete file length.

The resulting certificate remains subject to the Proof Protocol's byte, step,
formula-node, formula-depth, and formula-byte limits. The checker reconstructs
fixed axioms and valid schemas, validates each result against the canonical
per-formula limits, and charges its canonical bytes to the deterministic
formula-work budget. Once certificate construction succeeds, a schema with at
least `256` parameters fails the derived-formula depth preflight before
side-condition validation. A larger parameter list can instead exceed the
certificate byte limit first, because certificate construction precedes
checking. Limits fail closed: compilation never truncates, wraps, aliases, or
silently omits source.

The exact inherited executable limits are:

| Constant | Inclusive maximum |
| --- | ---: |
| `FORMULA_MAX_DEPTH` | `256` nodes on one root-to-leaf path |
| `FORMULA_MAX_NODES` | `65_536` nodes in one formula |
| `FORMULA_MAX_BYTES` | `393_216` canonical bytes in one formula |
| `CERTIFICATE_MAX_STEPS` | `65_536` steps |
| `CERTIFICATE_MAX_FORMULA_NODES` | `65_536` encoded formula nodes across one certificate |
| `CERTIFICATE_MAX_BYTES` | `4_194_304` canonical certificate bytes |
| `CHECKER_MAX_FORMULA_WORK_BYTES` | `4_194_304` cumulative canonical formula-work bytes |

`CompileError` reports the first failure reached in source order. The complete
source-length check precedes parsing. Within parsing, syntax, Foundation, name,
dependency, formula-depth, and cumulative certificate formula-node checks occur
when their token is reached; an earlier Foundation mismatch therefore precedes
errors in the theorem body, for example. Proof-expression operands are parsed
left to right in grammar order. A derived formula similarly parses its operands
left to right under the existing syntax and resource checks. Only after its
operands succeed does the compiler charge and depth-check the additional
primitive expansion at the derived operator's offset, before constructing or
cloning that expansion. Malformed operands and operand-local limit failures
therefore precede an expansion-only node or depth failure. The declared
statement's formula-limit checks complete when that formula has parsed, before
the rest of the theorem.
The first step beyond `CERTIFICATE_MAX_STEPS` returns that certificate-limit
error immediately, before parsing its proof expression or any later result or
EOF token. Otherwise an invalid or uppercase hexadecimal nibble returns
`Syntax` at that offending byte with `expected` equal to
`"a 64-digit lowercase hexadecimal ProofId"`; an early token delimiter or EOF
reports the same expectation at the proof-ID token's first byte. After exactly
64 valid digits, ordinary grammar resumes: a 65th digit therefore
returns `Syntax` at that extra byte with `expected` equal to `"`)`"`. No
`ProofReference` is constructed from partial or normalized input.
An unsupported `zfc-axiom` selector returns `Syntax` at the selector's first
byte with `expected` equal to `"a fixed ZFC axiom"`. A schema
parses its predicate, role names, and mandatory parameter list from left to
right; missing or malformed syntax therefore precedes mathematical schema
errors. Complete parsing, including the final-result and EOF requirements,
precedes certificate construction. Certificate errors precede checker errors;
checked-proof failure precedes declared-statement mismatch.

Normalization removes unreachable steps before checker execution and assigns
canonical variable identifiers. For each remaining schema step, the checker
applies the parameter-count depth preflight, then checks role collisions in
role order; for each parameter in list order, a role collision before a
duplicate; and, for each free predicate variable in normalized identifier
order, forbidden-role status before undeclared status. Only then does it expand
and resource-check the schema formula. Thus a valid schema paired with a
different declared statement returns `StatementMismatch` only after the schema
has checked. Every failure returns no `CompiledProof` and has no external side
effect.

Offsets below are zero-based UTF-8 byte offsets into the original source:

| Variant | Meaning |
| --- | --- |
| `SourceTooLong { actual, maximum }` | The complete source exceeds `AUTHORING_SOURCE_MAX_BYTES`. |
| `Syntax { offset, expected }` | A lexical or grammar boundary failed. |
| `FoundationMismatch { offset }` | The quoted Foundation identifier is not `naome:zfc`. |
| `DuplicateStep { offset, name }` | A step name repeats an earlier step name. |
| `UnknownStep { offset, name }` | A modus-ponens operand or generalization premise is unknown or not earlier. |
| `ResultNotFinal { offset }` | `result` does not name the final declared step. |
| `FormulaDepthLimitExceeded { offset, maximum }` | The recursively expanded primitive formula exceeds `FORMULA_MAX_DEPTH` (`256`). |
| `Statement { source }` | The declared statement violates a canonical Foundation formula limit. |
| `Certificate { source }` | Lowered proof structure violates the Proof Protocol. |
| `Check { source }` | The normalized proof fails deterministic checking. |
| `StatementMismatch` | The checked conclusion differs structurally from the declared statement. |

## Example

```nao
# Extensionality: sets with exactly the same members are equal.
foundation "naome:zfc";

theorem same_members_are_equal {
  statement
    (forall x (forall y
      (implies
        (forall z (iff (member z x) (member z y)))
        (equal x y))));

  proof {
    step axiom = (zfc-axiom extensionality);
    result axiom;
  }
}
```

The declared statement uses authoring-only `iff`; its recursive primitive
expansion exactly matches the fixed axiom selected by the proof. It is runnable
as `examples/extensionality.nao`. `examples/separation.nao` uses `exists`,
`iff`, and `and` to state an intersection with one explicit parameter, while
`examples/replacement.nao` uses the same derived forms to state the identity
image instance with the mandatory empty parameter list. The implication,
quantifier, equality-substitution, and minimal self-equality examples remain
available separately.

A reference-aware protocol application can compile the following source only
after block application has committed the cited self-equality proof to its
selected-chain journal. It passes that journal to
`compile_against_selected_chain`:

```nao
# Extend one exact checked proof with a local inference.
foundation "naome:zfc";

theorem reflexivity_for_every_y {
  statement (forall y (forall x (equal x x)));

  proof {
    step equality_is_reflexive =
      (proof-reference c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73);
    step for_every_y = (generalization equality_is_reflexive y);
    result for_every_y;
  }
}
```

The reference step reuses the selected checked conclusion `forall x, x = x`;
the local generalization derives `forall y, forall x, x = x`. The same source
fails through `naome proof`, with an empty selected journal, or while
the proof exists only in a candidate store or payload archive.

## Non-goals

This authoring contract defines no:

- additional primitive formulas, other connective aliases, implicit schema
  parameters, or alternate schema spellings;
- symbolic imports, proof aliases, theorem-name or `StatementId` lookup,
  multiple theorems, theorem libraries, definitions, constants, functions,
  namespaces, modules, macros, a canonical-source or formatting command, or
  compatibility aliases;
- proof discovery, fetching, dependency acquisition, proof-state construction
  or serialization, opening or selecting a journal, CLI state selection, or
  implicit choice among proofs of one statement;
- ledger registration, block construction, chain or candidate-store mutation,
  payload archival, networking, or peer policy; or
- fork choice, consensus, finality, validator policy, fees, rewards, staking,
  slashing, token issuance, or other economic state.
