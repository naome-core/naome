# NAOME Proof Authoring

## Scope and trust boundary

This document defines the prerelease `.nao` source accepted by
`naome_authoring::compile` and the `naome proof compile` command. The source is
a human presentation of one assumption-free Foundation proof. Compilation
lowers names to a `ProofCertificate`, derives its canonical proof normal form,
checks that proof through `naome-checker`, and requires its checked conclusion
to equal the source statement.

Every source proof expression lowers to an existing Proof Protocol step. The
authoring grammar adds no canonical encoding, checker rule, or public compiler
API.

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
             | "(" "generalization" name name ")"

result      := "result" name ";"

name        := name-start name-continue*
name-start  := ASCII letter | "_"
name-continue
            := name-start | ASCII digit | "-"
```

ASCII space, tab, carriage return, and line feed may occur between tokens. `#`
outside the Foundation string starts a comment extending to the next line feed
or end of file. Comments and whitespace cannot split a name or the fixed
Foundation string. No string escape or other comment form exists.

Keywords and rule names are case-sensitive. The complete input must match the
grammar; trailing tokens are rejected. The theorem name is presentation data.
Formula syntax alone does not make a statement derivable. Proof expressions
instantiate L1-L3, Q1-Q3, or E1-E2, or apply explicit modus ponens or
generalization; the checker still determines whether those steps derive the
declared statement.

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

Step names must be unique. Both modus-ponens operands and a generalization
premise must name previously declared steps, so source dependencies are finite
and backward-only. Modus-ponens operand order is significant: the first name is
the premise and the second is the implication. `result` must name the final
declared step. At least one step is required.
Earlier steps may be unreachable from that result; the Proof Protocol's normal
form removes them before checking and identity derivation.

Quantifier expressions refer to presentation variables, not binders already
present in their formula operands. `universal-distribution x A B` instantiates
Q1 with `x`, `A`, and `B`. `universal-instantiation x y A` instantiates Q3 by
binding the free occurrences of `x` in `A`, then capture-freely substituting
free `y` into the conclusion. Q2 has no source binder operand:
`vacuous-universal A` constructs a fresh nameless binder internally, so its
freshness side condition cannot depend on a presentation name.

The ten proof expressions lower exactly as follows:

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
| `(generalization premise x)` | generalization of the earlier `premise` step over `x` |

No source construct adds an implicit proof step. Q2's nameless binder is the
only universal quantifier introduced without a presentation-variable operand.

## Compilation

Compilation proceeds in this order:

1. require the source byte length to be at most
   `AUTHORING_SOURCE_MAX_BYTES` (`4_194_304` bytes);
2. parse the Foundation declaration and require the exact identifier
   `naome:zfc`;
3. parse the declared statement and require it to satisfy the canonical
   Foundation formula limits;
4. parse the proof in source order, resolving variables and backward-only step
   names, enforcing the cumulative certificate formula-node budget, and
   lowering each expression;
5. require one final result, both closing braces, and end of source;
6. construct one structurally valid `ProofCertificate`;
7. normalize and check that certificate through the dependency-free checker;
8. require the checked closed conclusion to equal the declared statement; and
9. return the checked canonical proof bytes with its `StatementId`,
   `DerivationId`, and `ProofId`.

The dependency-free checker is authoritative for mathematical validity and
closure. A declared statement does not override or supply the proof result.
Statement mismatch is checked only after a proof has passed structural and
mathematical checking.

Normalization removes presentation-only proof structure and canonicalizes
free-variable identifiers according to the Proof Protocol. Systematically
renaming theorem, step, or variable names, or changing only comments and
whitespace, therefore preserves the canonical proof bytes and all three IDs.

## Public API and command

`compile(&str) -> Result<CompiledProof, CompileError>` compiles one complete
source value. `CompiledProof` exposes `canonical_proof_bytes`, `statement_id`,
`derivation_id`, and `proof_id`; `into_canonical_proof_bytes` consumes it and
returns the owned canonical bytes. It is not an accepted ledger record and
carries no selected proof state.

The command:

```sh
naome proof compile proof.nao
```

reads one UTF-8 file and, on success, writes exactly four space-separated lines
of lowercase hexadecimal data:

```text
statement_id <32-byte StatementId>
derivation_id <32-byte DerivationId>
proof_id <32-byte ProofId>
canonical_proof <canonical proof bytes>
```

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
proof is bounded by the existing formula-node and certificate-step limits.
Every formula occurrence in a formula-bearing proof expression is charged
independently against `CERTIFICATE_MAX_FORMULA_NODES`, including textually equal
operands. This covers both operands of `simplification`,
`classical-contraposition`, and `universal-distribution`, all three operands of
`frege`, and the single operand of `vacuous-universal`,
`universal-instantiation`, and `equality-substitution`. The declared statement
has its separate standalone formula budget.
The CLI reads at most the limit plus one byte before decoding UTF-8. Its
over-limit diagnostic therefore states only that the limit was exceeded; it
does not misreport that bounded observation as the complete file length.

The resulting certificate remains subject to the Proof Protocol's byte, step,
formula-node, formula-depth, and formula-byte limits, and checking remains
subject to the checker's deterministic formula-work budget. Limits fail closed:
compilation never truncates, wraps, aliases, or silently omits source.

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
left to right in grammar order. The declared statement's formula-limit
checks complete when that formula has parsed, before the rest of the theorem.
The first step beyond `CERTIFICATE_MAX_STEPS` returns that certificate-limit
error immediately,
before later result or EOF tokens. Otherwise complete parsing, including the
final-result and EOF requirements, precedes certificate construction.
Certificate errors precede checker errors; checked-proof failure precedes
declared-statement mismatch. Every failure returns no `CompiledProof` and has
no external side effect.

Offsets below are zero-based UTF-8 byte offsets into the original source:

| Variant | Meaning |
| --- | --- |
| `SourceTooLong { actual, maximum }` | The complete source exceeds `AUTHORING_SOURCE_MAX_BYTES`. |
| `Syntax { offset, expected }` | A lexical or grammar boundary failed. |
| `FoundationMismatch { offset }` | The quoted Foundation identifier is not `naome:zfc`. |
| `DuplicateStep { offset, name }` | A step name repeats an earlier step name. |
| `UnknownStep { offset, name }` | A modus-ponens operand or generalization premise is unknown or not earlier. |
| `ResultNotFinal { offset }` | `result` does not name the final declared step. |
| `FormulaDepthLimitExceeded { offset, maximum }` | Source formula nesting exceeds `FORMULA_MAX_DEPTH` (`256`). |
| `Statement { source }` | The declared statement violates a canonical Foundation formula limit. |
| `Certificate { source }` | Lowered proof structure violates the Proof Protocol. |
| `Check { source }` | The normalized proof fails deterministic checking. |
| `StatementMismatch` | The checked conclusion differs structurally from the declared statement. |

## Example

```nao
# Equality substitution followed by explicit closure of every free variable.
foundation "naome:zfc";

theorem equality_preserves_membership {
  statement
    (forall x (forall y (forall set
      (implies (equal x y)
        (implies (member x set) (member y set))))));

  proof {
    step substitute =
      (equality-substitution x y (member x set));
    step for_set = (generalization substitute set);
    step for_y = (generalization for_set y);
    step for_x = (generalization for_y x);

    result for_x;
  }
}
```

The example proves `forall x forall y forall set, x = y -> (x in set -> y in
set)` directly through E2 and explicit generalization. It is runnable as
`examples/equality-substitution.nao`. The existing implication, quantifier, and
minimal self-equality examples remain available separately.

## Non-goals

This authoring contract defines no:

- additional formulas, ZFC axiom-step or schema syntax, or derived connectives;
- proof references, imports, multiple theorems, theorem libraries, definitions,
  constants, functions, namespaces, modules, macros, or compatibility aliases;
- ledger registration, block construction, chain or candidate-store mutation,
  payload archival, networking, dependency acquisition, or peer policy; or
- fork choice, consensus, finality, validator policy, fees, rewards, staking,
  slashing, token issuance, or other economic state.
