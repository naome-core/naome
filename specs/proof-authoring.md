# NAOME Proof Authoring

## Scope and trust boundary

This document defines the prerelease `.nao` source accepted by
`naome_authoring::compile`,
`naome_authoring::compile_against_selected_chain`, and the `naome proof`
command. The source is a non-authoritative presentation of one assumption-free
Foundation proof with one declared closed statement.
Compilation lowers names to a `ProofCertificate`, derives its canonical proof
normal form, checks that proof through `naome-checker`, and requires its checked
conclusion to equal the source statement.

Every source formula lowers to the existing primitive Foundation formula
language, and every proof expression lowers to an existing Proof Protocol step.
The authoring grammar adds no canonical encoding, checker rule, resolver
abstraction, or mutation path. The selected-chain adapter only supplies the
checker with the immutable proof state already owned by a healthy
`ProofChainJournal`.

Source text is not a canonical protocol object. Its formula-binding, step, and
variable names, comments, optional trailing commas, and whitespace are absent
from canonical proof bytes and all content identities. The checked canonical
proof remains governed by the [Proof Protocol](proof-protocol.md); the source
file grants no admission, selected-state membership, chain inclusion,
authorship, or consensus authority.

The source syntax is prerelease presentation syntax. It may be replaced without
a compatibility parser while no stable authoring-format commitment exists.

## Complete source grammar

One file contains exactly one Foundation declaration, an optional formula
binding block, one statement, and one proof:

```text
source      := "foundation" "=" foundation-id
               formula-bindings?
               "statement" "=" formula
               "proof" ":" step+ return EOF

foundation-id := '"naome:zfc"'

formula-bindings
            := "formulas" ":" formula-binding+
formula-binding
            := formula-binding-name "=" formula
formula-binding-name
            := name except any fixed source keyword, formula operator,
               or proof-expression name

formula     := "equal" "(" name "," name trailing-comma? ")"
             | "member" "(" name "," name trailing-comma? ")"
             | "not_" "(" formula trailing-comma? ")"
             | "implies" "(" formula "," formula trailing-comma? ")"
             | "forall" "(" name "," formula trailing-comma? ")"
             | "and_" "(" formula "," formula trailing-comma? ")"
             | "or_" "(" formula "," formula trailing-comma? ")"
             | "iff" "(" formula "," formula trailing-comma? ")"
             | "exists" "(" name "," formula trailing-comma? ")"
             | "not_equal" "(" name "," name trailing-comma? ")"
             | formula-reference
formula-reference
            := formula-binding-name

step        := step-name "=" proof-expression
step-name   := name except "return"

proof-expression
            := "simplification" "(" formula "," formula trailing-comma? ")"
             | "frege" "(" formula "," formula "," formula trailing-comma? ")"
             | "classical_contraposition" "(" formula "," formula trailing-comma? ")"
             | "universal_distribution" "(" name "," formula "," formula trailing-comma? ")"
             | "vacuous_universal" "(" formula trailing-comma? ")"
             | "universal_instantiation" "(" name "," name "," formula trailing-comma? ")"
             | "modus_ponens" "(" name "," name trailing-comma? ")"
             | "equality_reflexivity" "(" name trailing-comma? ")"
             | "equality_substitution" "(" name "," name "," formula trailing-comma? ")"
             | "zfc_axiom" "(" quoted-zfc-axiom-name trailing-comma? ")"
             | "separation" "(" formula "," name "," name "," name ","
                   schema-parameters trailing-comma? ")"
             | "replacement" "(" formula "," name "," name "," name "," name "," name ","
                   schema-parameters trailing-comma? ")"
             | "cite" "(" quoted-proof-id trailing-comma? ")"
             | "generalization" "(" name "," name trailing-comma? ")"

schema-parameters
            := "parameters" "=" "[" parameter-list? "]"
parameter-list
            := name ("," name)* trailing-comma?
trailing-comma
            := ","

quoted-zfc-axiom-name
            := '"extensionality"' | '"pairing"' | '"union"' | '"power_set"'
             | '"infinity"' | '"foundation"' | '"choice"'

return      := "return" name

name        := name-start name-continue*
name-start  := ASCII letter | "_"
name-continue
            := name-start | ASCII digit

quoted-proof-id
            := '"' lowercase-hex-digit{64} '"'
lowercase-hex-digit
            := ASCII digit | "a" | "b" | "c" | "d" | "e" | "f"
```

ASCII space, tab, carriage return, and line feed may occur between tokens. `#`
outside any quoted string starts a comment extending to the next line feed or
end of file. Comments and whitespace cannot split a name, quoted value, or
fixed identifier. No string escape or other comment form exists.

The examples use four-space indentation, but indentation and line boundaries
are presentation-only. Balanced calls, the fixed declaration order, `return`,
and EOF delimit the complete grammar. Tabs, different indentation, or a
single-line source therefore do not change the compiled proof. Commas between
operands are mandatory; one comma before a closing `)` or `]` is optional.
Missing, doubled, or additional operand commas are rejected.

Keywords and rule names are case-sensitive. The optional `formulas:` block may
occur at most once, directly after `foundation`, and must contain at least one
binding. `statement` terminates that block. A formula-binding name cannot equal
any fixed source keyword (`foundation`, `formulas`, `statement`, `proof`,
`return`, or `parameters`), formula operator, or proof-expression name. A
reserved name in a binding declaration or bare formula position is `Syntax`, as
is an unknown call such as `foo(...)`; an unknown non-reserved bare name is
`UnknownFormulaBinding`. `return` remains reserved as the proof terminator
rather than permitted as a step name. The complete input must match the grammar;
trailing tokens are rejected. The 64 characters inside a cited `ProofId` string
form one indivisible value: whitespace and comments cannot occur within it, and
uppercase hexadecimal is rejected. `and_`, `or_`, `iff`, `exists`, and
`not_equal` are the Foundation's exact eliminable abbreviations, not additional
primitive formulas. No alternate spelling exists. Formula syntax alone does
not make a statement derivable.
Proof expressions instantiate L1-L3, Q1-Q3, E1-E2, Separation, or Replacement;
select one of the seven fixed ZFC axioms; cite one exact checked proof; or apply
explicit modus ponens or generalization. The checker still determines whether
those steps derive the declared statement.

## Names and proof construction

Formula bindings, presentation variables, and proof steps have independent
namespaces. Binding names are unique within `formulas:`. Declarations resolve
from left to right, so a binding RHS may use only an earlier binding; self,
forward, and absent bare references fail as `UnknownFormulaBinding`. Each use
expands to the exact already-lowered primitive Foundation formula before its
surrounding formula is constructed.

Bindings are presentation aliases, not mathematical definitions or canonical
objects. An outer `forall(x, binding)` or `exists(x, binding)` captures free
occurrences of the same presentation variable exactly as if the binding's RHS
were written inline; binders already inside the RHS remain locally nameless and
capture-safe.

Variable names identify presentation variables throughout the source. The
compiler assigns internal free-variable identifiers deterministically and
`forall(x, A)` binds occurrences of `x` in `A`. Formula operands of
`simplification`, `frege`, and `classical_contraposition` instantiate the
corresponding Foundation schema in source order. An
`equality_substitution(from, to, A)` step constructs
`from = to -> (A -> A[from := to])` using capture-free substitution. A
`modus_ponens(premise, implication)` step derives the consequent of the earlier
implication step when its antecedent equals the earlier premise step. A
`generalization(premise, x)` step applies Foundation generalization to the
earlier step named by `premise` and binds the same presentation variable.

Derived formula forms recursively lower before certificate construction:

| Source | Primitive Foundation formula |
| --- | --- |
| `and_(A, B)` | `not_(implies(A, not_(B)))` |
| `or_(A, B)` | `implies(not_(A), B)` |
| `iff(A, B)` | `and_(implies(A, B), implies(B, A))` |
| `exists(x, A)` | `not_(forall(x, not_(A)))` |
| `not_equal(x, y)` | `not_(equal(x, y))` |

These are one-way source expansions. They create no proof step, new primitive
node, alternate canonical formula, or independent identity. In particular,
`iff` duplicates both operands exactly as its Foundation definition requires,
and `exists` binds the named variable capture-freely through the same locally
nameless representation as `forall`.

Step names must be unique. Both `modus_ponens` operands and a generalization
premise must name previously declared steps, so source dependencies are finite
and backward-only. `modus_ponens` operand order is significant: the first name is
the premise and the second is the implication. `return` must name the final
declared step. At least one step is required.
Earlier steps may be unreachable from that return value; the Proof Protocol's
normal form removes them before checking and identity derivation.

`cite("id")` takes one exact `ProofId`, not a theorem name or
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
present in their formula operands. `universal_distribution(x, A, B)`
instantiates Q1 with `x`, `A`, and `B`.
`universal_instantiation(x, y, A)` instantiates Q3 by binding the free
occurrences of `x` in `A`, then capture-freely substituting free `y` into the
conclusion. Q2 has no source binder operand: `vacuous_universal(A)` constructs
a fresh nameless binder internally, so its freshness side condition cannot
depend on a presentation name.

`zfc_axiom` takes one fixed, quoted, case-sensitive selector. It allocates no
source variable and carries no source formula: the checker reconstructs the
axiom's normative primitive Foundation formula from the existing protocol
step.

`separation(P, element, source, result, parameters=[p, q])` and
`replacement(P, input, output, witness, source, result, parameters=[p, q])`
preserve exactly that predicate, role order, and parameter order in the
existing Proof Protocol steps. The `parameters=[...]` list is mandatory and
may be empty; the compiler does not infer parameters from `P`. Its order is the
schema's universal quantifier order, so reordering it is not presentation-only
renaming.

For Separation, every role and parameter must be distinct; every free variable
of `P` must be `element`, `source`, or a declared parameter; and `result` must
not occur free in `P`. For Replacement, every role and parameter must be
distinct; every free variable of `P` must be `input`, `output`, `source`, or a
declared parameter; and neither `witness` nor `result` may occur free in `P`.
These are checker-enforced Foundation side conditions, not parser authority.

The fourteen proof-expression forms lower exactly as follows:

| Source | Proof certificate step |
| --- | --- |
| `simplification(A, B)` | Foundation L1 instantiated as `A -> (B -> A)` |
| `frege(A, B, C)` | Foundation L2 instantiated as `(A -> (B -> C)) -> ((A -> B) -> (A -> C))` |
| `classical_contraposition(A, B)` | Foundation L3 instantiated as `(not B -> not A) -> (A -> B)` |
| `universal_distribution(x, A, B)` | Foundation Q1 instantiated as `forall x (A -> B) -> (forall x A -> forall x B)` |
| `vacuous_universal(A)` | Foundation Q2 instantiated as `A -> forall _ A` with a fresh nameless binder |
| `universal_instantiation(x, y, A)` | Foundation Q3 instantiated as `forall x A -> A[x := y]` with capture-free substitution |
| `modus_ponens(premise, implication)` | modus ponens with the two earlier steps in premise-then-implication order |
| `equality_reflexivity(x)` | Foundation E1 for `x` |
| `equality_substitution(from, to, A)` | Foundation E2 instantiated as `from = to -> (A -> A[from := to])` with capture-free substitution |
| `zfc_axiom("name")` | the fixed ZFC axiom selected by `extensionality`, `pairing`, `union`, `power_set`, `infinity`, `foundation`, or `choice` |
| `separation(P, element, source, result, parameters=[p, q])` | Separation with predicate `P`, the three roles in source order, and parameters in quantifier order |
| `replacement(P, input, output, witness, source, result, parameters=[p, q])` | Replacement with predicate `P`, the five roles in source order, and parameters in quantifier order |
| `cite("id")` | `ProofReference { proof_id: id }` for the exact 32-byte `ProofId` |
| `generalization(premise, x)` | generalization of the earlier `premise` step over `x` |

No source construct adds an implicit proof step. Q2's nameless binder is the
only universal quantifier introduced without a presentation-variable operand.

## Compilation

Compilation proceeds in this order:

1. require the source byte length to be at most
   `AUTHORING_SOURCE_MAX_BYTES` (`4_194_304` bytes);
2. parse the Foundation declaration and require the exact identifier
   `naome:zfc`;
3. if present, parse the nonempty `formulas:` block from left to right, resolve
   only earlier bindings, and retain each expanded formula within the binding
   node budget;
4. parse and recursively expand the declared statement, then require the
   resulting primitive formula to satisfy the canonical Foundation limits;
5. parse the proof in source order, resolving variables and backward-only step
   names, enforcing the cumulative certificate formula-node budget, and
   lowering each expression;
6. require one final `return` naming the last step and end of source;
7. construct one structurally valid `ProofCertificate`;
8. normalize and check that certificate against either the empty state used by
   `compile` or the immutable selected journal state obtained by
   `compile_against_selected_chain`;
9. require the checked closed conclusion to equal the declared statement; and
10. return the checked canonical proof bytes with its `StatementId`,
   `DerivationId`, and `ProofId`.

The checker is authoritative for mathematical validity, reference resolution,
and closure. `compile` supplies an empty `ProofState`;
`compile_against_selected_chain` supplies only the exact state borrowed from
its journal. A declared statement does not override or supply the proof result.
Statement mismatch is checked only after a proof has passed structural and
mathematical checking.

Normalization removes presentation-only proof structure and canonicalizes
free-variable identifiers according to the Proof Protocol. Systematically
renaming a formula binding together with its uses, a step, or a variable, or
changing only comments, whitespace, indentation, line breaks, or optional
trailing commas, therefore preserves the canonical proof bytes and all three
IDs. So does reordering independent bindings, adding or removing unused
bindings, replacing a binding use with its exact RHS, or replacing a derived
formula with its exact primitive expansion.

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
compilation. `CompileError` exposes its stable `DiagnosticCode`, optional source
offset, and a structured `CompileDiagnostic` derived from the exact source that
failed. Diagnostic metadata is authoring information, never canonical proof
content or protocol state.

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
with a reachable `cite(...)` step fails as an unknown reference. The command
has no state, journal, dependency-file, network, or implicit discovery option.
Protocol applications that own an opened selected-chain journal use
`compile_against_selected_chain`.

Usage errors exit with status `2`. File, compilation, and output errors exit
with status `1`; success exits with status `0`. File and compilation failures
occur before identity output begins. As with any streamed command output, an
I/O failure while writing successful output may leave a partial byte stream.
One located compilation failure is written to standard error as
`naome: <path>:<line>:<column>: error[NAOxxxx]: <message>`; the bounded reader's
unlocated over-limit failure omits line and column. Each diagnostic is exactly
one line with no color, source echo, or caret, so an arbitrarily long source
line is never copied into error output. Path control characters, carriage
return, line feed, and the Unicode line and paragraph separators are escaped;
other printable Unicode and path separators are preserved.

## Resource and error contract

`AUTHORING_SOURCE_MAX_BYTES` equals the Proof Protocol's
`CERTIFICATE_MAX_BYTES`: `4_194_304`. Source length is measured in UTF-8 bytes
and rejected before parsing when it exceeds that inclusive limit. Names
and token count have no separate arbitrary cap; their total representation is
already bounded by source bytes, while the number that can reach a compiled
proof is bounded by the existing formula, schema-depth, step, and
certificate-byte limits.

The `formulas:` block may cumulatively retain at most `65_536` primitive formula
nodes across all expanded binding RHS values. This authoring-only budget has no
public constant. Declarations and nested references charge it left to right;
reusing an earlier binding inside a later binding charges every retained clone.
After a bare binding name resolves, the compiler charges the referenced
formula's complete expanded node count to the active binding, statement, or
certificate budget and preflights its resulting absolute depth, then clones it.
Statement and proof uses therefore incur exactly the same limits as an inline
RHS and cannot use bindings to bypass node or depth checks.

Formula node and depth limits apply to the recursively expanded primitive
formula, not to the shorter source spelling. If `A` and `B` expand to `nA` and
`nB` primitive nodes with root-to-leaf depths `dA` and `dB`, respectively, the
derived roots have these exact costs:

| Source | Primitive nodes | Primitive depth |
| --- | ---: | ---: |
| `and_(A, B)` | `3 + nA + nB` | `max(dA + 2, dB + 3)` |
| `or_(A, B)` | `2 + nA + nB` | `max(dA + 2, dB + 1)` |
| `iff(A, B)` | `5 + 2*nA + 2*nB` | `max(dA, dB) + 4` |
| `exists(x, A)` | `3 + nA` | `dA + 3` |
| `not_equal(x, y)` | `2` | `2` |

`iff` therefore charges both copied occurrences of each operand; source sugar
cannot bypass a formula or certificate budget.
Every formula occurrence in a formula-bearing proof expression is charged
independently against `CERTIFICATE_MAX_FORMULA_NODES`, including textually equal
operands. This covers both operands of `simplification`,
`classical_contraposition`, and `universal_distribution`, all three operands of
`frege`, and the single operand of `vacuous_universal`,
`universal_instantiation`, `equality_substitution`, `separation`, or
`replacement`. A schema predicate is encoded and charged once even though
schema expansion can reuse it; the reconstructed result is separately governed
by the checker formula and work limits. A `zfc_axiom` expression contributes
one certificate step but zero encoded certificate formula nodes. Its complete
canonical step encoding is the fixed-ZFC step tag plus one axiom tag. The
declared statement has its separate standalone formula budget.
A `cite` likewise contributes one certificate step and zero encoded
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

The exact executable limits relevant here are:

| Limit | Inclusive maximum |
| --- | ---: |
| `formulas:` retained primitive nodes (authoring-only) | `65_536` nodes |
| `FORMULA_MAX_DEPTH` | `256` nodes on one root-to-leaf path |
| `FORMULA_MAX_NODES` | `65_536` nodes in one formula |
| `FORMULA_MAX_BYTES` | `393_216` canonical bytes in one formula |
| `CERTIFICATE_MAX_STEPS` | `65_536` steps |
| `CERTIFICATE_MAX_FORMULA_NODES` | `65_536` encoded formula nodes across one certificate |
| `CERTIFICATE_MAX_BYTES` | `4_194_304` canonical certificate bytes |
| `CHECKER_MAX_FORMULA_WORK_BYTES` | `4_194_304` cumulative canonical formula-work bytes |

`CompileError` reports the first failure reached in source order. The complete
source-length check precedes parsing. Within parsing, syntax, Foundation, name,
dependency, formula-depth, and cumulative formula-node checks occur
when their token is reached; an earlier Foundation mismatch therefore precedes
errors in formula bindings, the statement, or the proof. An optional
`formulas:` block is parsed completely before `statement`. It must be nonempty
and cannot repeat. Each declaration first validates its non-reserved name and
rejects a duplicate before its `=` or RHS is parsed. At each RHS formula
call, the root primitive node is charged before the operator is classified. A
non-reserved bare name is instead resolved before any active-context node
charge, so an absent, self, or forward name is `UnknownFormulaBinding` even
when that node budget is already full. A known binding charges its complete
expanded node count, preflights depth, and only then clones. The exact RHS
operator, primitive leaf, or alias token whose left-to-right charge crosses the
retention limit is `FormulaBindingNodeLimitExceeded`. No incomplete declaration
is retained.

Call operands are parsed left to right in grammar order, with each mandatory
comma checked before the next operand. A derived formula follows the same
resource checks. Only after its operands succeed does the compiler charge and
depth-check the additional primitive expansion at the derived operator's
offset, before constructing or cloning that expansion. Malformed operands and
operand-local limit failures therefore precede an expansion-only node or depth
failure. The declared statement's formula-limit checks complete when that
formula has parsed, before the proof.
The first step beyond `CERTIFICATE_MAX_STEPS` returns that certificate-limit
error immediately, before parsing its proof call or any later `return` or EOF
token. `cite` first requires an opening quote. Otherwise an invalid or uppercase
hexadecimal nibble within its first 64 content bytes returns
`Syntax` at that offending byte with `expected` equal to
`"a 64-digit lowercase hexadecimal ProofId"`; early termination reports the
same expectation. After exactly 64 valid digits, a missing closing quote,
including a 65th hexadecimal digit, returns `Syntax` at that byte with
`expected` equal to
`"a closing quote after the ProofId"`. The call's closing `)` is checked only
after the quoted ID. No `ProofReference` is constructed from partial or
normalized input.

`zfc_axiom` first requires a quoted selector; a missing or malformed opening
quote expects `"a quoted ZFC axiom selector"`. An unsupported complete value
returns `Syntax` at the opening quote with `expected` equal to
`"a fixed ZFC axiom"`.

A schema parses its predicate, role names, and mandatory parameter list from
left to right; missing or malformed syntax therefore precedes mathematical
schema errors. Complete parsing, including the final `return` and EOF
requirements, precedes certificate construction. Certificate errors precede
checker errors; checked-proof failure precedes declared-statement mismatch.

Normalization removes unreachable steps, interns exact proof nodes, emits
dependency-first order, and assigns canonical variable identifiers. A traced
normalization sidecar maps each normalized step back to its source step solely
to map an authoring check failure, and is dropped after checking. If exact
reachable source steps intern into one normalized node, the lowest source
position is retained. The sidecar is absent from canonical bytes, identities,
checker semantics, selected state, and every successful `CompiledProof`.

For each remaining schema step, the checker
applies the parameter-count depth preflight, then checks role collisions in
role order; for each parameter in list order, a role collision before a
duplicate; and, for each free predicate variable in normalized identifier
order, forbidden-role status before undeclared status. Only then does it expand
and resource-check the schema formula. Thus a valid schema paired with a
different declared statement returns `StatementMismatch` only after the schema
has checked. Every failure returns no `CompiledProof` and has no external side
effect.

Offsets and `SourceSpan` bounds are zero-based UTF-8 byte offsets into the exact
original source. A span is half-open: its start is inclusive and its end is
exclusive. An EOF failure has an empty span at `source.len()`. Positions are
one-based; LF, CRLF, and bare CR each form one line boundary, while columns
count Unicode scalar values rather than bytes, grapheme clusters, or display
cells. A tab therefore advances one column.

A source-derived name in a structured message is debug-escaped and bounded to
its first `64` Unicode scalar values. A longer name appends ASCII `...` inside
the existing quotes. This display bound never shortens the primary
`SourceSpan`, which continues to address the complete source token for machine
repair.

| Code | Variant | Primary diagnostic span |
| --- | --- | --- |
| `NAO0001` | `SourceTooLong { actual, maximum }` | None; the failure is global. |
| `NAO0002` | `Syntax { offset, expected }` | The token beginning at `offset`, or an empty EOF span. |
| `NAO0003` | `FoundationMismatch { offset }` | The complete quoted Foundation identifier. |
| `NAO0004` | `DuplicateStep { offset, name }` | The duplicate step name. |
| `NAO0005` | `UnknownStep { offset, name }` | The unknown or forward step name. |
| `NAO0006` | `ReturnNotFinal { offset }` | The step name following `return`. |
| `NAO0007` | `FormulaDepthLimitExceeded { offset, maximum }` | The formula operator at the failing depth. |
| `NAO0008` | `Statement { offset, source }` | The statement token that exceeds its formula budget. |
| `NAO0009` | `Certificate { offset, source }` | The offending proof token, or `proof` for a whole-certificate failure. |
| `NAO0010` | `Check { span, source }` | The complete originating source-step assignment after traced normalization. |
| `NAO0011` | `StatementMismatch { span }` | The complete declared statement formula. |
| `NAO0012` | `DuplicateFormulaBinding { offset, name }` | The complete duplicate binding name. |
| `NAO0013` | `UnknownFormulaBinding { offset, name }` | The complete absent, self, or forward binding name. |
| `NAO0014` | `FormulaBindingNodeLimitExceeded { offset, maximum }` | The RHS operator, primitive leaf, or alias token whose charge crosses the retention limit. |

The three binding messages are respectively `duplicate formula binding "…"`,
`unknown or forward formula binding "…"`, and
`formula bindings exceed the {maximum}-node retention limit`, where `maximum`
is `65_536`. Their source-derived names use the same bounded display rule above;
their primary spans remain complete.

`diagnostic_code` returns the code without needing the source, while
`diagnostic(&source)` returns its source-oriented message, optional primary
span, and optional start position. `SourceTooLong` intentionally has no span or
position. All other current variants are source-local when the exact failing
source is supplied. Checker messages name the originating source step, not its
temporary normalized numeric position. Diagnostics do not recover from an
error, collect multiple failures, persist a source map, or change which error
wins.

## Example

```nao
# Extensionality: sets with exactly the same members are equal.
foundation = "naome:zfc"

statement = forall(
    x,
    forall(
        y,
        implies(
            forall(z, iff(member(z, x), member(z, y))),
            equal(x, y),
        ),
    ),
)

proof:
    p0 = zfc_axiom("extensionality")
    return p0
```

The declared statement uses authoring-only `iff`; its recursive primitive
expansion exactly matches the fixed axiom selected by the proof. It is runnable
as `examples/extensionality.nao`. `examples/separation.nao` uses `exists`,
`iff`, and `and_` to state an intersection with one explicit parameter, while
`examples/replacement.nao` uses the same derived forms to state the identity
image instance with the mandatory empty parameter list. The implication,
quantifier, equality-substitution, and minimal self-equality examples remain
available separately. `examples/implication-identity.nao` uses two backward-only
formula bindings while retaining its exact prior canonical bytes and IDs.

A reference-aware protocol application can compile the following source only
after block application has committed the cited self-equality proof to its
selected-chain journal. It passes that journal to
`compile_against_selected_chain`:

```nao
# Extend one exact checked proof with a local inference.
foundation = "naome:zfc"

statement = forall(y, forall(x, equal(x, x)))

proof:
    p0 = cite("c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73")
    p1 = generalization(p0, y)
    return p1
```

The reference step reuses the selected checked conclusion `forall x, x = x`;
the local generalization derives `forall y, forall x, x = x`. The same source
fails through `naome proof`, with an empty selected journal, or while
the proof exists only in a candidate store or payload archive.

## Non-goals

This authoring contract defines no:

- additional primitive formulas, other connective aliases, implicit schema
  parameters, or alternate schema spellings;
- parameterized, recursive, forward, exported, or cross-file formula bindings;
  canonical formula tables or references; mathematical definitions, constants,
  functions, namespaces, modules, or macros;
- symbolic imports, semantic proof aliases, theorem-name or `StatementId`
  lookup, multiple statements, theorem libraries, a canonical-source or
  formatting command, or compatibility aliases;
- proof discovery, fetching, dependency acquisition, proof-state construction
  or serialization, opening or selecting a journal, CLI state selection, or
  implicit choice among proofs of one statement;
- ledger registration, block construction, chain or candidate-store mutation,
  payload archival, networking, or peer policy; or
- fork choice, consensus, finality, validator policy, fees, rewards, staking,
  slashing, token issuance, or other economic state.
