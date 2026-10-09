---
name: nao-authoring
description: Generate, review, and repair complete NAO mathematical proof, conservative definition, and closed question sources using the single headerless language. Self-contained instructions for agents without repository access.
---

# NAO authoring

You author `.nao` files for a deterministic classical first-order set-theory checker. Use this document as the complete language reference when no project files are available. Produce exact, complete sources for the requested theorem, definition, or question. Preserve the requested mathematical meaning; a shorter or easier theorem is not a solution to another target.

A `.nao` file contains one proof, one conservative definition, or one closed question. The mathematical universe is sets, with equality and membership. A source is a certificate, not a natural-language argument or tactic program. Syntactic plausibility does not establish mathematical validity. Report actual checker verification separately from a proposed source. Do not claim universal ability to prove arbitrary statements, completeness under finite resource limits, scientific novelty, or network admission.

## Authoring contract

Before constructing a proof, identify the exact closed target, its quantifier order, and any supplied checked dependencies. If a mathematical term is informal or ambiguous, make the intended formal meaning explicit. If no checked context is supplied, use only the primitive language and the rules below. Never invent a dependency ID, assume a theorem has already been registered, or treat a formula binding as an established theorem.

Work backwards from the exact goal and forwards through individually justified steps. Track each step's complete primitive conclusion, especially before `mp`, `inst`, `subst`, and `gen`. Write the final step last and return that step. For a complex construction, split the reasoning into independently checked closed helper proofs and conservative definitions when the host supports an explicit checked context. Dependencies are mathematical inputs; loading or authoring them does not authorize publication or unrelated actions.

When the user requests a file, output its complete source without Markdown fences inside the file. When explaining a proposal in chat, put the complete source in a fenced block and keep explanations outside it. Source comments use `#`. Do not include ellipses, placeholders, pseudocode, unsupported tactics, or unverified hashes in a claimed runnable source. When no compiler is available, label the output as unverified and provide the exact intended target and dependency requirements.

## Lexical rules and file shapes

There is one headerless language. Begin with the optional sections or the main declaration below. There is no source version, foundation declaration, opt-in flag, compatibility mode, or automatic migration. Built-ins have exactly the spellings shown in this document.

Names match `[A-Za-z_][A-Za-z0-9_]*` and are case-sensitive. Space, tab, LF, and CR separate tokens. Indentation has no grammar meaning. `#` starts a comment through the next LF or end of input; a bare CR does not terminate a comment. Unicode is allowed in comments, but not in identifiers. Calls and nonempty lists allow one trailing comma. A semicolon is not a terminator. Strings have no escape syntax and are used only where explicitly specified. Entire input must be consumed; do not concatenate multiple artifacts into one file.

Proof shape (the `?` and `+` below are grammar notation, not source text):

```ebnf
proof-file = defs-section? refs-section? let-section?
             "goal" "=" formula
             "proof" ":" (name "=" rule-call)+
             "return" name EOF ;
defs-section = "defs" ":" (name "=" quoted-definition-id)+ ;
refs-section = "refs" ":" (name "=" quoted-proof-id)+ ;
let-section = "let" ":" (name "=" formula)+ ;
```

Definition shape:

```ebnf
definition-file = defs-section? refs-section?
                  "def" name "=" ("relation" | "function")
                  "(" distinct-parameter-list ")" ":" formula EOF ;
```

For definitions, omit `refs`: it may be parsed as a source section but cannot supply the computed function obligation or be used by a definition body. `let` is not allowed before `def`. There is no `goal`, `proof`, or `return` in a definition file. No recursive or mutually recursive declarations exist.

Question shape:

```ebnf
question-file = let-section? "goal" "=" primitive-formula
                ("success" "=" '"resolve"')? EOF ;
```

Questions permit all ten built-in formula notations (`eq`, `mem`, `ne`, `not`, `imp`, `all`, `ex`, `and`, `or`, `iff`), including ordered binder lists, and local formula bindings. Here `primitive-formula` means a formula built exclusively from these built-ins and their primitive expansions; it does not exclude the derived notations. No `defs`, `refs`, function terms, definitions, proof steps, hypotheses, imports, or arbitrary success strings are accepted. The optional `success="resolve"` is the only success selector.

Sections occur at most once in the stated order. A present section must have at least one assignment. Formula bindings and selected definition/proof aliases must have distinct names within and across these three namespaces. Do not reuse them as variable or step names even where a separate parser namespace permits it.

The following names are reserved for these aliases and formula bindings:

```text
eq mem ne not imp all ex and or iff
 defs refs let goal def relation function proof return parameters success
 simp frege contra dist vacuous inst mp refl subst axiom sep replace cite gen
```

Use descriptive variable names, short step names, and useful formula bindings. Avoid shadowing and unused material. Names are presentation; exact expanded formulas and checked certificates determine mathematical identities.

## Terms, formulas, and binding

Every primitive term is a set variable. There are no numerals, literals denoting sets, built-in arithmetic, constants, tuples, comprehensions, lambda expressions, or operators such as `=`, `∈`, `->` in formula position. Represent additional mathematics with set-theoretic relations and checked conservative definitions.

| Formula | Meaning | Exact primitive expansion |
| --- | --- | --- |
| `eq(x,y)` | equality | primitive |
| `mem(x,s)` | membership | primitive |
| `not(A)` | negation | primitive |
| `imp(A,B)` | implication | primitive |
| `all(x,A)` | universal quantification | primitive |
| `ne(x,y)` | inequality | `not(eq(x,y))` |
| `and(A,B)` | conjunction | `not(imp(A,not(B)))` |
| `or(A,B)` | disjunction | `imp(not(A),B)` |
| `iff(A,B)` | biconditional | `and(imp(A,B),imp(B,A))` |
| `ex(x,A)` | existential quantification | `not(all(x,not(A)))` |
| `all([x,y,z],A)` | ordered universal binders | `all(x,all(y,all(z,A)))` |
| `ex([x,y,z],A)` | ordered existential binders | `ex(x,ex(y,ex(z,A)))` |

`A` and `B` in this reference denote formulas; in source, supply formulas or earlier `let` names. Binary constructors always take exactly two arguments. Binder lists are nonempty. Order is significant. Nest mixed quantifiers explicitly. Derived notation is structural expansion, not a new logical rule.

A `let` binding abbreviates a formula by value. It is backward-only, nonrecursive, and has no arguments. A bare name in formula position must be an earlier binding; `P(x)` is not a binding application. Aliases can contain free variables. Expansion uses the shared source variable namespace, so an enclosing quantifier captures matching free occurrences. For example, after `let: P=mem(x,s)`, `all(x,P)` means `all(x,mem(x,s))`. It is not an independent closed theorem. Bound occurrences inside a binding remain bound when that binding is reused.

Variable names denote shared free-variable identities before quantification. A quantifier binds free occurrences of its named variable in its body. Substitution affects free occurrences only and avoids capture of existing bound occurrences. Internally, bound variables are nameless; consistent renaming of a closed binder preserves the formula. Reusing a binder name can make the outer quantifier vacuous: `all([x,x],eq(x,x))` is an outer vacuous universal followed by the universal that binds the equality. Prefer fresh binder names to make the intended scope clear.

Proof intermediate formulas can be open. The checked final conclusion must be closed: every free variable must have been quantified. Questions must be closed too. A definition has only its declared formal arguments free; local bound variables may occur in its body. To derive `all([x,y],A)`, apply `gen` to `y` first, then `x`. The returned conclusion must equal the expanded `goal` structurally, up to bound-variable renaming. Logical equivalence, commutativity, reordered binders, and double-negation simplification are not automatic proof-target matching.

## Complete proof-rule reference

The first eleven calls below are axiom instances or primitive inferences. `p` and `q` are names of earlier proof steps; `A`, `B`, `C` are formulas; `x`, `y` are variables. A formula argument never means a proof step. There is no hypothesis, assumption block, natural-deduction discharge, rewrite tactic, theorem search, or general automation command.

| Call | Reconstructed conclusion or condition |
| --- | --- |
| `simp(A,B)` | `imp(A,imp(B,A))` |
| `frege(A,B,C)` | `imp(imp(A,imp(B,C)),imp(imp(A,B),imp(A,C)))` |
| `contra(A,B)` | `imp(imp(not(B),not(A)),imp(A,B))` |
| `dist(x,A,B)` | `imp(all(x,imp(A,B)),imp(all(x,A),all(x,B)))` |
| `vacuous(A)` | `imp(A,all(v,A))`, with a fresh **vacuous** binder: no free occurrence of `A` is bound |
| `inst(x,y,A)` | `imp(all(x,A),A[x:=y])`, capture-avoiding substitution of free `x` by variable `y` |
| `refl(x)` | `eq(x,x)` |
| `subst(x,y,A)` | `imp(eq(x,y),imp(A,A[x:=y]))` |
| `mp(p,q)` | If `p` concludes exactly `A` and `q` exactly `imp(A,B)`, conclude `B`; argument order is premise, implication |
| `gen(p,x)` | `all(x,A)` where `p` concludes `A`; closes all free occurrences of `x` in `A` |
| `axiom("selector")` | The exact closed fixed ZFC formula for one selector in the catalogue below |
| `sep(P,e,s,r,parameters=[a,...])` | The validated Separation schema instance described below |
| `replace(P,x,y,w,s,r,parameters=[a,...])` | The validated Replacement schema instance described below |
| `cite(H)` or `cite("proof-id")` | The exact closed conclusion of that checked proof in the supplied context |

`inst` accepts variables as its first two arguments; it does not accept a theorem step as its first argument or a function term as replacement. To instantiate an earlier universal theorem, first construct `inst(...)`, then apply `mp(theorem,instantiation-step)`.

`vacuous(A)` has one formula argument, no variable argument. To print its result as `all(z,A)`, choose `z` absent from the free variables of `A`. `gen(p,x)` may quantify a present free variable or add a vacuous binder. All proof steps must reference earlier steps. `return` must name the last declared step, which is the normalization root. Unreachable steps are pruned by certificate normalization; never rely on an unused citation or unused step being checked or becoming a dependency. Put required reasoning on the path to the returned result.

## Fixed ZFC axioms: exact goal forms

The only selectors are `"extensionality"`, `"pairing"`, `"union"`, `"power_set"`, `"infinity"`, `"foundation"`, and `"choice"`. Each has zero formula/variable arguments. The quoted `"foundation"` here names the axiom of regularity. Every formula below is the exact fixed axiom, using descriptive bound-variable names and the structural abbreviations above. To prove one directly, use this formula as `goal`, add `proof: p=axiom("selector")`, and `return p`. Maintain the stated operand and binder order.

Extensionality:

```text
all([x,y],imp(all(z,iff(mem(z,x),mem(z,y))),eq(x,y)))
```

Pairing:

```text
all([x,y],ex(pair,all(z,iff(mem(z,pair),or(eq(z,x),eq(z,y))))))
```

Union:

```text
all(s,ex(u,all(e,iff(mem(e,u),ex(t,and(mem(e,t),mem(t,s)))))))
```

Power set:

```text
all(s,ex(p,all(t,iff(mem(t,p),all(e,imp(mem(e,t),mem(e,s)))))))
```

Infinity:

```text
ex(i,and(
  ex(e,and(all(c,not(mem(c,e))),mem(e,i))),
  all(x,imp(mem(x,i),ex(s,and(
    all(c,iff(mem(c,s),or(mem(c,x),eq(c,x)))),
    mem(s,i)
  ))))
))
```

Foundation:

```text
all(s,imp(ex(e,mem(e,s)),ex(e,and(mem(e,s),all(n,imp(mem(n,e),not(mem(n,s))))))))
```

Choice (the checker uses the pairwise-disjoint-family formulation):

```text
all(f,imp(
  and(
    all(a,imp(mem(a,f),ex(e,mem(e,a)))),
    all([a,b],imp(
      and(and(mem(a,f),mem(b,f)),ne(a,b)),
      not(ex(e,and(mem(e,a),mem(e,b))))
    ))
  ),
  ex(c,all(a,imp(mem(a,f),ex(e,and(
    and(mem(e,a),mem(e,c)),
    all(o,imp(and(mem(o,a),mem(o,c)),eq(o,e)))
  )))))
))
```

There is no `axiom("empty_set")`, `axiom("separation")`, `axiom("replacement")`, or axiom selector for a user theorem. Empty-set existence, for example, requires a derivation from the available axioms/schemas.

## Separation and Replacement

For both schemas, the role variables must be pairwise distinct. Parameters must be distinct and disjoint from every role variable. Every free predicate variable must be an allowed role or an explicitly listed parameter. A declared parameter need not occur in the predicate. Parameters are universally quantified in listed order, outside the rest of the schema. Bound predicate variables are not free parameters. Freshness means absence **free** in the predicate; use fresh names anyway.

`sep(P,e,s,r,parameters=[a,b])` allows free predicate roles `e` and `s`; forbids free `r`. Its conclusion is exactly:

```text
all([a,b],all(s,ex(r,all(e,iff(mem(e,r),and(mem(e,s),P))))))
```

For an empty parameter list, omit the outer parameter binders. `parameters=[]` is still mandatory in the call. Separation produces the existence of a selected subset; it does not produce a concrete constant naming that subset.

`replace(P,x,y,w,s,r,parameters=[a,b])` allows free predicate roles `x`, `y`, `s`; forbids free `w` and `r`. Let `Pw` mean the capture-avoiding substitution `P[y:=w]` in this explanatory template. It is **not** a built-in source macro. The conclusion is exactly:

```text
all([a,b],all(s,imp(
  all(x,imp(mem(x,s),ex(y,and(P,all(w,imp(Pw,eq(w,y))))))),
  ex(r,all(y,iff(mem(y,r),ex(x,and(mem(x,s),P)))))
)))
```

In an actual goal, write `Pw` explicitly or bind its expanded formula with `let`. Replacement supplies a conditional theorem: its antecedent expresses total unique output on the source set. Calling `replace` does not prove that antecedent. To obtain the consequent, prove that exact antecedent and use `mp`. If the antecedent is still open in `s`, first instantiate the schema's outer universal with `inst`, then use `mp` for the conditional.

## Selected dependencies and conservative definitions

`defs` resolves **DefinitionId** values from the caller's checked artifact state. `refs` names **ProofId** values, and `cite` resolves a referenced proof from that state when it is reachable. Each ID is a double-quoted string of exactly 64 lowercase hexadecimal characters. A StatementId, DerivationId, ArtifactId, ResolutionId, source hash, uppercase string, or natural-language theorem name cannot replace the required type. Declaring an alias does not fetch, register, or authenticate an artifact. Always establish the exact checked context separately.

A relation definition `def R=relation(x,y):P` abbreviates an explicitly given graph formula. Arity is positive. Parameters are distinct and introduced in declaration order; all and only those formal parameters must occur free in the expanded body. Additional variables must be bound locally. A selected relation alias is called in formula position with its exact arity: `R(x,y)`. It is not a term, proof step, axiom, or quantified theorem by itself. Definitions are not recursive and do not add assumptions. The source name and aliases do not become mathematical identities.

A function definition `def f=function(x1,...,xn,y):P` uses the first `n` parameters as inputs and the last as output, with `n>=1`. Every formal must occur free in the expanded graph. Before it can be checked, the context must already contain a checked proof of the computed obligation:

```text
all([x1,...,xn],ex(y,and(P,all(w,imp(P[y:=w],eq(w,y))))))
```

Here `w` is fresh and substitution in the template affects only free `y`. Expand this exact formula to create the obligation proof. The source cannot provide an `obligation=` hash or bypass the requirement with `refs`; the checker computes and resolves its StatementId. A graph that looks total or a correct-looking function declaration is insufficient.

A selected function alias is used only as a term with exactly `n` inputs: `f(x)` or nested terms such as `f(f(x))`. Each call introduces a fresh witness, its checked graph constraint, and existential binding **inside the surrounding atomic formula**, in deterministic argument order. Therefore `eq(f(x),x)` is a relationalized formula; its primitive shape is not just a textual substitution or simplification to `eq(x,x)`, even for an identity function. Function definitions are eliminated when checking; derive the exact expanded target. For difficult proofs, explicitly reason with graph relations and witnesses rather than treating function terms as an automatic rewrite system. Questions do not accept function terms or selected relation aliases; express their targets in primitive notation.

Function-term lowering has an exact order and grouping. Visit atomic arguments from left to right, and visit nested call arguments before their enclosing call. For fresh witnesses `w1,...,wn` and expanded graph-body constraints `G1,...,Gn` in that order, lower the atom to:

```text
ex(w1,ex(w2,...ex(wn,and(G1,and(G2,...and(Gn,Atom)...)))...))
```

For example, `eq(f(x),g(y))` lowers to `ex(u,ex(v,and(G_f(x,u),and(G_g(y,v),eq(u,v)))))`. For `eq(f(f(x)),x)`, the inner call comes first: `ex(u,ex(v,and(G_f(x,u),and(G_f(u,v),eq(v,x)))))`. `G_f` and `G_g` in these explanatory templates mean the **fully expanded graph bodies with inputs/output substituted**, not callable source aliases or new operators. To write a primitive question target, insert the actual checked graph formulas. If both graphs are the identity relation with body `eq(output,input)`, the first example's primitive target is `ex(u,ex(v,and(eq(u,x),and(eq(v,y),eq(u,v)))))`. All witnesses are fresh; keep this order and right-nested conjunction shape.

A negated equality atom also matters: `ne(f(x),x)` places `not(eq(u,x))` inside its graph-witness conjunction, whereas `not(eq(f(x),x))` negates the entire relationalized existential. Those targets can be logically equivalent for a checked total function but are structurally different. Preserve the exact form intended by the goal; do not substitute one spelling for the other without a derivation.

## Question orientation and identity

A question proposes a closed formula; it is not evidence for that formula. Only leading `not` operators are stripped to select a shared resolution core. Their parity determines the proved and refuted targets. If `C` is the core, an even parity question is proved by a checked proof of exactly `C` and refuted by a proof of exactly `not(C)`. An odd parity question reverses those outcomes. Internal negations and logical structure are preserved. Double negation does not give an automatic inference rule for ordinary proof goals.

Question targets include both `C` and `not(C)`, so both must fit question bounds. Renaming bound variables preserves the mathematical core. Changing whitespace, comments, bindings, or source spellings changes the exact-source hash and encoded question source; it need not change the resolution identity. Do not hand-edit canonical bytes or manufacture IDs. An encoded question retains its original source and recompiles that source using this language. Unsupported source is rejected; no legacy source decoder or migration is provided.

## Worked sources

Each fenced `nao` block below is a complete file. Examples are checked in document order: earlier proof/definition artifacts are explicitly registered in a fresh offline checked context for later context-dependent examples. A host must reproduce the stated context. Dependency-free proof and relation examples also work with an empty context. Question examples use the question compiler and do not inherit definition aliases. This sequence is an authoring demonstration, not a network publish script.

### 1. Closed self-equality and the meaning of generalization

The returned artifact's ProofId is `c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73`. That literal is specific to this exact checked certificate; do not derive or reuse other hashes by analogy. Later citation examples require this checked proof registered in the context.

<!-- nao-example: proof -->
```nao
goal=all(x,eq(x,x))
proof:
  p0=refl(x)
  p1=gen(p0,x)
  return p1
```

### 2. Hilbert identity for a compound quantified predicate

`P` is an abbreviation, not a hypothesis. The five implication steps derive `P -> P` without assumptions. `dist` then transfers the universal theorem to the implication between universally quantified predicates. The output is closed even though `P` initially has free `x`.

<!-- nao-example: proof -->
```nao
let:
  P=all(y,imp(mem(x,y),ex(z,and(mem(z,y),eq(x,z)))))
  I=imp(P,P)
  U=all(x,P)
goal=imp(U,U)
proof:
  p0=simp(P,P)
  p1=simp(P,I)
  p2=frege(P,I,P)
  p3=mp(p1,p2)
  p4=mp(p0,p3)
  p5=gen(p4,x)
  p6=dist(x,P,P)
  p7=mp(p5,p6)
  return p7
```

### 3. Equality transport through an existential and compound formula

`subst` replaces only free `x`; the existential `z` stays bound. Reverse generalization order constructs the declared ordered binders.

<!-- nao-example: proof -->
```nao
let:
  A=imp(mem(x,s),ex(z,and(mem(z,t),eq(x,z))))
  B=imp(mem(y,s),ex(z,and(mem(z,t),eq(y,z))))
goal=all([x,y,s,t],imp(eq(x,y),imp(A,B)))
proof:
  p0=subst(x,y,A)
  p1=gen(p0,t)
  p2=gen(p1,s)
  p3=gen(p2,y)
  p4=gen(p3,x)
  return p4
```

### 4. Instantiating a theorem, then closing a new variable

<!-- nao-example: proof -->
```nao
goal=all(y,eq(y,y))
proof:
  p0=refl(x)
  p1=gen(p0,x)
  p2=inst(x,y,eq(x,x))
  p3=mp(p1,p2)
  p4=gen(p3,y)
  return p4
```

### 5. Parameterized Separation with a compound predicate

The schema roles `e,s,r` are distinct. The free predicate variables besides `e` are declared as parameters. This proof concludes the exact schema, rather than naming a set constant.

<!-- nao-example: proof -->
```nao
let:
  P=and(mem(e,a),imp(mem(e,b),not(mem(e,c))))
goal=all([a,b,c],all(s,ex(r,all(e,iff(mem(e,r),and(mem(e,s),P))))))
proof:
  p0=sep(P,e,s,r,parameters=[a,b,c])
  return p0
```

### 6. Replacement with two parameters and an explicit uniqueness formula

This certifies the complete conditional Replacement instance. It does not prove the conditional's antecedent. `Pw` is written explicitly, matching free-output substitution in `P`.

<!-- nao-example: proof -->
```nao
let:
  P=and(eq(x,y),imp(mem(x,a),mem(y,b)))
  Pw=and(eq(x,w),imp(mem(x,a),mem(w,b)))
goal=all([a,b],all(s,imp(
  all(x,imp(mem(x,s),ex(y,and(P,all(w,imp(Pw,eq(w,y))))))),
  ex(r,all(y,iff(mem(y,r),ex(x,and(mem(x,s),P)))))
)))
proof:
  p0=replace(P,x,y,w,s,r,parameters=[a,b])
  return p0
```

### 7. A fixed ZFC axiom

<!-- nao-example: proof -->
```nao
goal=all([x,y],imp(all(z,iff(mem(z,x),mem(z,y))),eq(x,y)))
proof:
  p0=axiom("extensionality")
  return p0
```

### 8. A complete relation definition

This definition's DefinitionId is `4165ac271695531751ada582517549ab2e53d286a820b03de7ac3a0ddc372d19`. Register the checked definition before examples 9 and 10. The ID is not the source name `holds` or an artifact ID.

<!-- nao-example: definition -->
```nao
def holds=relation(element,set):mem(element,set)
```

### 9. A definition composed from a selected definition

The selected `holds` definition is required in the context. Only `left` and `right` occur free; `element` is locally bound. Register this resulting definition if you want to select it in later work.

<!-- nao-example: definition -->
```nao
defs:
  H="4165ac271695531751ada582517549ab2e53d286a820b03de7ac3a0ddc372d19"
def same_members=relation(left,right):all(element,iff(H(element,left),H(element,right)))
```

### 10. All three optional sections, typed citation, and relation expansion

The context must contain both example 1 and example 8. This illustrates the required section order and places the citation on the returned proof's dependency path. The theorem says that the selected relation holds from `a` to `s` implies itself, under two universal binders.

<!-- nao-example: proof -->
```nao
defs:
  H="4165ac271695531751ada582517549ab2e53d286a820b03de7ac3a0ddc372d19"
refs:
  R="c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73"
let:
  P=H(a,s)
  I=imp(P,P)
  T=all(x,eq(x,x))
goal=all([a,s],I)
proof:
  p0=cite(R)
  p1=simp(P,P)
  p2=simp(P,I)
  p3=frege(P,I,P)
  p4=mp(p2,p3)
  p5=mp(p1,p4)
  p6=simp(I,T)
  p7=mp(p5,p6)
  p8=mp(p0,p7)
  p9=gen(p8,s)
  p10=gen(p9,a)
  return p10
```

### 11. A closed question with negative orientation

This asks whether the negated universal identity can be resolved. A proof of the positive core refutes this question. Its bindings are primitive and do not import earlier proof artifacts.

<!-- nao-example: question -->
```nao
let:
  A=eq(x,x)
  I=imp(A,A)
goal=not(all(x,I))
success="resolve"
```

## Finite limits and complexity discipline

These are executable bounds, not promises that an arbitrary source at every independent maximum will pass. Expanded formulas, selected definitions, function witnesses, reconstructed rule conclusions, aggregate retained bindings, certificate size, and cumulative checker work all count. A compact spelling can still expand exponentially; repeatedly defining `B=iff(A,A)` multiplies retained structure.

| Resource | Bound |
| --- | --- |
| Complete proof/definition source | 4,194,304 UTF-8 bytes |
| Primitive formula nesting, counting root | 256 nodes in depth |
| Primitive nodes per canonical formula | 65,536 |
| Canonical primitive formula bytes | 393,216 |
| Aggregate retained `let` formula nodes for proof source | 65,536 |
| Formula-node accounting across source certificate arguments | 65,536 |
| Source proof steps / canonical certificate steps | 65,536 |
| Canonical proof certificate bytes | 4,194,304 |
| Cumulative deterministic checker formula work bytes | 4,194,304 |
| Definition graph arguments | 256 total; function inputs at most 255 |
| Complete question source | 16,384 UTF-8 bytes |
| Aggregate retained question-binding primitive nodes | 1,024 |
| Each expanded question target | 1,024 primitive nodes and depth 32 |

Question core `C` must leave room for `not(C)` in both target bounds. Intermediate question parsing also has bounded expansion and recursion; removing leading negations later does not exempt their input from parsing limits. Formula-bindings save source repetition; they do not share canonical formula nodes. A function graph introduces witness/constraint overhead, and a function's total-unique obligation duplicates its body. Stay comfortably inside the bounds and use checked helpers for large work. Never bypass a limit by changing a target, omitting necessary reasoning, or treating a rejected proof as accepted.

## Verification, repair, and delivery

If the installed authoring CLI is available, dependency-free proofs and relation definitions use `naome-author proof file.nao` or `naome-author proof --json file.nao`; questions use `naome-author question file.nao` or `naome-author question --json file.nao`. The `proof` command also accepts definition artifacts. Successful compilation returns canonical artifacts and their identities. A source error exits nonzero and yields no partial successful artifact output. JSON diagnostics report a stable code, message, original-source UTF-8 byte span, and one-based position when available.

The standalone CLI uses an empty checked context: it cannot validate examples 9 or 10 or authorize a function obligation. A context-aware host must compile and check dependencies first, register their exact verified artifacts in order, and then invoke context-aware compilation. If that facility is unavailable, explain the missing context; do not replace typed IDs with names or claim the dependent source passed the standalone CLI.

The stable source codes are listed here for diagnostic-driven repair. Numeric gaps are intentional; do not infer a source mode from them.

| Code | Failure class | Code | Failure class |
| --- | --- | --- | --- |
| `NAO0001` | source byte limit | `NAO0016` | duplicate definition alias |
| `NAO0002` | syntax | `NAO0017` | unknown definition alias |
| `NAO0004` | duplicate step | `NAO0018` | definition absent from checked context |
| `NAO0005` | unknown/forward step | `NAO0019` | definition arity mismatch |
| `NAO0006` | return is not final step | `NAO0020` | invalid definition structure |
| `NAO0007` | formula depth limit | `NAO0021` | definition checking failure |
| `NAO0008` | invalid statement formula | `NAO0022` | invalid definition-aware formula |
| `NAO0009` | invalid certificate structure | `NAO0023` | definition expansion failure |
| `NAO0010` | mathematical checker failure | `NAO0025` | duplicate proof-reference alias |
| `NAO0011` | goal/conclusion mismatch | `NAO0026` | unknown proof-reference alias |
| `NAO0012` | duplicate formula binding | `NAO0030` | question syntax |
| `NAO0013` | unknown formula binding | `NAO0031` | question expansion/target limit |
| `NAO0014` | retained binding-node limit | `NAO0032` | open question formula |
| `NAO0015` | definition supplied to proof-only API | `NAO0033` | invalid question formula |

Check the precise reported source span before changing a file. Common failures and their repairs:

| Failure | Correct repair |
| --- | --- |
| Unknown or forward step | Define it before use; references must point backwards |
| `mp` mismatch | Reconstruct both conclusions; pass the premise first and its exact implication second |
| Goal mismatch | Compare expanded primitive structure, quantifier order, and orientation; fix the derivation without weakening the goal |
| Open final conclusion/question | Quantify the intended free variables, in the correct order; do not quantify a variable that should remain a definition parameter |
| Unknown binding | Define it earlier with `let`; do not call it as a function |
| Wrong dependency type or missing context | Supply the exact checked ProofId or DefinitionId and its artifact; revalidate the context |
| Definition body omits or adds free formals | Make its declared interface match the actual graph; bind local variables |
| Function obligation missing | Prove and register the exact computed total-unique theorem first |
| Schema role/freshness error | Use distinct roles, disjoint unique parameters, and eliminate forbidden free variables |
| Expanded resource limit | Reduce unnecessary expansion or factor into genuine checked helper artifacts; preserve the target |
| Source syntax error | Use this grammar exactly, including section order, delimiters, built-in arities, and complete input |

For difficult proofs, validate the smallest useful helper first and pin its checked conclusion and ID before constructing the parent. After a repair, rerun the checker on the complete file and its exact dependency context. Successful parsing, a previous artifact, a similar proof, or an LLM's confidence is insufficient. A bounded failed attempt should produce the precise unresolved obligation and actual error, not a fabricated success.

Deliver the complete source, the exact target, the required context, and an accurate verification result. When only source is requested, return the source and state any verification limitation outside the file. Keep mathematical validity, identity preservation, context admission, runtime behavior, and scientific value as separate claims.
