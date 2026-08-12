# NAOME ZFC Foundation

## Identity

This document normatively defines the mathematical boundary identified as:

```text
naome:zfc:v0
```

A statement accepted under this identifier is derivable relative to Foundation. The identifier does not assert that ZFC is consistent or that every mathematical truth is decidable.

Foundation is immutable. Any change to primitive syntax, logical axioms, inference rules, set-theory axioms, or schema side conditions requires a new foundation identifier.

## Object language

The language has one sort, `Set`. Every object variable ranges over sets. There are no primitive constants or function symbols.

The primitive formula grammar is:

```text
Formula := Term = Term
         | Term ∈ Term
         | ¬ Formula
         | Formula → Formula
         | ∀ Formula

Term    := free-variable
         | bound-variable-index
```

The quantifier binds De Bruijn index zero in its body. Entering another quantifier increases the index needed to refer to an outer binder. A formula is well formed exactly when every bound-variable index is smaller than the number of enclosing quantifiers.

Free-variable identifiers and De Bruijn indices range over the natural numbers, including zero. The abstract language therefore has a countably infinite variable supply. Every individual formula is a finite tree and contains only finitely many identifiers and indices.

An implementation may impose finite representation and resource limits. If an identifier, index, binder depth, or formula size cannot be represented or processed, it must fail without admitting a formula. It must not truncate, wrap, saturate, alias, or otherwise map the input to a different abstract formula. Such a failure does not make the abstract formula invalid. Deterministic limits for encoded proof certificates belong to the proof-certificate protocol layer and do not change Foundation derivability.

The following are eliminable abbreviations, not primitive nodes:

```text
A ∧ B  := ¬(A → ¬B)
A ∨ B  := ¬A → B
A ↔ B  := (A → B) ∧ (B → A)
∃x A   := ¬∀x ¬A
x ≠ y  := ¬(x = y)
```

Human-readable binder names are presentation data and do not participate in structural formula identity.

## Semantics

A structure for the object language consists of a non-empty domain `D` and a binary relation `∈ᴹ ⊆ D × D`. The primitive equality symbol `=` is interpreted as identity on `D`, and the primitive membership symbol `∈` is interpreted as `∈ᴹ`.

A free-variable assignment `ρ` maps every free variable to an element of `D`. A De Bruijn environment `η` is a sequence of elements of `D` whose index zero denotes the innermost enclosing binder. Term interpretation is:

```text
⟦free-variable x⟧ρ,η = ρ(x)
⟦bound-variable-index i⟧ρ,η = η[i]
```

For a well-formed formula, satisfaction is defined recursively:

```text
M,ρ,η ⊨ s = t   iff ⟦s⟧ρ,η = ⟦t⟧ρ,η
M,ρ,η ⊨ s ∈ t   iff (⟦s⟧ρ,η, ⟦t⟧ρ,η) ∈ ∈ᴹ
M,ρ,η ⊨ ¬A      iff M,ρ,η ⊭ A
M,ρ,η ⊨ A → B   iff M,ρ,η ⊭ A or M,ρ,η ⊨ B
M,ρ,η ⊨ ∀A      iff for every d ∈ D, M,ρ,(d :: η) ⊨ A
```

Here `M = (D, ∈ᴹ)` and `d :: η` prepends `d` to the De Bruijn environment. Well-formedness guarantees that every bound-variable lookup is defined. A closed formula is true in `M` exactly when it is satisfied with the empty De Bruijn environment; its truth is independent of `ρ`.

A formula is logically valid when every structure satisfies it under every free-variable assignment. A structure is a model of Foundation when it satisfies every fixed ZFC axiom and every admissible instance of the Separation and Replacement schemas. A closed formula is a semantic consequence of Foundation when it is true in every such model.

## Substitution and binding

Binding a free variable replaces each of its free occurrences with the De Bruijn index of the new binder at that occurrence. Existing bound references retain their binder.

`A[x := y]` is the simultaneous replacement, throughout `A`, of every free occurrence of `x` with the free variable `y`. Occurrences of every other free variable and all bound-variable references remain unchanged. This is one structural substitution, not a sequence of replacements.

Foundation implementations must reject dangling bound indices before admitting a formula. Public formula construction must preserve well-formedness, and formula and schema construction must not capture a formerly free variable.

## Classical first-order logic with equality

Foundation uses the following logical axiom schemas. `A`, `B`, and `C` range over well-formed formulas.

```text
L1  A → (B → A)
L2  (A → (B → C)) → ((A → B) → (A → C))
L3  (¬B → ¬A) → (A → B)

Q1  ∀x(A → B) → (∀x A → ∀x B)
Q2  A → ∀x A                         when x is not free in A
Q3  ∀x A → A[x := y]

E1  x = x
E2  x = y → (A → A[x := y])
```

`Q3` and `E2` use capture-free substitution. The locally nameless representation makes bound and free variables disjoint. Values admitted as formulas are well formed by construction.

The primitive inference rules operate only on earlier lines of the same assumption-free derivation:

```text
Modus ponens:    from A and A → B, derive B
Generalization:  from A, derive ∀x A
```

Generalization binds the selected free variable `x` in `A`. It has no side condition because Foundation has no local assumptions, hypothesis contexts, or assumption-discharge rule.

A theorem conclusion must be well formed and closed. Intermediate formulas may contain free variables. Closure must be explicit in the derivation; implementations must not implicitly universally close a conclusion. Foundation does not permit an implementation to add hidden logical rules.

## Fixed ZFC axioms

The formulas below use the eliminable abbreviations above for readability. Every display abbreviation in this document is recursively expanded according to its definition here. That primitive expansion is normative; an implementation, including the Rust crate, must produce the same structure.

### Extensionality

```text
∀x∀y((∀z(z ∈ x ↔ z ∈ y)) → x = y)
```

### Pairing

```text
∀x∀y∃p∀z(z ∈ p ↔ (z = x ∨ z = y))
```

### Union

```text
∀x∃u∀z(z ∈ u ↔ ∃y(z ∈ y ∧ y ∈ x))
```

### Power Set

```text
∀x∃p∀z(z ∈ p ↔ ∀y(y ∈ z → y ∈ x))
```

### Infinity

`Empty(e)` and `Successor(x,s)` below are display abbreviations only:

```text
Empty(e)       := ∀z ¬(z ∈ e)
Successor(x,s) := ∀z(z ∈ s ↔ (z ∈ x ∨ z = x))

∃i(∃e(Empty(e) ∧ e ∈ i)
   ∧ ∀x(x ∈ i → ∃s(Successor(x,s) ∧ s ∈ i)))
```

The common ten-principle presentation of ZFC lists the Empty Set Axiom separately. Foundation does not include it as a primitive axiom because the formula above directly entails `∃e Empty(e)`; the Empty Set Axiom is therefore a theorem of Foundation.

### Foundation

```text
∀x((∃y y ∈ x) → ∃y(y ∈ x ∧ ∀z(z ∈ y → ¬(z ∈ x))))
```

### Choice

For every set `f` of pairwise-disjoint non-empty sets, there is a set `c` that meets each member of `f` in exactly one element:

```text
NonEmptyFamily(f) :=
  ∀a(a ∈ f → ∃x(x ∈ a))

PairwiseDisjoint(f) :=
  ∀a∀b(((a ∈ f ∧ b ∈ f) ∧ a ≠ b)
      → ¬∃x(x ∈ a ∧ x ∈ b))

ExistsExactlyOneIn(c,a) :=
  ∃x((x ∈ a ∧ x ∈ c)
      ∧ ∀y((y ∈ a ∧ y ∈ c) → y = x))

∀f(
  (NonEmptyFamily(f) ∧ PairwiseDisjoint(f))
  →
  ∃c∀a(a ∈ f → ExistsExactlyOneIn(c,a))
)
```

The three named predicates above are local display abbreviations, not Foundation symbols. Their recursive expansion according to the definitions above is the normative primitive Choice formula.

## ZFC axiom schemas

### Separation

For every well-formed predicate `P(x, a, parameters)`:

```text
∀parameters ∀a ∃b ∀x(x ∈ b ↔ (x ∈ a ∧ P(x,a,parameters)))
```

The element, source, result, and parameter variables must be pairwise distinct. Every free predicate variable must be the element, the source, or a declared parameter. The result variable must not occur free in the predicate.

### Replacement

For every well-formed predicate `P(x,y,a,parameters)`:

```text
∀parameters ∀a(
  (∀x(x ∈ a → ∃y(P(x,y,a,parameters)
      ∧ ∀y′(P(x,y′,a,parameters) → y′ = y))))
  →
  ∃b∀y(y ∈ b ↔ ∃x(x ∈ a ∧ P(x,y,a,parameters)))
)
```

The input, output, uniqueness witness, source, result, and parameter variables must be pairwise distinct. Every free predicate variable must be the input, output, source, or a declared parameter. Neither the result nor uniqueness-witness variable may occur free in the predicate.

## Definition boundary

Foundation contains no definition rule or defined mathematical symbol. Any
definition extension must be eliminable and conservative:

- relation definitions expand to existing formulas;
- constant definitions reference a proof of unique existence;
- function definitions reference a proof of total unique existence; and
- recursive definitions reference the required recursion theorem.

No defined symbol or definition construct is valid under `naome:zfc:v0`.

## Verification boundary

This specification is the sole normative definition of the abstract Foundation
boundary. The `naome-foundation` crate is its executable Rust reference. Neither
checks complete proofs. [Proof Protocol](proof-protocol.md) defines certificate
encoding and local references while preserving an empty hypothesis context,
only the rules above, and a closed final theorem. Checking is deterministic.

Canonical serialization, content hashing, proof certificates, definitions, parsers, theorem libraries, storage, networking, and economic consensus are outside Foundation.
