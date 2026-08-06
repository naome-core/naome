# NAOME ZFC Foundation V0

## Status and identity

This document normatively defines the mathematical boundary identified as:

```text
naome:zfc:v0
```

A statement accepted under this identifier is derivable relative to Foundation V0. The identifier does not assert that ZFC is consistent or that every mathematical truth is decidable.

Foundation V0 is immutable. Any change to primitive syntax, logical axioms, inference rules, set-theory axioms, or schema side conditions requires a new foundation identifier.

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

The following are eliminable abbreviations, not primitive nodes:

```text
A ∧ B  := ¬(A → ¬B)
A ∨ B  := ¬A → B
A ↔ B  := (A → B) ∧ (B → A)
∃x A   := ¬∀x ¬A
x ≠ y  := ¬(x = y)
```

Human-readable binder names are presentation data and do not participate in structural formula identity.

## Substitution and binding

Binding a free variable replaces each of its free occurrences with the De Bruijn index of the new binder at that occurrence. Existing bound references retain their binder. Substitution of one free variable for another never modifies bound references.

Foundation implementations must reject dangling bound indices. Formula and schema construction must not capture a formerly free variable.

## Classical first-order logic with equality

Foundation V0 uses the following logical axiom schemas. `A`, `B`, and `C` range over well-formed formulas.

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

`Q3` and `E2` use capture-free substitution. The locally nameless representation makes bound and free variables disjoint, but implementations must still validate the supplied formulas.

The primitive inference rules are:

```text
Modus ponens:    A, A → B  ⊢  B
Generalization:  A         ⊢  ∀x A
```

The future proof-block contract must define assumptions and theorem closure explicitly. Foundation V0 does not permit an implementation to add hidden logical rules.

## Fixed ZFC axioms

The formulas below use the eliminable abbreviations above for readability. The Rust representation expands them into primitive nodes.

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
  ∀a∀b((a ∈ f ∧ b ∈ f ∧ a ≠ b)
      → ¬∃x(x ∈ a ∧ x ∈ b))

ExistsExactlyOneIn(c,a) :=
  ∃x(x ∈ a ∧ x ∈ c
      ∧ ∀y((y ∈ a ∧ y ∈ c) → y = x))

∀f(
  (NonEmptyFamily(f) ∧ PairwiseDisjoint(f))
  →
  ∃c∀a(a ∈ f → ExistsExactlyOneIn(c,a))
)
```

The three named predicates above are local display abbreviations, not Foundation symbols. Their expansion is the primitive formula returned by `ZfcAxiom::Choice::formula`.

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

Foundation V0 contains no definition rule and no defined mathematical symbol. A later definition contract must ensure that definitions are eliminable and conservative:

- relation definitions expand to existing formulas;
- constant definitions reference a proof of unique existence;
- function definitions reference a proof of total unique existence; and
- recursive definitions reference the required recursion theorem.

Until that contract exists, no definition block is valid under Foundation V0.

## Verification boundary

This specification and the `naome-foundation` crate define the data and axiom boundary. They do not verify complete proofs. A later checker must consume only these declared axioms and inference rules and must return deterministic results.

Canonical serialization, content hashing, proof blocks, definitions, parsers, theorem libraries, storage, networking, and economic consensus are outside Foundation V0.
