# NAOME Proof Certificate V0

## Status and scope

This document defines the canonical binary representation of finite,
assumption-free derivations relative to NAOME Foundation V0. It is a prerelease
protocol contract and may change before the first stable protocol release.

A structurally valid certificate is not necessarily a mathematically valid
proof. The later checker must reconstruct every step, enforce all axiom-schema
side conditions and inference rules, and require a closed final formula.

External proof references, definitions, hashes, statement identity, blocks,
chain state, rewards, and human-readable `.nao` syntax are outside V0.

## Integer encoding

Counts, lengths, variable identifiers, and step indices are unsigned `u32`
values in big-endian byte order. They have exactly one four-byte
representation. Versions and tags are single `u8` values. No variable-length
integers, strings, maps, floats, or implicit Rust enum layouts occur in
canonical bytes. All tag literals and byte dumps in this document are
hexadecimal.

## Canonical formulas

Formulas use prefix order. Formula tags are:

| Tag | Node | Payload |
| --- | --- | --- |
| `00` | equality | two variables |
| `01` | membership | two variables |
| `02` | negation | one formula |
| `03` | implication | antecedent, consequent |
| `04` | universal quantifier | one formula |

Variable tags are:

| Tag | Variable | Payload |
| --- | --- | --- |
| `00` | free | identifier as `u32` |
| `01` | bound | De Bruijn index as `u32` |

Binder names are absent. A bound index must be smaller than the number of
enclosing universal quantifiers. Derived connectives and existential
quantification are encoded only after expansion to Foundation V0 primitives.

The V0 codec admits at most 65,536 formula nodes, a nesting depth of 256, and
393,216 formula bytes. These deterministic processing limits do not restrict
the abstract Foundation V0 language.

## Certificate envelope

```text
version     u8 = 00
step_count  u32
steps       step_count consecutive steps
EOF         no trailing bytes
```

A certificate contains at least one step. Steps are zero-indexed and their
encoded order is part of the concrete certificate. The final step is the
claimed conclusion.

The V0 codec admits at most 4,194,304 certificate bytes and 65,536 steps. These
standalone processing limits bound expansion into the owned proof model before
a block format exists; they are not limits of Foundation V0 derivability.

Every formula-valued step field is encoded as:

```text
formula_length  u32
formula_bytes   formula_length canonical formula bytes
```

Every schema parameter list is encoded as a `u32` count followed by exactly
that many free-variable identifiers in their quantifier order.

## Step encoding

Each step starts with one explicit tag:

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

No result formula is stored beside a step. The checker reconstructs it from the
step tag, its payload, and earlier results. This prevents a certificate from
carrying separate claimed and derived versions of the same line.

Q2 does not encode the quantified variable. Every finite formula leaves a free
variable identifier available that does not occur in it, and every such choice
produces the same nameless vacuous binder. The checker therefore reconstructs
one canonical formula without admitting redundant certificate bytes.

## Structural decoding

The decoder accepts bytes exactly when:

- the version and every tag are known;
- all fixed-width values and formula payloads are complete;
- the certificate is non-empty;
- the certificate byte length and step count are within the V0 processing
  limits;
- every modus-ponens or generalization reference is strictly smaller than the
  index of the referencing step;
- every canonical formula is well formed and within the V0 processing limits;
- all counts fit `u32`; and
- no bytes remain after the declared steps.

These conditions make local references finite and acyclic. Duplicate or unused
steps remain permitted because they do not make an encoding ambiguous.

The decoder does not check logical-axiom side conditions, ZFC schema side
conditions, modus ponens, generalization, or closure of the conclusion. Those
are mathematical-checker responsibilities.

## Golden certificate

Equality reflexivity for free variable `0x01020304` is:

```text
00                    version 0
00 00 00 01           one step
06                    equality-reflexivity step
01 02 03 04           free-variable identifier
```

Canonical bytes:

```text
00 00 00 00 01 06 01 02 03 04
```
