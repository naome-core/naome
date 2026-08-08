# NAOME Proof Certificate V0

## Status and scope

This document defines the canonical binary representation of finite,
assumption-free derivations relative to NAOME Foundation V0. It is a prerelease
protocol contract and may change before the first stable protocol release.

A structurally valid certificate is not necessarily a mathematically valid
proof. The checker reconstructs every step, enforces all axiom-schema
side conditions and inference rules, and requires a closed final formula.

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

Q2 does not encode a quantified-variable identifier. In the locally nameless
Formula V0 representation, the checker constructs the nameless vacuous binder
directly. This satisfies the abstract fresh-variable side condition without
admitting redundant certificate bytes.

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

## Mathematical checking

Checker V0 accepts a structurally valid certificate exactly when deterministic
execution of every step succeeds and the final result is closed. It processes
all steps in encoded order, including duplicate or unused steps. The first
failure in that order rejects the certificate and identifies the zero-based
step index.

Each step is reconstructed only through the corresponding Foundation V0
operation:

- L1 through L3, Q1, Q3, E1, and E2 instantiate their logical axioms;
- Q2 constructs nameless vacuous universal quantification directly; no variable
  identifier is selected or encoded;
- fixed ZFC steps expand their selected axiom;
- Separation and Replacement validate their schema side conditions before
  expansion;
- modus ponens consumes its referenced premise and implication; and
- generalization universally quantifies its referenced premise.

Every reconstructed result must satisfy the Formula V0 depth, node, and byte
limits before it can be referenced. A Separation or Replacement step with at
least 256 declared parameters is rejected with the Formula V0 depth-limit error
before schema expansion because those parameter binders alone cannot fit the
formula depth limit.

Checker V0 admits at most 4,194,304 bytes of cumulative canonical formula work.
The checker charges:

- the canonical lengths of both referenced operands before modus ponens;
- the canonical length of the referenced premise before generalization;
- the canonical length of every reconstructed result; and
- the conclusion length once more before checking closure.

An operation is rejected before execution when its operand charge would exceed
the remaining budget. Derived-formula codec errors take precedence over the
result charge. The final closure traversal is budgeted before the conclusion is
classified as open or closed.

The last reconstructed formula is returned only when it contains no free
variables. Checker V0 never inserts implicit universal quantifiers.

## Canonical proof normal form

One structurally valid certificate has exactly one V0 proof normal form. The
normal form is a deterministic projection for future content identity; it is
not an additional proof rule and does not establish mathematical validity.

Normalization proceeds from the certificate's final step as the root:

1. Traverse only root-reachable steps with an explicit stack. Modus-ponens
   dependencies are visited as premise then implication; generalization visits
   its premise. No dependency role is sorted.
2. Emit each step after its dependencies. This dependency-first postorder makes
   every remapped local reference point to an earlier output step.
3. During emission, map each previously unseen free-variable identifier to the
   smallest unused `u32`, starting at zero. Step fields use their wire order and
   formulas use canonical prefix order. Bound variables remain De Bruijn
   indices and are not mapped.
4. Replace local references with their emitted output indices.
5. Merge a step only when its normalized step tag, complete payload, and
   ordered local references have exactly the same canonical bytes as an
   already-emitted step.

The resulting steps use the existing Certificate V0 envelope and step codec.
Normalization is idempotent and cannot increase the encoded step count or byte
length. It is invariant under the original topological order, systematic free
variable renaming, unreachable steps, and exact duplicate proof nodes.

The normal form does not merge steps merely because the checker derives equal
formulas from them. Alternative rules, dependency structures, or ordered rule
roles remain distinct. It performs no theorem rewriting, commutative or
associative sorting, proof minimization, or other mathematical-equivalence
search.

Because ordinary Certificate V0 permits and checks unused steps, accepting an
arbitrary certificate requires this order:

```text
check the complete input certificate
derive its proof normal form
check the normal-form certificate
require both checked conclusions to be equal
```

The first check prevents an invalid or over-budget unused step from being
hidden by reachability pruning. The checker exposes this complete sequence as
one check-and-normalize operation. The proof crate's unchecked structural
transformation remains available for a future canonical-only admission boundary:
that boundary may first require submitted certificate bytes to equal their
normal-form bytes and then mathematically check only the unchanged normal-form
certificate. Once the complete input check has succeeded, any normal-form check
failure or conclusion mismatch is reported as a normalization-invariant
violation rather than as an input-proof failure.

### Normal-form golden vector

The following two structurally valid certificates differ in encoded order,
free-variable identifiers, and their unused fixed-ZFC step. Each also contains
duplicate equality-reflexivity and generalization nodes.

Input A:

```text
00 00000006
10 01
06 00000007
06 00000007
21 00000001 00000007
21 00000002 00000007
20 00000003 00000004
```

Input B:

```text
00 00000006
06 0000002a
10 06
21 00000000 0000002a
06 0000002a
21 00000003 0000002a
20 00000002 00000004
```

Both normalize to these exact bytes:

```text
00 00000003
06 00000000
21 00000000 00000000
20 00000001 00000001
```

The unused ZFC step is removed, the duplicate nodes share one output index,
free variable `7` or `42` becomes `0`, and both modus-ponens references become
`1`. The final modus-ponens step is intentionally not mathematically valid;
this vector isolates the structural normal form and must not be admitted as a
checked proof.

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
