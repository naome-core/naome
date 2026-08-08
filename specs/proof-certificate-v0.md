# NAOME Proof Certificate V0

## Status and scope

This document defines the canonical binary representation of finite,
assumption-free derivations relative to NAOME Foundation V0. It is a prerelease
protocol contract and may change before the first stable protocol release.

A structurally valid certificate is not necessarily a mathematically valid
proof. The direct checker reconstructs every supplied step, enforces all
axiom-schema side conditions and inference rules, and requires a closed final
formula. Proof admission first derives the root-proof normal form and checks
that normal form exactly once.

Definitions, blocks, persistent chain state, rewards, networking, and
human-readable `.nao` syntax are outside V0. Proof references resolve only
through the checked in-memory state defined below.

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
| `30` | proof reference | one 32-byte `ProofId` |

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

The decoder does not check proof-reference existence, logical-axiom side
conditions, ZFC schema side conditions, modus ponens, generalization, or
closure of the conclusion. Those are mathematical-checker responsibilities.

## Direct mathematical checking

The direct Checker V0 operation accepts a structurally valid certificate
exactly when deterministic execution of every supplied step succeeds and the
final result is closed. It processes steps in encoded order, including
duplicate or unused steps. The first failure in that order rejects the
certificate and identifies the zero-based step index. Proof admission applies
this operation to a normal-form certificate, not to presentation-only input
steps that normalization removes.

The dependency-free `check` entry point supplies an empty proof state and
therefore rejects every `ProofReference` as unknown. Reference-aware proof
admission executes the same checker operation with an explicit immutable
`ProofStateV0`.

Each step is reconstructed only through the corresponding Foundation V0
operation:

- L1 through L3, Q1, Q3, E1, and E2 instantiate their logical axioms;
- Q2 constructs nameless vacuous universal quantification directly; no variable
  identifier is selected or encoded;
- fixed ZFC steps expand their selected axiom;
- Separation and Replacement validate their schema side conditions before
  expansion;
- proof references reuse the closed conclusion registered for the exact
  selected `ProofId`;
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
- the canonical length of every reconstructed result, with a resolved
  proof-reference result charged before it is cloned; and
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

A proof reference is a leaf in this graph. Its `ProofId` introduces neither a
local step dependency nor a free-variable identifier. Exact duplicate
reference leaves merge through the same byte-exact interning rule as other
steps. Different `ProofId` values never merge, even when they resolve to the
same statement.

Proof admission uses this order:

```text
structurally decode the complete input certificate
derive its proof normal form
mathematically check every normal-form step exactly once, resolving each ProofId at its step
require a closed conclusion
```

Structural decoding still validates the complete input framing, size limits,
formula encoding, and backward-reference discipline before anything can be
pruned. Mathematical validity belongs only to the root-reachable normal form:
an unreachable invalid schema or inference step has no effect on admission,
while every reachable invalid step remains and is rejected. Mathematical
errors identify normal-form step indices and normalized free-variable IDs.

A later admission layer can require canonical submissions by comparing the
submitted bytes with the derived normal-form bytes before checking that normal
form once. That admission policy is outside this V0 certificate contract;
canonical equality never replaces mathematical checking.

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

## External proof references

A `ProofReference` contains exactly the raw 32 bytes of one concrete
`ProofId`. It does not repeat the referenced `StatementId`, conclusion, proof
bytes, or Foundation identifier. Structural decoding accepts any 32-byte value
and does not claim that the selected proof exists.

Mathematical checking resolves each reachable reference from an immutable
`ProofStateV0`. That state can only be populated from `CheckedProofV0` values,
so callers cannot attach an arbitrary formula to an identity. The state maps
each `ProofId` through its `DerivationId` to its `StatementId` and stores the
closed canonical conclusion only once per `StatementId`. Genuinely different
derivations of one statement therefore remain separately citable without
duplicating their conclusion in memory.

Resolution is local and deterministic:

- the exact `ProofId` must already exist in the supplied state;
- an absent reference rejects the normalized step before any inference that
  consumes it;
- the referenced conclusion is charged against Checker V0's formula-work
  budget before it is cloned;
- the previously checked proof certificate is not executed again; and
- unreachable references disappear during normalization and are not resolved
  during proof admission.

A reference may itself be the checked root: this is valid proof by citation.
Its `DerivationId` is exactly the referenced derivation identity. Registration
is stricter than mathematical checking: `ProofStateV0` rejects an already
registered `ProofId`, an already registered `DerivationId`, or a missing cited
dependency. Detectable identity conflicts fail closed rather than replacing
existing state.

The chosen citation remains part of the referencing proof's canonical bytes.
Changing only the boundary between inlined steps and references therefore
changes `ProofId` but not `DerivationId`. Citing genuinely different
derivations of the same statement changes both the dependent derivation and
its concrete proof artifact.

For the checked proof in the content-identity golden vector below, the exact
reference-only certificate is:

```text
00 00000001
30 5a90444e9a1f0e0138eb5bbca12d322ff705e55d155a9273474714dc698ae1bf
```

Its conclusion retains the golden `StatementId`, while the citation proof has:

```text
DerivationId = d19ab345081f610cd2ab47d68cc7fe8616818768227074fad2c2d83cacf5a449
ProofId      = c1d38d88a33f3015d797eccf9f391540ffdedafeedcc553e07ed328b5a88fa71
```

The derivation identity equals that of the cited proof, so registering this
alias after the cited proof fails as a duplicate derivation.

This in-memory state is the resolver contract, not a persistent blockchain
database. A later block layer can hold an immutable parent-state borrow while
checking a whole block and register new checked proofs only after the block is
accepted. Block storage, atomic apply/undo, reorgs, pruning, and network
synchronization remain outside this V0 contract.

## Content identity

Successful proof admission produces three distinct 32-byte content identities:

- `StatementId` identifies the checked closed conclusion independently of its
  derivation; and
- `DerivationId` identifies the checked inference DAG independently of which
  subgraphs were packaged inline or cited; and
- `ProofId` identifies the concrete checked proof normal form, including its
  chosen citation boundaries and cited `ProofId` values.

All three identities use SHA-256 as specified by FIPS 180-4. They are bound to
the exact UTF-8 bytes of the immutable Foundation V0 identifier
`naome:zfc:v0`. This is a protocol-namespace binding, not a hash of Foundation
source or documentation; Foundation V0 has no canonical content serialization.

The exact domain byte strings include their final `00` byte:

```text
statement_domain = 6e616f6d653a73746174656d656e743a763000
proof_domain     = 6e616f6d653a70726f6f663a763000
derivation_node_domain = 6e616f6d653a64657269766174696f6e2d6e6f64653a763000
foundation       = 6e616f6d653a7a66633a7630
```

Variable fields are framed by their four-byte big-endian length. The raw
32-byte `StatementId` has a fixed width and therefore no length prefix:

```text
StatementId = SHA256(
    statement_domain
    || u32be(length(foundation))
    || foundation
    || u32be(length(statement_bytes))
    || statement_bytes
)

ProofId = SHA256(
    proof_domain
    || u32be(length(foundation))
    || foundation
    || StatementId
    || u32be(length(normal_proof_bytes))
    || normal_proof_bytes
)
```

`DerivationId` is computed compositionally while Checker V0 reconstructs the
normal proof. For every local, non-reference step, let `result_bytes` be its
reconstructed Formula V0 bytes after renumbering that result's free variables
to `0, 1, ...` by first occurrence in canonical prefix order. Bound De Bruijn
indices remain unchanged. This per-node normalization makes the reconstructed
formula the node's canonical variable interface and prevents identifiers that
are local to one proof fragment from leaking across an inline/reference
boundary.

The node derivation identity is:

```text
node_derivation = SHA256(
    derivation_node_domain
    || u32be(length(foundation))
    || foundation
    || rule_tag
    || u32be(length(result_bytes))
    || result_bytes
    || ordered_parent_derivation_ids
)
```

`rule_tag` is the one-byte certificate step tag. Primitive axiom and schema
steps have no parents. Modus ponens appends exactly two raw 32-byte parent
identities in premise-then-implication order; generalization appends exactly
one premise identity. The rule tag fixes this arity, so no parent count is
encoded. A `ProofReference` creates no derivation node: it returns the resolved
proof's registered `DerivationId` unchanged. The final step's value is the
checked proof's `DerivationId`.

This transcript is defined for exactly the V0 rules above. A future rule whose
result and ordered parent identities do not preserve its complete variable
wiring must define additional canonical witness bytes or use a new derivation
identity version; it cannot silently reuse this transcript.

`statement_bytes` are the canonical Formula V0 bytes of the checked closed
conclusion. `normal_proof_bytes` are the canonical certificate bytes carried
by the checked `ProofNormalFormV0`, never the unnormalized submitted bytes.
Consequently, presentation-only step order, systematic free-variable renaming,
unreachable steps, and exact duplicate nodes do not change any identity.
Inlining or citing an already checked subderivation can change `ProofId` but
does not change `DerivationId`. Repeated reference-only aliases also retain the
referenced `DerivationId` and are rejected as duplicates at registration.

Different inference DAGs of one conclusion share a `StatementId` but normally
have different `DerivationId` and `ProofId` values. No logical-equivalence,
proof-minimization, or detour-elimination search is performed. Structurally
different closed formulas retain different statement identities, and reachable
alternative derivations remain distinct. Any future theorem-novelty or reward
policy must therefore use `StatementId`, not the number of distinct proof or
derivation artifacts.

An identity is an address, not proof that its content exists or is valid.
Admission must still perform normalization and mathematical checking before it
registers these identities.

### Content-identity golden vector

For the checked two-step proof `E1(x); Generalization(0,x)`, normalization maps
`x` to free-variable identifier `0`. Its closed conclusion and normal proof
bytes are:

```text
statement_bytes   = 040001000000000100000000
normal_proof_bytes = 00000000020600000000210000000000000000
```

The resulting identities are:

```text
StatementId  = 517cddb156208852af848fd6b204b1dca9728f6e52fd6ec9940ef1437b8af15a
DerivationId = d19ab345081f610cd2ab47d68cc7fe8616818768227074fad2c2d83cacf5a449
ProofId      = 5a90444e9a1f0e0138eb5bbca12d322ff705e55d155a9273474714dc698ae1bf
```

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
