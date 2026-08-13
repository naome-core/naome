# NAOME Proof Protocol

This document normatively defines NAOME's canonical proof certificate, checked
selected state, authenticated proof set, proof-state transition, and linear
proof block. The [ZFC Foundation](foundation.md) owns the mathematical language
and primitive rules. The [Proof Chain Journal](proof-chain-journal.md) owns
durable selected-state recovery.

The protocol pipeline is:

```text
canonical certificate
  -> deterministic mathematical checking
  -> immutable accepted record
  -> authenticated selected proof set
  -> exact proof-state transition
  -> exact-parent proof block
```

Mathematical checking decides Foundation-relative proof validity. State roots,
transition identities, blocks, ancestry, persistence, and later consensus may
commit ordering, inclusion, and provenance; none can make an invalid proof
valid or establish mathematical truth independently of checking.

## Proof certificate

A certificate is a finite, assumption-free derivation relative to Foundation.
Structural validity does not imply mathematical validity. Admission derives the
root-proof normal form, requires canonical bytes where applicable, and checks
that normal form exactly once.

### Integers and formulas

Counts, lengths, free-variable identifiers, and step indices are unsigned
big-endian `u32` values with exactly one four-byte representation. Tags are
single `u8` values. Canonical bytes contain no variable-length integers,
strings, maps, floats, padding, or implicit Rust enum layouts. Tag literals and
byte dumps below are hexadecimal.

Formulas use prefix order:

| Tag | Node | Payload |
| --- | --- | --- |
| `00` | equality | two variables |
| `01` | membership | two variables |
| `02` | negation | one formula |
| `03` | implication | antecedent, consequent |
| `04` | universal quantifier | one formula |

Variables are:

| Tag | Variable | Payload |
| --- | --- | --- |
| `00` | free | identifier as `u32` |
| `01` | bound | De Bruijn index as `u32` |

Binder names are absent. A bound index must be smaller than the number of
enclosing universal quantifiers. Derived connectives and existential
quantification are encoded only after expansion to Foundation primitives.

The standalone formula codec admits at most 65,536 nodes, nesting depth 256,
and 393,216 bytes in one formula. These processing limits do not restrict the
abstract Foundation language.

### Certificate envelope and steps

```text
step_count  u32
steps       step_count consecutive steps
EOF         no trailing bytes
```

A certificate contains at least one step. Steps are zero-indexed; encoded order
is part of the concrete certificate, and the final step is the claimed
conclusion.

The codec admits at most 4,194,304 certificate bytes, 65,536 steps, and 65,536
cumulative nodes across all explicitly encoded formula fields. Formula nodes
are charged in step and field order, including repeated equal occurrences,
before the next node is decoded or allocated. Fixed ZFC expansions, resolved
reference conclusions, and checker-derived results are excluded from this
payload budget and remain subject to the checker work budget.

Every formula-valued field is:

```text
formula_length  u32
formula_bytes   formula_length canonical formula bytes
```

A schema parameter list is a `u32` count followed by that many free-variable
identifiers in quantifier order. Each step begins with one tag:

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

No result formula is encoded beside a step; the checker reconstructs it from
the tag, payload, and earlier results. Q2 encodes no quantified-variable
identifier: the locally nameless representation constructs the nameless
vacuous binder directly, satisfying the abstract freshness condition without
redundant bytes.

### Structural decoding

The decoder accepts bytes exactly when:

- every tag is known;
- all fixed-width values and formula payloads are complete;
- the certificate is non-empty and within the byte, step, formula, and
  cumulative-node limits;
- every modus-ponens or generalization reference is strictly smaller than the
  referencing step index;
- every canonical formula is well formed;
- every count fits `u32`; and
- no bytes remain after the declared steps.

These rules make local references finite and acyclic. Duplicate and unused
steps are structurally valid. Structural decoding does not check reference
existence, axiom-schema side conditions, inference rules, or final closure.

### Mathematical checking

Checking executes every supplied step in encoded order and accepts exactly when
each operation succeeds and the final formula is closed. The first failure in
that order reports the zero-based step index. Admission checks the normal-form
certificate, not presentation-only steps removed by normalization. The
dependency-free entry point uses an empty proof state and therefore rejects
every proof reference; reference-aware checking uses an explicit immutable
selected proof state.

Each result is reconstructed only through its Foundation operation:

- L1 through L3, Q1, Q3, E1, and E2 instantiate their logical axioms;
- Q2 constructs nameless vacuous universal quantification;
- fixed ZFC steps expand their selected axiom;
- Separation and Replacement validate schema side conditions before expansion;
- proof references reuse the closed conclusion registered for the exact
  selected `ProofId`;
- modus ponens consumes its referenced premise and implication; and
- generalization universally quantifies its referenced premise.

Every reconstructed result must satisfy the formula depth, node, and byte
limits before it can be referenced. A Separation or Replacement step with at
least 256 parameters fails with the formula depth-limit error before expansion,
because those binders alone cannot fit the limit.

Checker admits at most 4,194,304 bytes of cumulative canonical formula work. It
charges both operand lengths before modus ponens, the premise length before
generalization, every reconstructed result, a resolved reference result before
cloning, and the conclusion once more before closure checking. An operand
charge that exceeds the remaining budget rejects before execution. A derived
formula codec error precedes its result charge; the final closure traversal is
charged before the conclusion is classified open or closed. Checker never
inserts implicit universal quantifiers.

### Canonical proof normal form

Every structurally valid certificate has one proof normal form. This is the
canonical input to proof identity, not an inference rule or validity claim.
Starting from the final step as root:

1. Traverse only root-reachable steps with an explicit stack. Modus-ponens
   dependencies retain premise-then-implication order; generalization visits
   its premise. Dependency roles are never sorted.
2. Emit each step after its dependencies, producing dependency-first postorder
   and backward-only remapped references.
3. During emission, map each first-seen free-variable identifier to the smallest
   unused `u32` from zero. Step fields retain wire order, formulas retain prefix
   order, and bound De Bruijn indices are unchanged.
4. Replace local references with emitted output indices.
5. Merge a step only when its normalized tag, complete payload, and ordered
   local references have byte-identical canonical encodings.

The normal form uses the existing envelope and step codec. Normalization is
idempotent, cannot increase byte length or step count, and is invariant under
presentation topological order, systematic free-variable renaming, unreachable
steps, and exact duplicate nodes. It does not merge equal derived formulas from
different rules or dependency structures and performs no theorem rewriting,
commutative or associative sorting, proof minimization, or mathematical-
equivalence search.

A proof reference is a leaf. It contributes no local dependency or free
variable; exact duplicate reference leaves merge byte-for-byte, while different
`ProofId` values never merge even if they resolve to one statement.

Encoded input follows this order:

```text
structurally decode the complete input certificate
derive its proof normal form
mathematically check every normal-form step exactly once, resolving each ProofId at its step
require a closed conclusion
```

Decoding validates all input framing and limits before pruning. Mathematical
validity belongs to the root-reachable normal form: unreachable invalid schema
or inference steps have no admission effect, while reachable invalid steps are
rejected. Mathematical errors identify normal-form indices and normalized free
variables. Strict external admission additionally compares submitted bytes with
normal-form bytes before checking; mismatch is rejected, never repaired.

#### Normal-form golden vector

These structurally valid certificates differ in order, free-variable names, an
unused fixed-ZFC step, and duplicate equality/generalization nodes.

Input A:

```text
00000006
10 01
06 00000007
06 00000007
21 00000001 00000007
21 00000002 00000007
20 00000003 00000004
```

Input B:

```text
00000006
06 0000002a
10 06
21 00000000 0000002a
06 0000002a
21 00000003 0000002a
20 00000002 00000004
```

Both normalize to:

```text
00000003
06 00000000
21 00000000 00000000
20 00000001 00000001
```

The unused step is removed, duplicate nodes share one output index, free
variable `7` or `42` becomes `0`, and both modus-ponens references become `1`.
The final modus-ponens step is intentionally invalid; this vector isolates
structural normalization and must not be admitted as a checked proof.

### External proof references

A `ProofReference` is exactly one raw 32-byte `ProofId`; it repeats no statement
identity, conclusion, proof bytes, or Foundation identifier. Structural decoding
accepts any 32-byte value without asserting existence.

Checking resolves each reachable reference from immutable selected state that
can contain only checked proofs. The state maps `ProofId` through `DerivationId`
to `StatementId` and stores one closed canonical conclusion and its length per
statement. Different derivations remain separately citable without duplicating
the conclusion.

Resolution requires the exact `ProofId` to exist. Absence fails at the
normalized reference step before dependent inference. The conclusion is charged
before cloning, the referenced certificate is not executed again, and
unreachable references removed by normalization are never resolved.

A reference may be the checked root. Its `DerivationId` equals the referenced
derivation. Registration rejects an existing `ProofId`, an existing
`DerivationId`, or a missing cited dependency rather than replacing state.
Changing only an inline/reference boundary changes `ProofId` but not
`DerivationId`; citing a genuinely different derivation changes the dependent
derivation and artifact identities.

For the checked proof in the identity golden below, the reference-only
certificate is:

```text
00000001
30 c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73
```

Its conclusion retains the golden `StatementId`, while the citation proof has:

```text
DerivationId = 59219d63c7c2353dcb6ffd1e604153143380ae6602e04215703bc0ea043243fb
ProofId      = bfd427b447e1514686cfa31b0b5aa1dd5036464cd8c5d73d0c3112cb46b0519b
```

Registering this alias beside the cited proof fails as a duplicate derivation.

### Content identity

Successful checking produces three distinct 32-byte identities:

- `StatementId` identifies the closed conclusion independently of derivation;
- `DerivationId` identifies the inference DAG independently of inline/citation
  packaging; and
- `ProofId` identifies the concrete checked normal form, including citation
  boundaries and cited `ProofId` values.

All use SHA-256 as specified by FIPS 180-4 and bind the exact UTF-8 Foundation
identifier `naome:zfc`. This identifier is a protocol namespace, not a hash
of Foundation source. Exact domain and Foundation bytes are:

```text
statement_domain = 6e616f6d653a73746174656d656e7400
proof_domain     = 6e616f6d653a70726f6f6600
derivation_node_domain = 6e616f6d653a64657269766174696f6e2d6e6f646500
foundation       = 6e616f6d653a7a6663
```

Variable fields have four-byte big-endian lengths. The fixed 32-byte
`StatementId` has no length prefix:

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

`DerivationId` is computed compositionally during checking. For each local,
non-reference step, `result_bytes` are the reconstructed formula bytes after
renumbering that result's free variables to `0, 1, ...` by canonical-prefix
first occurrence. Bound indices are unchanged. This makes the result formula
the node's canonical variable interface across inline/reference boundaries.

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

`rule_tag` is the certificate step tag. Primitive axioms and schemas have no
parents. Modus ponens appends two raw 32-byte parent identities in premise-then-
implication order; generalization appends one premise identity. The tag fixes
arity, so no parent count is encoded. A proof reference creates no node and
returns the registered derivation identity unchanged. The final step's value is
the checked proof's `DerivationId`.

Any added rule whose result and ordered parent identities do not preserve its
complete variable wiring must define additional canonical witness bytes or a
distinct derivation domain; it cannot reuse this transcript silently.

`statement_bytes` are the checked closed conclusion's canonical formula bytes;
`normal_proof_bytes` are the checked normal-form certificate bytes, never the
unnormalized submission. Presentation order, systematic free-variable
renaming, unreachable steps, and duplicate nodes change no identity. Inlining
versus citing can change `ProofId` but not `DerivationId`. Different inference
DAGs of one conclusion share `StatementId` but normally differ in the other two
identities. No logical-equivalence or proof-minimization search occurs.

An identity is an address, not evidence that content exists or is valid.
Admission still requires normalization and mathematical checking. Statement-
novelty policy must use `StatementId`, not counts of proof or derivation
artifacts.

#### Content-identity golden vector

For `E1(x); Generalization(0,x)`, normalization maps `x` to free-variable `0`:

```text
statement_bytes   = 040001000000000100000000
normal_proof_bytes = 000000020600000000210000000000000000

StatementId  = f902f799c24f064ea98bf7fa33c12c5178f1722fdfd94b223c64ea1aa9ae3d19
DerivationId = 59219d63c7c2353dcb6ffd1e604153143380ae6602e04215703bc0ea043243fb
ProofId      = c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73
```

#### Certificate golden vector

Equality reflexivity for free variable `0x01020304` is:

```text
00 00 00 01           one step
06                    equality-reflexivity step
01 02 03 04           free-variable identifier
```

Canonical bytes are:

```text
00 00 00 01 06 01 02 03 04
```

## Selected proof state and admission

Selected in-memory state contains one `ProofId -> DerivationId` entry for every
accepted concrete proof, one `DerivationId -> StatementId` entry for every
accepted inference DAG, and one canonical closed conclusion plus its canonical
length for every accepted statement. Only successfully checked proofs may add
entries; existing proof, derivation, or statement identities are never replaced.

State grows monotonically but is not an order-free mergeable CRDT. Separate
states may select different artifacts for one derivation; after one artifact is
selected, another with the same `DerivationId` fails as a duplicate derivation.

### Single-proof admission

The owned-certificate authoring path may normalize representation noise before
checking and atomic registration; it is not the external byte boundary. Strict
byte admission executes:

1. decode one structurally valid complete certificate;
2. derive its root-proof normal form;
3. require the submitted bytes to equal the normal-form encoding exactly;
4. check that normal form once against unchanged selected state;
5. for addressed admission, require its checked `ProofId` to equal the immutable
   expected `ProofId`;
6. atomically register the checked proof; and
7. return its accepted record.

Structural decoding errors precede `NonCanonicalProof`; canonicality errors
precede checker errors; checker errors precede `ProofIdMismatch`; identity
mismatch precedes registration errors. Identity mismatch reports expected and
actual checked IDs. The expected ID is request context, not proof content: it is
compared with the fully checked normal-form identity, never a raw byte hash or
caller field, and is not retained in the record.

The candidate remains invisible while checking, so every reference resolves
from unchanged selected state. Every error leaves state unchanged.

### Atomic rooted proof transactions

A rooted transaction admits one dependency closure all-or-none. The trusted
local path accepts canonical buffers and derives their IDs. The addressed path
accepts an immutable `requested_root` and candidates pairing each owned buffer
with its immutable expected `ProofId`. Network-derived data must use the
addressed path; raw peer bytes must never enter unaddressed admission.

A transaction contains `1..=8` candidates. Each remains independently subject
to the certificate byte, step, formula-node, and checker-work limits. The
maximum candidate payload is eight certificates, or `33_554_432` bytes. The
caller supplies dependency-first order; admission never sorts, retries,
deduplicates, or partially accepts candidates.

Addressed shape preflight executes before proof work:

1. reject an empty batch;
2. reject more than eight candidates;
3. reject the first duplicate expected `ProofId` in input order; and
4. require the final candidate's expected ID to equal `requested_root`.

Candidates are then processed in input order. Candidate `i` may resolve exact
references from the immutable selected base and successfully staged candidates
at lower indices, never itself or a later candidate. A missing or forward
reference returns the ordinary checker `UnknownProofReference` at that candidate
and normal-form step.

Each candidate follows this order:

1. decode;
2. verify canonical root-proof normal form;
3. mathematically check and derive all three identities;
4. when addressed, compare actual and expected `ProofId`;
5. validate proof, dependency, derivation, and statement registration against
   the base plus earlier staged candidates; and
6. stage its accepted record without mutating selected state.

The first candidate error stops processing, reports its index and supplied
expected ID, preserves the underlying ledger error, and discards all staged
state.

After every candidate succeeds individually, reachability is computed from the
final actual `ProofId` over direct exact-`ProofId` dependencies in checked normal
forms. Every candidate must be transitively reachable; dependencies already in
selected state are allowed but are not transaction candidates. Reachability
uses neither statement nor derivation identities, an unmatched expected address,
nor discarded presentation steps. The first unreachable candidate in input
order returns `UnreachableCandidate` and discards the transaction. Dependency-
first resolution plus root closure makes every successful addition acyclic and
dependency-closed and prevents unrelated-proof smuggling.

Candidates are staged privately against the immutable base. Only after checking
and root closure succeed are all registry entries and accepted records committed;
every possible insertion failure is validated before that infallible merge.

Success inserts every candidate exactly once. Any shape, decode, canonicality,
checker, expected-address, registration, or reachability error leaves unchanged:

- all proof, derivation, and statement registries;
- retained accepted records and selected proof count;
- authenticated-set topology and `ProofSetRoot`; and
- every membership and non-membership witness.

The call consumes its input even on failure; atomicity protects selected state,
not recovery of caller-owned buffers.

### Accepted records and proof DAG

Each successful candidate produces one immutable accepted record containing:

- exact canonical root-proof-normal-form certificate bytes;
- its checked `ProofId`, `DerivationId`, and `StatementId`; and
- each directly cited `ProofId` once, in canonical normal-form step order.

Direct dependencies exclude transitive dependencies and local indices. Exact
duplicate reference leaves have already been interned. Records expose no mutable
payload or dependency list. Exact canonical bytes are retained, dependencies
remain immutable, and replay-derived metadata must never bypass strict
admission. `ProofSetRoot` binds the selected exact `ProofId` set independently of
insertion order or transaction grouping.

Callers cannot insert unchecked bytes, identities, edges, or leaves directly.
The [Proof Chain Journal](proof-chain-journal.md) is the sole durable owner and
reconstructs selected state only through strict block replay.

Every candidate is decoded, canonicality-checked, and mathematically checked
once. Staging retains at most eight candidates without cloning, scanning, or
rebuilding selected state. Registry operations use ordered-map lookup;
authenticated-set operations traverse at most 256 key bits.

## Authenticated proof set

The selected exact `ProofId` set is a compressed binary Merkle-Patricia tree.
It has one insertion-order-independent `ProofSetRoot` and compact membership and
non-membership proofs. The only key is the complete 32-byte `ProofId`; certificate
bytes, statement and derivation identities, conclusions, and dependency indexes
are not separately hashed. Using `StatementId` or `DerivationId` would collapse
distinct accepted proof artifacts incorrectly.

### Key bits and canonical topology

Bits are read most-significant first:

```text
bit(key, d) = (key[d / 8] >> (7 - (d mod 8))) & 1
```

where `d` is in `0..=255`. For a finite key set `S`:

```text
Tree(empty) = Empty
Tree({key}) = Leaf(key)

Tree(S) = Branch(d, Tree(S0), Tree(S1))
```

For more than one key, `d` is the first bit at which the keys differ; `S0` and
`S1` are the nonempty zero- and one-bit subsets. Consequently every leaf stores
one key, every branch has two nonempty children, branch bits strictly increase
from root to leaf, a nonempty `n`-key tree has `n` leaves and `n - 1` branches,
and no empty, unary, or extension node is stored. Topology depends only on the
key set. Lookup, insertion, and one proof path traverse at most 256 branches.

### Hash transcript

Every digest is SHA-256. The exact domain includes its trailing NUL:

```text
naome:proof-set\0
```

Node digests are:

```text
E = SHA256("naome:proof-set\0" || 00)

L(key) = SHA256(
    "naome:proof-set\0"
    || 01
    || key[32]
)

B(d, left, right) = SHA256(
    "naome:proof-set\0"
    || 02
    || d_u8
    || left[32]
    || right[32]
)
```

`E` is the empty-set root; a singleton root is its leaf digest. A branch hashes
its discriminating bit and ordered children, with zero left and one right. The
branch bit is authenticated content and must not be omitted.

### Compact set proofs

A proof has an empty-tree, membership, or non-membership terminal. A non-member
terminal contains the different leaf reached while searching. Its root-to-
terminal path stores only each branch bit and sibling digest; direction derives
from the query and is not encoded.

The count-free canonical encoding is:

```text
Empty     = 00
Member    = 01 || Path
NonMember = 02 || terminal_proof_id[32] || Path

Path      = Step*
Step      = branch_bit_u8 || sibling_digest[32]
```

Steps appear root-to-terminal and are exactly 33 bytes, so the complete input
boundary determines their count. The query, expected root, directions, count,
and a format version are not repeated. Sizes are:

```text
Empty:      1 byte
Member:     1 + 33 * path_length bytes
NonMember: 33 + 33 * path_length bytes
```

A membership path may cover all 256 bit positions and reach 8,449 bytes. A
non-membership path has at most 255 positions and reaches 8,448 bytes because
its terminal key must differ at a bit not already present in the path.

Decoding executes:

1. reject input longer than 8,449 bytes before path allocation;
2. require one known terminal tag;
3. require an empty terminal to end the input immediately;
4. require a non-member terminal's complete 32-byte `ProofId`;
5. require remaining bytes to divide exactly into 33-byte steps;
6. enforce the terminal-specific 256- or 255-step limit;
7. require branch bits to increase strictly; and
8. reject an empty sibling digest.

This validates structure only. Because no redundant count is encoded, changing
an input by one complete step can produce another structurally canonical value;
verification must still reconstruct the trusted expected root. Partial steps
are rejected. Decoding never normalizes, infers, or repairs a proof.

Fixed proof encodings use `zero` for 32 zero bytes and `high` for `80` followed
by 31 zero bytes. The empty proof is `00`; singleton membership is `01`; and a
singleton non-membership proof terminating at `zero` is:

```text
02 0000000000000000000000000000000000000000000000000000000000000000
```

For `{zero, high}`, membership of `zero` is:

```text
01 00 93e7bd037407e8654873ed319b0130c3117246bd84e184e25dd7d10964a765ed
```

For the same set, non-membership of `40` followed by 31 zero bytes terminates at
`zero`:

```text
02 0000000000000000000000000000000000000000000000000000000000000000
   00 93e7bd037407e8654873ed319b0130c3117246bd84e184e25dd7d10964a765ed
```

Whitespace and line breaks above are not encoded.

Verification is fail-closed and executes:

1. enforce the terminal-specific path limit;
2. require strictly increasing branch bits;
3. reject an empty sibling digest;
4. require an empty terminal to have an empty path;
5. for non-membership, require the terminal key to differ from the query and
   choose the query's direction at every path bit;
6. start from `E`, `L(query)`, or `L(non_member_terminal)`;
7. fold terminal-to-root with children ordered by the query bit;
8. require the reconstructed root to equal the trusted expected root; and
9. only then return `Present` or `Absent`.

Non-membership in a nonempty tree terminates at a different leaf, never an empty
stored child. If the query existed elsewhere, its first differing bit would be
an authenticated branch and verification would fail.

### Integration, projection, and reconstruction

The authenticated tree directly owns accepted records. Strict decode,
canonicality, mathematical checking, dependency resolution, expected-address
comparison, and identity registration all succeed before insertion. Duplicate
rules make insertion logically infallible; failed admission changes neither
record count, topology, root, nor witnesses. The structure is append-only.

Transition preflight may project the root obtained by adding an exact ordered
list of one to eight unique `ProofId` keys. Projection has normal insertion
semantics but mutates no record, topology, root, witness, or selected registry.
It is bounded by those keys and their Patricia paths and must not clone, scan,
or rebuild the set. Projection accepts identities only; it performs no proof
decode, checking, dependency validation, root closure, or record admission.

The [Proof Chain Journal](proof-chain-journal.md) stores no Merkle nodes; strict
block replay reconstructs and verifies the set. Different valid block grouping
or order may produce one final set root but different ancestry. A head, root, or
witness from an untrusted peer establishes no freshness, selection, or finality;
verification must bind the expected root and queried `ProofId` to trusted caller
context.

### Golden roots

The empty-set root is:

```text
e9a980287e770ac389d3735ff064e7447f11c9640efdb90b91781766497f16ca
```

The all-zero `ProofId` singleton root is:

```text
6035299a52844d846d83ca0395e1a7df37e62b7de9adc638ea2cbaf97d799a04
```

The root for all-zero plus `80` followed by 31 zero bytes is:

```text
4c77fb731087d077c434cc706d41eea1fc9aa9b324638f709747b492cbb52687
```

Adding 31 zero bytes followed by `01` produces:

```text
00d65391369a613d7a56aca448277a0da7cc44e57a12a8b2159f0b1c5712c396
```

These commitments assume SHA-256 collision and second-preimage resistance.
Constructing a root from arbitrary bytes establishes only an address. A set
proof authenticates exact membership or absence relative to that address; it
does not replay a certificate, admit a proof, establish data availability, or
show consensus selection. Exact block ancestry and journal replay remain
responsible for order-dependent append integrity; block head and set root are
not interchangeable.

## Proof-state transition

A `ProofTransition` commits one bounded selected-state change:

```text
previous_proof_set_root:  ProofSetRoot
resulting_proof_set_root: ProofSetRoot
proof_ids:                1..=8 ProofId values
```

The ordered IDs are unique and dependency-first; the final ID is the rooted
transaction root. Order is semantic and must not be sorted, deduplicated, retried,
or normalized. Different valid topological presentations have different bytes
and, assuming collision resistance, different `ProofTransitionId` values even
when they produce one final set root. The codec cannot establish dependency
order or closure; checked rooted admission does.

### Encoding and identity

```text
Transition = previous_proof_set_root[32]
          || resulting_proof_set_root[32]
          || proof_count_u8
          || proof_ids[proof_count][32]
```

`proof_count` is in `1..=8`. There is no version, tag, length prefix, padding,
or checksum; the complete input boundary delimits the value. Exact length is:

```text
65 + 32 * proof_count bytes
```

The transition is 97 bytes for one proof and at most 321 bytes for eight.
Decoding executes:

1. reject input longer than 321 bytes before proof-ID allocation;
2. decode two complete roots and the count, returning unexpected-end when any
   of the first 65 bytes is absent;
3. reject count zero;
4. reject count above eight;
5. decode exactly the declared complete 32-byte IDs, returning unexpected-end
   at the first incomplete value;
6. reject trailing bytes; and
7. reject the first duplicate ID in supplied order.

No partially decoded transition is returned, and re-encoding reproduces the
accepted bytes exactly.

Transition identity is SHA-256 over the exact trailing-NUL domain and canonical
encoding:

```text
ProofTransitionId = SHA256(
    "naome:proof-transition\0"
    || canonical_transition_bytes
)
```

Exact domain bytes are:

```text
6e616f6d653a70726f6f662d7472616e736974696f6e00
```

For previous root `11` repeated 32 bytes, resulting root `22` repeated 32 bytes,
count `02`, and ordered IDs `33` then `44`, each repeated 32 bytes, the identity
is:

```text
7588941422cb2102d8c03f6aa8c1fc2c683d579f67b7f96e22eabd5b68c50070
```

Identity commits one exact proposed state change but establishes no inclusion,
freshness, availability, authorship, finality, or economic value.

### Correlation and projected root

Application takes the transition and an owned addressed-candidate list. Before
reading candidate bytes, it requires equal counts and then each immutable
expected candidate `ProofId` to equal the transition ID at the same index. The
first ordered mismatch fails. Unordered-set comparison, permutation, final-ID-
only correlation, or correlation derived from untrusted bytes is forbidden.

Correlation binds requested work to the commitment but does not validate a
candidate. Rooted admission remains authoritative for decoding, canonicality,
mathematics, checked-ID comparison, dependency resolution, registration, and
root closure.

Before checking proof bytes, application projects the root produced by inserting
the transition's IDs into the current authenticated set. Projection is read-only
and semantically identical to normal key insertion. It is bounded by eight keys
and their Patricia paths and must not clone, scan, or rebuild selected state. An
already selected key projects idempotently, while rooted admission still rejects
duplicate proof admission.

The projected root must equal `resulting_proof_set_root`; mismatch precedes any
certificate decode or check. Arbitrary projected keys are not thereby valid
proofs.

Local preparation may bind the current root, ordered IDs, and projected result
into a transition without checking proofs or mutating state. As an authoring
convenience it rejects the first already-selected ID. Applying a constructed or
decoded transition retains idempotent projection and leaves duplicate-proof
rejection to rooted admission.

### Atomic transition application

Application to one selected proof DAG executes:

1. require current `ProofSetRoot == previous_proof_set_root` before candidate
   inspection;
2. require exact candidate count;
3. require exact ordered candidate-ID correlation, stopping at the first
   mismatch;
4. require the read-only projected root to equal `resulting_proof_set_root`; and
5. invoke addressed rooted-batch admission exactly once with the final
   transition ID as `requested_root` and the correlated candidates unchanged.

Current-root mismatch precedes every candidate error; count mismatch precedes
ID mismatch; ID mismatch precedes resulting-root mismatch; and every transition
preflight error precedes rooted-batch errors. A rooted-batch error is preserved,
not reclassified or retried.

The transition layer must not duplicate certificate decoding, checking,
dependency resolution, reachability, or registration. Rooted admission is the
sole mutation after preflight. Success inserts each checked candidate exactly
once and leaves the DAG at `resulting_proof_set_root`. Every failure leaves all
registries, retained records, proof count, authenticated topology, root, and
existing witnesses unchanged. No fallible transition check occurs after rooted
admission commits.

Reapplying a successful transition to the same state fails at current-root
comparison before candidate work. This is state-relative, not global, replay
protection: another DAG with the declared previous root may apply it.

Read-only transition validation executes the same current-root, candidate-count,
ordered-correlation, projected-root, and addressed rooted-batch checks against
the selected state. It uses the same staged proof transaction as application but
discards every checked registration and record on both success and failure.
Validation and application therefore preserve the same preflight, batch,
candidate, and ledger error precedence, while validation returns no record or
transferable validation artifact.

Successful validation means only that the complete transition was executable
against that exact selected proof state during the call. It does not reserve the
transition or make later application infallible. Application always repeats the
complete validation because the selected state may have changed.

A transition contains no chain position, time, network, authority, or nonce.
Its identity and roots assume SHA-256 collision and second-preimage resistance.
The previous root prevents application to a different selected key set; ordered
correlation prevents substitution and permutation; pre-mutation projection
binds the proposed post-state. Neither root authenticates its selector or gives
an untrusted source provenance, freshness, availability, or consensus authority.

Transition decode and duplicate/correlation work are bounded by eight identities
and 321 bytes. Projection performs bounded Patricia work for eight keys and does
not scale by scanning selected state. Candidate payload and mathematical work
retain the independent certificate and admission limits above.

## Proof block and linear chain state

A `ProofBlock` binds one parent `ProofBlockId` and one complete canonical
`ProofTransition`. A canonical `ProofChainDefinition` derives one
`ProofChainId`, which derives the virtual genesis parent for an initially empty
chain state. Every admitted block must extend the exact current head and apply
its transition atomically to the privately owned selected proof DAG. The
[Proof Chain Journal](proof-chain-journal.md) persists this selected line
without changing block bytes or application rules.

Its canonical value is exactly:

```text
parent_block_id: ProofBlockId
transition:      ProofTransition
```

### Chain definition, identity, and virtual genesis

A `ProofChainDefinition` fixes the executable context of one proof-chain
deployment. The caller controls only one opaque 32-byte deployment
discriminator. The definition also binds the exact current Foundation identity
and the authenticated root of the empty proof set; callers cannot inject either
fixed field through the trusted construction path.

Its sole canonical representation is exactly 73 bytes:

```text
deployment_discriminator[32]
foundation_id[9]              = "naome:zfc"
genesis_proof_set_root[32]    = e9a980287e770ac389d3735ff064e744
                                7f11c9640efdb90b91781766497f16ca
```

All fields have fixed width, so the representation contains no version, tag,
length, padding, or checksum. Decoding executes:

1. require exactly 73 bytes, otherwise `InvalidLength`;
2. require the exact compiled Foundation bytes, otherwise
   `FoundationIdMismatch`; and
3. require the exact executable empty `ProofSetRoot`, otherwise
   `GenesisProofSetRootMismatch`.

Length validation precedes all fixed-field inspection. Decoding allocates no
memory, returns no partial definition, and re-encoding every accepted input
reproduces its bytes exactly. The empty root is the same value returned by the
authenticated proof-set implementation, not an independent genesis constant.

`ProofChainId` is the SHA-256 content identity of the complete canonical
definition:

```text
ProofChainId = SHA256(
    "naome:proof-chain-definition\0"
    || canonical_proof_chain_definition[73]
)
```

Exact definition-domain bytes are:

```text
6e616f6d653a70726f6f662d636861696e2d646566696e6974696f6e00
```

For a deployment discriminator containing 32 bytes of `11`, the canonical
definition and derived chain ID are:

```text
definition = 1111111111111111111111111111111111111111111111111111111111111111
             6e616f6d653a7a6663
             e9a980287e770ac389d3735ff064e7447f11c9640efdb90b91781766497f16ca

ProofChainId = 7174cae86b0cd18e2364805d1bb8da7a34262f3efa6f5e2b723ec6612a9ec15e
```

Changing the deployment discriminator, Foundation identity, or genesis root
changes the chain identity under collision resistance. The discriminator
separates intentional deployments that otherwise share the same executable
genesis semantics. It is not a secret, signature, operator identity, consensus
parameter, or authorization token.

A `ProofChainId` remains an exact 32-byte address on journal and network
boundaries. Constructing that address from raw bytes supports strict message
and file decoding; it does not establish that the bytes derive from a supported
definition. Trusted chain-state and journal construction accept the complete
definition and derive its ID instead of accepting an arbitrary address.

An empty chain derives its initial head as:

```text
virtual_genesis_parent = SHA256(
    "naome:proof-chain-genesis\0"
    || proof_chain_id[32]
)
```

Exact genesis-domain bytes are:

```text
6e616f6d653a70726f6f662d636861696e2d67656e6573697300
```

For the `11` discriminator definition above, the virtual genesis parent is:

```text
71ca84dceae51fd23311eb1d79fc97223dba62821d604cd6f4d5701034c5f62d
```

This anchor is not an admitted block and has no transition, payload, height, or
stored record. The first block names it as parent; every later block names the
exact identity of its admitted predecessor.

`ProofChainId` is not repeated in blocks, so standalone block bytes are not
self-labeling. Context comes from a supported definition, its derived chain ID,
and unbroken ancestry to its virtual genesis. Reusing one ancestry under another
definition fails at the first exact-head comparison unless the chain identity,
virtual genesis, or later block identity collides.

### Block encoding and identity

A block is:

```text
Block = parent_block_id[32]
     || canonical_proof_transition[97..321]
```

It adds only parent context; the transition retains roots and ordered proof IDs.
No version, tag, chain ID, height, timestamp, transition length, padding, or
checksum is encoded. The parent is always present. The complete input boundary
delimits the block and the transition count determines internal length. A block
is 129 through 353 bytes.

Decoding executes:

1. reject input longer than 353 bytes as `InputTooLong` before transition-ID
   allocation;
2. require the complete 32-byte parent, otherwise `UnexpectedEnd`;
3. decode the complete remaining slice with the transition decoder, preserving
   its validation order as `Transition { source }`; and
4. reject every transition truncation, invalid count, trailing byte, or
   duplicate identity.

No partial block is returned, and re-encoding reproduces accepted bytes exactly.

Block identity is SHA-256 over the exact trailing-NUL domain and complete
canonical bytes:

```text
ProofBlockId = SHA256(
    "naome:proof-block\0"
    || canonical_block_bytes
)
```

Exact block-domain bytes are:

```text
6e616f6d653a70726f6f662d626c6f636b00
```

For the `11` discriminator definition's virtual genesis and the transition
golden above—roots `11` and `22`, count `02`, IDs `33` and `44`—the 161-byte
block ID is:

```text
474983a016ebf466488b634485b9e6e93f1629bf3d0afa5afa5618f2e04a70f4
```

Changing parent or any transition byte changes the identity under collision
resistance. Parent recursively commits claimed ancestry; only successful exact-
head application establishes it for the local selected chain. Identity alone
does not establish ancestry availability, validity, selection, or finality.

### Preparation, validation, and exact-head application

A chain state begins from one supported definition with an empty private proof
DAG and its derived virtual genesis as current head. It accepts neither a raw
caller-selected chain ID, an arbitrary pre-populated DAG, nor a caller-selected
initial head.

Local preparation takes one ordered list of `1..=8` proof IDs, prepares a
transition using the read-only projection rules, and constructs a block whose
parent is the exact current head. It performs no checking, admission, head
advance, or other mutation. Multiple siblings may be prepared from one head;
the linear state can admit at most one before its head changes.

Read-only block validation takes one block and a separate ordered addressed-
candidate list. It first requires the block parent to equal the exact current
head, then invokes read-only transition validation with the supplied candidates.
It returns success without retaining proof records, advancing the head, or
creating a validation object. Multiple siblings can therefore validate against
one unchanged head. If one is later applied, every sibling with the old parent
becomes stale and fails before proof work.

Application takes one block and a separate ordered addressed-candidate list and
executes:

1. require `parent_block_id` to equal the exact current head before candidate
   inspection;
2. compute `ProofBlockId` before mutation;
3. invoke atomic transition application exactly once with the supplied
   candidates; and
4. only after transition success, assign the already computed identity as the
   new head infallibly.

Transition application alone owns current-root binding, candidate count and
order, projected post-root, certificate decode and canonicality, checking,
dependency resolution, root closure, and proof-state mutation. The block layer
must not duplicate, weaken, reorder, retry, or partially apply those checks.

Block validation delegates the same checks to the corresponding read-only
transition path. Durable or in-memory application never consumes validation
success as authority and always rechecks the block and proof closure against its
then-current state.

Parent mismatch precedes every transition or candidate error. Transition errors
retain their internal precedence and source. No fallible operation occurs after
proof-state commit. Every failure preserves head, registries, records, proof
count, authenticated topology/root, and existing witnesses. Success admits each
transition proof once, leaves the DAG at the committed resulting root, and
advances the head once to the block identity. The selected proof DAG is exposed
only immutably, so callers cannot bypass parentage.

Immediate replay or application of a sibling with the old parent fails at the
parent comparison before proof work. This defines one append-only local line,
not fork choice. Competing branches, sibling selection, rollback, reorganization,
and network-wide ordering require later policy. Journal replay reconstructs one
such line and an exact-ID index of its committed blocks; the index is not a
branch store or selection rule.

### Payload, resource, and trust boundaries

Block bytes contain transition commitments but no certificate payloads.
Validation and application receive addressed candidates separately and
correlate them through the exact ordered transition IDs. Possessing or retrieving
a block does not establish possession or availability of its proofs, and neither
retrieval, local journal retention, nor successful read-only validation
establishes network selection.

A block adds exactly 32 parent bytes to a 97-to-321-byte transition and is at
most 353 bytes. Decoding retains at most eight proof identities. Identity hashing
can process parent and transition directly without a second block buffer. The
parent comparison and head assignment are constant-size; preparation,
validation, and application must not clone, scan, or rebuild the complete
selected set or check a candidate more than once per call. Candidate bytes and
mathematical work retain their independent limits.

Chain-definition identity, virtual genesis, block identity, ancestry, transition
identities, and roots assume SHA-256 collision and second-preimage resistance.
Distinct domains separate definitions, genesis anchors, blocks, transitions,
proof identities, and authenticated-set nodes. Exact parent matching prevents
local replay and sibling application after head advance; roots bind selected
proof state before and after the block; addressed admission prevents
substitution, permutation, invalid-proof admission, and unrelated-proof
smuggling.

The definition and chain identifier are neither secret nor authentication keys.
A remote party can calculate the same identity and virtual genesis. A valid
definition, certificate, identity, set root, transition, ancestry, block, or
successful local application establishes no proposer identity, data
availability, consensus, finality, novelty, reward, fee, or economic value.
Source syntax, network selection, durable recovery, competing-history
selection, reorganization, consensus, finality, and economy remain separate
contracts.
