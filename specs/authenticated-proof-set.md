# NAOME Authenticated Proof Set

## Status and scope

This document defines the canonical authenticated set of exact `ProofId`
values retained by one selected NAOME `ProofDag`. It is a prerelease protocol
contract and may change before the first stable protocol release.

The set is represented as a compressed binary Merkle-Patricia tree. It defines
one insertion-order-independent `ProofSetRoot` and compact membership and
non-membership proofs. It does not define a block header, consensus selection,
finality, signatures, rewards, fees, economic state, network transport, proof
certificate encoding, persistent Merkle nodes, snapshots, pruning, or deletion.

## Authenticated content

The only set key is the complete 32-byte `ProofId`. A `ProofId` already binds
one exact checked canonical proof artifact, including its selected citation
boundaries. The proof set does not separately hash certificate bytes,
`StatementId`, `DerivationId`, conclusions, or dependency indexes.

Using `StatementId` or `DerivationId` as the key would incorrectly collapse
distinct accepted proof artifacts. The set root therefore answers only whether
an exact `ProofId` belongs to the selected state.

## Key bits and canonical topology

Proof ID bits are read most-significant-bit first:

```text
bit(key, d) = (key[d / 8] >> (7 - (d mod 8))) & 1
```

where `d` is in `0..=255`.

The canonical tree for a finite key set `S` is:

```text
Tree(empty) = Empty
Tree({key}) = Leaf(key)

Tree(S) = Branch(d, Tree(S0), Tree(S1))
```

For a set containing more than one key, `d` is the first bit at which the keys
in `S` do not all agree. `S0` and `S1` contain the keys whose bit `d` is zero
or one respectively. Both subsets are nonempty.

Consequently:

- every leaf contains one exact key;
- every branch has exactly two nonempty children;
- branch bits increase strictly from root to leaf;
- a nonempty set of `n` keys has exactly `n` leaves and `n - 1` branches; and
- no empty, unary, or extension nodes are stored.

The topology is a deterministic function of the key set. Insertion order does
not affect it. Lookup, insertion, and one proof path traverse at most 256
branches, including deliberately constructed worst cases.

## Hash transcript

Every hash is SHA-256. The exact domain bytes, including the trailing NUL, are:

```text
naome:proof-set\0
```

The three node digests are:

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

`E` is the root of the completely empty set. A singleton root is its leaf
digest. A branch root includes the discriminating bit and the ordered child
digests; bit zero is left and bit one is right.

The branch bit is consensus-relevant authenticated content. Omitting it would
leave compressed path positions unauthenticated.

## Compact set proofs

`ProofSetProof` represents exactly one of:

- an empty-tree terminal;
- a membership terminal whose leaf is the queried `ProofId`; or
- a non-membership terminal containing the different leaf reached while
  searching for the queried `ProofId`.

The proof also contains the root-to-terminal branch path. Each step contains
only its branch bit and sibling digest. Direction is derived from the queried
key and is not stored redundantly.

### Canonical wire encoding

One complete proof has this count-free canonical encoding:

```text
Empty     = 00
Member    = 01 || Path
NonMember = 02 || terminal_proof_id[32] || Path

Path      = Step*
Step      = branch_bit_u8 || sibling_digest[32]
```

The path is encoded from root to terminal. Each step is exactly 33 bytes, so
the complete input-slice boundary determines the step count. The queried
`ProofId`, expected root, branch directions, step count, and a format version
are not duplicated in the proof bytes.

Exact encoded sizes are:

```text
Empty:      1 byte
Member:     1 + 33 * path_length bytes
NonMember: 33 + 33 * path_length bytes
```

A membership path may contain all 256 key-bit positions and therefore reaches
the global maximum of 8,449 bytes. A non-membership path contains at most 255
positions and reaches at most 8,448 bytes: its terminal key must differ from
the query at a bit that is not already an authenticated branch position.

Decoding executes this order:

1. reject an input longer than 8,449 bytes before path allocation;
2. require one known terminal tag;
3. require an empty terminal to end the complete input immediately;
4. require a non-member terminal to contain its complete 32-byte `ProofId`;
5. require all remaining bytes to divide exactly into 33-byte path steps;
6. enforce the terminal-specific 256- or 255-step limit;
7. require branch bits to increase strictly; and
8. reject an empty sibling digest.

Canonical decoding validates structure only. Because the format intentionally
has no redundant step count, truncating or extending a proof by one complete
33-byte step can produce a different structurally canonical value. Such a
value must still reconstruct the trusted expected root during verification;
partial steps are rejected during decoding.

There is exactly one encoding for each in-memory proof value. Decoding does
not normalize, infer, or repair a proof.

The following canonical encodings are fixed goldens. Let `zero` be 32 zero
bytes and `high` be `80` followed by 31 zero bytes. The empty proof is `00`, a
singleton membership proof is `01`, and a singleton non-membership proof that
terminates at `zero` is:

```text
02 0000000000000000000000000000000000000000000000000000000000000000
```

For the set `{zero, high}`, membership of `zero` has this one-step encoding:

```text
01 00 93e7bd037407e8654873ed319b0130c3117246bd84e184e25dd7d10964a765ed
```

For the same set, non-membership of `40` followed by 31 zero bytes terminates
at `zero` and has this encoding:

```text
02 0000000000000000000000000000000000000000000000000000000000000000
   00 93e7bd037407e8654873ed319b0130c3117246bd84e184e25dd7d10964a765ed
```

Whitespace and line breaks above are explanatory and are not encoded.

### Verification

Verification is fail-closed and executes this order:

1. enforce the terminal-specific path limit;
2. require branch bits to increase strictly;
3. reject an empty sibling digest because every stored branch has two nonempty
   children;
4. require an empty terminal to have an empty path;
5. for a non-membership terminal, require the terminal key to differ from the
   query and to choose the same direction as the query at every path bit;
6. start from `E`, `L(query)`, or `L(non_member_terminal)` as appropriate;
7. fold the path from terminal to root, ordering children by the query bit;
8. require the reconstructed root to equal the trusted expected root; and
9. only then return `Present` or `Absent`.

A non-membership proof in a nonempty Patricia tree ends at a different leaf,
not an empty stored child. If the queried key were present elsewhere, the
first differing bit would already be an authenticated branch and the supplied
terminal path would fail verification.

## Proof DAG integration and atomicity

`ProofDag` owns one private authenticated proof set whose leaves own the
accepted proof records. This single structure replaces a separate retained
record map; lookup, root calculation, and proof generation cannot diverge
across duplicate indexes.

Strict proof admission remains owned by the ledger boundary. Decode,
canonicality, mathematical checking, dependency resolution, any expected
`ProofId` comparison, and identity registration all succeed before the new
record is inserted into the private tree. Ledger duplicate rules make that
insertion logically infallible. Every failed admission leaves the record count,
topology, root, and all existing proofs unchanged.

The structure is append-only. Deletion, undo, and state merging require future
consensus and persistence contracts and are not inferred here.

## Read-only transition projection

The [Proof-State Transition](proof-state-transition.md) preflight projects the
root that would result from adding its exact ordered list of one to eight
unique `ProofId` values. Projection has the same key-set semantics as normal
authenticated-set insertion but does not mutate the selected set, retained
records, topology, root, or existing witnesses. It is bounded by those eight
keys and their Patricia paths and must not clone, scan, or rebuild the complete
set.

Projection accepts identities, not proofs. It does not decode certificates,
check mathematics, establish dependency order, enforce root closure, or admit
records. The transition compares the projected root with its committed
resulting root before delegating once to the existing atomic addressed rooted
batch. That batch remains the sole proof-validation and mutation boundary.

## Chain-journal reconstruction and expected heads

The [Proof Chain Journal](proof-chain-journal.md) stores no Merkle nodes. Each
entry instead stores one canonical exact-parent block and the exact ordered
canonical proof payloads named by that block's transition. Strict block replay
reconstructs the authenticated set from those payloads and verifies every
committed previous and resulting `ProofSetRoot` through `ProofChainState`.

Different valid block orderings or groupings of independent proofs may produce
the same final `ProofSetRoot`, but they produce different block ancestry and
journal entry sequences. The set root remains insertion-order-independent;
the block head and physical journal order intentionally are not.

`ProofChainJournal::open_verified` first completes lock, chain-context, format,
block-ID footer, and strict block-replay checks. It then compares the
reconstructed exact `ProofBlockId` head with one caller-supplied expected head.
A mismatch returns no journal handle and performs no incomplete-tail recovery.
Only a matching head permits tail recovery or stabilization.

The expected head must come from a separately trusted source. Under the block
hash assumptions it recursively commits every admitted block and every
transition root; strict replay verifies that the reconstructed set realizes
those commitments. A separate expected proof-set root would therefore be
redundant. Neither a head nor a root value is self-authenticating or establishes
consensus selection or finality. Exact verification rejects a valid journal
that is behind, ahead of, or on a different ancestry from the supplied head.

Likewise, a root and proof supplied together by one untrusted peer establish no
trust or freshness. Higher protocols must bind the expected root, queried
`ProofId`, and canonical proof-set-proof bytes to their own authenticated
request or response context. A previously valid proof remains valid against
its old root; this codec does not detect rollback to that root.

## Golden roots

The empty-set root is:

```text
e9a980287e770ac389d3735ff064e7447f11c9640efdb90b91781766497f16ca
```

For the all-zero `ProofId`, the singleton root is:

```text
6035299a52844d846d83ca0395e1a7df37e62b7de9adc638ea2cbaf97d799a04
```

For the set containing the all-zero key and `80` followed by 31 zero bytes,
the root is:

```text
4c77fb731087d077c434cc706d41eea1fc9aa9b324638f709747b492cbb52687
```

Adding the key of 31 zero bytes followed by `01` produces:

```text
00d65391369a613d7a56aca448277a0da7cc44e57a12a8b2159f0b1c5712c396
```

## Security boundary

The commitment relies on SHA-256 collision and second-preimage resistance.
Creating `ProofSetRoot` from arbitrary bytes establishes only an address.
Proof-set verification authenticates exact set membership relative to that
address; it does not independently replay the proof certificate, establish
that the root was selected by consensus, prove data availability, or assign
economic novelty.

In particular, a membership proof does not insert its terminal `ProofId` into
another `ProofDag`. A cited proof remains unavailable there until its complete
canonical certificate bytes have passed normal proof admission.

The order-dependent exact block ancestry and strict journal replay remain
responsible for local append-entry integrity. The exact block head commits
ancestry, while this order-independent proof-set root commits selected set
membership. Neither may be substituted for the other.
