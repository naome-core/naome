# NAOME Authenticated Proof Set

## Status and scope

This document defines the canonical authenticated set of exact `ProofId`
values retained by one selected NAOME `ProofDag`. It is a prerelease protocol
contract and may change before the first stable protocol release.

The set is represented as a compressed binary Merkle-Patricia tree. It defines
one insertion-order-independent `ProofSetRoot` and compact membership and
non-membership proofs. It does not define a block header, consensus selection,
finality, signatures, rewards, fees, economic state, network transport, proof
wire encoding, persistent Merkle nodes, snapshots, pruning, or deletion.

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

`ProofSetProof` is currently an opaque in-process value and has no protocol
wire encoding. It represents exactly one of:

- an empty-tree terminal;
- a membership terminal whose leaf is the queried `ProofId`; or
- a non-membership terminal containing the different leaf reached while
  searching for the queried `ProofId`.

The proof also contains the root-to-terminal branch path. Each step contains
only its branch bit and sibling digest. Direction is derived from the queried
key and is not stored redundantly.

Verification is fail-closed and executes this order:

1. reject more than 256 path steps;
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

Strict proof admission remains unchanged through the ledger boundary. Decode,
canonicality, mathematical checking, dependency resolution, and identity
registration all succeed before the new record is inserted into the private
tree. Ledger duplicate rules make that insertion logically infallible. Every
failed admission leaves the record count, topology, root, and all existing
proofs unchanged.

The structure is append-only. Deletion, undo, and state merging require future
consensus and persistence contracts and are not inferred here.

## Journal reconstruction and expected roots

The Proof DAG Journal stores no Merkle nodes or roots. Strict dependency-first
replay reconstructs the authenticated set from canonical proof payloads.
Different physical orders of mutually admissible independent proofs produce
different journal digest chains but the same `ProofSetRoot`.

`ProofDagJournal::open_verified` first completes every lock, format, digest,
strict replay, tail recovery, and stabilization check. It then compares the
root of the complete replayed state with one caller-supplied expected root. A
mismatch returns no journal handle.

The expected root must come from a separately trusted source. A root value is
not self-authenticating and does not itself provide consensus selection or
finality. Exact verification also rejects a valid journal that is either
behind or ahead of the supplied complete-state root.

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

The order-dependent journal digest remains responsible for local append-chain
integrity. It must not be replaced by the order-independent proof-set root.
