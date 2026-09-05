# Authenticated artifact set

The selected exact `ArtifactId` set is a compressed binary Merkle-Patricia tree.
It has one insertion-order-independent `ArtifactSetRoot` and compact membership
and non-membership proofs. Its sole key is the complete 32-byte `ArtifactId`.
Typed payloads, `ProofId`, `DefinitionId`, statement and derivation identities,
conclusions, and dependency indexes are not separately hashed into this set.

### Key bits and topology

Bits are read most-significant first:

```text
bit(key, d) = (key[d / 8] >> (7 - (d mod 8))) & 1
```

For `d` in `0..=255` and finite key set `S`:

```text
Tree(empty) = Empty
Tree({key}) = Leaf(key)
Tree(S)     = Branch(d, Tree(S0), Tree(S1))
```

For more than one key, `d` is the first differing bit; `S0` and `S1` are the
nonempty zero- and one-bit subsets. Every branch therefore has two nonempty
children, branch bits increase strictly from root to leaf, and a nonempty
`n`-key tree has `n` leaves and `n - 1` branches. There are no empty, unary, or
extension nodes. Lookup, insertion, projection, and one proof path traverse at
most 256 branches.

### Hash transcript

Every digest is SHA-256 under the exact trailing-NUL domain:

```text
artifact_set_domain = "naome:artifact-set:v0\0"

E = SHA256(artifact_set_domain || 00)
L(key) = SHA256(artifact_set_domain || 01 || key[32])
B(d, left, right) = SHA256(
  artifact_set_domain || 02 || d_u8 || left[32] || right[32]
)
```

`E` is the empty root. Branch children are ordered with zero left and one right;
the discriminating bit is authenticated content.

### Compact set proofs

A proof has an empty-tree, membership, or non-membership terminal. A non-member
terminal contains the different leaf reached by the query. The root-to-terminal
path stores only the branch bit and sibling digest because direction derives
from the queried `ArtifactId`.

```text
Empty     = 00
Member    = 01 | Path
NonMember = 02 | terminal_artifact_id[32] | Path

Path = Step*
Step = branch_bit u8 | sibling_digest[32]
```

The complete input boundary determines the count. A membership proof can cover
all 256 bit positions and is at most 8,449 bytes. A non-membership proof can
cover at most 255 positions and is at most 8,448 bytes because its terminal key
must differ at another bit.

Decoding rejects oversize input before allocation, unknown or incomplete
terminals, partial 33-byte steps, excessive paths, non-increasing branch bits,
empty siblings, and a path after an empty terminal. This establishes structure
only. Verification additionally requires the non-member key to differ from the
query and follow the same authenticated path, folds the terminal digest back to
the root using query directions, and returns membership only after equality with
the trusted expected root.

The empty-set root is:

```text
976e576ec6145d57b5e192d1c37a0938bb5c76663532d0354fcd98ba3fbf597a
```

For all-zero `ArtifactId`, the singleton root is:

```text
f8d94326ff427a5311fd43c28524588f5fa955cb1b1be096a34b1b724c103963
```

For all-zero plus `80` followed by 31 zero bytes, the root is:

```text
f89fb7c7336af38296e54143f3111c23dc352f8795ed76742549767ea42880a5
```

Adding 31 zero bytes followed by `01` produces:

```text
c8ecb7085200b45d99f505bd00fa791d0fdd2bbfc3d65014b89aa9491095d768
```

An `ArtifactSetRoot` or verified witness authenticates set membership relative
to a caller-trusted root only. It does not check payloads, establish ancestry,
prove availability, select a fork, or establish finality.

### Integration and projection

Strict typed admission, dependency resolution, expected-address comparison,
and registration all succeed before tree insertion. Duplicate rules then make
insertion logically infallible. Failed admission changes neither record count,
topology, root, nor existing witnesses.

Block preparation and preflight project the root produced by one `ArtifactId`
without mutating records or topology. Projection performs no payload decode,
checking, dependency resolution, or registry admission and must not clone or
scan the selected set. Journal replay stores no Merkle nodes; it reconstructs
and verifies the set through strict block application.
