# Selected artifact state and admission

Selected in-memory `ArtifactState` contains:

- `ProofId -> DerivationId` for every selected concrete proof;
- `DerivationId -> StatementId` for every selected inference DAG;
- one canonical primitive conclusion and encoded length for every selected
  statement; and
- one exact checked, primitive, self-contained graph for every selected
  `DefinitionId`.

Only strict proof or definition admission may add entries. Existing identities
are never replaced. State grows monotonically but is not an order-free CRDT:
dependency availability and duplicate derivation rules make admission depend on
the selected prefix.

### Typed payload and strict admission

One externally admitted payload is:

```text
artifact = type_tag u8 | typed_payload

00 | canonical proof certificate
01 | canonical definition certificate
```

The envelope has no inner length, is at most 4,194,305 bytes, and must end with
its typed payload. Exact definition encoding and semantics are specified in
[Mathematical Definitions](mathematical-definitions.md).

Strict addressed admission executes:

1. decode one complete tagged payload;
2. for a proof, derive root-proof normal form and require the submitted inner
   bytes to equal it; for a definition, require exact canonical re-encoding;
3. check the proof or conservative definition against unchanged selected
   artifact state;
4. derive `ArtifactId` from the resulting `ProofId` or `DefinitionId`;
5. require it to equal the immutable expected `ArtifactId`;
6. revalidate duplicates and every direct selected dependency; and
7. atomically register one accepted record.

Decode errors precede canonicality errors; canonicality precedes mathematical
checking; checking precedes expected-address comparison; address mismatch
precedes registration failure. The expected address is request context, never a
trusted payload field. Every failure leaves all selected state unchanged.

The owned-certificate authoring path may normalize a proof before checking and
registration. It is not an external byte-admission substitute. Definitions
have one canonical encoding and are never normalized from another form.

### Accepted records and artifact DAG

An accepted proof record contains the exact tagged canonical payload; its
`ArtifactId`, `ProofId`, `DerivationId`, and `StatementId`; directly cited
`ProofId` values in normal-form step order; and unique direct `DefinitionId`
values in canonical occurrence order. An accepted definition record contains
the exact tagged payload; its `ArtifactId` and `DefinitionId`; and its optional
derived obligation `StatementId`. Definition certificates contain no selected
definition or proof address.

Dependencies are direct, not transitive. Accepted bytes and dependency lists are
immutable. Callers cannot insert unchecked records, identities, edges, or set
leaves. Registration rechecks direct dependencies so a checked value cannot be
moved from a different selected context. The canonical proof library owns its
checked DAG and matching publication
provenance within the complete ledger state. `naome-storage::state` is the sole
durable selected-history owner; strict replay reconstructs the complete state
and its library. Standalone artifact admission remains available for offline
proof and definition checking and supplies no finality or publication authority.
See [component ownership](ownership.md).

Duplicate concrete proofs, derivations, and definitions are rejected. Multiple
different checked derivations may establish one `StatementId`, but selecting a
second packaging of an already selected derivation is rejected. Identity
collision checks are fail-closed.
