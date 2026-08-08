# NAOME Ledger State V0

## Status and scope

This document defines the deterministic in-memory transition from one accepted
NAOME proof state to the next. It is a prerelease protocol contract and may
change before the first stable protocol release.

One transition processes exactly one Foundation V0 proof certificate. It does
not define block bytes, a block identifier, persistence, undo, reorganization,
pruning, rewards, fees, networking, or human-readable source syntax.

## State

Ledger State V0 owns one checked `ProofStateV0`. That state contains:

- one `ProofId -> DerivationId` entry for every accepted concrete proof;
- one `DerivationId -> StatementId` entry for every accepted inference DAG;
- one canonical closed conclusion for every accepted `StatementId`; and
- the canonical conclusion length required by deterministic reference-work
  accounting.

Only a successfully checked proof may add entries. Existing entries are never
replaced. Identity conflicts fail closed.

## Single-proof transition

Given one structurally valid `ProofCertificateV0` and the accepted
pre-transition state, Ledger V0 applies this order:

1. derive the certificate's canonical root-proof normal form;
2. mathematically check that normal form exactly once while resolving every
   reachable `ProofReference` exclusively from the unchanged pre-transition
   state;
3. compute its `StatementId`, `DerivationId`, and `ProofId` as specified by
   Proof Certificate V0;
4. classify the statement as `New` when its `StatementId` is absent from the
   pre-transition state, otherwise as `Existing`;
5. register the checked proof without replacing any existing state; and
6. return the three identities and the statement classification.

The candidate proof is not visible during step 2. A reference succeeds if and
only if its exact `ProofId` is present in the unchanged pre-transition state.

The existing Proof Certificate V0 limits bound the only proof processed by a
transition. Ledger V0 adds no batch or caller-configurable resource limit.

## Statement novelty

`New` and `Existing` describe only whether the exact closed `StatementId` was
present before the transition:

- an absent `StatementId` produces `New` when registration succeeds;
- a present `StatementId` produces `Existing` when a distinct derivation
  registers successfully;
- an existing `ProofId` or `DerivationId` is a registration error and produces
  no novelty result.

This classification is relative only to the selected pre-transition state. It
does not establish global theorem novelty, calculate a reward, or claim general
mathematical equivalence between structurally different statements. A later
consensus policy may use it only together with its topology, finality, fee, and
resource rules.

## Atomicity and errors

Normalization and mathematical checking do not mutate the pre-transition state.
Registration validates every proof, dependency, derivation, and statement
identity condition before inserting anything. Consequently, every error leaves
the state exactly unchanged and a successful call inserts exactly one checked
proof.

Checker errors precede registration errors. Within checking and registration,
the deterministic error order defined by Proof Certificate V0 remains
unchanged. Ledger errors retain the complete underlying `CheckError` or
`ProofStateError` as their source.

## Future block boundary

A future `BlockV0` contains exactly one proof. It must validate that proof
against an immutable accepted proof-state snapshot selected by the future
consensus protocol. A proof merely received from the network, or otherwise
absent from that selected state, is unavailable to resolve a reference.

The block topology and the rule that selects or combines accepted proof-state
snapshots remain outside this V0 contract. This includes whether proof blocks
form a linear history or a DAG.

The future block decoder must additionally require that submitted proof bytes
already equal their canonical root-proof normal form. Ledger V0 accepts the
owned certificate model and performs normalization; it does not define or
silently repair block bytes.
