# ADR 0001: Define an independent ZFC Foundation V0

## Status

Accepted for Foundation V0.

## Problem

NAOME cannot validate theorem or definition blocks before the protocol fixes the formal language, inference boundary, and mathematical axioms relative to which those blocks are valid.

## Decision

Foundation V0 is an independent NAOME formal system consisting of:

- a locally nameless abstract syntax for first-order set theory;
- classical first-order logic with equality;
- modus ponens and generalization as primitive inference rules;
- seven fixed set-theory axioms;
- Separation and Replacement as parameterized axiom schemas; and
- explicit schema side-condition validation.

The seven fixed axioms are Extensionality, Pairing, Union, Power Set, Infinity, Foundation, and Choice. Together with Separation and Replacement they form the conventional nine ZFC axiom groups selected for NAOME.

Bound variables use De Bruijn indices. Human-readable variable names are deliberately excluded from the mathematical identity of a formula. Free variables use numeric identifiers and serve as explicit schema parameters.

Metamath is prior art for understanding how a small trusted base can represent first-order logic and ZFC. Foundation V0 does not consume Metamath source, use its verifier, or promise format or proof compatibility.

## Definition boundary

Foundation V0 introduces no mathematical definitions. Empty set notation, pairs, functions, natural numbers, arithmetic, and all other derived concepts must be introduced by later definition and theorem blocks.

Definition admission is a separate protocol contract. In particular, constants and functions will require referenced existence and uniqueness proofs rather than becoming unchecked axioms.

## Alternatives considered

- **Adopt Metamath directly:** rejected because NAOME requires its own canonical object model and protocol evolution boundary.
- **Start with a checker before fixing a foundation:** rejected because validity would be undefined.
- **Embed familiar mathematical constants:** rejected because this would enlarge the trusted base and bypass the intended dependency graph.
- **Minimize the ZFC axiom list by deriving Pairing or Separation:** deferred. The conventional presentation is easier to audit, while a smaller equivalent basis would increase bootstrap proof complexity.
- **Use named binders internally:** rejected because alpha-equivalent formulas would have different structural identities.

## Failure modes addressed

- dangling bound-variable indices;
- accidental variable capture;
- undeclared schema parameters;
- schema result variables occurring in predicates;
- duplicate or colliding role variables;
- ambiguous or mutable foundation identity; and
- silently treating derived notation as primitive mathematics.

## Compatibility

Foundation V0 is the first foundation contract and has no predecessor. Any future semantic change creates a new foundation identifier; it does not mutate `naome:zfc:v0`.

Canonical byte encoding and content hashing are intentionally deferred. The Rust values in this change establish structural identity only and must not yet be serialized as a consensus format.

## Acceptance criteria

- every Foundation V0 primitive is represented by dependency-free Rust types;
- every fixed ZFC axiom expands to a closed, well-formed primitive formula;
- Separation and Replacement accept declared parameters and reject invalid side conditions;
- alpha-renamed binders have identical structural representations;
- derived connectives expand to primitive formula nodes; and
- the workspace formatting, documentation, lint, test, and release gates pass.

## Non-goals

- parsing source notation;
- verifying complete proofs;
- canonical serialization or hashing;
- definition blocks;
- importing a theorem library;
- blockchain, consensus, storage, or networking; and
- claiming consistency, independence, or semantic completeness of ZFC.

## Open risks

- The selected Hilbert-style logical basis and pure-set formulation of Choice require independent formal review before Foundation V0 can be treated as a production consensus boundary.
- This change checks structural well-formedness and schema side conditions, not semantic soundness or complete proof derivations.
- Resource limits for adversarial formulas belong to the checker contract and remain unspecified.
