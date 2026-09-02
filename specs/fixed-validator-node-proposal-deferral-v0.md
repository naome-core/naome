# Fixed-Validator Node Higher-Round Proposal Deferral V0

## Authority and scope

This document defines one synchronous, caller-routed fixed-validator V0 node
operation that fully admits one artifact-only proposal for a round strictly
higher than the node signer's current round and returns one caller-owned
in-memory token. The operation exists so proposal bytes may be checked and
retained before independently supplied quorum evidence or another existing
event advances the local signer to that round.

The token is descriptive retained input, not cached consensus authority.
Possession of it grants no round or phase advancement, vote, lock change,
signature, proposal selection, branch choice, finality, rollback, persistence,
network provenance, or peer trust. A proposal's embedded valid-round proof may
help the proposal pass complete admission, but it is not a separately supplied
higher-round catch-up certificate and never advances the node.

This boundary creates one token per successful invocation. The token is not a
singleton, collection, queue, or pool. Callers may hold multiple independent
tokens or move them into the separately specified
`FixedValidatorNodeProposalBufferV0`. This deferral contract does not own or
consult that buffer, choose its caller-local limits, or itself make uniqueness,
deduplication, replacement, eviction, arrival-order, evidence-preference, or
aggregate resource-policy claims.

## Inputs and ordered admission

The consuming `FixedValidatorNodeSigningScopeV0` operation accepts:

- complete canonical proposal-control bytes;
- the owned complete canonical artifact payload;
- a descriptive proposal round `P`; and
- an inclusive caller-local sequential-work ceiling `M`.

The route `(P, M)` is unauthenticated metadata. It cannot retarget the signer
or establish proposal validity. The proposal producer authorization must
independently authenticate the exact derived position.

Admission has this normative order:

1. Read the persisted fixed-validator finality replay ceiling.
2. Require an operational signing session with no pending vote, height, or
   higher-round checkpoint work.
3. Derive the node branch's round-zero cursor, require signer and branch height
   coherence, enforce the persisted ceiling on the current signer round, then
   enforce `M`, and sequentially reconstruct the exact current round `R`.
4. Preflight a representable `R + 1`, enforcing the persisted finality ceiling
   before `M`. This check precedes comparison of `P` and inspection of proposal
   bytes.
5. Require `P > R`.
6. Enforce the persisted finality ceiling on `P` before enforcing `M`.
7. Derive each same-branch round from `R + 1` through `P` in sequence.
8. At the sole derived round `P`, perform the unchanged complete proposal
   admission: bounded canonical framing and value decoding, exact chain and
   consensus identities, ancestry and state commitment, scheduled-proposer
   authorization, artifact block and payload validity, and any embedded
   valid-round proof.
9. Only after every check succeeds, move the exact canonical control and
   payload bytes into a new caller-owned token and return the unchanged signing
   scope.

The caller-local ceiling limits work for this invocation only. It is not a
consensus rule. Persisted-finality policy has diagnostic precedence whenever
both ceilings reject the same required round.

No live round cursor is retained after admission. Sequential derivation is
bounded by both ceilings, and the operation verifies exactly one bounded
proposal-control value and one artifact payload.

## Owned token

`FixedValidatorNodeDeferredProposalV0` has private fields, no raw constructor,
no canonical or durable encoding, and deliberately implements neither `Clone`
nor serialization. It owns:

- the verified parent coordinate, exact target position, and proposal value;
- the proposal signing root only as a value-derived accessor, not as separately
  retained state; and
- the byte-identical canonical proposal-control and complete artifact payload
  inputs that passed admission.

It owns no `FixedConsensusRoundV0`, `FixedConsensusBranchV0`, artifact-successor
snapshot, certificate capability, peer identity, signing key, voting session,
or other state-transition capability. The copied descriptors support
inspection only. They cannot be supplied back as trusted verification inputs.

The token may outlive the proposal verifier's borrowed round and the source
signing callback in the same process. Dropping it has no effect. Strict node
restart does not reconstruct it, because this operation performs no durable
write and defines no recovery format.

Consuming the token yields only the two raw canonical byte vectors. The
invocation-only caller ceiling is not retained, and the target round and
proposal root are derived from the retained position and value rather than
cached separately. Extraction explicitly discards any earlier branch-relative
verified status.

## Later authority-bearing use

The extracted raw inputs may enter only an existing authority-bearing consumer.
A current-round voting or finality consumer requires the node to have
independently reached the token's exact height and round in its required live
phase. If the signer has advanced beyond the token's round, the existing
strictly lower-round finality consumer may admit the same raw inputs only under
its own explicit lower-round route and ceilings and with an independently valid
matching non-nil precommit certificate.

Every such consumer derives its exact branch-relative round and repeats complete
proposal and artifact verification before any lock, journal, anchor, key-use,
signature, or finality effect. It does not trust the token's copied descriptors
or its earlier successful admission. Consequently:

- submission before the target round is future input and cannot vote;
- submission after the target round is stale for current-round voting, although
  the separate strictly lower-round finality contract may still evaluate it;
- input whose parent branch is no longer the live parent cannot drive
  current-round voting or direct next-height finality; an already-selected-height
  sibling is handled only by the separate existing finality-conflict contract
  after its own complete verification;
- any invalid modification to retained control or payload bytes is rejected by
  complete re-verification, while a coherently replaced valid input is evaluated
  as new raw input and inherits no validity from the former token; and
- an embedded valid-round proof does not substitute for the separately
  authenticated quorum event needed for higher-round progression.

No dedicated token-to-vote, token-to-transition, token-to-certificate, or
token-to-verified-proposal conversion exists.

## Outcomes, failures, and state

Success returns the unchanged signing scope and one token. A non-higher route,
caller-work or persisted-finality capacity failure, malformed proposal,
foreign identity, invalid proposer, invalid artifact or payload, or invalid
optional proof is a pre-effect rejection that also returns the unchanged
scope. These paths change no live position, phase, lock, valid value, finality
journal or anchor, or signer journal or anchor.

A branch/signer height mismatch, impossible exact-round derivation, exhausted
round space, current signer position above persisted policy, or non-operational
session consumes the scope and returns no token. This matches the existing node
boundary: callers must not reuse authority whose coherence or session health
could not be established. Proposal deferral itself never begins a durable
operation, so it creates no ambiguous commit or repair case.

## Exclusions

This component does not define or perform:

- ownership or implicit consultation of the separately composed volatile
  proposal buffer, protocol-wide proposal storage or limits, evidence-variant
  preference, replacement, eviction, expiry, retry, or restart reconstruction;
- proposal discovery, event observation, arrival-order policy, automatic
  certificate pairing or release, timeout measurement or scheduling, daemon
  ownership, network transport, peer discovery, provenance trust, or
  peer-selected admission;
- quorum construction, round or phase advancement, locking, signing, proposal
  or branch selection, finality, height advancement, rollback, reorganization,
  or candidate-store mutation; or
- dynamic validator sets, multi-key coordination, key loading, rotation,
  remote signing, production custody, or cross-file atomicity.

These exclusions are authority boundaries for this deferral component, not a
claim that the broader product does not require the corresponding capabilities.
The separately specified buffer supplies only bounded volatile token ownership.
The separately specified exact caller-addressed pairing coordinator supplies
one certificate-coupled release path. The consensus ledger continues to track
automatic observation and pairing, durable recovery, routing, orchestration,
and networking separately.
