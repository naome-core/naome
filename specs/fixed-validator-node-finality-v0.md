# Fixed-Validator Node Finality V0

## Authority and scope

This document defines the synchronous live-finality coordination boundary for
one closure-scoped fixed-validator V0 node signer. It composes the existing
sealed consensus transition or candidate-backed verification boundary,
anchored finality journal, and anchored per-key vote-safety session. It does
not create another way to select, rank, or construct a transition.

The sealed-transition ingress accepts one
`OwnedVerifiedFixedConsensusTransitionV0`. Its private fields prove that
complete typed branch verification already bound the exact parent coordinate,
consensus position, value, canonical envelope, canonical artifact payload, and
immutable child branch.

The candidate-backed direct-child ingress instead requires one exact
caller-selected unselected direct-child `ArtifactBlockId`, caller-routed
matching-chain candidate and Foundation payload stores, one complete canonical
finality envelope, and an inclusive caller-local round ceiling. The existing
candidate-backed finality boundary integrity-reads the exact retained block and
payload, fully verifies the envelope against the current selected head under
both round ceilings, and only then commits the internally sealed transition.

The separate candidate-backed conflict ingress accepts the same explicit input
shape only for a height already retained by finality. It rejects an
evidence-free value equal to the selected value before source reads, fully
verifies a preliminarily distinct value against that height's exact retained
selected parent, and admits only the existing terminal sibling-conflict result.
The stores supply availability bytes only and receive no durable mutation;
source-integrity failures retain each store's existing poison-and-reopen
boundary.

In both forms the caller explicitly chooses the one transition or target to
submit. That choice does not grant peer evidence, candidate availability, or
this coordinator any truth, preference, fork-choice, or finality authority
beyond the finality journal's existing rules. Neither candidate-backed form
discovers a target or promotes a suffix, and only the deny-only conflict form
admits a fully verified selected-height sibling without selecting either value.

The operation consumes `FixedValidatorNodeSigningScopeV0`. The scope retains a
mutable finality borrow internally, but exposes only read-only finality
diagnostics to callers. Its public `FixedValidatorNodeVotingSessionV0` facade
exposes ordinary round, vote-preparation, and key-use operations but withholds
the lower-level finality height-transition and conflict-stop methods. The
node-owned finality journal is therefore the exclusive source of height and
stop authority for this scope. Only `commit_verified_finality` and
`commit_candidate_backed_finality` may couple its height capability into the
signer. `commit_verified_finality` and the separate
`commit_candidate_backed_finality_conflict` may couple only an exact anchored
sibling-conflict capability into the signer. There is no public mutable-journal
or raw signing-session escape hatch. A continuation scope is returned only by a
complete nonterminal outcome; the candidate conflict method has no continuation
return type.

## Ordered transitions

`commit_verified_finality` applies exactly one sealed transition in this order:

1. Consume the transition through the anchored finality journal. A new record
   is published only after its journal footer and independent finality anchor
   synchronize under the existing journal contract.
2. If one new direct child finalized, issue the exact retained
   finality-to-signer height capability for that finalized height.
3. Consume that capability through the sole live signing session. The vote
   journal preflights the current lineage and pending state, appends the exact
   sequential child lineage, and advances the independent signer anchor before
   returning its prepared-height capability.
4. Acknowledge that exact anchored capability to move signer memory to the
   sealed child's round zero.
5. Only then return a replacement signing scope containing that child branch,
   the advanced node-scoped voter, and read-only diagnostics for the same
   selected finality head.

The transition is not a cross-file transaction. A later failure never removes,
replaces, rolls back, or reinterprets an earlier durable journal or anchor
step.

`commit_candidate_backed_finality` first applies the complete read-only source
and envelope verification described above. It then commits exactly one new
direct child through the same anchored finality pair and enters steps 2 through
5 of the shared signer handoff. One explicit call advances at most one height.
The candidate and payload stores are not participants in either anchored pair
and receive no durable insert, replacement, mark, refresh, or deletion from
this call.

`commit_candidate_backed_finality_conflict` consumes the scope and applies the
deny-only selected-height preflight and complete retained-parent verification
described above. A same-selected-value or unselected-height input returns an
error and no scope before source access. A distinct value can reach finality
only after complete authentication; its anchored terminal halt then enters the
same stop-capability and signer-stop sequence as the sealed-transition path.
The method returns only the paired terminal evidence after both anchors advance.

## Nonterminal outcomes

A newly selected direct child returns `Finalized` metadata naming its exact
authenticated position, ancestry identity, complete-envelope identity, and
anchored finality state identity. Continued signing authority appears only
beside this metadata after the ordered signer handoff completes.

A candidate-backed child returns `CandidateBackedFinalized` metadata naming
the exact caller-selected target plus the same authenticated position,
ancestry, complete-envelope, and finality-state identities. It returns beside
continued signing authority only after the same complete signer handoff. The
candidate-backed direct-child boundary has no replay or conflict result; stale,
deep, already-selected, or sibling input is rejected instead.

If the transition's exact value is already selected at its retained height,
the finality journal returns `AlreadyFinalized`. This classification is based
on the selected value, not on byte identity of its evidence variant: a later
round may carry a different valid envelope for the unchanged value. The
retained first envelope identity remains authoritative, neither journal or
anchor writes, and the already aligned branch and signer are returned
unchanged. The replay does not replace finality evidence or move the signer.

An unselected parent, unsupported future gap, excessive authenticated round,
terminal journal, poisoned handle, or other finality rejection returns no
continuation scope even when the rejection itself wrote no byte. This strict
consume-on-error rule prevents callers from treating error categories as a
second signing-authority protocol.

## Conflict outcome

When either eligible ingress makes the finality journal durably admit a distinct
verified sibling of an already selected value, it appends and anchors its
existing terminal conflict record. The coordinator then obtains only that
halt's opaque signer-stop capability and consumes it through the current signing
session. The stop preempts pending vote, height, or higher-round work under the
existing signer contract. The candidate-backed ingress cannot reach this step
from store presence, peer provenance, a merely decoded value, or a selected-value
replay; complete branch-relative verification is mandatory.

Only after the signer-stop record and independent vote anchor synchronize does
the coordinator return `FinalityStopped`, pairing the exact finality halt with
the matching per-key stop. It never returns a branch or signing scope from this
path. The conflict records evidence and stops; it does not choose a winning
sibling, roll back the retained selected value, or revoke bytes that a caller
already received before the stop.

## Failure and restart

Every error consumes the scope and returns no signing authority. Error stages
distinguish:

- finality commit rejection or ambiguous finality durability;
- candidate source or envelope rejection, or ambiguous candidate-backed
  finality durability;
- failure to issue height authority after known finality success;
- signer child-lineage prepare or live acknowledgement failure after known
  finality success;
- failure to issue stop authority after a known finality halt; and
- signer-stop persistence failure after a known finality halt.

Errors after a known finality result retain that `Finalized` or
`CandidateBackedFinalized` metadata or exact halt. This is diagnostic evidence
of ordering, not rollback or repair authority. A pending vote can therefore
leave a newly finalized child durable while the signer remains pending at its
prior lineage; the call returns no scope. Strict create-or-restart handling is
the only classifier for the actual anchored prefixes. Exact matching pairs may
resume through the existing recovery and selected-suffix catch-up rules. A
complete journal suffix ahead of its independent anchor remains an explicit
anchor-behind failure requiring separate operator recovery policy.

## Exclusions

This coordinator does not define or perform:

- proposal authoring or producer signing;
- consensus event routing, phase scheduling, timeouts, or asynchronous daemon
  ownership;
- proposal, vote, quorum-certificate, or competing-evidence buffering;
- network transport, peer discovery, provenance trust, or peer-selected
  admission;
- candidate discovery, branch discovery, sibling ranking or winner selection,
  rollback, source mutation, or multi-height promotion;
- cross-journal atomicity, automatic repair, or operator crash-gap recovery;
- dynamic validator sets, multi-key stop fanout, key loading, rotation, remote
  signing, or production custody; or
- non-Unix file-anchor runtime guarantees or coordinated-device rollback
  detection.

The exclusive node-owned source rule is a node integration boundary only. It
does not change the lower-level storage contract, where independently opened,
content-equivalent histories may still produce semantically equivalent opaque
capabilities for storage-layer recovery tests. Those capabilities cannot enter
this node's public voting facade.

These are separate required product capabilities, not unnecessary work. The
candidate-backed integration intentionally stops at the already decided
caller-selected one-target direct-child or deny-only conflict boundary. Any
automatic selection, peer-driven promotion, or conflict-triggering policy
requires a separate explicit authority and policy decision.
