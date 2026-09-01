# Fixed-Validator Node Finality V0

## Authority and scope

This document defines the synchronous live-finality coordination boundary for
one closure-scoped fixed-validator V0 node signer. It composes the existing
sealed consensus transition, anchored finality journal, and anchored per-key
vote-safety session. It does not create another way to verify, select, rank, or
construct a transition.

The sole ingress is one `OwnedVerifiedFixedConsensusTransitionV0`. Its private
fields prove that complete typed branch verification already bound the exact
parent coordinate, consensus position, value, canonical envelope, canonical
artifact payload, and immutable child branch. The caller still chooses which
already sealed transition to submit. That choice does not grant peer evidence,
candidate availability, or this coordinator any truth, preference, fork-choice,
or finality authority beyond the finality journal's existing rules.

The operation consumes `FixedValidatorNodeSigningScopeV0`. The scope retains a
mutable finality borrow internally, but exposes only read-only finality
diagnostics to callers. Its public `FixedValidatorNodeVotingSessionV0` facade
exposes ordinary round, vote-preparation, and key-use operations but withholds
the lower-level finality height-transition and conflict-stop methods. The
node-owned finality journal is therefore the exclusive source of height and
stop authority for this scope, and only `commit_verified_finality` may couple
those capabilities into the signer. There is no public mutable-journal or raw
signing-session escape hatch. A continuation scope is returned only by a
complete nonterminal outcome.

## Ordered transition

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

## Nonterminal outcomes

A newly selected direct child returns `Finalized` metadata naming its exact
authenticated position, ancestry identity, complete-envelope identity, and
anchored finality state identity. Continued signing authority appears only
beside this metadata after the ordered signer handoff completes.

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

When the finality journal durably admits a distinct verified sibling of an
already selected value, it appends and anchors its existing terminal conflict
record. The coordinator then obtains only that halt's opaque signer-stop
capability and consumes it through the current signing session. The stop
preempts pending vote, height, or higher-round work under the existing signer
contract.

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
- failure to issue height authority after known finality success;
- signer child-lineage prepare or live acknowledgement failure after known
  finality success;
- failure to issue stop authority after a known finality halt; and
- signer-stop persistence failure after a known finality halt.

Errors after a known finality result retain that `Finalized` metadata or exact
halt. This is diagnostic evidence of ordering, not rollback or repair
authority. A pending vote can therefore leave a newly finalized child durable
while the signer remains pending at its prior lineage; the call returns no
scope. Strict create-or-restart handling is the only classifier for the actual
anchored prefixes. Exact matching pairs may resume through the existing
recovery and selected-suffix catch-up rules. A complete journal suffix ahead of
its independent anchor remains an explicit anchor-behind failure requiring
separate operator recovery policy.

## Exclusions

This coordinator does not define or perform:

- proposal authoring or producer signing;
- consensus event routing, phase scheduling, timeouts, or asynchronous daemon
  ownership;
- proposal, vote, quorum-certificate, or competing-evidence buffering;
- network transport, peer discovery, provenance trust, or peer-selected
  admission;
- candidate or payload lookup, branch discovery, sibling ranking, rollback, or
  multi-height promotion;
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
next candidate-backed integration may reuse this coordinator only after a
caller explicitly chooses the target and the existing stores strictly verify
its retained bytes into the same sealed-transition authority boundary.
