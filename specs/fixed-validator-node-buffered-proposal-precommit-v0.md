# Fixed-Validator Node Buffered Proposal Precommit V0

## Authority and scope

This document defines one synchronous, exact-addressed composition for a live
fixed-validator V0 signer. It pairs one caller-owned volatile proposal-buffer
entry with one caller-supplied canonical higher-round quorum certificate. A
successful call catches the signer up to the proposal's exact round, locks and
retains that proposal, durably signs its matching precommit, and only then
removes and losslessly returns the exact buffered token.

The consuming operation is exposed on `FixedValidatorNodeSigningScopeV0`. The
caller separately owns and mutably supplies one
`FixedValidatorNodeProposalBufferV0`, both complete canonical byte strings that
address one exact retained token, one complete canonical quorum certificate,
and one inclusive caller-local round-work ceiling. Neither the buffer nor the
coordinator searches by round or proposal root, observes events, constructs a
certificate, or chooses among retained tokens or competing evidence.

The sole actionable certificate is an authenticated quorum at the token's
exact `(height, round)`, with `Prevote` role and
`Proposal(token.proposal_signing_root())` target. A prevote/nil certificate
does not release a proposal. A precommit certificate remains evidence for the
separate finality boundary and does not enter this operation.

## Ordered preflight and exact admission

Before borrowing or inspecting one retained token, the coordinator:

1. requires an operational signing session with no pending proposal, vote,
   height, or higher-round work;
2. derives the signer's exact current branch round, requiring the branch next
   height to equal the signer height;
3. requires the current round to fit the persisted finality replay ceiling and
   caller-local ceiling; and
4. preflights representable `R + 1` capacity, reporting the persisted finality
   ceiling before the caller ceiling where both reject that first successor.

Only then does healthy-buffer exact access compare both caller-supplied byte
strings. Saturation rejects ordinary pairing under the buffer's existing
deny-only contract. A missing pair changes nothing. The operation temporarily
leases only an exact match; the lease is private, gives no caller access, and
restores the same token and checked byte accounting on every path except
completed signed success.

For the leased token, the coordinator requires its authenticated proposal
round `P` to satisfy `P > R` and both round ceilings, with persisted-finality
precedence where both reject `P`. It makes one bounded, fallible temporary copy
of the token's canonical artifact payload so that the original owned token can
remain recoverable until the whole operation succeeds. It sequentially
derives the node-owned branch round `P` and completely repeats proposal-control,
producer, optional-valid-round-proof, artifact, payload, and state-transition
verification. The token's copied descriptors grant no cached validity.

The lock kernel then strictly frames and fully verifies the supplied quorum
against that exact branch-derived fixed-set snapshot. After verification, but
before certificate copying, checkpoint encoding, or storage append, it requires
the quorum's authenticated position, role, and target to equal respectively
the proposal position, `Prevote`, and `Proposal(proposal_root)`. Wrong-round,
wrong-role, nil, competing-root, malformed, foreign, duplicate, inactive,
invalid-signature, or insufficient evidence is a mutation-free rejection.

## Durable catch-up and signing sequence

Only complete proposal admission and exact quorum matching may enter this
ordered sequence:

1. Derive the existing source-bound higher-round transition from the verified
   quorum, preserving the complete prior lock and valid-value state.
2. Append and synchronize its complete higher-round checkpoint.
3. Advance the independent vote-safety anchor to that checkpoint.
4. Acknowledge the exact prepared checkpoint in the same live session and
   publish only `P/Prevote`.
5. Re-admit the same recovered raw proposal-control and copied payload against
   the now-live exact round `P`.
6. Reapply the same canonical prevote/proposal quorum through the ordinary
   current-round lock kernel, which locks and retains the proposal and derives
   only its matching precommit intent.
7. Persist and anchor the complete precommit intent, authorize key use, sign
   and self-verify the canonical vote, persist completion, and advance the
   independent anchor.
8. Only after the completed signed precommit is available, remove the leased
   exact token and return it together with the vote and replacement scope.

The higher-round checkpoint and precommit are distinct durable operations, not
one cross-file atomic transaction. The finality journal and anchor are never
written by this composition.

## Outcomes, failures, and restart

A missing token, saturated buffer, token round at or below the signer, caller
or persisted destination-capacity failure, payload-copy reservation failure,
complete proposal rejection, or exact-quorum rejection occurs before durable
mutation. It returns the unchanged signing scope, restores the leased token if
one was taken, preserves every sibling token and counter, and changes neither
signer nor finality authority files.

A branch/signer mismatch, impossible current- or target-round derivation,
exhausted round space, signer already above persisted policy, non-operational
session, or internal transition invariant failure consumes the scope. Once the
higher-round checkpoint path begins, any checkpoint append, anchor,
acknowledgement, repeated-admission, decision, vote preparation, key-use,
completion, or completion-anchor failure also returns no scope and no signed
vote. The private lease still restores the exact token, but its presence grants
no retry authority. Strict anchored restart is the sole classifier of the
possibly durable signer prefix.

A same-slot conflict discovered by the existing vote-safety path returns only
the durable signer-stop evidence, no replacement scope, and no proposal token;
the separately owned buffer retains the leased token. No failure performs
rollback, repair, automatic retry, or finality mutation.

Successful return proves only that the one exact precommit and token removal
completed in this process. The returned token is byte-identical to the
addressed input pair. Every other buffered token, including another evidence
variant for the same root or a competing root, remains retained without
preference. Strict reopen independently restores the anchored signer at
`P/Precommit` with the exact lock and complete valid-value proof; the volatile
buffer itself still has no restart reconstruction.

## Public API boundary and exclusions

The public node coordinator is consuming and indivisible. Exact proposal
leasing is private, and the node facade exposes none of its split checkpoint,
acknowledgement, lock-effect, vote-preparation, key-use, or completion stages.
Lower consensus and storage crates retain their separately typed transition and
durability capabilities under their existing contracts. The existing general
higher-round progression and current-round voting methods remain separately
available; this operation does not weaken or reinterpret them.

This component does not define or perform:

- proposal or certificate discovery, vote observation, accumulation,
  delivery-completeness inference, construction, filtering, grouping,
  competing-evidence choice, arrival-order preference, or automatic pairing;
- event routing, timeout measurement or expiry, scheduling, retry ordering,
  daemon ownership, network transport, peer discovery, provenance trust, or
  peer-selected admission;
- finality, height advancement, branch or sibling selection, rollback,
  reorganization, candidate promotion, or candidate/payload-store mutation;
- protocol-wide or durable proposal buffering, restart reconstruction,
  reconciliation, crash-gap repair, or cross-file atomicity; or
- dynamic validator sets, multi-key coordination, key loading, rotation,
  remote signing, hardware monotonicity, or production key custody.

These are authority boundaries for this exact synchronous composition, not
claims that the broader product can omit those capabilities. Later routing and
daemon work may invoke this operation only after independently deciding which
exact already-retained token and complete certificate to supply; it must not
turn buffer presence, arrival order, or peer provenance into consensus truth or
selection authority.
