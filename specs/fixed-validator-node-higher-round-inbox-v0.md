# Fixed-Validator Node Higher-Round Inbox V0

## Authority and scope

This document defines one caller-owned, process-local fixed-validator V0 inbox
for fully admitted higher-round proposal tokens and individually authenticated
proposal prevotes. The inbox may outlive successive closure-scoped node signing
callbacks in one process. It is not contained in node startup or signer state,
has no canonical or durable encoding, and is empty after runtime-owner or
process loss.

The inbox is an explicit composition above the existing proposal token, proposal
buffer, exact signed-vote verifier, fixed typed round, canonical exact-batch
certificate builder, and buffered proposal/precommit coordinator. It grants no
new validity to any retained input. Every proposal token was fully admitted
before insertion, every prevote is admitted against one exact typed round before
insertion, and the selected proposal and prevote batch are fully verified again
against live node state before any durable effect.

Neither insertion nor retention advances a round or phase, changes a lock or
valid value, constructs a signing intent, writes an authority file, or selects a
proposal, certificate, branch, or finalized value. Pairing occurs only when the
caller explicitly invokes `try_pair_higher_round_inbox_at` with an exact
position and inclusive caller-local round-work ceiling.

## Combined local limits and representation

Construction requires two positive caller-local limits:

- a maximum combined retained entry count; and
- a maximum combined canonical-input byte count.

One proposal token contributes one entry and exactly
`canonical_proposal_control_bytes.len() + canonical_artifact_bytes.len()` bytes.
One distinct proposal-prevote variant contributes one entry and exactly the
fixed 214-byte canonical signed-vote length. Every conversion, item increment,
and byte sum is checked. The inner proposal buffer uses the same upper limits,
but is private and cannot be mutated independently of the combined accounting.

The byte count is a logical retained-input bound. It does not include collection
metadata, fixed descriptors, collection spare capacity, or temporary
selection/reverification copies. The inbox's newly introduced vote-storage and
selection-scratch reservations plus its explicit proposal-address copies are
fallible and reject without mutation. Downstream certificate construction and
encoding retain their existing allocation behavior, so these local limits are
not a protocol-wide resource schedule or a claim that allocation cannot abort.

The inbox and its entries are not cloneable. A retained prevote owns its sole
canonical bytes plus descriptive parent-coordinate, position, proposal-root,
and signer fields derived during typed admission. Those descriptors are private
indexing aids, not cached authority.

## Proposal insertion

Proposal insertion accepts one owned `FixedValidatorNodeDeferredProposalV0` and
uses the existing exact control-plus-artifact duplicate identity. In a healthy
inbox, an exact duplicate is no-growth idempotence and returns the attempted
token intact before capacity checks. A byte-distinct proposal-evidence variant
for the same root, and a proposal for a competing root, are independently
retained whenever the combined limits and fallible collection reservation fit.

For a nonduplicate, the operation checks the prospective combined entry and byte
totals before mutating the private proposal buffer. Declared-capacity or checked
arithmetic failure returns the attempted token intact, retains every prior
input, and latches the exact saturation reason. Inner collection-reservation
failure returns the attempted token and source while leaving the healthy inbox,
all entries, and all counters unchanged.

## Exact typed-round prevote admission

Proposal-prevote insertion takes one caller-derived `FixedConsensusRoundV0` and
one complete canonical signed-vote byte string. A saturated inbox rejects before
input inspection. Otherwise the typed round:

1. strictly decodes the fixed-length vote and verifies its canonical branch
   context and Ed25519 signature;
2. requires the authenticated height and round to equal the typed round;
3. requires the `Prevote` role and a non-nil proposal target; and
4. requires the authenticated signer to be present in that round's immutable
   active fixed-validator snapshot.

This admits only an opaque proposal root. It does not establish proposal
availability or validity and does not establish quorum. The round's complete
parent coordinate is retained with the canonical vote so an equal
context/position vote admitted for another branch-relative round cannot be used
by this pairing operation.

Within one parent coordinate, exact canonical vote replay is no-growth
idempotence before capacity. A byte-distinct valid signature variant for the
same semantic `(position, role, target, signer)` vote is independently retained;
it is not target equivocation. A valid same-signer prevote for another proposal
root is also retained independently and may later contribute that signer's
weight once to that distinct target. Capacity or accounting failure latches
saturation without retaining the attempted vote. Collection reservation failure
leaves the healthy inbox unchanged.

## Deny-only saturation and explicit recovery

Saturation preserves the exact pre-attempt retained set and byte count. It denies
every later proposal or prevote insertion and every `try_pair` operation,
including one whose desired inputs were already retained. This prevents an
arrival-dependent retained prefix from silently becoming an actionable set
after a later distinct input was denied.

The sole recovery operation atomically drains every owned proposal token and
canonical prevote, clears both counters and the saturation marker, and restores
the same inbox owner to healthy empty. Proposal items are yielded before vote
items only as collection detail. Drain order grants no evidence, proposal, or
consensus preference. No height, round, timeout, finality event, or age
automatically prunes, drains, or resets the inbox.

## Explicit-position pairing and local preference

Pairing consumes one live node signing scope and borrows the inbox. Before inbox
selection it preserves the existing buffered-proposal coordinator's ordered
session, branch-height, current-round, first-successor, persisted-finality-round,
and caller-round-work preflight. The caller-selected position must name the live
branch's next height, be strictly above the signer round, and fit both ceilings.
Saturation is then checked before retained-set inspection.

Selection considers only entries admitted for the live branch's complete parent
coordinate and the caller-selected exact position. It is deterministic over
that complete retained unsaturated snapshot at the instant of this call:

1. Group retained non-nil prevotes by proposal root.
2. Within each `(root, signer)` group, choose the lexicographically smallest
   complete 214-byte canonical signed vote. Because every other canonical field
   is equal in that group, this is also the smallest signature variant.
3. Build and fully verify one exact certificate from those distinct active
   signers. Each signer contributes weight at most once to that root. A signer
   that validly voted for multiple roots may contribute once to each; the roots'
   weights are never combined.
4. Treat a root as actionable for this operation only when the selected votes
   have strict greater-than-two-thirds weight and at least one matching admitted
   proposal token is retained. A vote-only quorum remains authenticated evidence
   for other separately authorized round-progression paths; proposal absence
   means only that it is not pairable here.
5. If no root is actionable, return a typed no-effect rejection. If two or more
   roots are actionable, return a typed ambiguity naming the lexicographically
   first two roots and leave all evidence unchanged. This fail-closed result
   neither chooses a fork nor classifies, punishes, or finalizes equivocation.
6. For exactly one actionable root, choose the proposal-evidence variant by
   lexicographic tuple order over
   `(canonical_proposal_control_bytes, canonical_artifact_bytes)`. Unchosen
   proposal and signature variants remain retained.

The selected vote variants form the complete signer set present for that root
in this inbox snapshot. The resulting certificate is canonical for those exact
selected inputs, but the operation does not claim a globally canonical signer
subset or evidence representative. A later call or another node may have a
different retained set because caller invocation time and network view remain
external.

## Reverification, durable effect, and outcomes

After unique selection, the implementation fallibly copies only the two exact
proposal address strings needed to enter the unchanged private proposal-buffer
lease boundary. It then invokes the existing prebuilt-certificate buffered
proposal coordinator. That coordinator leases only the selected exact token,
makes its separately bounded payload copy, rederives the exact branch round,
fully readmits proposal control and artifact state, and fully verifies the
constructed certificate before any durable work.

Only that complete pair may append and anchor the higher-round checkpoint,
publish the live `P/Prevote` state, repeat proposal admission, apply the quorum to
lock and retain the proposal, and execute the existing persist-anchor-sign-
complete-anchor precommit sequence. Only after the completed signed precommit
exists does the proposal lease release and combined inbox accounting remove that
one selected token. Every retained prevote, every other proposal variant for the
same root, and every competing-root proposal remain unchanged. The finality
journal and anchor are not written.

Every pre-effect route, capacity, saturation, inbox reservation or address-copy
failure, no-action, ambiguity, proposal, or certificate rejection returns the
unchanged signing scope and inbox. Every fatal or post-checkpoint path retains
the existing no-scope and strict-anchored-restart boundary while the private
proposal lease restores the selected token and every vote remains retained. A
durable same-slot signer stop returns no signing scope; it does not consume inbox
evidence. No path rolls back, repairs, retries, or changes finality.

## Restart and exclusions

The caller may retain this inbox while strictly reopening signer journals in the
same process, but reopen neither reconstructs nor validates it. Runtime-owner
loss or process termination drops all entries, and a fresh inbox is empty.

This component does not define or perform:

- network receipt, peer discovery, peer provenance or trust, relay, gossip,
  delivery-completeness inference, or peer-selected admission;
- automatic event observation, pairing, routing, timeout measurement or expiry,
  scheduling, retries, daemon ownership, or lifecycle attachment;
- protocol-wide/canonical/durable evidence retention, evidence preference,
  replacement, eviction, expiry, admission priority, or resource constants;
- equivocation punishment, slashing, branch or sibling selection, finality,
  height advancement, rollback, reorganization, or candidate promotion;
- durable inbox encoding, restart reconstruction, reconciliation, repair,
  migration, or cross-file atomicity; or
- dynamic validator sets, multi-key coordination, key loading, rotation, remote
  signing, hardware monotonicity, or production key custody.

These exclusions are authority boundaries for this explicit local inbox, not
claims that the broader product can omit those capabilities.
