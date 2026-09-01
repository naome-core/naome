# Fixed-Validator Node Proposal Authoring V0

## Authority and scope

This document defines the synchronous current-round proposal-authoring boundary
for one closure-scoped fixed-validator V0 node signer. It composes the exact
branch and complete lock state already owned by
`FixedValidatorNodeSigningScopeV0`, the deterministic current-round proposer,
complete artifact validation, and the anchored per-key signing journal. One
successful call returns canonical proposal-control bytes only after both the
complete proposal intent and its producer authorization are durable and the
independent signer anchor names each resulting journal state.

The caller explicitly supplies one availability input:

- `Fresh`, containing one caller-selected `ArtifactBlock` and its owned
  canonical artifact payload, when the signer retains no valid value; or
- `RetainedValid`, containing the owned canonical artifact payload for the
  exact value and exact earlier-round prevote certificate already retained by
  the private lock state.

The caller also supplies an inclusive local round-work ceiling. Input presence,
candidate-store membership, arrival order, routing, network receipt, or peer
provenance grants no proposal, signer, selection, or finality authority. The
node owns neither event choice nor availability policy.

### Fresh candidate-store adapter

The separate `author_candidate_backed_fresh_proposal` facade accepts one exact
caller-selected `ArtifactBlockId`, one caller-routed artifact-block candidate
store, one caller-routed canonical artifact-payload store, and the same
inclusive local round-work ceiling. It is only an availability adapter for the
`Fresh` path. The direct `author_proposal` facade remains the sole path for a
`RetainedValid` source, so local candidate-store membership cannot become a new
liveness requirement for a privately retained valid value.

Before either store is read, the adapter requires an operational session, an
exact signer/branch height, both round ceilings, bounded reconstruction of the
current round, Proposal phase, the scheduled local proposer, and no retained
valid value. It then requires the candidate store's chain identity to equal the
round context, reads exactly the caller-selected block address, and reads
exactly that block's artifact address from the Foundation-scoped payload store.
It performs no inventory, scan, fallback, ranking, or target substitution.

The two owned records are converted only into the existing `Fresh` source. The
unchanged consensus path then rechecks phase and proposer and completely
validates the block and payload against the node-owned branch snapshot before
any signer-journal effect. Missing records, a foreign candidate-store chain,
store read or integrity errors, or complete proposal-validation rejection
return the unchanged signing scope. Each source handle retains its existing
error-specific poison-and-reopen boundary, but neither source failure poisons
or mutates the signer, finality journal, branch, or other source store.

## Complete proposal intent

The live lock kernel may seal one proposal intent only in Proposal phase, for
its exact position and exact branch-derived round, and only when the local
signer equals that round's deterministic proposer. Proposer and phase checks
precede artifact work.

When no valid value is retained, `Fresh` derives the sole 268-byte V0 value from
the supplied artifact block and the node-owned round. When a valid value is
retained, `RetainedValid` must use that value byte-identically, and its retained
certificate is reverified as an exact earlier-round prevote/proposal quorum for
the same context, height, root, fixed set, and stored evidence identity. The
opposite source variant is rejected.

Both paths then strictly validate the complete canonical artifact payload as
the supplied value's immutable child of the branch-coupled artifact snapshot.
Only after all of those checks succeed may the lock kernel publish one sealed
`FixedValidatorProposalIntentV0`. The intent creates no signature and grants no
persistence or release authority by itself.

The canonical intent is:

```text
"naome:fixed-validator-proposal-intent:v0\0"[41]
|| complete_proposal_phase_state_snapshot[288..=25,572]
|| canonical_value[268]
|| scheduled_proposer[32]
```

It is therefore exactly 629..=25,913 bytes. The state snapshot is the canonical
state portion already defined by `fixed-validator-vote-safety-journal-v0.md`,
from context through optional valid-value evidence, without a vote-intent
header, role, target, or signer. Its phase tag must be `0x00` Proposal. A lock,
when present, adds exactly 276 bytes. A valid value adds 312 bytes plus one
complete 216..=24,696-byte canonical prevote certificate. The separate value
suffix must match the retained valid value exactly when that slot is present;
otherwise it must match the value derived from the exact branch and artifact
block. The proposer suffix must equal the expected scheduled proposer.

Header-bound replay verifies canonical framing, exact context, fixed-set
identity, Proposal phase, value/state consistency, proposer equality, and all
bounded retained state. It does not expose a signing transcript or completion
method. Only a newly sealed live intent can expose the existing producer-
authorization transcript and accept one signature. Completing that signature
strictly self-verifies the unchanged 212-byte producer authorization and
assembles the existing proposal-control format:

```text
canonical_value[268]
|| producer_authorization[212]
|| proof_tag[1]
|| exact_retained_prevote_certificate_or_empty
```

No new wire signature role or domain is introduced. Fresh proposals use the
existing no-proof tag. Retained-valid proposals include the exact retained
certificate and use the existing valid-round-proof tag.

## Additive journal records and activation

Proposal authoring is an additive capability of the existing per-key vote-
safety journal. Its 185-byte journal header, state-ID derivation, 256-byte
independent anchor, filename, and existing tags remain unchanged. A caller-
supplied positive `FixedValidatorProposalReplayLimitV0` is activated exactly
once in place and independently of the existing prepared-vote ceiling. Both a
fresh journal and a healthy pre-feature journal must persist and anchor that
activation before any signing session or recovery authority can be issued.
Repeating the exact limit is no-write idempotence; another limit fails typed.

The additive records use the existing frame
`body_length_u32_be || tag_u8 || payload || state_id[32]`:

| Tag | Payload | Body bytes | Frame bytes |
| ---: | --- | ---: | ---: |
| `0x07` | positive proposal replay limit as `u64` big-endian | 9 | 45 |
| `0x08` | one canonical proposal intent | 630..=25,914 | 666..=25,950 |
| `0x09` | the exact completing producer authorization | 213 | 249 |
| `0x0a` | one non-identical canonical intent for an occupied proposal position | 630..=25,914 | 666..=25,950 |

The proposal ceiling counts only new distinct `0x08` preparations. Activation,
completion, byte-identical replay, and terminal conflict do not consume another
slot. Reaching the ceiling cannot prevent a same-slot conflict from being
durably stopped. Proposal positions are strictly increasing within one signing
lineage. A proposal must not follow a vote at an equal or later position, and a
vote must not precede the latest retained proposal position. Proposal and vote
preparations share the sole pending-effect boundary.

Strict replay permits a healthy pre-feature history with no activation so node
startup can migrate it before issuing authority. It rejects repeated or zero
activation, proposal records before activation, preparations beyond the
activated ceiling or outside the retained signing lineage, duplicate or
nonmonotonic positions, invalid phase ordering, malformed intent or completion
bytes, completion without its exact preparation, records after a terminal
cause, and every chained-state mismatch. A fully prepared but uncompleted
proposal is diagnostic-only on restart: no signing session, recovery
capability, signature, or proposal bytes are issued. A completed proposal may
restore only the latest current-lineage Proposal-phase state against the exact
typed round.

## Ordered key use and exact replay

One new proposal follows this order:

1. Derive the exact node-owned current round below both persisted and caller-
   local work ceilings.
2. Check Proposal phase and scheduled-proposer equality before artifact work.
3. Fully validate the fresh or retained-valid source and seal the complete
   current-state intent.
4. Append and synchronize `0x08`, then advance the independent signer anchor.
5. Issue key-use authority only for that exact anchored preparation.
6. Sign the existing producer-authorization transcript and strictly self-
   verify the signature.
7. Append and synchronize `0x09`, then advance the signer anchor again.
8. Only then release the canonical proposal-control bytes and replacement
   signing scope.

For the candidate-store adapter, source resolution is inserted between steps 2
and 3 in this exact order: reject a retained valid value, compare the candidate
store chain, load the exact caller target, then load that block's exact payload.
Those reads grant availability only; step 3 remains the sole validity gate.

An exact live prepared repeat reuses only its matching preparation capability.
An exact completed repeat returns byte-identical proposal-control bytes without
another write or key operation. Any preparation, acknowledgement, key-use,
self-verification, completion, or anchor failure after the first signer effect
consumes the node scope; strict restart is the sole durable-prefix classifier.

A second non-identical complete intent for the same `(context, height, round,
Proposal)` slot appends and anchors `0x0a` before returning only a terminal
`FixedValidatorProposalSafetyHaltV0`. It stops this local key owner and clears
the matching pending proposal, if that exact slot is pending. Another pending
proposal or vote makes the record invalid rather than allowing it to erase
unrelated work. Each diagnostic intent digest is exactly:

```text
SHA256(
  "naome:fixed-validator-proposal-intent-digest:v0\0"
  || canonical_proposal_intent
)
```

The retained and conflicting roots and intent digests are local diagnostics.
They are not by themselves objective equivocation proof, signer attribution,
peer evidence, branch selection, or finality authority; `PROD-015` remains
separately unfinished.

## Startup and node outcomes

Fresh node creation activates and anchors proposal authoring after creating the
vote journal and before binding the initial signing lineage. Strict restart
opens both journal/anchor pairs, classifies finality and existing signer stops,
then classifies an incomplete proposal before issuing recovery authority. A
healthy older journal is activated and anchored before recovery issuance. This
ordered migration is not a header rewrite and is not cross-file atomic.

The consuming direct and candidate-backed authoring facades have three outcome
classes:

- `Authored` returns the exact durable proposal and replacement scope;
- `Rejected` returns the unchanged scope only for a caller round ceiling or
  another pre-write source or proposal-input failure; and
- `SignerStopped` returns terminal proposal-safety diagnostics and no scope.

Node coherence, session health, persistence, acknowledgement, signing, or
anchor errors are fatal and return no scope or proposal. Public callers cannot
obtain the raw proposal signing transcript, split prepare/acknowledge/key-use
stages, inject a caller-assembled intent, replace the private lock state, or
select a recovery branch.

## Exclusions

This boundary does not perform or grant:

- event selection, proposal scheduling, timeout measurement, retry policy,
  buffering, quorum construction, or an asynchronous consensus loop;
- network transport, gossip, peer discovery, provenance trust, or availability
  discovery;
- candidate ranking, discovery, ingestion, or persistence, block ordering,
  branch selection, finality, rollback, reorganization, or repair;
- dynamic validator sets, multi-key coordination, key loading, rotation,
  remote signing, hardware custody, or seed exclusivity;
- cross-file atomicity, coordinated-rollback detection, or non-Unix file-anchor
  runtime guarantees.

These are separate required product capabilities. This component does not
silently acquire their authority merely because it can now construct and
durably sign one exact local proposal.
