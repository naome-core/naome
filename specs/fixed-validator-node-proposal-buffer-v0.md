# Fixed-Validator Node Proposal Buffer V0

## Authority and scope

This document defines one separately composed, process-local buffer for fully
admitted fixed-validator V0 higher-round proposal tokens. The caller constructs
one `FixedValidatorNodeProposalBufferV0` outside a closure-scoped signing
coordinator and may mutably capture that same owner in successive coordinator
callbacks. The buffer, rather than the caller as individual-token owner, owns
every successfully inserted `FixedValidatorNodeDeferredProposalV0` until exact
retrieval, explicit drain-and-reset, or drop.

Neither `FixedValidatorNodeReadyV0` nor `FixedValidatorNodeSigningScopeV0`
constructs, contains, recovers, or implicitly consults this buffer. The existing
direct deferral operation remains public and may still return tokens that never
enter this buffer. Consequently the limits below bound only tokens successfully
inserted into this exact buffer owner. They are not a process-global proposal
limit, network admission policy, or consensus validity rule.

## Local limits and retained representation

Construction requires two positive caller-local limits:

- a maximum retained entry count; and
- a maximum aggregate canonical-input byte count.

For each retained token, the logical byte count is exactly
`canonical_proposal_control_bytes.len() + canonical_artifact_bytes.len()`, with
every conversion and sum checked. The aggregate limit does not claim to count
allocator metadata, collection capacity, or fixed per-entry Rust metadata; the
positive item limit bounds the number of those entries independently.

Every `PROD-080-001` token is constructed with its private canonical control and
artifact owners normalized to exact-length boxed slices before it can be offered
to this buffer. A caller-provided artifact `Vec` therefore cannot carry unused
spare capacity into retained token storage. Consuming the token still returns
the unchanged public pair of owned raw `Vec<u8>` inputs.

The buffer and its entries are not cloneable and have no canonical or durable
encoding. It adds no proposal, envelope, semantic-message, or consensus identity
domain.

## Exact insertion

Insertion accepts only one owned `FixedValidatorNodeDeferredProposalV0` that was
already produced by complete proposal and payload admission. It applies this
order:

1. If the buffer is saturated, reject immediately with the retained saturation
   reason and return the attempted token intact.
2. Compare both complete canonical byte strings against every retained token.
   If both strings exactly match one entry, return the attempted duplicate
   intact as no-growth idempotence. This comparison precedes capacity, so an
   exact duplicate at both exact limits does not saturate.
3. Compute the prospective item count, this token's two-length byte sum, and the
   prospective aggregate byte count with checked arithmetic.
4. If either caller limit would be exceeded, or either count cannot be
   represented, retain none of the attempted token, preserve every existing
   entry and both published counters, return the attempted token intact, and
   enter the corresponding immutable saturated state. A capacity report exposes
   both prospective totals and both limits, so simultaneous excess has no
   diagnostic precedence.
5. Fallibly reserve one collection slot before mutation. Collection-reservation
   failure returns the attempted token and source error while leaving entries,
   counters, and healthy state unchanged. The collection error may represent
   collection-capacity overflow or allocator exhaustion and is not reclassified
   as a declared-capacity or checked byte-accounting decision.
6. Move the unique token into the buffer and publish the already checked
   aggregate byte count.

Only exact equality of the two raw canonical inputs is duplicate identity.
Parent coordinates, positions, proposal roots, and values are diagnostics, not
deduplication or preference keys. Distinct valid proposal-control evidence for
one unchanged proposal root is retained independently, as is each distinct
competing proposal root, whenever both checked limits fit and collection
reservation succeeds. The buffer exposes no
ordinary healthy-state first-entry, iteration, round/root lookup, ranking,
replacement, or eviction operation. The all-entry drain described below is the
sole iteration exception.

## Saturation and explicit recovery

Saturation is a deny-only local state. It preserves the pre-attempt retained
multiset and byte count, rejects every later insertion with its attempted token
intact, and denies ordinary exact retrieval even for an entry known to be
present. The only recovery operation atomically removes every retained entry,
clears the byte count and saturation marker, and returns a lossless owning drain
iterator from the now healthy empty buffer. Drain order is collection detail and
has no consensus, proposal, or evidence preference meaning.

This deny-only guarantee is buffer-local. It prevents a buffer-retained token
from being returned through the ordinary buffer API while saturated. It cannot
revoke the overflow token returned to the caller, another directly retained
token, or equivalent raw bytes held elsewhere.

No height, round, timeout, finality, age, or arrival event automatically prunes
or resets the buffer. Old entries may continue consuming the caller's local
capacity until exact healthy retrieval or explicit drain-and-reset.

## Exact retrieval and later verification

Healthy retrieval requires both complete canonical proposal-control bytes and
complete canonical artifact bytes. A missing pair changes nothing. An exact
match removes only that token and subtracts only its checked logical byte count.
The operation accepts no position, proposal root, certificate, peer identity,
or preferred-evidence selector.

The retrieved value remains the same inert deferred token. Its descriptors are
not cached validity, and consuming it yields only raw inputs. Every later
authority-bearing consumer must independently reconstruct the exact live branch
round and repeat complete proposal-control, producer, optional valid-round
proof, artifact, payload, and state-transition verification before any vote,
lock, journal, anchor, progression, finality, or other effect.

## Callback and restart lifetime

Because the buffer is an owned, borrow-free value, a caller may retain it
outside `run_with_signing_session` and capture a mutable borrow in callbacks from
Proposal, Prevote, or Precommit state. Callback completion drops the borrowed
signing scope, not the separately owned buffer. A caller may also deliberately
retain the same in-memory buffer while strictly reopening signer journals in the
same process; that reopen neither reconstructs nor validates buffer entries.

Dropping the buffer, losing its runtime owner, or terminating the process drops
its entries. A fresh buffer is empty. Node startup defines no reconstruction,
reconciliation, clearing handshake, or durable recovery format for this state.

## Exclusions

This component does not define or perform:

- proposal discovery, event observation, peer provenance, peer trust, network
  transport, relay, admission priority, event-loop ownership, or daemon policy;
- protocol-wide candidate/evidence limits, deterministic actionable selection
  after saturation, preferred evidence, replacement, eviction, expiry, retry,
  or automatic height/round/finality cleanup;
- quorum or certificate collection, automatic matching, pairing or release,
  round or phase advancement, proposal or branch selection, voting, locking,
  signing, finality, height advancement, rollback, or reorganization;
- durable encoding, restart reconstruction, repair, migration, cross-file
  atomicity, or candidate/payload-store mutation; or
- dynamic validator sets, multi-key coordination, key loading, rotation, remote
  signing, or production key custody.

These exclusions are authority boundaries for this volatile buffer, not claims
that the broader product does not require those capabilities. In particular,
certificate-coupled use and release of buffered proposals, durable recovery,
routing, daemon orchestration, and networking remain separate backlog work.
