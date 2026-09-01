# Fixed-Validator Node Startup V0

## Authority and scope

This document defines the first reference-node integration boundary for one
local fixed-validator V0 signer. It composes the existing anchored finality and
per-key vote-safety journals into an explicit create-or-restart workflow. It
does not define an executable daemon, operator configuration format, genesis
ceremony, key loader or custodian, scheduler, timeout policy, consensus-message
transport, peer policy, proposal buffer, branch choice, or dynamic validator
set.

The caller supplies the exact artifact-chain definition, consensus context,
preselected fixed agreement entries, one in-memory Ed25519 signing key, four
journal or anchor directories, positive finality and vote-journal replay
limits, an inclusive signer-recovery round ceiling that may be zero, and an
inclusive signer catch-up height-handoff limit that may also be zero. These
values are configuration authority. Startup proves only that the supplied
local files and key are mutually consistent with those exact values.

## Provisioning preflight

Before creating or opening any file, startup reconstructs the exact virtual-
genesis fixed-validator branch and rejects an invalid agreement snapshot,
chain/context mismatch, or signing key absent from the supplied fixed set. It
derives the fixed-set identity only from that branch. The journal limit types
have already validated their own positive bounds; paths are used exactly as
supplied rather than probed or normalized by preflight. No fixed-set identity,
signer, branch, height, or round is inferred from a journal after a failed
preflight.

The directory paths are accepted exactly as supplied. Startup neither creates
directories nor chooses a layout. Journal and anchor implementations retain
their existing create-new, exclusive-lock, synchronization, and strict replay
rules.

## Fresh creation

Fresh creation performs these ordered steps:

1. Create the anchored finality journal at virtual genesis.
2. Create the anchored per-key vote-safety journal for the preflighted fixed
   set and signer.
3. Derive round zero from the created finality head.
4. Bind that exact branch, height, and signer as the initial vote-journal
   lineage, including its anchor update.

Only completion of all four steps returns a ready node owner. There is no
cross-journal or cross-anchor transaction. A later-step failure does not delete,
replace, roll back, or reinterpret an earlier durable file; the caller must
inspect the typed error and provision fresh caller-chosen paths rather than
retrying as if creation were atomic.

## Strict restart

Restart first opens the anchored finality pair and then the anchored per-key
vote pair. Each pair must independently match its exact typed anchor. A missing,
behind, ahead, divergent, corrupt, foreign, or locked pair returns no ready
owner and is never repaired or reconciled.

After both pairs open, startup applies the following order:

1. If finality is terminally conflict-halted, issue its exact internally
   anchored signer-stop capability and route it into the vote journal before
   issuing recovery authority. A new or byte-identical existing signer stop is
   returned as a typed finality-stopped outcome. Any incompatible terminal
   signer state or stop-persistence failure returns an error and no session.
2. Otherwise, return a typed signer-stopped outcome for an existing vote-safety
   same-slot halt or finality-conflict stop.
3. Otherwise, return a typed pending-preparation outcome for the sole durable
   incomplete vote. Startup never resumes, signs, drops, or replaces it.
4. Otherwise, let the vote journal issue its opaque anchored recovery
   capability and let the finality journal reconstruct only the exact retained
   branch named by that capability.
5. If selected finality is ahead of that recovered signer lineage, consume each
   exact retained selected transition in height order through the existing
   anchored finality-to-signer handoff until the signer reaches the finality
   head. Before the first handoff, compute the complete nonnegative height gap
   and reject it typed, without a catch-up write or callback, when it exceeds
   the caller's inclusive height-handoff limit. A signer lineage ahead of the
   selected finality head is a distinct typed invariant failure. Any admitted
   handoff or anchor failure returns no callback and retains the existing
   fail-closed journal behavior. Every earlier completed handoff remains
   durable, and a later failure neither rolls it back nor makes the whole suffix
   atomic. Strict restart resumes only from an exact resulting journal/anchor
   pair or the already permitted incomplete-tail recovery; a complete
   unanchored suffix fails closed as anchor-behind and requires separate
   operator recovery.

The ready owner retains that opaque recovered-branch authority until the caller
starts its sole signing scope. It exposes no caller-selected branch or history
lookup.

## Scoped signing session

A ready owner is consumed by `run_with_signing_session`. The method attempts to
issue the vote journal's only session, using either the freshly bound exact
branch or the capability-recovered branch under the caller's inclusive
sequential round-work ceiling. A recovered round above that ceiling returns an
error before the closure runs or the session latch changes. After recovered
session issuance but before any height handoff, startup applies the separate
caller-local catch-up height limit to the complete gap; rejecting that limit
does not run the closure or change either durable journal or anchor and a strict
reopen can retry with another caller-selected limit. Successful issuance and
catch-up invoke one higher-ranked closure with:

- the owned exact branch for the current signing lineage, already caught up to
  the selected finality head;
- read-only caller access to the anchored finality journal; and
- mutable access to a node-scoped voting facade over the anchored vote-safety
  signing session.

The closure result cannot borrow the scope. The signing session therefore
cannot outlive the owning vote journal or be retained for a second invocation.
The supplied finality diagnostics and voting facade preserve all existing vote,
anchor, ordering, and failure rules. The facade exposes no height-transition or
finality-conflict stop method, so only the scope's consuming live-finality
method may apply capabilities from its node-owned finality journal. The scope
also exposes no raw mutable finality handle or raw storage signing session. Its
live-finality method is specified by `fixed-validator-node-finality-v0.md`:
every new finality commit or conflict must reach the matching signer advance or
stop before another signing scope can be returned.

## Failure and authority boundaries

Startup may validate explicit configuration, own local handles, classify local
terminal or pending states, monotonically propagate an already anchored
finality conflict into the matching signer, and reconstruct the exact persisted
signing lineage, then advance that signer only through the already selected
retained finality suffix. It cannot:

- select, rank, roll back, repair, or replace a branch, journal, anchor, or key;
- create new finality, accept a peer statement as authority, or infer chronology
  across independent files;
- load, generate, rotate, export, or remotely operate a signing key, or define
  production key-custody policy;
- discover peers, route network events, buffer proposals or votes, schedule
  timeouts, or run a consensus event loop;
- make multiple journals or anchors one atomic commit; or
- claim coordinated-rollback detection, hardware monotonicity, production key
  custody, dynamic-validator operation, or a runnable node process.

Those exclusions identify separate required product work. They are not claims
that the excluded capabilities are unnecessary. The reference file-anchor path
currently requires durable Unix parent-directory synchronization; non-Unix
startup fails typed before publishing a ready node and supplies no Windows or
cross-platform anchor-runtime evidence.
