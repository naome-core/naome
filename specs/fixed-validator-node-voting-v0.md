# Fixed-Validator Node Voting V0

## Authority and scope

This document defines the synchronous current-round vote-execution boundary for
one closure-scoped fixed-validator V0 node signer. It composes the exact branch
already owned by `FixedValidatorNodeSigningScopeV0`, complete proposal or quorum
input verification, optional exact signed-vote-batch quorum construction, the
private lock kernel, and the anchored per-key vote-safety session. One
successful call returns one completed signed prevote or precommit together with
the replacement signing scope.

The caller explicitly submits exactly one of five events through the direct
input boundary:

- complete canonical proposal-control bytes plus the complete canonical
  artifact payload for Proposal-to-Prevote;
- an explicit Proposal-phase close carrying its exact consensus context and
  source position;
- complete canonical proposal-control and artifact bytes plus one canonical
  current-round prevote/proposal certificate for Prevote-to-Precommit;
- one canonical current-round prevote/nil certificate; or
- an explicit Prevote-phase close carrying its exact consensus context and
  source position.

Each quorum-bearing path has a sibling adapter that accepts one complete
caller-routed batch of canonical signed prevotes in place of the already-built
certificate. The exact typed round requires every vote to strictly verify,
match its position and the path's exact prevote role and proposal-or-nil target,
name one distinct active signer, and collectively exceed two thirds of the
unchanged fixed-snapshot weight. It then includes every supplied vote in one
canonical key-sorted certificate and passes those exact bytes to the unchanged
lock-kernel path. It never filters, deduplicates, groups, accumulates, or chooses
a signer subset or competing target.

Each of the two proposal-bearing events also has a separate opt-in local-store
adapter. The caller still supplies the complete canonical proposal-control
bytes and explicitly selects one exact `ArtifactBlockId`, but routes the
proposal's block and payload through one matching-chain
`ArtifactBlockCandidateStore` and one Foundation-scoped
`CanonicalArtifactPayloadStore`. The proposal-quorum adapter additionally
supplies either the same canonical current-round prevote certificate as the
direct path or one exact signed-prevote batch under the construction contract
above. The adapters do not replace or weaken the direct input methods, and no
adapter discovers a target from store inventory.

The caller also supplies an inclusive local round-work ceiling. Mere submission,
presence, routing, or caller classification of a proposal, certificate,
phase-close request, candidate-store entry, network receipt, or peer provenance
grants no authority. Successful complete verification authorizes only that
proposal or certificate as the corresponding lock-kernel input; it does not
grant selection, finality, or peer-trust authority. The operation does not choose
among available events, infer a timeout, or decide that a phase ought to close.

## Exact round and input admission

Before proposal or lock-state admission, the coordinator first requires the
signing session to be operational and free of pending vote, height, or
higher-round work. It then derives round zero on the scope's node-owned branch
and requires its height to match the signer, requires the signer round not to
exceed the node-owned finality journal's persisted replay ceiling, and separately
compares it with the caller's inclusive work ceiling. Only after those checks
does it reconstruct that exact round by advancing sequentially. A
caller-work-ceiling violation is a retryable no-effect rejection. A poisoned,
terminal, or pending session, branch/signer mismatch, round reconstruction
failure, or signer position above the finality ceiling is a fatal error that
consumes the scope. Session readiness therefore precedes caller-ceiling,
proposal, and certificate rejection. The caller ceiling limits local derivation
work; it is not a consensus rule and does not change the signer's current round.

For either phase-close path, the coordinator next requires the event context to
equal the node-derived round context and the event position to equal that exact
height and round. A foreign, future, or stale event returns the unchanged scope
before the lock kernel or any signer write. The kernel then requires the exact
Proposal or Prevote phase before deriving an effect; wrong phase remains its
typed, mutation-free `UnexpectedPhase` rejection. Context is checked before
position, and both checks remain after session readiness and bounded exact-round
reconstruction so stale input cannot mask ambiguous or terminal signer state.
The supplied identity is descriptive only: it is not a caller cursor and cannot
retarget the node's signer to another round.

Direct proposal paths decode and fully verify the supplied proposal-control
bytes and owned artifact bytes against that exact branch-derived round. This
verification retains the existing context, height, proposer, fixed-set,
ancestry, artifact, payload, state-commitment, producer-authorization, and
optional valid-round-proof rules. The direct methods do not require, read, or
mutate a candidate or payload store.

The optional store-backed proposal paths retain the same session and exact-round
preflight and require the path's exact Proposal or Prevote phase before reading
either source. They then bound and structurally decode the supplied proposal
control far enough to require its embedded consensus context and height to equal
the exact branch-derived round and its embedded artifact block to name the
caller-selected target. They require the candidate store's chain to equal that
context's artifact chain before reading an entry, integrity-read only that exact
candidate, require its complete canonical block bytes to equal the block
embedded in the proposal, and integrity-read only that block's exact canonical
artifact payload. Missing entries, source read or
integrity failures, a foreign candidate-store chain, an early proposal mismatch,
or unequal candidate bytes reject before a lock effect or signer write. Each
source handle retains its existing error-specific poison-and-reopen behavior;
corruption of one source cannot poison the other source or the signing scope.

The loaded bytes are only availability input and pass through the unchanged
complete proposal verification described above. Candidate or payload
membership, successful source reads, structural decoding, caller target choice,
and byte equality grant no proposal validity, vote-target, selection, finality,
provenance, networking, or peer-trust authority. In particular, the existing
lock rule may make a successful proposal prevote target the retained lock rather
than the caller-selected proposal; the adapter must not reinterpret the
candidate target as vote-target authority.

Proposal-quorum and nil-quorum paths additionally pass the exact canonical
certificate to the private lock kernel. A signed-vote-batch adapter first
constructs those bytes through the exact typed-round contract above; any empty,
over-bound, malformed, foreign-context, wrong-position, wrong-role,
wrong-target, duplicate, inactive, invalid-signature, or insufficient-weight
batch is rejected in full before a lock effect or signer write. The lock kernel
then verifies the certificate against the same current round's immutable
fixed-set snapshot and enforces its exact role and target. Store presence,
decoding alone, caller classification, or one partial valid subset cannot
substitute for complete proposal, batch, or certificate verification.

## Ordered vote execution

Each admitted event follows one consuming public operation. This ordered
operation is not a cross-file atomic transaction:

1. Require an operational signing session with no pending vote, height, or
   higher-round work.
2. Derive the exact current typed round under the persisted finality and
   caller-local ceilings.
3. For a phase close, match its exact context and source position. For a direct
   proposal or quorum path, fully verify every supplied byte required by that
   path, including every signed vote when the exact-batch adapter is used. For
   an opt-in store-backed proposal path, first require its exact live
   phase, admit the exact proposal identity, integrity-read the caller-selected
   candidate and payload as above, and then perform the same complete
   verification.
4. Let the private lock kernel derive the sole unsigned vote effect and its
   exact post-effect phase, lock, and valid-value state.
5. Persist and anchor the complete post-effect state plus exact vote intent.
6. For a new or already matching live preparation, convert only that exact
   anchored preparation into key-use authority.
7. Sign the canonical vote, self-verify it, persist its completion, and advance
   the independent vote anchor.
8. Only then return the signed bytes with a replacement scope.

An exact `AlreadySigned` preparation outcome re-releases only its retained
completed durable vote without another key operation or signer write. A
`Halted` outcome returns only the same-slot signer-halt evidence and no scope.
`Prepared` and `AlreadyPrepared` both require the exact acknowledgement and
completion path before signed bytes are returned.

The five event paths preserve the existing kernel rules:

- an admitted Proposal-phase proposal prevotes that proposal when unlocked or
  permitted by the valid-round rule, and otherwise prevotes the retained lock;
- an exact current Proposal-phase close prevotes the retained lock or nil;
- a matching current-round prevote/proposal quorum locks or relocks the admitted
  proposal, retains it as the latest valid value and proof, and precommits it;
- a current-round prevote/nil quorum clears the lock, preserves the latest valid
  value and proof, and precommits nil; and
- an exact current Prevote-phase close preserves lock and valid-value state and
  precommits nil.

The two close methods classify only one exact explicit caller event. Exact
context and position prevent a delayed close for round `R` from being
reinterpreted when the same phase is live at round `R + 1`. They do not prove
that a timeout elapsed, that a proposal or quorum is unavailable elsewhere, or
that network collection is complete. Nor do they establish same-position event
freshness, timer generation, cancellation, race ordering, or exactly-once
delivery.

## Outcomes, failures, and restart

A pre-effect rejection returns the unchanged signing scope with a typed reason.
Rejections include a caller-local round-work ceiling violation, phase-close
context or position mismatch, complete proposal rejection, exact vote-batch
construction rejection, a mutation-free lock-kernel input rejection, or an
optional store adapter's proposal-identity, candidate-chain,
candidate-availability, candidate-integrity, candidate-byte,
payload-availability, or payload-integrity rejection. Existing identity,
source, batch, and lock-kernel validation ordering ensures a rejected event
changes no volatile lock state, candidate or payload entry, or durable signer
state. A
source-integrity failure may poison only that borrowed source handle under its
existing contract while the unchanged signing scope remains available for an
explicit direct-input retry. A poisoned, terminal, or pending signing session
is not an input rejection: it consumes the scope through a fatal session error.

Once the lock kernel has emitted an effect, any preparation,
preparation-acknowledgement, signing, completion, or anchor error consumes the
scope and returns no signed bytes. The caller cannot safely distinguish a
non-write from an ambiguous durable prefix through the live handle. Strict
restart against the independent vote anchor is the only classifier. A halted
signer similarly returns only its terminal stop evidence and no
continuation scope.

A successful result returns the exact `FixedValidatorSignedVoteV0` only after
both preparation and completion have passed the existing journal and anchor
contract. It grants authority to release that one signed vote; it grants no
authority to finalize a value, advance height, select a branch, or reuse the key
outside the anchored session.

## Public API boundary

The node voting facade retains read-only position, phase, lock, and valid-value
diagnostics plus the direct proposal-byte methods, their exact-batch quorum
siblings, and the separate opt-in store-backed adapters for both certificate
and exact-batch input. Identity-free phase closes, current-round decision
effects, raw cursor-supplied round advancement, vote preparation, anchor
acknowledgement, and key use are absent or crate-private. External callers
therefore cannot split the ordered current-round sequence, retarget a delayed
close to the live round, or insert a caller-constructed unsigned effect between
its steps. Store-backed availability is optional and cannot become a liveness or
validity requirement for the direct methods.

Height advancement and finality-conflict stop remain available only through the
separate consuming node-finality coordinator. Higher-round quorum catch-up and
exact-event-bound sequential round advancement remain separate consuming
round-progression operations and are not reclassified as current-round vote
execution.

## Exclusions

This coordinator does not define or perform:

- proposal authoring, producer signing, proposal or certificate selection, or
  competing-evidence ranking;
- stateful vote collection, duplicate-delivery policy, conflicting-vote or
  equivocation retention, signature-variant preference, certificate freezing
  or renewal, or competing-target grouping;
- asynchronous event routing, proposal or vote buffering, phase scheduling,
  timer generation or cancellation, timeout measurement, timeout expiry,
  same-position event freshness, retry ordering, exactly-once delivery, or
  daemon ownership;
- network transport, peer discovery, provenance trust, or peer-selected
  admission;
- finality, height advancement, branch selection, sibling winner selection,
  rollback, reorganization, candidate promotion, or durable source-entry
  mutation;
- dynamic validator sets, multi-key coordination, key loading, rotation, remote
  signing, or production custody;
- cross-file atomicity, automatic repair, or coordinated rollback detection; or
- non-Unix file-anchor runtime guarantees.

These are separate required product capabilities, not unnecessary work. This
boundary deliberately completes the exact current-round validated-bytes-to-
anchored-signature path without silently assigning any of those authorities to
input arrival order or to a peer.
