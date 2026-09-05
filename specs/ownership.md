# Specification and implementation ownership

This index routes readers to the owning contracts. It adds no protocol rule or
completion claim. [consensus-rules.md](consensus-rules.md) remains the stable
implementation ledger; its IDs, statuses, prerequisites, and same-line evidence
control backlog completion.

| Responsibility | Owning crate | Normative contracts |
| --- | --- | --- |
| Primitive language, axioms, and proof rules | `naome-foundation` | [Foundation](foundation.md) |
| Proof and definition representations, canonical bytes, and identities | `naome-proof` | [Proof Protocol](proof-protocol.md), [Mathematical Definitions](mathematical-definitions.md) |
| Foundation-relative proof checking and conservative definition checking | `naome-checker` | [Foundation](foundation.md), [Proof Protocol](proof-protocol.md), [Mathematical Definitions](mathematical-definitions.md) |
| Strict typed admission and immutable accepted records | `naome-ledger` | [Artifact Admission](artifact-admission.md) |
| Authenticated selected set, exact-parent blocks, and candidate-branch snapshots | `naome-chain` | [Artifact Set](artifact-set.md), [Artifact Chain](artifact-chain.md) |
| Selected-history persistence, unselected stores, strict replay, and durable signing safety | `naome-storage` | [Artifact Chain Journal](artifact-chain-journal.md), [Candidate Store](artifact-block-candidate-store.md), [Payload Store](canonical-artifact-payload-store.md), [Recovery Bundle](candidate-branch-recovery-bundle.md), [Vote Safety Journal](fixed-validator-vote-safety-journal-v0.md), [Finality Journal](fixed-validator-finality-journal-v0.md), [External Anchor](fixed-validator-external-anchor-v0.md) |
| Transport-neutral artifact, block, head, and announcement messages | `naome-protocol` | [Transport-neutral messages](artifact-network-transport.md#transport-neutral-messages); existing workspace-root module paths remain compatibility reexports |
| Authenticated sessions, peer records, caller-owned acquisition, and store serving | `naome-network` | [Peer Addressing](peer-addressing.md), [Artifact Network Transport](artifact-network-transport.md), [Caller-Selected Orchestration](caller-selected-orchestration.md), [Consensus Transport](fixed-validator-consensus-transport-v0.md) |
| Fixed-validator transition semantics and verified agreement/producer evidence | `naome-consensus` | [Agreement Evidence](fixed-validator-agreement-evidence-v0.md), [Producer Authorization](fixed-validator-producer-authorization-v0.md), [Proposer State](fixed-validator-proposer-state-v0.md), [Priority Snapshot Transition](proposer-priority-snapshot-transition-v0.md), [Proposal Control](fixed-validator-proposal-control-v0.md), [Consensus Envelope](fixed-validator-artifact-consensus-envelope-v0.md) |
| Sole signing-scope custody and ordered node execution | `naome-node` | [Startup](fixed-validator-node-startup-v0.md), [Driver](fixed-validator-node-driver-v0.md), [Voting](fixed-validator-node-voting-v0.md), [Round Progression](fixed-validator-node-round-progression-v0.md), [Finality](fixed-validator-node-finality-v0.md), [Proposal Authoring](fixed-validator-node-proposal-authoring-v0.md) |
| Caller-configured timing, raw routing, and bounded publication delivery | `naome-runtime` | [Fixed-Validator Runtime](fixed-validator-runtime-v0.md); consensus, node, and storage retain their existing verification, signing, and finality authority |
| Bounded volatile proposal/evidence retention | `naome-node` | [Current Inbox](fixed-validator-node-current-round-inbox-v0.md), [Finality Inbox](fixed-validator-node-current-round-finality-inbox-v0.md), [Nil-Precommit Inbox](fixed-validator-node-current-round-nil-precommit-inbox-v0.md), [Higher Inbox](fixed-validator-node-higher-round-inbox-v0.md), [Proposal Buffer](fixed-validator-node-proposal-buffer-v0.md), [Deferral](fixed-validator-node-proposal-deferral-v0.md), [Buffered Precommit](fixed-validator-node-buffered-proposal-precommit-v0.md) |
| Source parsing, proof lowering, diagnostics, and selected-chain authoring | `naome-authoring` | [Proof Authoring](proof-authoring.md) |
| Economic rules and workspace-root integration | `naome-economy`, workspace root | The `BASE`, `ECON`, and `WEIGHT` rules and their exact implementation evidence in [the ledger](consensus-rules.md) |

The authority boundaries follow the contracts above. Decoding supplies no
checked proof; an authenticated response supplies no validity or selection;
candidate and payload retention supply no selected-state authority. Consensus
owns transition semantics, storage owns durable replay and signing-safety
records, and the node owns the sole live signing scope and command custody.
Alternative selected-history journal owners use the same exclusive directory
lock and require explicit clean replacement.

Within `naome-network`, `transport` owns sessions, requests, permits, and terminal
correlation; `peer_records` owns untrusted record admission and routing;
`acquisition` owns caller-selected reconstruction and retention; `serving` owns
caller-routed store lookups. Within `naome-node`, `fixed_validator` separates
startup, signing scope, driver, inboxes, proposals, voting, round progression,
and finality. Driver work classification has one shared precedence definition.
Storage journal families separate their private mutation owners from replay,
record encoding, durable append, and error reporting. These internal modules
preserve the existing public crate exports and authority boundaries.
