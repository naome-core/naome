# Specification and implementation ownership

This index routes readers to the retained component contracts. The
[MVP requirements](../research/mvp/requirements.md) define the trusted research
workflow and its acceptance criteria. The research implementation and the retained
mathematical and fixed-validator foundation are indexed below. The
[verification map](../research/mvp/verification.md) records acceptance evidence
separately from implementation. The former public-network
backlog, dynamic-membership profile, and economic projections are not part of
this MVP branch. Historical rule IDs in retained contracts identify their
original implementation slices; they are not an active MVP backlog or an
additional source of authority.

| Responsibility | Owning crate | Normative contracts |
| --- | --- | --- |
| Immutable research profile/genesis, questions, deterministic phases, normalized proof library, settlement, rewards, and passive claims | `naome-ledger` | [MVP requirements and R1–R11](../research/mvp/requirements.md) |
| Canonical complete state record, finalized envelope framing, exact-parent replay and provisional successor binding | `naome-chain::state` | [State-format boundary](#state-format-integration-boundary) |
| Full research-record agreement and bounded round transitions | `naome-consensus::state` | [MVP full research records](../research/mvp/requirements.md#r8) |
| Research history, independent replay, exclusive signer custody, and anchored crash recovery | `naome-storage::state`, `naome-node::state` | [MVP operational rules](../research/mvp/requirements.md), [Recovery procedures](../research/mvp/operations.md) |
| Authenticated research records, history and proof transfer, bounded request custody, and live scheduling | `naome-protocol::state_exchange`, `naome-network::transport::state_exchange`, `naome-runtime::state` | [MVP authentication and limits](../research/mvp/requirements.md) |
| Operator CLI, durable local actions, bounded operator-agent review, inspection and portable offline archive replay | `naome-cli`; `naome-validator start` and `naome-verifier verify` | [Operating guide](../research/mvp/operations.md), [Acceptance evidence](../research/mvp/verification.md) |
| Primitive language, axioms, and proof rules | `naome-foundation` | [Foundation](foundation.md) |
| Proof and definition representations, canonical bytes, and identities | `naome-proof` | [Proof Protocol](proof-protocol.md), [Mathematical Definitions](mathematical-definitions.md) |
| Foundation-relative proof checking and conservative definition checking | `naome-checker` | [Foundation](foundation.md), [Proof Protocol](proof-protocol.md), [Mathematical Definitions](mathematical-definitions.md) |
| Strict typed admission and immutable accepted records | `naome-ledger` | [Artifact Admission](artifact-admission.md) |
| Authenticated selected set, exact-parent blocks, and candidate-branch snapshots | `naome-chain` | [Artifact Set](artifact-set.md), [Artifact Chain](artifact-chain.md) |
| Selected-history persistence, unselected stores, strict replay, and durable signing safety | `naome-storage` | [Artifact Chain Journal](artifact-chain-journal.md), [Candidate Store](artifact-block-candidate-store.md), [Payload Store](canonical-artifact-payload-store.md), [Recovery Bundle](candidate-branch-recovery-bundle.md), [Vote Safety Journal](fixed-validator-vote-safety-journal-v0.md), [Finality Journal](fixed-validator-finality-journal-v0.md), [External Anchor](fixed-validator-external-anchor-v0.md) |
| Transport-neutral artifact, block, head, and announcement messages | `naome-protocol` | [Transport-neutral messages](artifact-network-transport.md#transport-neutral-messages) |
| Authenticated fixed-peer sessions, caller-owned acquisition, and store serving | `naome-network` | [Artifact Network Transport](artifact-network-transport.md), [Caller-Selected Orchestration](caller-selected-orchestration.md), [Consensus Transport](fixed-validator-consensus-transport-v0.md) |
| Fixed-validator transition semantics and verified agreement/producer evidence | `naome-consensus` | [Agreement Evidence](fixed-validator-agreement-evidence-v0.md), [Producer Authorization](fixed-validator-producer-authorization-v0.md), [Proposer State](fixed-validator-proposer-state-v0.md), [Proposal Control](fixed-validator-proposal-control-v0.md), [Consensus Envelope](fixed-validator-artifact-consensus-envelope-v0.md) |
| Sole signing-scope custody and ordered node execution | `naome-node` | [Startup](fixed-validator-node-startup-v0.md), [Driver](fixed-validator-node-driver-v0.md), [Voting](fixed-validator-node-voting-v0.md), [Round Progression](fixed-validator-node-round-progression-v0.md), [Finality](fixed-validator-node-finality-v0.md), [Proposal Authoring](fixed-validator-node-proposal-authoring-v0.md) |
| Caller-configured timing, raw routing, and bounded publication delivery | `naome-runtime` | [Fixed-Validator Runtime](fixed-validator-runtime-v0.md); consensus, node, and storage retain their existing verification, signing, and finality authority |
| Bounded volatile proposal/evidence retention | `naome-node` | [Current Inbox](fixed-validator-node-current-round-inbox-v0.md), [Finality Inbox](fixed-validator-node-current-round-finality-inbox-v0.md), [Nil-Precommit Inbox](fixed-validator-node-current-round-nil-precommit-inbox-v0.md), [Higher Inbox](fixed-validator-node-higher-round-inbox-v0.md), [Proposal Buffer](fixed-validator-node-proposal-buffer-v0.md), [Deferral](fixed-validator-node-proposal-deferral-v0.md), [Buffered Precommit](fixed-validator-node-buffered-proposal-precommit-v0.md) |
| Source parsing, proof lowering, diagnostics, and selected-chain authoring | `naome-authoring` | [Proof Authoring](proof-authoring.md) |
| Validator and verifier processes, provisioning, and qualification | `naome-validator`, `naome-verifier`, `naome-cli`, `devnet/qualify.py` | [Canonical Process Operations](../research/mvp/operations.md), [Devnet Operations](../devnet/OPERATIONS.md) |

The authority boundaries follow the contracts above. Decoding supplies no
checked proof; an authenticated response supplies no validity or selection;
candidate and payload retention supply no selected-state authority. Consensus
owns transition semantics, storage owns durable replay and signing-safety
records, and the node owns the sole live signing scope and command custody.
Alternative selected-history journal owners use the same exclusive directory
lock and require explicit clean replacement.

Within `naome-network`, `transport` owns sessions, requests, permits, and terminal
correlation; `acquisition` owns caller-selected reconstruction and retention;
`serving` owns
caller-routed store lookups. Within `naome-node`, `fixed_validator` separates
startup, signing scope, driver, inboxes, proposals, voting, round progression,
and finality. Driver work classification has one shared precedence definition.
Storage journal families separate their private mutation owners from replay,
record encoding, durable append, and error reporting. These internal modules
preserve the fixed-validator authority boundaries. The repository root is a
virtual Cargo workspace; the `naome-author` source-authoring CLI remains in `naome-authoring`; the canonical state CLI is `naome-cli` (`naome`).

## State-format integration boundary

The state integration introduces a fresh `state-v1` genesis and encoding family.
This is an explicit compatibility break, not a conversion of an existing run.
The former research-v1 golden bytes remain immutable negative fixtures in chain
and consensus tests. They must not acquire authority through a renamed header,
new filename, or imported signer snapshot. The complete state record and finalized
envelope belong to `naome-chain`. Main validator/verifier entry points now use
only that full-state path. Remaining V0 artifact library APIs are still present
at this intermediate milestone and remain integration work.

| Surface | Previous encoding | State integration encoding / owner |
| --- | --- | --- |
| Profile and genesis | `NAORMVP1`, `NAORGEN1`, research checker/profile identity | `NAOPROF1`, `NAOGENS1`, `state-v1`; ledger profile |
| Complete application record | `NRRC` plus version 1 | `NSRC` plus version 1; `naome-chain::StateRecord` |
| Signed actions, originals, certified time reports | `NRUA`, `NROR`, `NRTM` | `NSUA`, `NSOR`, `NSTM`; ledger authentication/operations/time |
| Consensus value, proposal, vote, finality | `NRCB1`, `NRCP1`, `NRCV1`, `NRCF1` | `NSCB1`, `NSCP1`, `NSCV1`; consensus; `NSCF1` outer framing in chain, authenticated by consensus |
| Lock events and checked snapshots | `NRCE1`, `NRCS1` | `NSCE1`, `NSCS1`; consensus |
| History, signing journal, external anchor | `NAORHIS1`, `NAORSIG1`, `NAORANC1` | `NAOSHIS1`, `NAOSSIG1`, `NAOSANC1`; storage |
| Authenticated exchange | `/naome/research-mvp-v1`, envelope version 1 | `/naome/state-v1`, envelope version 2; network/protocol |
| Private key and durable commitment bundle | `NRKEY001`, `NRSEC001` | `NSKEY001`, `NSSEC001`; CLI |
| Hash and signature domains | `naome:research:*:v1` | `naome:state:*:v1`; corresponding owning component |

Field order, integer widths, limits, signature roles, fixed membership, reward
arithmetic, and deterministic execution rules are preserved. Mathematical proof
and Foundation encodings are unchanged. State identities and signatures are
intentionally different, including the genesis, account, resolution, library,
record, and branch commitments. Old history is not silently discarded, migrated,
or resumed: operators must retain old runs with their original executable and
provision an explicitly new directory and genesis for this format.

Existing Rust `Research*` API names and V0 library APIs remain inventoried by
the ownership table above. The main executables no longer dispatch V0 commands
or a `state` alias. Setup alone initializes fresh full-state authority while
generating new keys and genesis; validator startup can only reopen it. Canonical
process tests cover strict custody, retransmission, conflict halt, bounded
control framing, output backpressure, and SIGINT/SIGTERM. The portable verifier
reads only public canonical archives and has no network or signing command. Chain and consensus golden vectors cover the new wire
identities and a full submit/vote/commit/reveal/settlement replay. Negative vectors
cover old records, signed operations, time, proposals, votes, and finality;
storage and transport tests reject old framing without rewriting history.

`naome-ledger::ResearchState::execute` returns provisional `LedgerExecution`
without constructing a record. Only `naome-chain::StateRecordExecution`
constructs a complete record, enforces its total byte limit, replays claimed
records against their exact parent, and compares every encoded effect and state
commitment. Binding an identifier onto provisional ledger output grants no
finality: consensus branches cannot be initialized from a non-genesis successor.
Consensus authenticates `FinalizedStateRecord` evidence before mathematical
replay, and storage installs only that verified result. The format vectors are
unchanged by this ownership transfer.
