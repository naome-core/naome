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
| Authenticated complete records, history and proof transfer, bounded request custody, and live scheduling | `naome-protocol::state_exchange`, `naome-network::transport::state_exchange`, `naome-runtime::state` | [MVP authentication and limits](../research/mvp/requirements.md) |
| Operator CLI, durable local actions, bounded operator-agent review, inspection and portable offline archive replay | `naome-cli`; `naome-validator start` and `naome-verifier verify` | [Operating guide](../research/mvp/operations.md), [Acceptance evidence](../research/mvp/verification.md) |
| Primitive language, axioms, and proof rules | `naome-foundation` | [Foundation](foundation.md) |
| Proof and definition representations, canonical bytes, and identities | `naome-proof` | [Proof Protocol](proof-protocol.md), [Mathematical Definitions](mathematical-definitions.md) |
| Foundation-relative proof checking and conservative definition checking | `naome-checker` | [Foundation](foundation.md), [Proof Protocol](proof-protocol.md), [Mathematical Definitions](mathematical-definitions.md) |
| Strict typed admission and immutable accepted records | `naome-ledger` | [Artifact Admission](artifact-admission.md) |
| Checked artifact DAG, strict admission, and authenticated exact set inside the complete proof library | `naome-ledger` | [Artifact Set](artifact-set.md), [Artifact Admission](artifact-admission.md) |
| Source parsing, proof lowering, diagnostics, and finalized-history and offline-context authoring | `naome-authoring` | [Proof Authoring](proof-authoring.md) |
| Validator and verifier processes, provisioning, and qualification | `naome-validator`, `naome-verifier`, `naome-cli`, `devnet/qualify.py` | [Canonical Process Operations](../research/mvp/operations.md), [Devnet Operations](../devnet/OPERATIONS.md) |

The authority boundaries follow the contracts above. Decoding supplies no
checked proof; an authenticated response supplies no validity or selection;
candidate and payload retention supply no selected-state authority. Consensus
owns transition semantics, storage owns durable replay and signing-safety
records, and the node owns the sole live signing scope and command custody.
The canonical history is the sole selected-state journal owner. Unsupported
V0 bytes fail closed; creating a fresh run never converts old authority.

Within `naome-network`, `transport` owns the sole canonical state exchange,
fixed genesis sessions, request permits, and terminal correlation. The V0
artifact/block/head/candidate/recovery/consensus-push exchanges, acquisition,
and store-serving APIs are removed. `naome-protocol` contains only the bounded
state envelope. `naome-runtime::state` owns live canonical scheduling, delivery,
proof fetch, and history catch-up; its V0 runtime and auxiliary journals are
removed. No artifact-only transport or runtime authority remains. The old artifact
blocks, V0 consensus branches, node coordinator, candidate/payload stores, and
separate finality/signing journals are removed. The canonical node owns its
bounded lock/round state; storage owns canonical history, its separately
anchored signer, and strict replay. Shared quorum/proposer arithmetic and
platform durability primitives remain without an alternate history path. The repository root is a
virtual Cargo workspace; the `naome-author` source-authoring CLI remains in `naome-authoring`; the canonical state CLI is `naome-cli` (`naome`).

## State-format integration boundary

The state integration introduces a fresh `state-v1` genesis and encoding family.
This is an explicit compatibility break, not a conversion of an existing run.
The former research-v1 golden bytes remain immutable negative fixtures in chain
and consensus tests. They must not acquire authority through a renamed header,
new filename, or imported signer snapshot. The complete state record and finalized
envelope belong to `naome-chain`. Main validator/verifier entry points now use
only that full-state path. V0 artifact-chain, consensus, node, and journal
authority APIs have been removed.

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

Existing Rust `Research*` API names and historical on-disk filenames still
await their neutral naming boundary; they denote the sole canonical state path. The main executables no longer dispatch V0 commands
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

The checked artifact DAG and authenticated set now belong to `naome-ledger`.
`ProofLibrary` stages the already metered checked normalized proofs in that DAG,
checks expected identity before registration, and publishes the DAG with its
matching provenance records atomically. The complete library/state bytes and
replay vectors are unchanged. Its immutable resolver serves authoring through
the sealed selected full-history interface; the old artifact-journal authoring
adapter has been removed. Definition authoring remains offline and does not
extend MVP publication rules. The temporary `naome-chain` DAG reexports and their V0 callers are removed.

The canonical safety model exhausts four possible Byzantine placements, three
rounds, and two complete state values. Its progress rules match the canonical
kernel, including mixed-target three-signer timeouts and two-signer higher-round
catch-up. Witnesses replay through real anchored honest signers, cold reopen,
and complete-state finality; weak-quorum and forgotten-lock mutants establish
that the safety oracle detects conflicts. All 128 role/subset/fault-placement
cases check the actual four-unit-validator quorum boundary. Separate arithmetic
oracles cover 19,164 eligible weighted configurations, 19 symmetry classes, and
full-width thresholds; this is not weighted-network qualification.
