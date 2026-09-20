# Specification and implementation ownership

The [MVP requirements](../docs/mvp/requirements.md) define the trusted research
workflow and its acceptance criteria. This index maps its current component
contracts. The [verification map](../docs/mvp/verification.md) separately records
implementation, local checks, CI, and runtime evidence.

| Responsibility | Owning crate | Normative contracts |
| --- | --- | --- |
| Immutable research profile/genesis, questions, deterministic phases, normalized proof library, settlement, rewards, and passive claims | `naome-ledger` | [MVP requirements and R1–R11](../docs/mvp/requirements.md) |
| Canonical complete state record, finalized envelope framing, exact-parent replay and provisional successor binding | `naome-chain::state` | [Canonical state formats](#canonical-state-formats) |
| Full state-record agreement, deterministic proposer selection, and bounded round transitions | `naome-consensus` | [MVP full state records](../docs/mvp/requirements.md#r8), [Proposer selection](proposer-selection.md) |
| Canonical history, independent replay, exclusive signer custody, and anchored crash recovery | `naome-storage::state`, `naome-node::state` | [MVP operational rules](../docs/mvp/requirements.md), [Recovery procedures](../docs/mvp/operations.md) |
| Authenticated complete records, history and proof transfer, bounded request custody, and live scheduling | `naome-protocol::state_exchange`, `naome-network::transport::state_exchange`, `naome-runtime::state` | [MVP authentication and limits](../docs/mvp/requirements.md) |
| Operator CLI, durable local actions, bounded operator-agent review, inspection and portable offline archive replay | `naome-cli`; `naome-validator start` and `naome-verifier verify` | [Operating guide](../docs/mvp/operations.md), [Acceptance evidence](../docs/mvp/verification.md) |
| Primitive language, axioms, and proof rules | `naome-foundation` | [Foundation](foundation.md) |
| Proof and definition representations, canonical bytes, and identities | `naome-proof` | [Proof Protocol](proof-protocol.md), [Mathematical Definitions](mathematical-definitions.md) |
| Foundation-relative proof checking and conservative definition checking | `naome-checker` | [Foundation](foundation.md), [Proof Protocol](proof-protocol.md), [Mathematical Definitions](mathematical-definitions.md) |
| Strict typed admission and immutable accepted records | `naome-ledger` | [Artifact Admission](artifact-admission.md) |
| Checked artifact DAG, strict admission, and authenticated exact set inside the complete proof library | `naome-ledger` | [Artifact Set](artifact-set.md), [Artifact Admission](artifact-admission.md) |
| Source parsing, proof lowering, diagnostics, and finalized-history and offline-context authoring | `naome-authoring` | [Proof Authoring](proof-authoring.md) |
| Validator and verifier processes, provisioning, and qualification | `naome-validator`, `naome-verifier`, `naome-cli`, `devnet/qualify.py` | [Canonical Process Operations](../docs/mvp/operations.md), [Devnet Operations](../devnet/OPERATIONS.md) |

## Authority boundaries

Decoding supplies no checked proof. An authenticated response supplies no
validity or selection. The ledger owns deterministic state transitions; the
chain owns complete records; consensus owns agreement and finality. Storage owns
durable replay and signing-safety records. The node owns the sole live signing
scope and command custody. The canonical history is the sole selected-state
journal owner.

The checked artifact DAG and authenticated set belong to `naome-ledger`.
`ProofLibrary` stages metered checked normalized proofs, compares expected
identity before registration, and atomically publishes its DAG with matching
provenance. Its immutable resolver serves authoring through the sealed selected
full-history interface. Standalone DAG and definition authoring support offline
checking without extending MVP publication rules.

`LedgerState::execute` returns provisional `LedgerExecution`. Only
`naome-chain::StateRecordExecution` constructs a complete record, enforces its
total byte limit, replays it against the exact parent, and compares every encoded
effect and state commitment. Binding an identifier onto provisional output grants
no finality: consensus branches cannot be initialized from a non-genesis
successor. Consensus authenticates `FinalizedStateRecord` evidence before
mathematical replay; storage installs only the verified result.

Within `naome-network`, `transport` owns canonical state exchange, fixed genesis
sessions, request permits, and terminal correlation. `naome-protocol` owns the
bounded state envelope. `naome-runtime::state` owns live scheduling, delivery,
proof fetch, and history catch-up. The node owns bounded lock/round state; storage
owns history, its separately anchored signer, and strict replay.

The repository root is a virtual Cargo workspace. `naome-author` is the offline
source-authoring CLI in `naome-authoring`; `naome` is the operator CLI in
`naome-cli`. `naome-validator start` reopens existing signing authority.
`naome-verifier verify` reads public archives with no network or signing command.
Setup alone initializes fresh authority while generating new keys and genesis.

## Canonical state formats

The `state-v1` profile uses a fresh genesis. Mathematical proof and Foundation
encodings are independent of this state-format family.

| Surface | Encoding and owner |
| --- | --- |
| Profile and genesis | `NAOPROF1`, `NAOGENS1`, `state-v1`; ledger profile |
| Complete application record | `NSRC` plus version 1; `naome-chain::StateRecord` |
| Signed actions, originals, certified time reports | `NSUA`, `NSOR`, `NSTM`; ledger authentication/operations/time |
| Consensus value, proposal, vote, finality | `NSCB1`, `NSCP1`, `NSCV1`; consensus; `NSCF1` outer framing in chain, authenticated by consensus |
| Lock events and checked snapshots | `NSCE1`, `NSCS1`; consensus |
| History, signing journal, external anchor | `NAOSHIS1`, `NAOSSIG1`, `NAOSANC1`; storage |
| Authenticated exchange | `/naome/state-v1`, envelope version 2; network/protocol |
| Private key and durable commitment bundle | `NSKEY001`, `NSSEC001`; CLI |
| State hash and signature domains | `naome:state:*:v1`; corresponding owning component |

Storage uses `state.journal`, `state.lock`, `state-finality.anchor`, and
`state-signer-KEY.*`. Node configuration version 2 uses `agenda_profile`.
Relative configuration paths resolve beside the configuration file; absolute
paths retain their meaning. This permits private [pilot bundles](../docs/mvp/pilot.md)
to move before startup without changing genesis or creating new signing state.
Explicit peer endpoints may use either standard or compact pre-genesis limits.
Unsupported artifact/research/V0 authority filenames, old framing, and version-1
configuration are rejected before locks or writes, including during read-only
observation. No old directory, history, or signing authority is automatically
converted. Historical data requires its original executable; a fresh run uses a
new directory and genesis.

The former research-v1 golden bytes remain immutable negative fixtures in
chain and consensus tests. Renamed headers, filenames, or imported snapshots must
not grant them authority. The [codec contract](codec-conformance.md) inventories
current formats, limits, and malformed-input evidence. Mathematical and proposer
hash domains with literal `v0` suffixes remain current where their owning
contracts specify them; changing those bytes would change identity.

## Safety and recovery verification

The canonical safety model exhausts four Byzantine placements, three rounds,
and two complete state values. Its progress rules include mixed-target
three-signer timeouts and two-signer higher-round catch-up. Witnesses replay
through real anchored honest signers, cold reopen, and complete-state finality.
Weak-quorum and forgotten-lock mutants check that the oracle detects conflicts.
All 128 role/subset/fault-placement cases exercise the four-unit quorum boundary.
Separate arithmetic oracles cover 19,164 eligible weighted configurations,
19 symmetry classes, and full-width thresholds; this is not weighted-network
qualification.

Canonical process tests cover strict custody, retransmission, conflict halt,
bounded control framing, output backpressure, SIGINT/SIGTERM, and independent
archive replay. The [verification map](../docs/mvp/verification.md) links the
actual tests and measured process/lab runs. Bounded tests and fixed trusted
membership do not establish permissionless-network security.
