# Specification and implementation ownership

The [MVP requirements](../docs/mvp/requirements.md) define the trusted research
workflow and its acceptance criteria. This index maps its current component
contracts. The [verification map](../docs/mvp/verification.md) separately records
implementation, local checks, CI, and runtime evidence.

| Responsibility | Owning crate | Normative contracts |
| --- | --- | --- |
| Immutable research profile/genesis, questions, deterministic phases, normalized proof library, settlement, rewards, claims, join queue, and authority transition | `naome-ledger` | [MVP requirements and R1–R11](../docs/mvp/requirements.md), [Authority periods](authority-periods.md) |
| Canonical complete state record with its handoff plan, finalized envelope framing, exact-parent replay and provisional successor binding | `naome-chain::state` | [Canonical state formats](#canonical-state-formats) |
| Full state-record agreement, stable-slot proposer selection, bounded rounds, and two-quorum seal verification | `naome-consensus` | [Proposer selection](proposer-selection.md), [Authority periods](authority-periods.md) |
| Canonical history, independent replay, exclusive period signer and candidate custody, READY/TERMINAL journal, and anchored crash recovery | `naome-storage::state`, `naome-node::state` | [Authority periods](authority-periods.md), [Recovery procedures](../docs/mvp/operations.md) |
| Authenticated complete records, handoff/recovery messages, history and proof transfer, bounded request custody, staged transports, and live scheduling | `naome-protocol::state_exchange`, `naome-network::transport::state_exchange`, `naome-runtime::state` | [Authority periods](authority-periods.md), [MVP authentication and limits](../docs/mvp/requirements.md) |
| Operator CLI, candidate provisioning, durable local actions, bounded operator-agent review, inspection and portable offline archive replay | `naome-cli`; `naome-validator start` and `naome-verifier verify` | [Operating guide](../docs/mvp/operations.md), [Acceptance evidence](../docs/mvp/verification.md) |
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

`LedgerState::execute` derives a provisional successor from certified time,
ordered operations, and an exact `HandoffPlan`.
`naome-chain::StateRecordExecution` constructs the complete record, enforces its
total byte limit, replays it against the exact selected parent, and compares
every encoded effect and state commitment. Consensus agreement produces
`StateAgreement`, which exposes a provisional state but no selectable branch.
A verified incoming READY quorum and outgoing TERMINAL quorum produce
`StateFinality`. Only its sealed branch may be durably selected; observing a
record or agreement grants no signing authority. Historical evidence is
authenticated against its exact selected parent, not a header or peer hint.

Within `naome-network`, `transport` owns canonical state exchange, selected
period identities, staged handoff and recovery sessions, request permits, and
terminal correlation. `naome-protocol` owns the bounded state envelope.
`naome-runtime::state` owns live scheduling, delivery, proof fetch, history
catch-up, and period transition. The node owns bounded lock/round state;
storage owns selected history, separately anchored signer/custody/handoff
journals, and strict replay.

The repository root is a virtual Cargo workspace. `naome-author` is the offline
source-authoring CLI in `naome-authoring`; `naome` is the operator CLI in
`naome-cli`. `naome-validator start` reopens existing selected signing
authority. `naome-verifier verify` reads public archives with no network or
signing command. Initial setup creates fresh genesis keys and private authority
stores. `naome candidate-setup` independently replays finalized history and
imports the exact keys from a claim holder's finalized intent into separate
private custody; it creates no active signer. Research keys gain account
authority only through finalized registration.

## Canonical state formats

The `state-v5` handoff run requires a fresh genesis with protocol version 5.
The profile and genesis framing retain `NAOPROF4` and `NAOGENS4`; their
versioned contents and IDs reject the previous state run. Genesis commits an
exact permutation of the four bootstrap validator IDs as their retirement
order. No order is inferred from sorted keys. Mathematical proof and
Foundation encodings are independent of this state-format family.

| Surface | Encoding and owner |
| --- | --- |
| Profile and genesis | `NAOPROF4`, `NAOGENS4`, protocol version 5; ledger profile |
| Authority snapshot and handoff plan | `NSAU5`, `NSHP5`; owner/period offers and candidate readiness `NSCA5`; ledger authority |
| Complete application record | `NSRC` plus version 5, including certified time and handoff plan; `naome-chain::StateRecord` |
| Signed actions, originals, certified time reports | `NSUA`/`NSOR` version 4 and `NSTM` version 1, bound to v5 genesis and selected authority where required; ledger authentication/operations/time |
| Consensus value, proposal, vote, agreement and sealed finality | `NSCB5`, `NSCP5`, `NSCV5`, `NSAG5`; consensus; `NSCF5` outer proposal/QC/seal envelope in chain |
| Seal signature, seal, lock events and checked snapshots | `NSSG5`, `NSSL5`, `NSCE5`, `NSCS5`; consensus |
| History, period signer, handoff, period offer and candidate import journals | `NAOSHIS1` with v5 genesis context, `NAOSSIG5`, `NAOSHOF5`, `NAOSOFJ5`, `NAOCAND5`; storage; external anchor `NAOSANC1` |
| Authenticated exchange | `/naome/state-v5`, envelope version 3; network/protocol |
| Private key and durable commitment bundle | `NSKEY001`, `NSSEC001`; CLI |
| Normalization receipt | Version 2 includes the exact outgoing service authority used for reward recomputation; ledger receipt; archive inspection reads it only after full selected-history replay |
| State hash and signature domains | Authority, application state, record and consensus use v5 domains; unchanged profile, genesis, action, original and commitment identities retain v4 domains and bind the new genesis |

Storage uses `state.journal`, `state.lock`, `state-finality.anchor`,
`state-signer-KEY.*`, plus exact-height handoff and period custody journals.
Node configuration version 5 records independent primary/handoff endpoints,
recovery endpoints and an optional candidate family. Relative configuration
paths resolve beside the configuration file; absolute paths retain their
meaning. A candidate's owner key is separate from its imported consensus and
transport custody. Startup reopens selected authority and never initializes a
missing store. Old framing, journals, or genesis contents are rejected rather
than migrated. A fresh run uses a new directory and genesis.

The [codec contract](codec-conformance.md) inventories current formats,
limits, and malformed-input evidence. Mathematical and proposer hash domains
with literal `v0` suffixes remain current where their owning contracts
specify them; changing those bytes changes identity.

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
actual tests and measured process/lab runs. Bounded tests and the trusted four-slot pilot do not establish
permissionless-network security or physical multi-machine acceptance.
