# Canonical codec conformance

`TEST-001`, `TEST-003`, `TEST-091` and `TEST-092` apply to the current
serialized formats below. A new consensus-critical representation must extend
this inventory and its executable vectors, mutation corpus and resource oracles
in the same change. This contract does not declare unfinished protocol rules or
future dynamic-validator formats implemented.

## Acceptance and evidence

A complete input accepted by a canonical decoder must re-encode byte-for-byte
from its decoded fields. Successful decoding must not panic. Structural
acceptance, signature verification, branch-relative artifact admission and
recovered signing authority are different boundaries: each test uses the actual
acceptance boundary of its codec. An opaque payload in a transport or archive
frame remains opaque at that layer; its independent artifact or consensus codec
has its own typed re-encoding oracle. Returning an entire retained input buffer
is not a re-encoding oracle.

Journals distinguish a complete accepted image from successful recovery of an
incomplete suffix. Only complete acceptance requires equality with the whole
input. Recovery tests instead require the exact last complete prefix and the
existing external-anchor conditions. A recovered prefix is never counted as an
accepted complete image by the corpus.

Fixed vectors include independently assembled field layouts, literal byte and
hash vectors, and complete-byte SHA-256 fingerprints for signing-state fixtures.
They run through the ordinary workspace test commands in both profiles on
Linux x86_64, macOS ARM64 and Windows x86_64. Raw driver custody and the
runtime evidence-file owner retain their existing Unix-only support boundary;
their integration corpus runs on Linux and macOS. The receipt decoder and
in-memory journal/frame codecs run on all three platforms. These tests do not
add a Windows signer or runtime authority implementation.

## Deterministic mutation campaign

`tests/support/codec_corpus.rs` is compiled only into tests, without a production
API or an additional dependency. Each invocation requires positive seeds and
runs these reproducible cases:

- Each seed, every prefix for inputs up to 1,024 bytes, or 1,025 evenly spaced
  prefixes for longer inputs, including the empty and complete prefix.
- Up to 128 evenly spaced byte positions, each changed by XOR with `0x01`,
  `0x80` and `0xff`, deleted once, and preceded by an inserted `0xff`.
- The complete seed followed by `0x00` or `0xff`.
- 512 deterministic xorshift64 byte strings of lengths from zero through
  4,096, starting from seed `0x4e414f4d455f5630`.

Every accepted case is re-encoded and compared exactly. Panics fail the test
with the deterministic case index. The campaign requires both acceptance and
rejection and bounds its generated cases by
`seed_count * (1 + 1025 + 128 * 5 + 2) + 512`. This is a bound on test generation,
not a proof of parser cost. Existing exhaustive short-vector bit mutations and
prefix tests remain in place. Journal-body, recovery-bundle and receipt tests
also recompute framing hashes so malformed fields reach the inner parser.

Resource evidence uses actual decoded node counts, explicit byte/count/depth
errors, cursor read positions and retention-permit accounting. It does not use
elapsed time as a resource oracle. These are bounded regression campaigns,
not an exhaustive enumeration of all byte strings or a coverage-guided fuzzing
service. A successful run establishes the assertions for its executed cases.

## Format inventory

Paths in the following tables are relative to `crates/`. The named test files
contain both the existing fixed vectors and the expanded corpus unless a
separate source is given.

### Consensus and artifact representations

| Format and variants | Fixed-vector and corpus evidence | Deterministic resource evidence |
| --- | --- | --- |
| Primitive `Formula`: equality, membership, negation, implication, quantification, free and bound variables | `naome-foundation/src/formula/canonical/tests.rs`; `naome-proof/src/codec_conformance.rs`; `naome-chain/tests/canonical_decoders.rs` | 393,216 bytes, depth 256, 65,536 nodes; exact caller node counts and rejection before visiting the next node in `canonical/tests.rs` |
| `DefinedFormula` and embedded `ProofFormula`: primitive subset and defined-relation applications | `naome-proof/src/defined_formula.rs` tests; `naome-proof/src/codec_conformance.rs`; `naome-proof/src/codec/tests/golden.rs` | Same formula byte/depth/node bounds; counted-node, zero-budget, malformed next-node and depth-boundary tests; declared argument count must fit the remaining five-byte variable fields before allocation |
| `ProofCertificate`: all fourteen step variants and seven fixed ZFC axiom tags | `naome-proof/src/codec/tests/golden.rs`; `naome-chain/tests/canonical_decoders.rs` | 4,194,304 bytes, 65,536 steps and cumulative 65,536 formula nodes across all fields/steps; `naome-proof/src/codec/tests/limits.rs` includes an attack-shaped certificate exactly at the byte limit |
| `DefinitionCertificate`: relation and positive-input-arity function graph | `naome-proof/src/definition.rs` tests; `naome-proof/src/codec_conformance.rs` | `9 + FORMULA_MAX_BYTES`; graph arity at most 256; exact used formal-variable validation, impossible declared body length and enclosing-byte rejection before body decoding |
| `ArtifactPayload`: proof and definition tags | `naome-proof/src/tests.rs`; `naome-proof/src/codec_conformance.rs`; `naome-chain/tests/canonical_decoders.rs` | 4,194,305 bytes; tag and complete inner codec bounds |
| `ArtifactChainDefinition`, `ArtifactBlock` | `naome-chain/src/block/tests.rs`; `naome-chain/tests/canonical_decoders.rs` | Exact widths: chain definition is discriminator plus compiled Foundation ID plus genesis set root; block is 128 bytes; every other width fails |
| `ArtifactSetProof`: empty, member, nonmember and branching paths | `naome-chain/src/artifact_set/codec/tests.rs` | At most 256 ordered path steps; complete framing checked before retention; exact maximum member/nonmember proofs and a full-depth mutation seed |
| `ConsensusValueV0` | `naome-consensus/src/consensus_value/tests.rs` and `tests/codec_conformance.rs` | Exact 268 bytes; reserved height and context checks |
| Producer authorization | `naome-consensus/src/producer_authorization/tests.rs`; `naome-consensus/src/consensus_value/tests/codec_conformance.rs` | Exact 212 bytes; context, position, scheduled key and membership checks before strict signature work |
| Signed vote: prevote/precommit, nil/proposal target | `naome-consensus/src/agreement_evidence/tests.rs`; `naome-consensus/src/consensus_value/tests/codec_conformance.rs` | Exact 214 bytes; exact tags, nil padding, context and strict signatures |
| Quorum certificate, including the non-nil precommit wrapper | `naome-consensus/src/agreement_evidence/tests.rs`; `naome-consensus/src/consensus_value/tests/codec_conformance.rs` | 216 through 24,696 bytes; 1 through 256 strictly ordered distinct signers; count/width bounds before allocation and verification; maximum-set tests |
| Proposal control: fresh and retained valid-round certificate | `naome-consensus/src/consensus_value/tests.rs` and `tests/codec_conformance.rs` | 481 through 25,177 bytes; exact optional tag/remainder and bounded embedded certificate; typed value, authorization and proof are re-encoded separately |
| Finality envelope | `naome-consensus/src/consensus_value/tests.rs` and `tests/codec_conformance.rs` | 696 through 25,176 bytes; enclosing bounds precede nested crypto/artifact work; maximum-signer test |
| Signing snapshot, vote intent, proposal intent and higher-round checkpoint | `naome-consensus/src/fixed_validator_lock_state/tests.rs`; proposal corpus helper in `naome-consensus/src/fixed_validator_proposal_authoring.rs` | Snapshot 288 through 25,572 bytes; vote intent 391 through 25,675; proposal intent 629 through 25,913; checkpoint 606 through 50,370; state invariants and bounded embedded certificate framing. Snapshot and vote/checkpoint fields are independently re-encoded; proposal decoding also verifies its snapshot's typed re-encoding |

Fixed-set, proposer-priority, state-binding, signing-root and domain-separated
identity preimages are encoder-only representations. Their independent vectors
remain in `naome-consensus/src/proposer_selection/tests.rs`,
`naome-consensus/src/agreement_evidence/tests.rs`,
`naome-consensus/src/consensus_value/tests.rs`, and the corresponding proof,
chain and journal vector tests. They do not introduce another arbitrary-input
decoder. Descriptive routing/header peeks inspect only part of an enclosing
message and do not accept it as canonical or valid; the enclosing strict codec
is covered above. Exact vote batches and sealed in-memory capabilities likewise
have no additional serialized representation.

### Authority journals and auxiliary custody

| Format | Fixed-vector and corpus evidence | Bound and authority boundary |
| --- | --- | --- |
| Artifact-chain journal | `naome-storage/src/artifact_chain_journal/tests/admission.rs` and `tests/replay.rs` | Fixed header/chain ID, bounded block-plus-payload body, derived footer, strict ordered artifact replay; incomplete suffix recovery remains a separate oracle |
| Finality journal: finalize, selected conflict, preselection conflict pair | `naome-storage/src/fixed_validator_finality_journal/tests/replay.rs` and `tests/preselection_conflict.rs` | Tag-specific component widths, configured round-work ceiling before replay, strict transition verification, chained state identity and external anchor; repaired-footer mutations exercise inner fields |
| Vote-safety journal: tags `0x01` through `0x0c` | `naome-storage/src/fixed_validator_vote_safety_journal/tests/codec_replay.rs`, `tests/round_progression.rs` and `tests/conflict_stop.rs` | Tag-specific bounded width union; preparation limits, phase/lineage/order/pending/terminal guards and expected state identity. Corpus replay includes the exact prerequisite prefix and re-encodes record metadata plus independently covered embedded codecs |
| Finality and per-key vote anchors | `naome-storage/src/fixed_validator_anchor/tests.rs` | Exact widths and caller-expected context/set/key/limit; checksum-repaired field mutations, typed sequence/state re-encoding |
| Candidate-block and payload source logs | `naome-storage/src/block_candidate_store/tests.rs`; `naome-storage/src/payload_store/tests.rs` | Fixed block frames or bounded payload frames, integrity/footer checks and configured entry/total-payload limits; no source-log consensus validity or selection authority |
| Candidate recovery bundle | `naome-storage/src/artifact_chain_journal/tests/candidate_branch_recovery_bundle.rs` | Configured block, aggregate payload and complete-byte bounds; exhaustive truncations and repaired-digest mutations; independent field/entry encoder. Structural bundle decoding grants no artifact admission or branch preference |
| Artifact/block/head exchange, head announcement, recovery push, peer-record framing | `naome-network/src/transport/codec/tests.rs`; semantic fixed-field vectors in `naome-protocol/src/` | Exact request widths and EOF; response/count/length caps before body reads. Opaque frame acceptance is distinct from artifact admission and external signed peer-record validation |
| Consensus push: vote, proposal, receipt | `naome-network/src/transport/consensus_push/codec/tests.rs` | Both declared lengths rejected before body reads; aggregate inbound event/byte budget and permit release after accepted/rejected corpus cases |
| Finality exchange: request, unavailable/found response | `naome-network/src/transport/finality_exchange/tests.rs` | Positive requested height, exact request width, envelope/payload bounds before body reads and existing custody-budget tests |
| Raw retained-evidence image | `naome-node/src/fixed_validator/tests/driver/evidence_recovery.rs` | Four class budgets, total count/size, refusal mask, class/kind order, duplicates and historical-parent re-verification; all four classes have an independently assembled frame and accepted restore/export equality; authority files stay byte-identical |
| Runtime evidence-file checksum wrapper | `naome-runtime/src/evidence_journal/tests.rs` | Configured file/image byte cap, regular-file/length/checksum checks; raw image custody remains Unix-only and grants no signing authority |
| Runtime publication-delivery receipts | `naome-runtime/src/publication_journal/tests.rs` | Source-history count bound, sorted unique completion IDs, fixed per-peer counters and allowed receipt bits; independent two-record vector, repaired-checksum corpus, duplicate/reorder/unused-peer/false-receipt rejection with a fresh decoding owner |

The vote-safety tag inventory is: vote prepare (`01`), vote completion (`02`),
vote conflict stop (`03`), signing lineage (`04`), selected-finality stop (`05`),
higher-round checkpoint (`06`), proposal activation (`07`), proposal prepare
(`08`), legacy proposal completion (`09`), proposal conflict stop (`0a`),
preselection-finality stop (`0b`) and payload-bearing proposal completion (`0c`).
Journal replay of `0c` retains bounded opaque artifact bytes; historical-parent
payload validation belongs to node recovery. Checkpoint replay proves structural
consistency; quorum authentication belongs to typed state recovery. The corpus
must preserve both separations.

Peer identity envelopes, addresses, process configuration text, JSON/TOML and
local diagnostic output are not NAOME consensus-canonical representations.
Their existing framing/configuration checks remain separate. This inventory
adds no peer trust, automatic branch preference, rollback protection, signing,
selection or finality authority.
