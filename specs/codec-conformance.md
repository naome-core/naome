# Canonical codec conformance

This contract covers the current serialized formats below. A new
consensus-critical representation must extend this inventory and its executable
vectors, mutation corpus and resource oracles in the same change. State-v5
adds a selected authority snapshot, exact record-bound handoff plan, and a
sealed finality envelope. Structural decoding alone never selects them.

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
hash vectors, and exact complete-state replay. Workspace validation executes the
portable codecs on Linux, macOS, and Windows. Canonical key custody and live node
execution remain Unix-only; portable offline verification remains separate.

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
prefix tests remain in place. Journal-body and receipt tests
also recompute framing hashes so malformed fields reach the inner parser.

Resource evidence uses actual decoded node counts, explicit byte/count/depth
errors, cursor read positions and retention-permit accounting. It does not use
elapsed time as a resource oracle. These are bounded regression campaigns,
not an exhaustive enumeration of all byte strings or a coverage-guided fuzzing
service. A successful run establishes the assertions for its executed cases.

## Current format inventory

Paths are relative to `crates/`. The shared mutation campaign above applies to
proof/definition/set codecs. The state family additionally has fixed replay
vectors and explicit malformed-input tests at its actual acceptance boundaries;
this does not claim every state parser uses the shared campaign.

| Format | Executable evidence | Bound or authority boundary |
| --- | --- | --- |
| Primitive and defined formulas; proof certificates; conservative definitions; tagged artifact payloads | `naome-foundation/src/formula/canonical/tests.rs`, `naome-proof/src/codec/tests/`, `naome-proof/src/codec_conformance.rs`, `naome-ledger/tests/canonical_decoders.rs` | Exact canonical re-encoding; compiled byte, node, depth, step, and arity limits; decoding grants no checked admission |
| Artifact-set membership and nonmembership proofs | `naome-ledger/src/artifact_set/codec/tests.rs` | At most 256 ordered path steps, exact framing and full-depth corpus; set membership supplies no finality |
| State profile, genesis, authenticated operations, certified time, complete records and handoff plans | `naome-chain/src/state/tests/golden.rs`, `naome-chain/src/state/tests/golden-current.txt`, `naome-ledger/src/profile.rs`, `naome-ledger/src/time/tests.rs`, `naome-ledger/src/state/tests.rs` | Protocol version 5, genesis-bound limits and domains, selected-parent time/authority, owner and new-key possession, exact-parent execution and byte-identical effects/state commitment |
| Authority snapshots, period offers and candidate readiness | `naome-ledger/src/authority.rs`, `naome-ledger/src/authority/plan.rs`, `naome-ledger/src/state/tests.rs` | Four stable weighted slots, at least three current offers, live oldest-eligible intent, original receipt/expiry, fresh keys, exact selected parent; shape decoding grants no authority |
| State values, proposals, votes, quorum evidence, agreement, READY/TERMINAL seal and finalized envelopes | `naome-consensus/src/state/tests.rs`, `naome-consensus/src/state/tests/handoff.rs`, `naome-consensus/src/state/tests/golden.rs`, `naome-consensus/src/state/tests/golden-current.txt` | Outgoing snapshot, role, position, scheduled stable slot, distinct three-of-four signers, both seal quorums, framing and round bound; complete exact-parent authentication precedes mathematical replay |
| Settlement receipts and exact reward allocation | `naome-chain/src/state/receipt_tests.rs` | Truncation and altered reward rejection; receipts derive from actual canonical settlements and outgoing service accounts |
| Canonical history, period signer/custody, candidate import, handoff journal and independent anchors | `naome-storage/src/state/tests.rs`, `naome-storage/src/state/log_tests.rs`, `naome-storage/tests/exclusive_lock.rs` | Bounded complete frames, chained identity, exact sealed replay, owner/anchor locks, prepare-before-READY, save-and-retire-before-TERMINAL-release; incomplete suffix recovery requires the anchored prefix |
| State request/response, staged handoff, recovery and proof transfer | `naome-protocol/src/state_exchange/tests.rs`, `naome-network/src/transport/state_exchange/tests/` | Version/genesis/profile/direction, EOF, frame/proof bounds, transport custody permits, recovery nonce and exact response correlation; peer provenance grants no selected authority |
| Public offline archive and candidate setup | `naome-cli/src/archive_tests.rs`, `naome-cli/src/app/setup/candidate.rs`, `naome-verifier/tests/canonical.rs` | Bounded regular input, full independent sealed replay, corruption/context rejection; candidate custody imports only an exact finalized intent, while verifier opens no signing stores |

The V0 artifact blocks, legacy candidate bundles and old node evidence images
are retired. They are not alternate accepted encodings. State-v5 agreement,
seal and custody journals are the current formats. Old state framing is rejected
without rewriting or importing it as selected authority.

Peer addresses, process configuration, and diagnostic JSON are not canonical
consensus representations. Their independent framing and configuration checks
grant no trust, signing permission, selection, or finality. A local replay or
codec campaign does not establish physical multi-machine operation.
