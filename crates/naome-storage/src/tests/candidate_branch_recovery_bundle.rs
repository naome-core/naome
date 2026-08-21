use std::io::{Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};

use super::*;
use crate::fault_io::{Fault, ScriptedIo};
use crate::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreLimits, ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits,
    CandidateBranchRecoveryBundleLimits, CandidateBranchRecoveryBundleV0,
    CanonicalArtifactPayloadStore,
};

const CANDIDATE_STORE_FILE_NAME: &str = "artifact-block-candidate-store.log";
const CANDIDATE_STORE_HEADER: &[u8] = b"naome:artifact-block-candidate-store:v0\0";
const PAYLOAD_STORE_FILE_NAME: &str = "artifact-payload-store.log";
const BUNDLE_HEADER: &[u8] = b"naome:candidate-branch-recovery-bundle:v0\0";
const BUNDLE_DIGEST_DOMAIN: &[u8] = b"naome:candidate-branch-recovery-bundle-digest:v0\0";
const DIGEST_BYTES: usize = 32;
const FIXED_CONTEXT_BYTES: usize = 4 * 32;
const BLOCK_COUNT_BYTES: usize = 4;
const TOTAL_PAYLOAD_BYTES: usize = 8;
const PAYLOAD_LENGTH_BYTES: usize = 4;
const BUNDLE_PREFIX_BYTES: usize =
    BUNDLE_HEADER.len() + FIXED_CONTEXT_BYTES + BLOCK_COUNT_BYTES + TOTAL_PAYLOAD_BYTES;

fn candidate_limits(entries: usize) -> ArtifactBlockCandidateStoreLimits {
    ArtifactBlockCandidateStoreLimits::new(entries).unwrap()
}

fn genesis_root(definition: ArtifactChainDefinition) -> ArtifactSetRoot {
    ArtifactChainState::new(definition)
        .artifact_dag()
        .artifact_set_root()
}

fn payload_limits(entries: usize, payload_bytes: usize) -> ArtifactPayloadStoreLimits {
    ArtifactPayloadStoreLimits::new(entries, u64::try_from(payload_bytes).unwrap()).unwrap()
}

fn bundle_limits(
    blocks: usize,
    payload_bytes: usize,
    bundle_bytes: usize,
) -> CandidateBranchRecoveryBundleLimits {
    CandidateBranchRecoveryBundleLimits::new(
        blocks,
        u64::try_from(payload_bytes).unwrap(),
        u64::try_from(bundle_bytes).unwrap(),
    )
    .unwrap()
}

fn encoded_bundle_len(blocks: usize, payload_bytes: usize) -> usize {
    BUNDLE_PREFIX_BYTES
        + blocks * (ARTIFACT_BLOCK_BYTES + PAYLOAD_LENGTH_BYTES)
        + payload_bytes
        + DIGEST_BYTES
}

fn exact_bundle_limits(
    blocks: &[ArtifactBlock],
    payloads: &[Vec<u8>],
) -> CandidateBranchRecoveryBundleLimits {
    let payload_bytes = payloads.iter().map(Vec::len).sum::<usize>();
    bundle_limits(
        blocks.len(),
        payload_bytes,
        encoded_bundle_len(blocks.len(), payload_bytes),
    )
}

fn branch_blocks(
    definition: ArtifactChainDefinition,
    payloads: &[Vec<u8>],
    artifact_ids: &[ArtifactId],
) -> Vec<ArtifactBlock> {
    assert_eq!(payloads.len(), artifact_ids.len());
    let mut branch = ArtifactChainState::new(definition);
    let mut blocks = Vec::with_capacity(payloads.len());
    for (payload, artifact_id) in payloads.iter().zip(artifact_ids.iter().copied()) {
        let block = branch.prepare_block(artifact_id).unwrap();
        branch.apply_block(&block, payload.clone()).unwrap();
        blocks.push(block);
    }
    blocks
}

fn insert_candidates(store: &mut ArtifactBlockCandidateStore, blocks: &[ArtifactBlock]) {
    for block in blocks {
        assert_eq!(
            store.insert(block).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
    }
}

fn archive_payloads(
    store: &mut CanonicalArtifactPayloadStore,
    payloads: &[Vec<u8>],
    retained: &[usize],
) -> Vec<ArtifactId> {
    let mut source = ArtifactDag::new();
    payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            let record = source
                .apply_canonical_artifact_bytes(payload.clone())
                .unwrap();
            let artifact_id = record.artifact_id();
            if retained.contains(&index) {
                assert_eq!(
                    store.insert(record).unwrap(),
                    ArtifactPayloadInsertOutcome::Inserted
                );
            }
            artifact_id
        })
        .collect()
}

fn encode_bundle(
    chain_id: ArtifactChainId,
    anchor_block_id: ArtifactBlockId,
    anchor_root: ArtifactSetRoot,
    target_block_id: ArtifactBlockId,
    blocks: &[ArtifactBlock],
    payloads: &[Vec<u8>],
) -> Vec<u8> {
    assert_eq!(blocks.len(), payloads.len());
    let total_payload_bytes = payloads.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(encoded_bundle_len(blocks.len(), total_payload_bytes));
    bytes.extend_from_slice(BUNDLE_HEADER);
    bytes.extend_from_slice(chain_id.as_bytes());
    bytes.extend_from_slice(anchor_block_id.as_bytes());
    bytes.extend_from_slice(anchor_root.as_bytes());
    bytes.extend_from_slice(target_block_id.as_bytes());
    bytes.extend_from_slice(&u32::try_from(blocks.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&u64::try_from(total_payload_bytes).unwrap().to_be_bytes());
    for (block, payload) in blocks.iter().zip(payloads) {
        bytes.extend_from_slice(&block.to_canonical_bytes());
        bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(payload);
    }
    let digest = bundle_digest(&bytes);
    bytes.extend_from_slice(&digest);
    bytes
}

fn bundle_digest(body: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(BUNDLE_DIGEST_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

fn replace_digest(bytes: &mut [u8]) {
    let body_len = bytes.len() - DIGEST_BYTES;
    let digest = bundle_digest(&bytes[..body_len]);
    bytes[body_len..].copy_from_slice(&digest);
}

fn flip_byte(path: &std::path::Path, offset: u64) {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&[byte[0] ^ 1]).unwrap();
    file.sync_all().unwrap();
}

fn selected_snapshot(
    journal: &ArtifactChainJournal,
    directory: &TestDirectory,
) -> SelectedSnapshot {
    SelectedSnapshot {
        head: journal.head_block_id().unwrap(),
        root: journal.artifact_set_root().unwrap(),
        len: journal.len().unwrap(),
        bytes: fs::read(directory.journal_path()).unwrap(),
    }
}

fn assert_selected_unchanged(
    journal: &ArtifactChainJournal,
    directory: &TestDirectory,
    before: &SelectedSnapshot,
) {
    assert_eq!(journal.head_block_id().unwrap(), before.head);
    assert_eq!(journal.artifact_set_root().unwrap(), before.root);
    assert_eq!(journal.len().unwrap(), before.len);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), before.bytes);
}

struct SelectedSnapshot {
    head: ArtifactBlockId,
    root: ArtifactSetRoot,
    len: usize,
    bytes: Vec<u8>,
}

fn decode_bundle(
    bytes: &[u8],
    blocks: usize,
    payload_bytes: usize,
) -> CandidateBranchRecoveryBundleV0 {
    CandidateBranchRecoveryBundleV0::from_canonical_bytes(
        bytes,
        bundle_limits(blocks, payload_bytes, bytes.len()),
    )
    .unwrap()
}

fn assert_decode_rejected(bytes: &[u8], limits: CandidateBranchRecoveryBundleLimits) {
    assert!(CandidateBranchRecoveryBundleV0::from_canonical_bytes(bytes, limits).is_err());
}

struct BundleFixture {
    definition: ArtifactChainDefinition,
    payloads: Vec<Vec<u8>>,
    blocks: Vec<ArtifactBlock>,
    bytes: Vec<u8>,
    limits: CandidateBranchRecoveryBundleLimits,
}

impl BundleFixture {
    fn new(block_count: usize) -> Self {
        let definition = chain_definition(CHAIN_BYTE);
        let (payloads, artifact_ids) = dependency_chain_with_len(block_count);
        let blocks = branch_blocks(definition, &payloads, &artifact_ids);
        let bytes = encode_bundle(
            definition.id(),
            definition.id().virtual_genesis_block_id(),
            genesis_root(definition),
            blocks.last().unwrap().id(),
            &blocks,
            &payloads,
        );
        let limits = exact_bundle_limits(&blocks, &payloads);
        Self {
            definition,
            payloads,
            blocks,
            bytes,
            limits,
        }
    }

    fn payload_bytes(&self) -> usize {
        self.payloads.iter().map(Vec::len).sum()
    }

    fn decode(&self) -> CandidateBranchRecoveryBundleV0 {
        CandidateBranchRecoveryBundleV0::from_canonical_bytes(&self.bytes, self.limits).unwrap()
    }

    fn below_each_limit(&self) -> [CandidateBranchRecoveryBundleLimits; 3] {
        [
            bundle_limits(1, self.payload_bytes(), self.bytes.len()),
            bundle_limits(
                self.blocks.len(),
                self.payload_bytes() - 1,
                self.bytes.len(),
            ),
            bundle_limits(
                self.blocks.len(),
                self.payload_bytes(),
                self.bytes.len() - 1,
            ),
        ]
    }
}

fn export_source(
    directory: &TestDirectory,
    fixture: &BundleFixture,
    candidate_definition: ArtifactChainDefinition,
    candidate_indices: &[usize],
    payload_indices: &[usize],
) -> (
    ArtifactChainJournal,
    ArtifactBlockCandidateStore,
    CanonicalArtifactPayloadStore,
) {
    let journal = ArtifactChainJournal::create(&directory.path, fixture.definition).unwrap();
    let mut candidates = ArtifactBlockCandidateStore::create(
        &directory.path,
        candidate_definition,
        candidate_limits(candidate_indices.len().max(1)),
    )
    .unwrap();
    for &index in candidate_indices {
        insert_candidates(&mut candidates, &fixture.blocks[index..=index]);
    }
    let retained_bytes = payload_indices
        .iter()
        .map(|&index| fixture.payloads[index].len())
        .sum::<usize>();
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(payload_indices.len().max(1), retained_bytes.max(1)),
    )
    .unwrap();
    archive_payloads(&mut payloads, &fixture.payloads, payload_indices);
    (journal, candidates, payloads)
}

fn assert_import_rejected(
    journal: &mut ArtifactChainJournal,
    directory: &TestDirectory,
    bundle: &CandidateBranchRecoveryBundleV0,
    limits: CandidateBranchRecoveryBundleLimits,
) {
    let before = selected_snapshot(journal, directory);
    assert!(
        journal
            .import_candidate_branch_recovery_bundle_v0(bundle, limits)
            .is_err()
    );
    assert_selected_unchanged(journal, directory, &before);
}

fn assert_export_rejected_unchanged(
    journal: &ArtifactChainJournal,
    directory: &TestDirectory,
    target: ArtifactBlockId,
    candidates: &mut ArtifactBlockCandidateStore,
    payloads: &mut CanonicalArtifactPayloadStore,
    limits: CandidateBranchRecoveryBundleLimits,
) {
    let selected = selected_snapshot(journal, directory);
    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    assert!(
        journal
            .export_candidate_branch_recovery_bundle_v0(target, candidates, payloads, limits)
            .is_err()
    );
    assert_selected_unchanged(journal, directory, &selected);
    assert_eq!(
        fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
}

#[test]
fn exported_bundle_round_trips_and_imports_without_mutating_recovery_stores() {
    let directory = TestDirectory::new();
    let fixture = BundleFixture::new(2);
    let genesis = fixture.definition.id().virtual_genesis_block_id();
    let (mut journal, mut candidates, mut payload_store) =
        export_source(&directory, &fixture, fixture.definition, &[0, 1], &[0, 1]);
    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let before_export = selected_snapshot(&journal, &directory);

    let bundle = journal
        .export_candidate_branch_recovery_bundle_v0(
            fixture.blocks.last().unwrap().id(),
            &mut candidates,
            &mut payload_store,
            fixture.limits,
        )
        .unwrap();
    assert_selected_unchanged(&journal, &directory, &before_export);
    assert_eq!(
        fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
    assert_eq!(
        (
            bundle.chain_id(),
            bundle.anchor_block_id(),
            bundle.anchor_artifact_set_root(),
            bundle.target_block_id(),
            bundle.block_count(),
            bundle.total_payload_bytes(),
        ),
        (
            fixture.definition.id(),
            genesis,
            genesis_root(fixture.definition),
            fixture.blocks.last().unwrap().id(),
            fixture.blocks.len(),
            u64::try_from(fixture.payload_bytes()).unwrap(),
        )
    );

    let canonical = bundle.canonical_bytes().to_vec();
    assert_eq!(
        canonical,
        encode_bundle(
            fixture.definition.id(),
            genesis,
            genesis_root(fixture.definition),
            fixture.blocks.last().unwrap().id(),
            &fixture.blocks,
            &fixture.payloads,
        )
    );
    assert_eq!(
        canonical.len(),
        encoded_bundle_len(fixture.blocks.len(), fixture.payload_bytes())
    );
    let decoded =
        CandidateBranchRecoveryBundleV0::from_canonical_bytes(&canonical, fixture.limits).unwrap();
    assert_eq!(decoded.canonical_bytes(), canonical);
    assert_eq!(decoded.into_canonical_bytes(), canonical);

    let outcome = journal
        .import_candidate_branch_recovery_bundle_v0(&bundle, fixture.limits)
        .unwrap();
    assert_eq!(
        (
            outcome.anchor_block_id(),
            outcome.resumed_from_block_id(),
            outcome.target_block_id(),
            outcome.already_selected_block_count(),
            outcome.committed_block_count(),
            outcome.total_payload_bytes(),
        ),
        (
            genesis,
            genesis,
            fixture.blocks.last().unwrap().id(),
            0,
            fixture.blocks.len(),
            bundle.total_payload_bytes(),
        )
    );
    assert_eq!(journal.head_block_id().unwrap(), bundle.target_block_id());
    assert_eq!(journal.len().unwrap(), fixture.blocks.len());
    assert_eq!(
        fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
}

#[test]
fn export_rejects_each_local_cap_without_mutating_any_store() {
    let directory = TestDirectory::new();
    let fixture = BundleFixture::new(2);
    let (journal, mut candidates, mut payloads) =
        export_source(&directory, &fixture, fixture.definition, &[0, 1], &[0, 1]);
    for limits in fixture.below_each_limit() {
        assert_export_rejected_unchanged(
            &journal,
            &directory,
            fixture.blocks[1].id(),
            &mut candidates,
            &mut payloads,
            limits,
        );
    }
}

#[test]
fn export_rejects_chain_mismatch_and_missing_candidate_or_payload() {
    let fixture = BundleFixture::new(2);
    for (candidate_definition, candidate_indices, payload_indices) in [
        (
            chain_definition(CHAIN_BYTE ^ 0xff),
            &[0, 1][..],
            &[0, 1][..],
        ),
        (fixture.definition, &[1][..], &[0, 1][..]),
        (fixture.definition, &[0, 1][..], &[0][..]),
    ] {
        let directory = TestDirectory::new();
        let (journal, mut candidates, mut payloads) = export_source(
            &directory,
            &fixture,
            candidate_definition,
            candidate_indices,
            payload_indices,
        );
        assert_export_rejected_unchanged(
            &journal,
            &directory,
            fixture.blocks[1].id(),
            &mut candidates,
            &mut payloads,
            fixture.limits,
        );
    }
}

#[test]
fn export_candidate_corruption_poisons_only_that_store_and_never_writes_selected_state() {
    let directory = TestDirectory::new();
    let fixture = BundleFixture::new(2);
    let (journal, mut candidates, mut payloads) =
        export_source(&directory, &fixture, fixture.definition, &[0, 1], &[0, 1]);
    flip_byte(
        &directory.path.join(CANDIDATE_STORE_FILE_NAME),
        u64::try_from(CANDIDATE_STORE_HEADER.len() + ArtifactChainId::BYTE_LENGTH).unwrap(),
    );

    assert_export_rejected_unchanged(
        &journal,
        &directory,
        fixture.blocks[1].id(),
        &mut candidates,
        &mut payloads,
        fixture.limits,
    );
    assert!(matches!(
        candidates.len(),
        Err(crate::ArtifactBlockCandidateStoreError::Poisoned)
    ));
    assert_eq!(payloads.len().unwrap(), fixture.payloads.len());
}

#[test]
fn decoder_rejects_every_truncation_trailing_bytes_and_digest_change() {
    let fixture = BundleFixture::new(2);

    for length in 0..fixture.bytes.len() {
        assert!(
            CandidateBranchRecoveryBundleV0::from_canonical_bytes(
                &fixture.bytes[..length],
                fixture.limits
            )
            .is_err(),
            "accepted truncated bundle length {length}"
        );
    }

    let mut trailing = fixture.bytes.clone();
    trailing.push(0xff);
    assert_decode_rejected(
        &trailing,
        bundle_limits(
            fixture.blocks.len(),
            fixture.payload_bytes(),
            trailing.len(),
        ),
    );

    let mut bad_header = fixture.bytes.clone();
    bad_header[0] ^= 1;
    assert_decode_rejected(&bad_header, fixture.limits);

    let mut bad_digest = fixture.bytes.clone();
    *bad_digest.last_mut().unwrap() ^= 1;
    assert_decode_rejected(&bad_digest, fixture.limits);
}

#[test]
fn decoder_enforces_count_payload_and_complete_byte_limits_and_consistency() {
    assert!(CandidateBranchRecoveryBundleLimits::new(0, 1, 1).is_err());
    assert!(CandidateBranchRecoveryBundleLimits::new(1, 0, 1).is_err());
    assert!(CandidateBranchRecoveryBundleLimits::new(1, 1, 0).is_err());

    let fixture = BundleFixture::new(2);

    for limits in fixture.below_each_limit() {
        assert_decode_rejected(&fixture.bytes, limits);
    }

    let count_offset = BUNDLE_HEADER.len() + FIXED_CONTEXT_BYTES;
    let total_offset = count_offset + BLOCK_COUNT_BYTES;
    let first_payload_length_offset = BUNDLE_PREFIX_BYTES + ARTIFACT_BLOCK_BYTES;

    let mut zero_count = fixture.bytes.clone();
    zero_count[count_offset..count_offset + 4].copy_from_slice(&0_u32.to_be_bytes());
    replace_digest(&mut zero_count);
    assert_decode_rejected(
        &zero_count,
        bundle_limits(
            fixture.blocks.len(),
            fixture.payload_bytes(),
            zero_count.len(),
        ),
    );

    let mut wrong_total = fixture.bytes.clone();
    wrong_total[total_offset..total_offset + 8]
        .copy_from_slice(&(u64::try_from(fixture.payload_bytes()).unwrap() + 1).to_be_bytes());
    replace_digest(&mut wrong_total);
    assert_decode_rejected(
        &wrong_total,
        bundle_limits(
            fixture.blocks.len(),
            fixture.payload_bytes() + 1,
            wrong_total.len(),
        ),
    );

    let mut zero_payload = fixture.bytes.clone();
    zero_payload[first_payload_length_offset..first_payload_length_offset + 4]
        .copy_from_slice(&0_u32.to_be_bytes());
    replace_digest(&mut zero_payload);
    assert_decode_rejected(
        &zero_payload,
        bundle_limits(
            fixture.blocks.len(),
            fixture.payload_bytes(),
            zero_payload.len(),
        ),
    );

    let mut oversized_payload = fixture.bytes.clone();
    oversized_payload[first_payload_length_offset..first_payload_length_offset + 4]
        .copy_from_slice(&u32::MAX.to_be_bytes());
    replace_digest(&mut oversized_payload);
    assert_decode_rejected(
        &oversized_payload,
        bundle_limits(
            fixture.blocks.len(),
            u32::MAX as usize,
            oversized_payload.len(),
        ),
    );
}

#[test]
fn import_rejects_cross_chain_anchor_root_target_and_path_changes_before_writing() {
    let fixture = BundleFixture::new(2);
    let bundle = fixture.decode();
    let wrong_chain_directory = TestDirectory::new();
    let wrong_definition = chain_definition(CHAIN_BYTE ^ 0xff);
    let mut wrong_chain_journal =
        ArtifactChainJournal::create(&wrong_chain_directory.path, wrong_definition).unwrap();
    assert_import_rejected(
        &mut wrong_chain_journal,
        &wrong_chain_directory,
        &bundle,
        fixture.limits,
    );

    let genesis = fixture.definition.id().virtual_genesis_block_id();
    for (anchor, root) in [
        (
            ArtifactBlockId::from_bytes([0xa5; 32]),
            genesis_root(fixture.definition),
        ),
        (genesis, ArtifactSetRoot::from_bytes([0x5a; 32])),
    ] {
        let first = ArtifactBlock::new(
            anchor,
            root,
            fixture.blocks[0].resulting_artifact_set_root(),
            fixture.blocks[0].artifact_id(),
        );
        let second = ArtifactBlock::new(
            first.id(),
            first.resulting_artifact_set_root(),
            fixture.blocks[1].resulting_artifact_set_root(),
            fixture.blocks[1].artifact_id(),
        );
        let blocks = [first, second];
        let bytes = encode_bundle(
            fixture.definition.id(),
            anchor,
            root,
            second.id(),
            &blocks,
            &fixture.payloads,
        );
        let changed = decode_bundle(&bytes, blocks.len(), fixture.payload_bytes());
        let directory = TestDirectory::new();
        let mut journal =
            ArtifactChainJournal::create(&directory.path, fixture.definition).unwrap();
        assert_import_rejected(
            &mut journal,
            &directory,
            &changed,
            bundle_limits(blocks.len(), fixture.payload_bytes(), bytes.len()),
        );
    }

    let target_offset = BUNDLE_HEADER.len()
        + ArtifactChainId::BYTE_LENGTH
        + ArtifactBlockId::BYTE_LENGTH
        + ArtifactSetRoot::BYTE_LENGTH;
    let mut wrong_target = fixture.bytes.clone();
    wrong_target[target_offset] ^= 1;
    replace_digest(&mut wrong_target);
    assert!(
        CandidateBranchRecoveryBundleV0::from_canonical_bytes(&wrong_target, fixture.limits)
            .is_err()
    );

    let malformed_second = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0xa5; 32]),
        fixture.blocks[1].previous_artifact_set_root(),
        fixture.blocks[1].resulting_artifact_set_root(),
        fixture.blocks[1].artifact_id(),
    );
    let malformed_blocks = [fixture.blocks[0], malformed_second];
    let malformed = encode_bundle(
        fixture.definition.id(),
        genesis,
        genesis_root(fixture.definition),
        malformed_second.id(),
        &malformed_blocks,
        &fixture.payloads,
    );
    assert!(
        CandidateBranchRecoveryBundleV0::from_canonical_bytes(
            &malformed,
            bundle_limits(
                malformed_blocks.len(),
                fixture.payload_bytes(),
                malformed.len()
            )
        )
        .is_err()
    );
}

#[test]
fn import_rechecks_payload_canonicality_and_committed_identity_before_writing() {
    let fixture = BundleFixture::new(2);
    let payload_start = BUNDLE_PREFIX_BYTES + ARTIFACT_BLOCK_BYTES + PAYLOAD_LENGTH_BYTES;
    let replacement = axiom_bytes(ZfcAxiom::Union);
    assert_eq!(replacement.len(), fixture.payloads[0].len());

    let mut noncanonical = fixture.bytes.clone();
    noncanonical[payload_start] = 0xff;
    replace_digest(&mut noncanonical);
    let mut wrong_identity = fixture.bytes.clone();
    wrong_identity[payload_start..payload_start + replacement.len()].copy_from_slice(&replacement);
    replace_digest(&mut wrong_identity);

    for bytes in [noncanonical, wrong_identity] {
        let bundle = decode_bundle(&bytes, fixture.blocks.len(), fixture.payload_bytes());
        let directory = TestDirectory::new();
        let mut journal =
            ArtifactChainJournal::create(&directory.path, fixture.definition).unwrap();
        journal
            .apply_block(&fixture.blocks[0], fixture.payloads[0].clone())
            .unwrap();
        assert_import_rejected(&mut journal, &directory, &bundle, fixture.limits);
        assert_eq!(
            journal.head_block_id().unwrap(),
            fixture.blocks[0].id(),
            "invalid replayed prefix payload advanced the selected journal"
        );
    }
}

#[test]
fn invalid_late_payload_preflight_selects_no_valid_prefix() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let genesis = definition.id().virtual_genesis_block_id();
    let first_payload = axiom_bytes(ZfcAxiom::Pairing);
    let mut first_source = ArtifactDag::new();
    let first_id = first_source
        .apply_canonical_artifact_bytes(first_payload.clone())
        .unwrap()
        .artifact_id();

    let mut other_context = ArtifactDag::new();
    let dependency = other_context
        .apply_canonical_artifact_bytes(axiom_bytes(ZfcAxiom::Union))
        .unwrap();
    let second_payload = referenced_generalization(
        dependency.as_proof().unwrap().proof_id(),
        FreeVariable::new(17),
    );
    let second_id = other_context
        .apply_canonical_artifact_bytes(second_payload.clone())
        .unwrap()
        .artifact_id();

    let mut shape = ArtifactChainState::new(definition);
    let first = shape.prepare_block(first_id).unwrap();
    shape.apply_block(&first, first_payload.clone()).unwrap();
    let target = shape.prepare_block(second_id).unwrap();
    let payloads = [first_payload, second_payload];
    let blocks = [first, target];
    let canonical = encode_bundle(
        definition.id(),
        genesis,
        genesis_root(definition),
        target.id(),
        &blocks,
        &payloads,
    );
    let bundle = decode_bundle(
        &canonical,
        blocks.len(),
        payloads.iter().map(Vec::len).sum(),
    );
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let before = selected_snapshot(&journal, &directory);

    assert!(
        journal
            .import_candidate_branch_recovery_bundle_v0(
                &bundle,
                bundle_limits(
                    blocks.len(),
                    payloads.iter().map(Vec::len).sum(),
                    canonical.len()
                ),
            )
            .is_err()
    );
    assert_selected_unchanged(&journal, &directory, &before);
    assert!(journal.artifact(first_id).unwrap().is_none());
}

#[test]
fn import_resumes_only_an_exact_selected_prefix_and_is_idempotent_at_target() {
    let fixture = BundleFixture::new(2);
    let bundle = fixture.decode();
    let genesis = fixture.definition.id().virtual_genesis_block_id();

    let destination = TestDirectory::new();
    let mut journal = ArtifactChainJournal::create(&destination.path, fixture.definition).unwrap();
    journal
        .apply_block(&fixture.blocks[0], fixture.payloads[0].clone())
        .unwrap();
    let resumed = journal
        .import_candidate_branch_recovery_bundle_v0(&bundle, fixture.limits)
        .unwrap();
    assert_eq!(resumed.anchor_block_id(), genesis);
    assert_eq!(resumed.resumed_from_block_id(), fixture.blocks[0].id());
    assert_eq!(resumed.already_selected_block_count(), 1);
    assert_eq!(resumed.committed_block_count(), 1);
    assert_eq!(journal.head_block_id().unwrap(), fixture.blocks[1].id());

    let completed_image = fs::read(destination.journal_path()).unwrap();
    let idempotent = journal
        .import_candidate_branch_recovery_bundle_v0(&bundle, fixture.limits)
        .unwrap();
    assert_eq!(idempotent.resumed_from_block_id(), fixture.blocks[1].id());
    assert_eq!(idempotent.already_selected_block_count(), 2);
    assert_eq!(idempotent.committed_block_count(), 0);
    assert_eq!(
        fs::read(destination.journal_path()).unwrap(),
        completed_image
    );
}

#[test]
fn divergent_or_longer_selected_history_cannot_be_skipped_or_rolled_back() {
    let fixture = BundleFixture::new(3);
    let bundled_blocks = &fixture.blocks[..2];
    let bundled_payloads = &fixture.payloads[..2];
    let canonical = encode_bundle(
        fixture.definition.id(),
        fixture.definition.id().virtual_genesis_block_id(),
        genesis_root(fixture.definition),
        bundled_blocks.last().unwrap().id(),
        bundled_blocks,
        bundled_payloads,
    );
    let bundle = decode_bundle(
        &canonical,
        bundled_blocks.len(),
        bundled_payloads.iter().map(Vec::len).sum(),
    );
    let limits = bundle_limits(
        bundled_blocks.len(),
        bundled_payloads.iter().map(Vec::len).sum(),
        canonical.len(),
    );

    let longer = TestDirectory::new();
    let mut longer_journal =
        ArtifactChainJournal::create(&longer.path, fixture.definition).unwrap();
    for (block, payload) in fixture.blocks.iter().zip(&fixture.payloads) {
        longer_journal.apply_block(block, payload.clone()).unwrap();
    }
    assert_import_rejected(&mut longer_journal, &longer, &bundle, limits);

    let divergent = TestDirectory::new();
    let mut divergent_journal =
        ArtifactChainJournal::create(&divergent.path, fixture.definition).unwrap();
    let sibling_payload = axiom_bytes(ZfcAxiom::PowerSet);
    let sibling_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(sibling_payload.clone())
        .unwrap()
        .artifact_id();
    let sibling = divergent_journal.prepare_block(sibling_id).unwrap();
    divergent_journal
        .apply_block(&sibling, sibling_payload)
        .unwrap();
    assert_import_rejected(&mut divergent_journal, &divergent, &bundle, limits);
}

#[test]
fn tighter_import_limits_redecode_the_owned_bundle_before_any_write() {
    let directory = TestDirectory::new();
    let fixture = BundleFixture::new(2);
    let bundle = fixture.decode();
    let mut journal = ArtifactChainJournal::create(&directory.path, fixture.definition).unwrap();

    for limits in fixture.below_each_limit() {
        assert_import_rejected(&mut journal, &directory, &bundle, limits);
    }
}

#[test]
fn commit_faults_report_only_acknowledged_blocks_and_reopen_resumes_exact_durable_prefix() {
    let fixture = BundleFixture::new(2);
    let bundle = fixture.decode();
    let genesis = fixture.definition.id().virtual_genesis_block_id();
    let first_body_bytes = 4 + ARTIFACT_BLOCK_BYTES + fixture.payloads[0].len();
    for (fault, acknowledged, failed, last_acknowledged) in [
        (
            Fault::Write {
                phase: AppendPhase::Body,
                after: first_body_bytes + 1,
            },
            1,
            fixture.blocks[1].id(),
            fixture.blocks[0].id(),
        ),
        (
            Fault::SyncAfter {
                phase: AppendPhase::Commit,
            },
            0,
            fixture.blocks[0].id(),
            genesis,
        ),
    ] {
        let io = ScriptedIo::new(journal_prefix(fixture.definition.id()), Some(fault.clone()));
        let mut core = JournalCore::empty(io, ArtifactChainState::new(fixture.definition));
        let error = core
            .import_candidate_branch_recovery_bundle_v0(&bundle, fixture.limits)
            .unwrap_err();
        let crate::CandidateBranchRecoveryBundleImportError::Commit { source } = error else {
            panic!("fault {fault:?} returned a non-commit error")
        };
        assert_eq!(source.failed_block_id(), failed);
        assert_eq!(source.committed_block_count(), acknowledged);
        assert_eq!(source.last_acknowledged_head_block_id(), last_acknowledged);
        assert!(matches!(
            core.ensure_healthy(),
            Err(ArtifactChainJournalError::Poisoned)
        ));

        let durable = core.file.durable.clone();
        let mut reopened = JournalCore::replay(
            ScriptedIo::from_images(durable.clone(), durable),
            fixture.definition,
            None,
        )
        .unwrap();
        assert_eq!(reopened.chain.head_block_id(), fixture.blocks[0].id());
        let resumed = reopened
            .import_candidate_branch_recovery_bundle_v0(&bundle, fixture.limits)
            .unwrap();
        assert_eq!(resumed.resumed_from_block_id(), fixture.blocks[0].id());
        assert_eq!(resumed.already_selected_block_count(), 1);
        assert_eq!(resumed.committed_block_count(), 1);
        assert_eq!(reopened.chain.head_block_id(), fixture.blocks[1].id());
    }
}
