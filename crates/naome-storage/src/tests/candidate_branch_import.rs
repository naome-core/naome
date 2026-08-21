use std::io::{Read, Seek, SeekFrom, Write};

use super::*;
use crate::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError, ArtifactBlockCandidateStoreLimits,
    ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits, CandidateBranchArchiveImportError,
    CandidateBranchArchiveImportLimits, CandidateBranchArchiveImportLimitsError,
    CandidateBranchArchiveImportPreflightError, CanonicalArtifactPayloadStore,
};

const CANDIDATE_STORE_FILE_NAME: &str = "artifact-block-candidate-store.log";
const CANDIDATE_STORE_HEADER: &[u8] = b"naome:artifact-block-candidate-store:v0\0";
const PAYLOAD_STORE_FILE_NAME: &str = "artifact-payload-store.log";
const PAYLOAD_STORE_HEADER: &[u8] = b"naome:artifact-payload-store:v1\0";
const FOUNDATION_ID: &[u8] = b"naome:zfc";

fn candidate_limits(entries: usize) -> ArtifactBlockCandidateStoreLimits {
    ArtifactBlockCandidateStoreLimits::new(entries).unwrap()
}

fn payload_limits(entries: usize, payload_bytes: u64) -> ArtifactPayloadStoreLimits {
    ArtifactPayloadStoreLimits::new(entries, payload_bytes).unwrap()
}

fn import_limits(blocks: usize, payload_bytes: usize) -> CandidateBranchArchiveImportLimits {
    CandidateBranchArchiveImportLimits::new(blocks, u64::try_from(payload_bytes).unwrap()).unwrap()
}

fn payload_bytes(payloads: &[Vec<u8>]) -> usize {
    payloads.iter().map(Vec::len).sum()
}

fn insert_candidates(store: &mut ArtifactBlockCandidateStore, blocks: &[ArtifactBlock]) {
    for block in blocks {
        assert_eq!(
            store.insert(block).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
    }
}

fn archive_selected_payloads(
    store: &mut CanonicalArtifactPayloadStore,
    payloads: &[Vec<u8>],
    retained_indices: &[usize],
) -> Vec<ArtifactId> {
    let mut source = ArtifactDag::new();
    let mut artifact_ids = Vec::with_capacity(payloads.len());
    for (index, payload) in payloads.iter().enumerate() {
        let record = source
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap();
        artifact_ids.push(record.artifact_id());
        if retained_indices.contains(&index) {
            assert_eq!(
                store.insert(record).unwrap(),
                ArtifactPayloadInsertOutcome::Inserted
            );
        }
    }
    artifact_ids
}

fn branch_blocks(
    definition: ArtifactChainDefinition,
    payloads: &[Vec<u8>],
    artifact_ids: &[ArtifactId],
) -> (Vec<ArtifactBlock>, ArtifactSetRoot) {
    assert_eq!(payloads.len(), artifact_ids.len());
    let mut branch = ArtifactChainState::new(definition);
    let mut blocks = Vec::with_capacity(payloads.len());
    for (payload, artifact_id) in payloads.iter().zip(artifact_ids.iter().copied()) {
        let block = branch.prepare_block(artifact_id).unwrap();
        branch.apply_block(&block, payload.clone()).unwrap();
        blocks.push(block);
    }
    (blocks, branch.artifact_dag().artifact_set_root())
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

#[test]
fn reopened_genesis_import_commits_the_exact_dependency_branch_offline() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let genesis = definition.id().virtual_genesis_block_id();
    let (payloads_to_archive, artifact_ids) = dependency_chain_with_len(2);
    let (blocks, expected_root) = branch_blocks(definition, &payloads_to_archive, &artifact_ids);
    let target = blocks[1];
    let candidate_policy = candidate_limits(blocks.len());
    let payload_policy = payload_limits(
        payloads_to_archive.len(),
        u64::try_from(payload_bytes(&payloads_to_archive)).unwrap(),
    );

    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_policy).unwrap();
    insert_candidates(&mut candidates, &blocks);
    let mut payloads =
        CanonicalArtifactPayloadStore::create(&directory.path, payload_policy).unwrap();
    archive_selected_payloads(&mut payloads, &payloads_to_archive, &[0, 1]);
    drop(payloads);
    drop(candidates);
    drop(journal);

    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let mut journal =
        ArtifactChainJournal::open_verified(&directory.path, definition, genesis).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::open(&directory.path, definition, candidate_policy).unwrap();
    let mut payloads =
        CanonicalArtifactPayloadStore::open(&directory.path, payload_policy).unwrap();

    let outcome = journal
        .import_candidate_branch_from_archive(
            target.id(),
            &mut candidates,
            &mut payloads,
            import_limits(blocks.len(), payload_bytes(&payloads_to_archive)),
        )
        .unwrap();
    assert_eq!(outcome.anchor_block_id(), genesis);
    assert_eq!(outcome.target_block_id(), target.id());
    assert_eq!(outcome.committed_block_count(), blocks.len());
    assert_eq!(
        outcome.buffered_payload_bytes(),
        u64::try_from(payload_bytes(&payloads_to_archive)).unwrap()
    );
    assert_eq!(journal.head_block_id().unwrap(), target.id());
    assert_eq!(journal.artifact_set_root().unwrap(), expected_root);
    assert_eq!(journal.len().unwrap(), blocks.len());
    for artifact_id in artifact_ids {
        assert_eq!(
            journal
                .artifact(artifact_id)
                .unwrap()
                .unwrap()
                .artifact_id(),
            artifact_id
        );
    }
    assert_eq!(
        fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );

    drop(journal);
    let reopened =
        ArtifactChainJournal::open_verified(&directory.path, definition, target.id()).unwrap();
    assert_eq!(reopened.head_block_id().unwrap(), target.id());
    assert_eq!(reopened.artifact_set_root().unwrap(), expected_root);
    assert_eq!(reopened.len().unwrap(), blocks.len());
}

#[test]
fn reopened_import_extends_only_the_exact_nonempty_current_head() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (all_payloads, artifact_ids) = dependency_chain_with_len(3);
    let (all_blocks, expected_root) = branch_blocks(definition, &all_payloads, &artifact_ids);
    let selected_base = all_blocks[0];
    let candidates_to_import = &all_blocks[1..];
    let target = all_blocks[2];
    let candidate_policy = candidate_limits(candidates_to_import.len());
    let archived_payload_bytes = payload_bytes(&all_payloads[1..]);
    let payload_policy = payload_limits(
        candidates_to_import.len(),
        u64::try_from(archived_payload_bytes).unwrap(),
    );

    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    journal
        .apply_block(&selected_base, all_payloads[0].clone())
        .unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_policy).unwrap();
    insert_candidates(&mut candidates, candidates_to_import);
    let mut payloads =
        CanonicalArtifactPayloadStore::create(&directory.path, payload_policy).unwrap();
    archive_selected_payloads(&mut payloads, &all_payloads, &[1, 2]);
    drop(payloads);
    drop(candidates);
    drop(journal);

    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let mut journal =
        ArtifactChainJournal::open_verified(&directory.path, definition, selected_base.id())
            .unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::open(&directory.path, definition, candidate_policy).unwrap();
    let mut payloads =
        CanonicalArtifactPayloadStore::open(&directory.path, payload_policy).unwrap();

    let outcome = journal
        .import_candidate_branch_from_archive(
            target.id(),
            &mut candidates,
            &mut payloads,
            import_limits(candidates_to_import.len(), archived_payload_bytes),
        )
        .unwrap();
    assert_eq!(outcome.anchor_block_id(), selected_base.id());
    assert_eq!(outcome.target_block_id(), target.id());
    assert_eq!(outcome.committed_block_count(), candidates_to_import.len());
    assert_eq!(journal.head_block_id().unwrap(), target.id());
    assert_eq!(journal.artifact_set_root().unwrap(), expected_root);
    assert_eq!(journal.len().unwrap(), all_blocks.len());
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
fn late_missing_payload_preflight_commits_nothing_and_a_fresh_retry_succeeds() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (payloads_to_archive, artifact_ids) = dependency_chain_with_len(2);
    let (blocks, expected_root) = branch_blocks(definition, &payloads_to_archive, &artifact_ids);
    let target = blocks[1];
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(2))
            .unwrap();
    insert_candidates(&mut candidates, &blocks);
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(
            2,
            u64::try_from(payload_bytes(&payloads_to_archive)).unwrap(),
        ),
    )
    .unwrap();
    archive_selected_payloads(&mut payloads, &payloads_to_archive, &[0]);
    let before = selected_snapshot(&journal, &directory);
    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_prefix = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();

    assert!(matches!(
        journal.import_candidate_branch_from_archive(
            target.id(),
            &mut candidates,
            &mut payloads,
            import_limits(2, payload_bytes(&payloads_to_archive)),
        ),
        Err(CandidateBranchArchiveImportError::Preflight {
            source: CandidateBranchArchiveImportPreflightError::PayloadNotRetained {
                block_id,
                artifact_id,
            },
        }) if block_id == target.id() && artifact_id == artifact_ids[1]
    ));
    assert_selected_unchanged(&journal, &directory, &before);
    assert_eq!(
        fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_prefix
    );

    archive_selected_payloads(&mut payloads, &payloads_to_archive, &[1]);
    let outcome = journal
        .import_candidate_branch_from_archive(
            target.id(),
            &mut candidates,
            &mut payloads,
            import_limits(2, payload_bytes(&payloads_to_archive)),
        )
        .unwrap();
    assert_eq!(outcome.committed_block_count(), 2);
    assert_eq!(journal.head_block_id().unwrap(), target.id());
    assert_eq!(journal.artifact_set_root().unwrap(), expected_root);
}

#[test]
fn invalid_last_payload_context_fails_complete_preflight_without_selecting_its_valid_prefix() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let first_payload = axiom_bytes(ZfcAxiom::Pairing);
    let mut first_source = ArtifactDag::new();
    let first_record = first_source
        .apply_canonical_artifact_bytes(first_payload.clone())
        .unwrap();
    let first_id = first_record.artifact_id();

    let absent_dependency_payload = axiom_bytes(ZfcAxiom::Union);
    let mut other_context = ArtifactDag::new();
    let absent_dependency = other_context
        .apply_canonical_artifact_bytes(absent_dependency_payload)
        .unwrap();
    let absent_proof_id = absent_dependency.as_proof().unwrap().proof_id();
    let invalid_here_payload = referenced_generalization(absent_proof_id, FreeVariable::new(7));
    let invalid_here_record = other_context
        .apply_canonical_artifact_bytes(invalid_here_payload.clone())
        .unwrap();
    let invalid_here_id = invalid_here_record.artifact_id();

    let mut branch = ArtifactChainState::new(definition);
    let first = branch.prepare_block(first_id).unwrap();
    branch.apply_block(&first, first_payload.clone()).unwrap();
    let target = branch.prepare_block(invalid_here_id).unwrap();
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(2))
            .unwrap();
    insert_candidates(&mut candidates, &[first, target]);
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(
            2,
            u64::try_from(first_payload.len() + invalid_here_payload.len()).unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(
        payloads.insert(first_record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    assert_eq!(
        payloads.insert(invalid_here_record).unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    let before = selected_snapshot(&journal, &directory);

    assert!(matches!(
        journal.import_candidate_branch_from_archive(
            target.id(),
            &mut candidates,
            &mut payloads,
            import_limits(2, first_payload.len() + invalid_here_payload.len()),
        ),
        Err(CandidateBranchArchiveImportError::Preflight {
            source: CandidateBranchArchiveImportPreflightError::BlockValidation {
                block_id,
                ..
            },
        }) if block_id == target.id()
    ));
    assert_selected_unchanged(&journal, &directory, &before);
    assert!(journal.artifact(first_id).unwrap().is_none());
}

#[test]
fn a_historical_selected_fork_is_rejected_instead_of_reorganizing_the_current_head() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (branch_payloads, branch_ids) = dependency_chain_with_len(2);
    let mut branch = ArtifactChainState::new(definition);
    let selected_base = branch.prepare_block(branch_ids[0]).unwrap();
    branch
        .apply_block(&selected_base, branch_payloads[0].clone())
        .unwrap();
    let historical_child = branch.prepare_block(branch_ids[1]).unwrap();

    let current_payload = axiom_bytes(ZfcAxiom::PowerSet);
    let mut current_source = ArtifactDag::new();
    let current_id = current_source
        .apply_canonical_artifact_bytes(current_payload.clone())
        .unwrap()
        .artifact_id();
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    journal
        .apply_block(&selected_base, branch_payloads[0].clone())
        .unwrap();
    let current_head = journal.prepare_block(current_id).unwrap();
    journal.apply_block(&current_head, current_payload).unwrap();

    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(1))
            .unwrap();
    insert_candidates(&mut candidates, &[historical_child]);
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(1, u64::try_from(branch_payloads[1].len()).unwrap()),
    )
    .unwrap();
    archive_selected_payloads(&mut payloads, &branch_payloads, &[1]);
    let before = selected_snapshot(&journal, &directory);

    assert!(matches!(
        journal.import_candidate_branch_from_archive(
            historical_child.id(),
            &mut candidates,
            &mut payloads,
            import_limits(1, branch_payloads[1].len()),
        ),
        Err(CandidateBranchArchiveImportError::Preflight {
            source: CandidateBranchArchiveImportPreflightError::DivergentAncestry {
                expected_anchor,
                encountered,
            },
        }) if expected_anchor == current_head.id() && encountered == selected_base.id()
    ));
    assert_selected_unchanged(&journal, &directory, &before);
}

#[test]
fn ancestry_and_payload_limits_fail_before_any_selected_mutation() {
    assert!(matches!(
        CandidateBranchArchiveImportLimits::new(0, 1),
        Err(CandidateBranchArchiveImportLimitsError::ZeroMaxBlocks)
    ));
    assert!(matches!(
        CandidateBranchArchiveImportLimits::new(1, 0),
        Err(CandidateBranchArchiveImportLimitsError::ZeroMaxBufferedPayloadBytes)
    ));

    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (payloads_to_archive, artifact_ids) = dependency_chain_with_len(2);
    let (blocks, _) = branch_blocks(definition, &payloads_to_archive, &artifact_ids);
    let target = blocks[1];
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(2))
            .unwrap();
    insert_candidates(&mut candidates, &blocks);
    let total_payload_bytes = payload_bytes(&payloads_to_archive);
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(2, u64::try_from(total_payload_bytes).unwrap()),
    )
    .unwrap();
    archive_selected_payloads(&mut payloads, &payloads_to_archive, &[0, 1]);
    let before = selected_snapshot(&journal, &directory);

    assert!(matches!(
        journal.import_candidate_branch_from_archive(
            target.id(),
            &mut candidates,
            &mut payloads,
            import_limits(1, total_payload_bytes),
        ),
        Err(CandidateBranchArchiveImportError::Preflight {
            source: CandidateBranchArchiveImportPreflightError::BlockLimitExceeded {
                maximum: 1,
                next_block_id,
            },
        }) if next_block_id == blocks[0].id()
    ));
    assert_selected_unchanged(&journal, &directory, &before);

    assert!(matches!(
        journal.import_candidate_branch_from_archive(
            target.id(),
            &mut candidates,
            &mut payloads,
            import_limits(2, total_payload_bytes - 1),
        ),
        Err(CandidateBranchArchiveImportError::Preflight {
            source: CandidateBranchArchiveImportPreflightError::PayloadByteLimitExceeded {
                block_id,
                artifact_id,
                maximum,
                attempted,
            },
        }) if block_id == target.id()
            && artifact_id == artifact_ids[1]
            && maximum == u64::try_from(total_payload_bytes - 1).unwrap()
            && attempted == u64::try_from(total_payload_bytes).unwrap()
    ));
    assert_selected_unchanged(&journal, &directory, &before);
}

#[test]
fn chain_target_and_missing_candidate_precedence_preserve_selected_state() {
    let mismatch_directory = TestDirectory::new();
    let selected_definition = chain_definition(0x41);
    let candidate_definition = chain_definition(0x42);
    let mut journal =
        ArtifactChainJournal::create(&mismatch_directory.path, selected_definition).unwrap();
    journal.core.poisoned = true;
    let mut candidates = ArtifactBlockCandidateStore::create(
        &mismatch_directory.path,
        candidate_definition,
        candidate_limits(1),
    )
    .unwrap();
    let mut payloads =
        CanonicalArtifactPayloadStore::create(&mismatch_directory.path, payload_limits(1, 1))
            .unwrap();
    assert!(matches!(
        journal.import_candidate_branch_from_archive(
            ArtifactBlockId::from_bytes([0xf1; 32]),
            &mut candidates,
            &mut payloads,
            import_limits(1, 1),
        ),
        Err(CandidateBranchArchiveImportError::Preflight {
            source: CandidateBranchArchiveImportPreflightError::ChainIdMismatch {
                selected,
                candidates,
            },
        }) if selected == selected_definition.id() && candidates == candidate_definition.id()
    ));

    let selected_directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let mut source = ArtifactDag::new();
    let artifact_id = source
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let mut journal = ArtifactChainJournal::create(&selected_directory.path, definition).unwrap();
    let selected = journal.prepare_block(artifact_id).unwrap();
    journal.apply_block(&selected, payload).unwrap();
    let mut candidates = ArtifactBlockCandidateStore::create(
        &selected_directory.path,
        definition,
        candidate_limits(1),
    )
    .unwrap();
    let mut payloads =
        CanonicalArtifactPayloadStore::create(&selected_directory.path, payload_limits(1, 1))
            .unwrap();
    let before = selected_snapshot(&journal, &selected_directory);
    assert!(matches!(
        journal.import_candidate_branch_from_archive(
            selected.id(),
            &mut candidates,
            &mut payloads,
            import_limits(1, 1),
        ),
        Err(CandidateBranchArchiveImportError::Preflight {
            source: CandidateBranchArchiveImportPreflightError::TargetAlreadySelected {
                block_id,
            },
        }) if block_id == selected.id()
    ));
    assert_selected_unchanged(&journal, &selected_directory, &before);

    let missing_directory = TestDirectory::new();
    let mut journal = ArtifactChainJournal::create(&missing_directory.path, definition).unwrap();
    let mut candidates = ArtifactBlockCandidateStore::create(
        &missing_directory.path,
        definition,
        candidate_limits(1),
    )
    .unwrap();
    let mut payloads =
        CanonicalArtifactPayloadStore::create(&missing_directory.path, payload_limits(1, 1))
            .unwrap();
    let missing_target = ArtifactBlockId::from_bytes([0xf2; 32]);
    let before = selected_snapshot(&journal, &missing_directory);
    assert!(matches!(
        journal.import_candidate_branch_from_archive(
            missing_target,
            &mut candidates,
            &mut payloads,
            import_limits(1, 1),
        ),
        Err(CandidateBranchArchiveImportError::Preflight {
            source: CandidateBranchArchiveImportPreflightError::CandidateNotRetained {
                block_id,
            },
        }) if block_id == missing_target
    ));
    assert_selected_unchanged(&journal, &missing_directory, &before);
}

#[test]
fn root_discontinuity_precedes_payload_reads_and_changes_no_store() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (payloads_to_archive, artifact_ids) = independent_axioms();
    let mut fixture = ArtifactChainState::new(definition);
    let parent = fixture.prepare_block(artifact_ids[0]).unwrap();
    fixture
        .apply_block(&parent, payloads_to_archive[0].clone())
        .unwrap();
    let valid_child = fixture.prepare_block(artifact_ids[1]).unwrap();
    let wrong_previous_root = ArtifactSetRoot::from_bytes([0xee; 32]);
    assert_ne!(wrong_previous_root, parent.resulting_artifact_set_root());
    let child = ArtifactBlock::new(
        parent.id(),
        wrong_previous_root,
        valid_child.resulting_artifact_set_root(),
        valid_child.artifact_id(),
    );
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(2))
            .unwrap();
    insert_candidates(&mut candidates, &[parent, child]);
    let mut payloads =
        CanonicalArtifactPayloadStore::create(&directory.path, payload_limits(1, 1)).unwrap();
    let before = selected_snapshot(&journal, &directory);
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();

    assert!(matches!(
        journal.import_candidate_branch_from_archive(
            child.id(),
            &mut candidates,
            &mut payloads,
            import_limits(2, 1),
        ),
        Err(CandidateBranchArchiveImportError::Preflight {
            source: CandidateBranchArchiveImportPreflightError::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            },
        }) if preceding_block_id == parent.id()
            && expected == parent.resulting_artifact_set_root()
            && actual == wrong_previous_root
    ));
    assert_selected_unchanged(&journal, &directory, &before);
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
    assert!(payloads.is_empty().unwrap());
}

#[test]
fn corrupt_candidate_read_precedes_the_also_corrupt_payload_and_poison_is_typed() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let mut source = ArtifactDag::new();
    let artifact_id = source
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_id).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(1))
            .unwrap();
    insert_candidates(&mut candidates, &[block]);
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(1, u64::try_from(payload.len()).unwrap()),
    )
    .unwrap();
    archive_selected_payloads(&mut payloads, std::slice::from_ref(&payload), &[0]);
    flip_byte(
        &directory.path.join(CANDIDATE_STORE_FILE_NAME),
        u64::try_from(CANDIDATE_STORE_HEADER.len() + ArtifactChainId::BYTE_LENGTH).unwrap(),
    );
    flip_byte(
        &directory.path.join(PAYLOAD_STORE_FILE_NAME),
        u64::try_from(
            PAYLOAD_STORE_HEADER.len() + FOUNDATION_ID.len() + 4 + ArtifactId::BYTE_LENGTH,
        )
        .unwrap(),
    );
    let before = selected_snapshot(&journal, &directory);

    assert!(matches!(
        journal.import_candidate_branch_from_archive(
            block.id(),
            &mut candidates,
            &mut payloads,
            import_limits(1, payload.len()),
        ),
        Err(CandidateBranchArchiveImportError::Preflight {
            source: CandidateBranchArchiveImportPreflightError::CandidateStoreRead {
                block_id,
                source,
            },
        }) if block_id == block.id()
            && matches!(
                source.as_ref(),
                ArtifactBlockCandidateStoreError::StoredEntryChanged { .. }
            )
    ));
    assert_selected_unchanged(&journal, &directory, &before);
    assert!(matches!(
        candidates.len(),
        Err(ArtifactBlockCandidateStoreError::Poisoned)
    ));
    assert_eq!(payloads.len().unwrap(), 1);
}
