use std::io::{Read, Seek, SeekFrom, Write};

use naome_checker::CheckError;

use super::*;
use crate::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError, ArtifactBlockCandidateStoreLimits,
    ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits, CandidateBranchPayloadArchiveError,
    CandidateBranchReconstructionError, CandidateBranchReconstructionLimits,
    CandidateBranchReconstructionLimitsError, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError,
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

fn reconstruction_limits(blocks: usize) -> CandidateBranchReconstructionLimits {
    CandidateBranchReconstructionLimits::new(blocks).unwrap()
}

fn artifact_id(payload: &[u8]) -> ArtifactId {
    ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.to_vec())
        .unwrap()
        .artifact_id()
}

fn archive_payloads(
    store: &mut CanonicalArtifactPayloadStore,
    payloads: &[Vec<u8>],
    expected_ids: &[ArtifactId],
) {
    assert_eq!(payloads.len(), expected_ids.len());
    let mut source = ArtifactDag::new();
    for (payload, expected_id) in payloads.iter().zip(expected_ids.iter().copied()) {
        let record = source
            .apply_canonical_artifact_bytes_with_expected_id(payload.clone(), expected_id)
            .unwrap();
        assert_eq!(
            store.insert(record).unwrap(),
            ArtifactPayloadInsertOutcome::Inserted
        );
    }
}

fn insert_candidates(store: &mut ArtifactBlockCandidateStore, blocks: &[ArtifactBlock]) {
    for block in blocks {
        assert_eq!(
            store.insert(block).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
    }
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
fn branch_payload_gate_archives_idempotently_and_returns_only_durable_successors() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let candidate_artifact_id = artifact_id(&payload);
    let state = ArtifactChainState::new(definition);
    let predecessor = state.branch_snapshot();
    let block = state.prepare_block(candidate_artifact_id).unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(1, payload.len() as u64),
    )
    .unwrap();

    let first = payloads
        .validate_and_insert_branch_payload(&predecessor, &block, payload.clone())
        .unwrap();
    assert_eq!(
        first.insertion_outcome(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    assert_eq!(first.successor().head_block_id(), block.id());
    assert_eq!(predecessor.head_block_id(), block.parent_block_id());
    let first_successor = first.into_successor();
    let committed = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();

    let repeated = payloads
        .validate_and_insert_branch_payload(&predecessor, &block, payload.clone())
        .unwrap();
    assert_eq!(
        repeated.insertion_outcome(),
        ArtifactPayloadInsertOutcome::AlreadyPresent
    );
    assert_eq!(repeated.successor().head_block_id(), block.id());
    assert_eq!(
        repeated.successor().artifact_set_root(),
        first_successor.artifact_set_root()
    );
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        committed
    );
    assert_eq!(
        payloads
            .get(candidate_artifact_id)
            .unwrap()
            .unwrap()
            .canonical_artifact_bytes(),
        payload
    );
}

#[test]
fn branch_payload_gate_checks_archive_health_then_validation_before_capacity() {
    let poisoned_directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let candidate_artifact_id = artifact_id(&payload);
    let state = ArtifactChainState::new(definition);
    let predecessor = state.branch_snapshot();
    let block = state.prepare_block(candidate_artifact_id).unwrap();
    let mut poisoned = CanonicalArtifactPayloadStore::create(
        &poisoned_directory.path,
        payload_limits(1, payload.len() as u64),
    )
    .unwrap();
    archive_payloads(
        &mut poisoned,
        std::slice::from_ref(&payload),
        std::slice::from_ref(&candidate_artifact_id),
    );
    let payload_offset = u64::try_from(
        PAYLOAD_STORE_HEADER.len() + FOUNDATION_ID.len() + 4 + ArtifactId::BYTE_LENGTH,
    )
    .unwrap();
    flip_byte(
        &poisoned_directory.path.join(PAYLOAD_STORE_FILE_NAME),
        payload_offset,
    );
    assert!(matches!(
        poisoned.get(candidate_artifact_id),
        Err(CanonicalArtifactPayloadStoreError::StoredEntryChanged { .. })
    ));
    assert!(matches!(
        poisoned.validate_and_insert_branch_payload(&predecessor, &block, vec![0]),
        Err(CandidateBranchPayloadArchiveError::Archive { source })
            if matches!(source.as_ref(), CanonicalArtifactPayloadStoreError::Poisoned)
    ));

    let capacity_directory = TestDirectory::new();
    let retained_payload = axiom_bytes(ZfcAxiom::Union);
    let retained_id = artifact_id(&retained_payload);
    let mut full = CanonicalArtifactPayloadStore::create(
        &capacity_directory.path,
        payload_limits(1, retained_payload.len() as u64),
    )
    .unwrap();
    archive_payloads(
        &mut full,
        std::slice::from_ref(&retained_payload),
        std::slice::from_ref(&retained_id),
    );
    let committed = fs::read(capacity_directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();

    assert!(matches!(
        full.validate_and_insert_branch_payload(&predecessor, &block, vec![0]),
        Err(CandidateBranchPayloadArchiveError::Validation { .. })
    ));
    assert!(matches!(
        full.validate_and_insert_branch_payload(&predecessor, &block, payload),
        Err(CandidateBranchPayloadArchiveError::Archive { source })
            if matches!(
                source.as_ref(),
                CanonicalArtifactPayloadStoreError::EntryLimitExceeded {
                    actual: 2,
                    maximum: 1,
                }
            )
    ));
    assert_eq!(predecessor.head_block_id(), block.parent_block_id());
    assert_eq!(
        fs::read(capacity_directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        committed
    );
    assert!(!full.contains(candidate_artifact_id).unwrap());
}

#[test]
fn reconstruction_rebuilds_branch_only_dependencies_from_a_historical_selected_fork() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (branch_payloads, branch_artifact_ids) = dependency_chain_with_len(3);
    let sibling_payload = axiom_bytes(ZfcAxiom::PowerSet);
    let sibling_artifact_id = artifact_id(&sibling_payload);
    let candidate_policy = candidate_limits(2);
    let payload_policy = payload_limits(
        2,
        branch_payloads[1..].iter().map(Vec::len).sum::<usize>() as u64,
    );

    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let selected_base = journal.prepare_block(branch_artifact_ids[0]).unwrap();
    journal
        .apply_block(&selected_base, branch_payloads[0].clone())
        .unwrap();

    let mut branch = ArtifactChainState::new(definition);
    branch
        .apply_block(&selected_base, branch_payloads[0].clone())
        .unwrap();
    let first_candidate = branch.prepare_block(branch_artifact_ids[1]).unwrap();
    branch
        .apply_block(&first_candidate, branch_payloads[1].clone())
        .unwrap();
    let target = branch.prepare_block(branch_artifact_ids[2]).unwrap();
    branch
        .apply_block(&target, branch_payloads[2].clone())
        .unwrap();
    let expected_branch_root = branch.artifact_dag().artifact_set_root();

    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_policy).unwrap();
    insert_candidates(&mut candidates, &[first_candidate, target]);
    let mut payloads =
        CanonicalArtifactPayloadStore::create(&directory.path, payload_policy).unwrap();
    let selected_snapshot = journal
        .branch_snapshot_at(selected_base.id())
        .unwrap()
        .unwrap();
    let first_archive = payloads
        .validate_and_insert_branch_payload(
            &selected_snapshot,
            &first_candidate,
            branch_payloads[1].clone(),
        )
        .unwrap();
    assert_eq!(
        first_archive.insertion_outcome(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    let target_archive = payloads
        .validate_and_insert_branch_payload(
            first_archive.successor(),
            &target,
            branch_payloads[2].clone(),
        )
        .unwrap();
    assert_eq!(
        target_archive.insertion_outcome(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    assert_eq!(target_archive.successor().head_block_id(), target.id());

    let selected_sibling = journal.prepare_block(sibling_artifact_id).unwrap();
    journal
        .apply_block(&selected_sibling, sibling_payload)
        .unwrap();
    let selected_head = selected_sibling.id();
    let selected_root = journal.artifact_set_root().unwrap();
    let selected_len = journal.len().unwrap();
    drop(payloads);
    drop(candidates);
    drop(journal);

    let journal_image = fs::read(directory.journal_path()).unwrap();
    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let journal =
        ArtifactChainJournal::open_verified(&directory.path, definition, selected_head).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::open(&directory.path, definition, candidate_policy).unwrap();
    let mut payloads =
        CanonicalArtifactPayloadStore::open(&directory.path, payload_policy).unwrap();

    let recovered = journal
        .reconstruct_candidate_branch(
            target.id(),
            &mut candidates,
            &mut payloads,
            reconstruction_limits(2),
        )
        .unwrap();
    assert_eq!(recovered.anchor_block_id(), selected_base.id());
    assert_eq!(recovered.target_block_id(), target.id());
    assert_eq!(recovered.block_count(), 2);
    assert_eq!(recovered.snapshot().head_block_id(), target.id());
    assert_eq!(
        recovered.snapshot().artifact_set_root(),
        expected_branch_root
    );
    assert_eq!(journal.head_block_id().unwrap(), selected_head);
    assert_eq!(journal.artifact_set_root().unwrap(), selected_root);
    assert_eq!(journal.len().unwrap(), selected_len);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), journal_image);
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
fn virtual_genesis_reconstruction_obeys_the_exact_caller_block_limit() {
    assert!(matches!(
        CandidateBranchReconstructionLimits::new(0),
        Err(CandidateBranchReconstructionLimitsError::ZeroMaxBlocks)
    ));
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let genesis = definition.id().virtual_genesis_block_id();
    let (payloads_to_archive, artifact_ids) = dependency_chain_with_len(2);
    let mut branch = ArtifactChainState::new(definition);
    let first = branch.prepare_block(artifact_ids[0]).unwrap();
    branch
        .apply_block(&first, payloads_to_archive[0].clone())
        .unwrap();
    let target = branch.prepare_block(artifact_ids[1]).unwrap();
    branch
        .apply_block(&target, payloads_to_archive[1].clone())
        .unwrap();
    let expected_root = branch.artifact_dag().artifact_set_root();
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(2))
            .unwrap();
    insert_candidates(&mut candidates, &[first, target]);
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(
            2,
            payloads_to_archive.iter().map(Vec::len).sum::<usize>() as u64,
        ),
    )
    .unwrap();
    archive_payloads(&mut payloads, &payloads_to_archive, &artifact_ids);

    assert!(matches!(
        journal.reconstruct_candidate_branch(
            target.id(),
            &mut candidates,
            &mut payloads,
            reconstruction_limits(1),
        ),
        Err(CandidateBranchReconstructionError::BlockLimitExceeded {
            maximum: 1,
            next_block_id,
        }) if next_block_id == first.id()
    ));

    let recovered = journal
        .reconstruct_candidate_branch(
            target.id(),
            &mut candidates,
            &mut payloads,
            reconstruction_limits(2),
        )
        .unwrap();
    assert_eq!(recovered.anchor_block_id(), genesis);
    assert_eq!(recovered.target_block_id(), target.id());
    assert_eq!(recovered.block_count(), 2);
    assert_eq!(recovered.into_snapshot().artifact_set_root(), expected_root);
    assert!(journal.is_empty().unwrap());
}

#[test]
fn reconstruction_checks_chain_context_before_selected_or_store_health() {
    let directory = TestDirectory::new();
    let selected_definition = chain_definition(0x21);
    let candidate_definition = chain_definition(0x22);
    let mut journal = ArtifactChainJournal::create(&directory.path, selected_definition).unwrap();
    journal.core.poisoned = true;
    let mut candidates = ArtifactBlockCandidateStore::create(
        &directory.path,
        candidate_definition,
        candidate_limits(1),
    )
    .unwrap();
    let mut payloads =
        CanonicalArtifactPayloadStore::create(&directory.path, payload_limits(1, 1)).unwrap();

    assert!(matches!(
        journal.reconstruct_candidate_branch(
            ArtifactBlockId::from_bytes([0xff; 32]),
            &mut candidates,
            &mut payloads,
            reconstruction_limits(1),
        ),
        Err(CandidateBranchReconstructionError::ChainIdMismatch {
            selected,
            candidates,
        }) if selected == selected_definition.id() && candidates == candidate_definition.id()
    ));
}

#[test]
fn reconstruction_rejects_a_selected_target_before_candidate_lookup() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_id(&payload);
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let selected = journal.prepare_block(artifact_id).unwrap();
    journal.apply_block(&selected, payload).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(1))
            .unwrap();
    let mut payloads =
        CanonicalArtifactPayloadStore::create(&directory.path, payload_limits(1, 1)).unwrap();

    assert!(matches!(
        journal.reconstruct_candidate_branch(
            selected.id(),
            &mut candidates,
            &mut payloads,
            reconstruction_limits(1),
        ),
        Err(CandidateBranchReconstructionError::TargetAlreadySelected { block_id })
            if block_id == selected.id()
    ));
}

#[test]
fn reconstruction_distinguishes_missing_candidate_and_payload_inputs() {
    let missing_candidate_directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let journal =
        ArtifactChainJournal::create(&missing_candidate_directory.path, definition).unwrap();
    let mut candidates = ArtifactBlockCandidateStore::create(
        &missing_candidate_directory.path,
        definition,
        candidate_limits(1),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &missing_candidate_directory.path,
        payload_limits(1, 1),
    )
    .unwrap();
    let missing_target = ArtifactBlockId::from_bytes([0xee; 32]);
    assert!(matches!(
        journal.reconstruct_candidate_branch(
            missing_target,
            &mut candidates,
            &mut payloads,
            reconstruction_limits(1),
        ),
        Err(CandidateBranchReconstructionError::CandidateNotRetained { block_id })
            if block_id == missing_target
    ));

    let missing_payload_directory = TestDirectory::new();
    let journal =
        ArtifactChainJournal::create(&missing_payload_directory.path, definition).unwrap();
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_id(&payload);
    let block = journal.prepare_block(artifact_id).unwrap();
    let mut candidates = ArtifactBlockCandidateStore::create(
        &missing_payload_directory.path,
        definition,
        candidate_limits(1),
    )
    .unwrap();
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &missing_payload_directory.path,
        payload_limits(1, payload.len() as u64),
    )
    .unwrap();
    assert!(matches!(
        journal.reconstruct_candidate_branch(
            block.id(),
            &mut candidates,
            &mut payloads,
            reconstruction_limits(1),
        ),
        Err(CandidateBranchReconstructionError::PayloadNotRetained {
            block_id,
            artifact_id: actual,
        }) if block_id == block.id() && actual == artifact_id
    ));
}

#[test]
fn reconstruction_maps_integrity_failures_and_poisoning_from_each_input_store() {
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_id(&payload);

    let candidate_directory = TestDirectory::new();
    let journal = ArtifactChainJournal::create(&candidate_directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_id).unwrap();
    let mut candidates = ArtifactBlockCandidateStore::create(
        &candidate_directory.path,
        definition,
        candidate_limits(1),
    )
    .unwrap();
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &candidate_directory.path,
        payload_limits(1, payload.len() as u64),
    )
    .unwrap();
    archive_payloads(
        &mut payloads,
        std::slice::from_ref(&payload),
        std::slice::from_ref(&artifact_id),
    );
    flip_byte(
        &candidate_directory.path.join(CANDIDATE_STORE_FILE_NAME),
        u64::try_from(CANDIDATE_STORE_HEADER.len() + ArtifactChainId::BYTE_LENGTH).unwrap(),
    );
    assert!(matches!(
        journal.reconstruct_candidate_branch(
            block.id(),
            &mut candidates,
            &mut payloads,
            reconstruction_limits(1),
        ),
        Err(CandidateBranchReconstructionError::CandidateStoreRead {
            block_id,
            source,
        }) if block_id == block.id()
            && matches!(source.as_ref(), ArtifactBlockCandidateStoreError::StoredEntryChanged { .. })
    ));
    assert!(matches!(
        candidates.len(),
        Err(ArtifactBlockCandidateStoreError::Poisoned)
    ));

    let payload_directory = TestDirectory::new();
    let journal = ArtifactChainJournal::create(&payload_directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_id).unwrap();
    let mut candidates = ArtifactBlockCandidateStore::create(
        &payload_directory.path,
        definition,
        candidate_limits(1),
    )
    .unwrap();
    insert_candidates(&mut candidates, std::slice::from_ref(&block));
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &payload_directory.path,
        payload_limits(1, payload.len() as u64),
    )
    .unwrap();
    archive_payloads(
        &mut payloads,
        std::slice::from_ref(&payload),
        std::slice::from_ref(&artifact_id),
    );
    let payload_offset = u64::try_from(
        PAYLOAD_STORE_HEADER.len() + FOUNDATION_ID.len() + 4 + ArtifactId::BYTE_LENGTH,
    )
    .unwrap();
    flip_byte(
        &payload_directory.path.join(PAYLOAD_STORE_FILE_NAME),
        payload_offset,
    );
    assert!(matches!(
        journal.reconstruct_candidate_branch(
            block.id(),
            &mut candidates,
            &mut payloads,
            reconstruction_limits(1),
        ),
        Err(CandidateBranchReconstructionError::PayloadStoreRead {
            block_id,
            artifact_id: actual,
            source,
        }) if block_id == block.id()
            && actual == artifact_id
            && matches!(source.as_ref(), CanonicalArtifactPayloadStoreError::StoredEntryChanged { .. })
    ));
    assert!(matches!(
        payloads.len(),
        Err(CanonicalArtifactPayloadStoreError::Poisoned)
    ));
}

#[test]
fn root_discontinuity_precedes_any_payload_lookup() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let parent_payload = axiom_bytes(ZfcAxiom::Pairing);
    let child_payload = axiom_bytes(ZfcAxiom::Union);
    let parent_id = artifact_id(&parent_payload);
    let child_id = artifact_id(&child_payload);
    let mut fixture = ArtifactChainState::new(definition);
    let parent = fixture.prepare_block(parent_id).unwrap();
    fixture.apply_block(&parent, parent_payload).unwrap();
    let wrong_previous_root = ArtifactSetRoot::from_bytes([0xff; 32]);
    assert_ne!(wrong_previous_root, parent.resulting_artifact_set_root());
    let child = ArtifactBlock::new(
        parent.id(),
        wrong_previous_root,
        ArtifactSetRoot::from_bytes([0xee; 32]),
        child_id,
    );
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(2))
            .unwrap();
    insert_candidates(&mut candidates, &[parent, child]);
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(1, child_payload.len() as u64),
    )
    .unwrap();

    assert!(matches!(
        journal.reconstruct_candidate_branch(
            child.id(),
            &mut candidates,
            &mut payloads,
            reconstruction_limits(2),
        ),
        Err(CandidateBranchReconstructionError::ArtifactSetRootMismatch {
            preceding_block_id,
            expected,
            actual,
        }) if preceding_block_id == parent.id()
            && expected == parent.resulting_artifact_set_root()
            && actual == wrong_previous_root
    ));
    assert!(payloads.is_empty().unwrap());
}

#[test]
fn strict_branch_validation_failure_returns_no_snapshot_and_changes_no_durable_state() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (payloads_to_archive, artifact_ids) = dependency_chain_with_len(2);
    let missing_dependency_proof_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payloads_to_archive[0].clone())
        .unwrap()
        .as_proof()
        .unwrap()
        .proof_id();
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let target = journal.prepare_block(artifact_ids[1]).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(1))
            .unwrap();
    insert_candidates(&mut candidates, std::slice::from_ref(&target));
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(
            2,
            payloads_to_archive.iter().map(Vec::len).sum::<usize>() as u64,
        ),
    )
    .unwrap();
    archive_payloads(&mut payloads, &payloads_to_archive, &artifact_ids);
    let journal_image = fs::read(directory.journal_path()).unwrap();
    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let head = journal.head_block_id().unwrap();
    let root = journal.artifact_set_root().unwrap();

    assert!(matches!(
        journal.reconstruct_candidate_branch(
            target.id(),
            &mut candidates,
            &mut payloads,
            reconstruction_limits(1),
        ),
        Err(CandidateBranchReconstructionError::BlockValidation {
            block_id,
            source,
        }) if block_id == target.id()
            && matches!(
                source.as_ref(),
                ArtifactBlockApplyError::Admission {
                    source: LedgerError::ProofCheck {
                        source: CheckError::UnknownProofReference {
                            step: 0,
                            proof_id,
                        },
                    },
                } if *proof_id == missing_dependency_proof_id
            )
    ));
    assert_eq!(journal.head_block_id().unwrap(), head);
    assert_eq!(journal.artifact_set_root().unwrap(), root);
    assert_eq!(journal.len().unwrap(), 0);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), journal_image);
    assert_eq!(
        fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
}
