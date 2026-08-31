use super::*;
use crate::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreError, ArtifactBlockCandidateStoreLimits,
    ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits, CandidateBranchRecoveryBundleLimits,
    CandidateBranchRecoveryBundleStageFailure, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError,
    candidate_branch_recovery_staging::{
        CandidateBranchRecoveryBundleStageTestFault, CandidateBranchRecoveryBundleStageTestOptions,
        stage_candidate_branch_recovery_bundle_v0_with_test_fault,
    },
    stage_candidate_branch_recovery_bundle_v0,
};

struct StagingFixture {
    definition: ArtifactChainDefinition,
    payloads: Vec<Vec<u8>>,
    blocks: Vec<ArtifactBlock>,
    limits: CandidateBranchRecoveryBundleLimits,
    bundle_bytes: Vec<u8>,
}

impl StagingFixture {
    fn new(block_count: usize) -> Self {
        let definition = chain_definition(0x91);
        let (payloads, artifact_ids) = dependency_chain_with_len(block_count);
        let mut branch = ArtifactChainState::new(definition);
        let mut blocks = Vec::with_capacity(block_count);
        for (payload, artifact_id) in payloads.iter().zip(artifact_ids) {
            let block = branch.prepare_block(artifact_id).unwrap();
            branch.apply_block(&block, payload.clone()).unwrap();
            blocks.push(block);
        }
        let payload_bytes = payloads.iter().map(Vec::len).sum::<usize>();
        let limits = CandidateBranchRecoveryBundleLimits::new(
            block_count,
            u64::try_from(payload_bytes).unwrap(),
            16 * 1024 * 1024,
        )
        .unwrap();

        let source = TestDirectory::new();
        let journal = ArtifactChainJournal::create(&source.path, definition).unwrap();
        let mut candidates = ArtifactBlockCandidateStore::create(
            &source.path,
            definition,
            ArtifactBlockCandidateStoreLimits::new(block_count).unwrap(),
        )
        .unwrap();
        for block in &blocks {
            assert_eq!(
                candidates.insert(block).unwrap(),
                ArtifactBlockCandidateInsertOutcome::Inserted
            );
        }
        let mut payload_store = CanonicalArtifactPayloadStore::create(
            &source.path,
            ArtifactPayloadStoreLimits::new(block_count, u64::try_from(payload_bytes).unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut dag = ArtifactDag::new();
        for payload in &payloads {
            let record = dag.apply_canonical_artifact_bytes(payload.clone()).unwrap();
            assert_eq!(
                payload_store.insert(record).unwrap(),
                ArtifactPayloadInsertOutcome::Inserted
            );
        }
        let bundle_bytes = journal
            .export_candidate_branch_recovery_bundle_v0(
                blocks.last().unwrap().id(),
                &mut candidates,
                &mut payload_store,
                limits,
            )
            .unwrap()
            .into_canonical_bytes();

        Self {
            definition,
            payloads,
            blocks,
            limits,
            bundle_bytes,
        }
    }

    fn anchor(&self) -> ArtifactBlockId {
        self.definition.id().virtual_genesis_block_id()
    }

    fn target(&self) -> ArtifactBlockId {
        self.blocks.last().unwrap().id()
    }

    fn payload_bytes(&self) -> u64 {
        u64::try_from(self.payloads.iter().map(Vec::len).sum::<usize>()).unwrap()
    }
}

fn create_destination(
    directory: &TestDirectory,
    fixture: &StagingFixture,
    selected_prefix: usize,
    candidate_capacity: usize,
    payload_entry_capacity: usize,
    payload_byte_capacity: u64,
) -> (
    ArtifactChainJournal,
    ArtifactBlockCandidateStore,
    CanonicalArtifactPayloadStore,
) {
    let mut selected = ArtifactChainJournal::create(&directory.path, fixture.definition).unwrap();
    for (block, payload) in fixture
        .blocks
        .iter()
        .zip(&fixture.payloads)
        .take(selected_prefix)
    {
        selected.apply_block(block, payload.clone()).unwrap();
    }
    let candidates = ArtifactBlockCandidateStore::create(
        &directory.path,
        fixture.definition,
        ArtifactBlockCandidateStoreLimits::new(candidate_capacity).unwrap(),
    )
    .unwrap();
    let payloads = CanonicalArtifactPayloadStore::create(
        &directory.path,
        ArtifactPayloadStoreLimits::new(payload_entry_capacity, payload_byte_capacity).unwrap(),
    )
    .unwrap();
    (selected, candidates, payloads)
}

fn store_images(directory: &TestDirectory) -> (Vec<u8>, Vec<u8>) {
    (
        fs::read(directory.path.join("artifact-block-candidate-store.log")).unwrap(),
        fs::read(directory.path.join("artifact-payload-store.log")).unwrap(),
    )
}

#[test]
fn staging_validates_then_retains_only_the_unselected_suffix_and_preserves_bytes() {
    let fixture = StagingFixture::new(2);
    let destination = TestDirectory::new();
    let (selected, mut candidates, mut payloads) =
        create_destination(&destination, &fixture, 1, 2, 2, fixture.payload_bytes());
    let selected_bytes = fs::read(destination.journal_path()).unwrap();
    let selected_head = selected.head_block_id().unwrap();
    let bundle_ptr = fixture.bundle_bytes.as_ptr();
    let anchor = fixture.anchor();
    let target = fixture.target();

    let outcome = stage_candidate_branch_recovery_bundle_v0(
        fixture.bundle_bytes,
        anchor,
        target,
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap();

    assert_eq!(outcome.bundle_bytes().as_ptr(), bundle_ptr);
    assert_eq!(outcome.anchor_block_id(), anchor);
    assert_eq!(outcome.target_block_id(), target);
    assert_eq!(outcome.selected_prefix_count(), 1);
    assert_eq!(outcome.candidate_block_count(), 1);
    assert_eq!(outcome.candidate_inserted_count(), 1);
    assert_eq!(outcome.payload_inserted_count(), 1);
    assert_eq!(candidates.len().unwrap(), 1);
    assert_eq!(candidates.get(target).unwrap(), Some(fixture.blocks[1]));
    assert_eq!(payloads.len().unwrap(), 1);
    assert_eq!(
        payloads
            .get(fixture.blocks[1].artifact_id())
            .unwrap()
            .unwrap()
            .canonical_artifact_bytes(),
        fixture.payloads[1]
    );
    assert_eq!(selected.head_block_id().unwrap(), selected_head);
    assert_eq!(
        fs::read(destination.journal_path()).unwrap(),
        selected_bytes
    );
}

#[test]
fn staging_restarts_from_candidate_and_payload_prefixes_idempotently() {
    let fixture = StagingFixture::new(2);
    let destination = TestDirectory::new();
    let (selected, mut candidates, mut payloads) =
        create_destination(&destination, &fixture, 0, 2, 2, fixture.payload_bytes());
    for block in &fixture.blocks {
        assert_eq!(
            candidates.insert(block).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
    }
    let predecessor = selected
        .branch_snapshot_at(fixture.anchor())
        .unwrap()
        .unwrap();
    let payload_outcome = payloads
        .validate_and_insert_branch_payload(
            &predecessor,
            &fixture.blocks[0],
            fixture.payloads[0].clone(),
        )
        .unwrap();
    assert_eq!(
        payload_outcome.insertion_outcome(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    drop(candidates);
    drop(payloads);

    let mut candidates = ArtifactBlockCandidateStore::open(
        &destination.path,
        fixture.definition,
        ArtifactBlockCandidateStoreLimits::new(2).unwrap(),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::open(
        &destination.path,
        ArtifactPayloadStoreLimits::new(2, fixture.payload_bytes()).unwrap(),
    )
    .unwrap();
    let anchor = fixture.anchor();
    let target = fixture.target();
    let first = stage_candidate_branch_recovery_bundle_v0(
        fixture.bundle_bytes,
        anchor,
        target,
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap();
    assert_eq!(first.candidate_inserted_count(), 0);
    assert_eq!(first.payload_inserted_count(), 1);
    let candidate_image =
        fs::read(destination.path.join("artifact-block-candidate-store.log")).unwrap();
    let payload_image = fs::read(destination.path.join("artifact-payload-store.log")).unwrap();

    let second = stage_candidate_branch_recovery_bundle_v0(
        first.into_bundle_bytes(),
        anchor,
        target,
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap();
    assert_eq!(second.candidate_inserted_count(), 0);
    assert_eq!(second.payload_inserted_count(), 0);
    assert_eq!(
        fs::read(destination.path.join("artifact-block-candidate-store.log")).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(destination.path.join("artifact-payload-store.log")).unwrap(),
        payload_image
    );
}

#[test]
fn ambiguous_store_commits_report_prior_prefixes_and_reopen_to_idempotent_completion() {
    let fixture = StagingFixture::new(2);
    let anchor = fixture.anchor();
    let target = fixture.target();

    let candidate_directory = TestDirectory::new();
    let (selected, mut candidates, mut payloads) = create_destination(
        &candidate_directory,
        &fixture,
        0,
        2,
        2,
        fixture.payload_bytes(),
    );
    let selected_bytes = fs::read(candidate_directory.journal_path()).unwrap();
    let candidate_bytes = fixture.bundle_bytes.clone();
    let candidate_bytes_pointer = candidate_bytes.as_ptr();
    let candidate_error = stage_candidate_branch_recovery_bundle_v0_with_test_fault(
        candidate_bytes,
        anchor,
        target,
        &selected,
        &mut candidates,
        &mut payloads,
        CandidateBranchRecoveryBundleStageTestOptions::new(
            fixture.limits,
            CandidateBranchRecoveryBundleStageTestFault::CandidateAfterDurableCommit { index: 1 },
        ),
    )
    .unwrap_err();
    assert_eq!(
        candidate_error.bundle_bytes().as_ptr(),
        candidate_bytes_pointer
    );
    assert!(matches!(
        candidate_error.failure(),
        CandidateBranchRecoveryBundleStageFailure::CandidateCommit { block_id, .. }
            if *block_id == fixture.blocks[1].id()
    ));
    assert_eq!(candidate_error.candidate_acknowledged_count(), 1);
    assert_eq!(candidate_error.candidate_inserted_count(), 1);
    assert_eq!(candidate_error.payload_acknowledged_count(), 0);
    assert_eq!(candidate_error.payload_inserted_count(), 0);
    assert!(matches!(
        candidates.len(),
        Err(ArtifactBlockCandidateStoreError::Poisoned)
    ));
    assert_eq!(payloads.len().unwrap(), 0);
    drop(candidates);
    drop(payloads);

    let mut candidates = ArtifactBlockCandidateStore::open(
        &candidate_directory.path,
        fixture.definition,
        ArtifactBlockCandidateStoreLimits::new(2).unwrap(),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::open(
        &candidate_directory.path,
        ArtifactPayloadStoreLimits::new(2, fixture.payload_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(candidates.len().unwrap(), 2);
    assert_eq!(payloads.len().unwrap(), 0);
    let completed = stage_candidate_branch_recovery_bundle_v0(
        candidate_error.into_bundle_bytes(),
        anchor,
        target,
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap();
    assert_eq!(completed.bundle_bytes().as_ptr(), candidate_bytes_pointer);
    assert_eq!(completed.candidate_inserted_count(), 0);
    assert_eq!(completed.payload_inserted_count(), 2);
    assert_eq!(
        fs::read(candidate_directory.journal_path()).unwrap(),
        selected_bytes
    );

    let payload_directory = TestDirectory::new();
    let (selected, mut candidates, mut payloads) = create_destination(
        &payload_directory,
        &fixture,
        0,
        2,
        2,
        fixture.payload_bytes(),
    );
    let selected_bytes = fs::read(payload_directory.journal_path()).unwrap();
    let payload_bytes = fixture.bundle_bytes.clone();
    let payload_bytes_pointer = payload_bytes.as_ptr();
    let payload_error = stage_candidate_branch_recovery_bundle_v0_with_test_fault(
        payload_bytes,
        anchor,
        target,
        &selected,
        &mut candidates,
        &mut payloads,
        CandidateBranchRecoveryBundleStageTestOptions::new(
            fixture.limits,
            CandidateBranchRecoveryBundleStageTestFault::PayloadAfterDurableCommit { index: 1 },
        ),
    )
    .unwrap_err();
    assert_eq!(payload_error.bundle_bytes().as_ptr(), payload_bytes_pointer);
    assert!(matches!(
        payload_error.failure(),
        CandidateBranchRecoveryBundleStageFailure::PayloadCommit {
            block_id,
            artifact_id,
            ..
        } if *block_id == fixture.blocks[1].id()
            && *artifact_id == fixture.blocks[1].artifact_id()
    ));
    assert_eq!(payload_error.candidate_acknowledged_count(), 2);
    assert_eq!(payload_error.candidate_inserted_count(), 2);
    assert_eq!(payload_error.payload_acknowledged_count(), 1);
    assert_eq!(payload_error.payload_inserted_count(), 1);
    assert_eq!(candidates.len().unwrap(), 2);
    assert!(matches!(
        payloads.len(),
        Err(CanonicalArtifactPayloadStoreError::Poisoned)
    ));
    drop(candidates);
    drop(payloads);

    let mut candidates = ArtifactBlockCandidateStore::open(
        &payload_directory.path,
        fixture.definition,
        ArtifactBlockCandidateStoreLimits::new(2).unwrap(),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::open(
        &payload_directory.path,
        ArtifactPayloadStoreLimits::new(2, fixture.payload_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(candidates.len().unwrap(), 2);
    assert_eq!(payloads.len().unwrap(), 2);
    let completed = stage_candidate_branch_recovery_bundle_v0(
        payload_error.into_bundle_bytes(),
        anchor,
        target,
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap();
    assert_eq!(completed.bundle_bytes().as_ptr(), payload_bytes_pointer);
    assert_eq!(completed.candidate_inserted_count(), 0);
    assert_eq!(completed.payload_inserted_count(), 0);
    assert_eq!(
        fs::read(payload_directory.journal_path()).unwrap(),
        selected_bytes
    );
}

#[test]
fn caller_target_and_store_capacities_fail_before_any_write() {
    let fixture = StagingFixture::new(2);

    let wrong_target_directory = TestDirectory::new();
    let (selected, mut candidates, mut payloads) = create_destination(
        &wrong_target_directory,
        &fixture,
        0,
        2,
        2,
        fixture.payload_bytes(),
    );
    let wrong_target = ArtifactBlockId::from_bytes([0x55; 32]);
    let before = store_images(&wrong_target_directory);
    let bytes = fixture.bundle_bytes.clone();
    let bytes_ptr = bytes.as_ptr();
    let error = stage_candidate_branch_recovery_bundle_v0(
        bytes,
        fixture.anchor(),
        wrong_target,
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap_err();
    assert_eq!(error.bundle_bytes().as_ptr(), bytes_ptr);
    assert!(matches!(
        error.failure(),
        CandidateBranchRecoveryBundleStageFailure::UnexpectedTarget { .. }
    ));
    assert_eq!(candidates.len().unwrap(), 0);
    assert_eq!(payloads.len().unwrap(), 0);
    assert_eq!(store_images(&wrong_target_directory), before);

    let candidate_capacity_directory = TestDirectory::new();
    let (selected, mut candidates, mut payloads) = create_destination(
        &candidate_capacity_directory,
        &fixture,
        0,
        1,
        2,
        fixture.payload_bytes(),
    );
    let before = store_images(&candidate_capacity_directory);
    let error = stage_candidate_branch_recovery_bundle_v0(
        fixture.bundle_bytes.clone(),
        fixture.anchor(),
        fixture.target(),
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap_err();
    assert!(matches!(
        error.failure(),
        CandidateBranchRecoveryBundleStageFailure::CandidateEntryLimitExceeded { .. }
    ));
    assert_eq!(candidates.len().unwrap(), 0);
    assert_eq!(payloads.len().unwrap(), 0);
    assert_eq!(store_images(&candidate_capacity_directory), before);

    let payload_capacity_directory = TestDirectory::new();
    let (selected, mut candidates, mut payloads) = create_destination(
        &payload_capacity_directory,
        &fixture,
        0,
        2,
        1,
        fixture.payload_bytes(),
    );
    let anchor = fixture.anchor();
    let target = fixture.target();
    let before = store_images(&payload_capacity_directory);
    let error = stage_candidate_branch_recovery_bundle_v0(
        fixture.bundle_bytes.clone(),
        anchor,
        target,
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap_err();
    assert!(matches!(
        error.failure(),
        CandidateBranchRecoveryBundleStageFailure::PayloadEntryLimitExceeded { .. }
    ));
    assert_eq!(error.candidate_acknowledged_count(), 0);
    assert_eq!(candidates.len().unwrap(), 0);
    assert_eq!(payloads.len().unwrap(), 0);
    assert_eq!(store_images(&payload_capacity_directory), before);

    let payload_byte_capacity_directory = TestDirectory::new();
    let (selected, mut candidates, mut payloads) = create_destination(
        &payload_byte_capacity_directory,
        &fixture,
        0,
        2,
        2,
        fixture.payload_bytes() - 1,
    );
    let before = store_images(&payload_byte_capacity_directory);
    let error = stage_candidate_branch_recovery_bundle_v0(
        fixture.bundle_bytes,
        anchor,
        target,
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap_err();
    assert!(matches!(
        error.failure(),
        CandidateBranchRecoveryBundleStageFailure::PayloadByteLimitExceeded { .. }
    ));
    assert_eq!(error.candidate_acknowledged_count(), 0);
    assert_eq!(candidates.len().unwrap(), 0);
    assert_eq!(payloads.len().unwrap(), 0);
    assert_eq!(store_images(&payload_byte_capacity_directory), before);
}

#[test]
fn malformed_bundle_and_selected_target_publish_no_store_prefix() {
    let fixture = StagingFixture::new(2);
    let malformed_directory = TestDirectory::new();
    let (selected, mut candidates, mut payloads) = create_destination(
        &malformed_directory,
        &fixture,
        0,
        2,
        2,
        fixture.payload_bytes(),
    );
    let mut malformed = fixture.bundle_bytes.clone();
    let before = store_images(&malformed_directory);
    malformed[0] ^= 0xff;
    let error = stage_candidate_branch_recovery_bundle_v0(
        malformed,
        fixture.anchor(),
        fixture.target(),
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap_err();
    assert!(matches!(
        error.failure(),
        CandidateBranchRecoveryBundleStageFailure::Decode { .. }
    ));
    assert_eq!(candidates.len().unwrap(), 0);
    assert_eq!(payloads.len().unwrap(), 0);
    assert_eq!(store_images(&malformed_directory), before);

    let selected_directory = TestDirectory::new();
    let (selected, mut candidates, mut payloads) = create_destination(
        &selected_directory,
        &fixture,
        2,
        2,
        2,
        fixture.payload_bytes(),
    );
    let anchor = fixture.anchor();
    let target = fixture.target();
    let before = store_images(&selected_directory);
    let error = stage_candidate_branch_recovery_bundle_v0(
        fixture.bundle_bytes,
        anchor,
        target,
        &selected,
        &mut candidates,
        &mut payloads,
        fixture.limits,
    )
    .unwrap_err();
    assert!(matches!(
        error.failure(),
        CandidateBranchRecoveryBundleStageFailure::TargetAlreadySelected { .. }
    ));
    assert_eq!(candidates.len().unwrap(), 0);
    assert_eq!(payloads.len().unwrap(), 0);
    assert_eq!(store_images(&selected_directory), before);
}
