use super::*;
use crate::{
    CandidateBranchRecoveryBundleExportError as ExportError, CandidateBranchRecoveryBundleLimits,
    CandidateBranchRecoveryBundleV0, SelectedArtifactHistory, SelectedArtifactHistoryError,
    export_candidate_branch_recovery_bundle_v0,
};

fn limits() -> CandidateBranchRecoveryBundleLimits {
    CandidateBranchRecoveryBundleLimits::new(8, 1024 * 1024, 2 * 1024 * 1024).unwrap()
}

#[test]
fn reopened_raw_and_anchored_history_export_identical_current_head_bundles_read_only() {
    let fixture = Fixture::new();
    let raw_directory = TestDirectory::new("bundle-export-raw");
    let anchored_directory = TestDirectory::new("bundle-export-anchored");
    let anchor_directory = TestDirectory::new("bundle-export-anchor");
    let artifact_directory = TestDirectory::new("bundle-export-artifact");
    let sources = TestDirectory::new("bundle-export-sources");
    let mut raw = fixture.create(&raw_directory);
    let mut anchored = fixture.create_anchored(&anchored_directory, &anchor_directory);
    let mut artifact =
        ArtifactChainJournal::create(&artifact_directory.0, fixture.definition).unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let genesis = selected.head_block_id();
    let mut selected_ids = vec![genesis];
    let mut old_branches = vec![selected.clone()];
    for axiom in [ZfcAxiom::Pairing, ZfcAxiom::Union] {
        let transition = fixture.transition(raw.head().unwrap(), &mut selected, axiom, 0);
        let anchored_transition =
            fixture.transition(anchored.head().unwrap(), &mut selected, axiom, 0);
        let block = transition.value().artifact_block();
        let payload = transition.canonical_artifact_bytes().to_vec();
        let _ = raw.commit_verified(transition).unwrap();
        let _ = anchored.commit_verified(anchored_transition).unwrap();
        artifact.apply_block(&block, payload.clone()).unwrap();
        selected.apply_block(&block, payload).unwrap();
        selected_ids.push(block.id());
        old_branches.push(selected.clone());
    }
    let current_head = selected.head_block_id();
    let current_root = selected.artifact_dag().artifact_set_root();
    let state = raw.state_id().unwrap();
    assert_eq!(anchored.state_id().unwrap(), state);
    drop(raw);
    drop(anchored);
    let raw = fixture.open(&raw_directory, state).unwrap();
    let anchored = fixture
        .open_anchored(&anchored_directory, &anchor_directory)
        .unwrap();

    let mut candidates = create_candidate_store(&sources, fixture.definition);
    let mut payloads = create_payload_store(&sources);
    // The first suffix payload needs the selected Pairing proof, so a genesis
    // snapshot cannot substitute for the exact non-genesis anchor.
    let (pairing_payloads, pairing_ids) = dependency_payloads(ZfcAxiom::Pairing);
    let second_payload = proof_payload(ZfcAxiom::PowerSet);
    let ids = [pairing_ids[1], artifact_id(&second_payload)];
    let branch_payloads = [pairing_payloads[1].clone(), second_payload];
    let mut snapshot = selected.branch_snapshot();
    let mut branch_blocks = Vec::new();
    for (payload, id) in branch_payloads.iter().zip(ids) {
        let block = selected.prepare_block(id).unwrap();
        let _ = candidates.insert(&block).unwrap();
        snapshot = payloads
            .validate_and_insert_branch_payload(&snapshot, &block, payload.clone())
            .unwrap()
            .into_successor();
        selected.apply_block(&block, payload.clone()).unwrap();
        branch_blocks.push(block);
    }
    let target = branch_blocks[1].id();
    let mut old_targets = Vec::new();
    for old in old_branches.iter().take(2) {
        let payload = proof_payload(ZfcAxiom::Choice);
        let block = old.prepare_block(artifact_id(&payload)).unwrap();
        let _ = candidates.insert(&block).unwrap();
        let _ = payloads
            .validate_and_insert_branch_payload(&old.branch_snapshot(), &block, payload)
            .unwrap();
        old_targets.push((block.id(), old.head_block_id()));
    }
    let images = || {
        (
            fs::read(raw_directory.journal()).unwrap(),
            fs::read(anchored_directory.journal()).unwrap(),
            fs::read(anchor_directory.finality_anchor()).unwrap(),
            fs::read(artifact_directory.0.join("artifact-chain.journal")).unwrap(),
            candidate_image(&sources),
            payload_image(&sources),
        )
    };
    let before = images();
    let expected = artifact
        .export_candidate_branch_recovery_bundle_v0(
            target,
            &mut candidates,
            &mut payloads,
            limits(),
        )
        .unwrap();
    let payload_bytes = branch_payloads
        .iter()
        .map(|bytes| bytes.len() as u64)
        .sum::<u64>();
    let bundle_bytes = expected.canonical_bytes().len() as u64;
    let exact = CandidateBranchRecoveryBundleLimits::new(2, payload_bytes, bundle_bytes).unwrap();
    for history in [&raw as &dyn SelectedArtifactHistory, &anchored] {
        let bundle = export_candidate_branch_recovery_bundle_v0(
            history,
            target,
            &mut candidates,
            &mut payloads,
            exact,
        )
        .unwrap();
        assert_eq!(bundle.canonical_bytes(), expected.canonical_bytes());
        let decoded =
            CandidateBranchRecoveryBundleV0::from_canonical_bytes(bundle.canonical_bytes(), exact)
                .unwrap();
        assert_eq!(decoded.chain_id(), fixture.definition.id());
        assert_eq!(decoded.anchor_block_id(), current_head);
        assert_eq!(decoded.anchor_artifact_set_root(), current_root);
        assert_eq!(decoded.target_block_id(), target);
        assert_eq!(decoded.block_count(), 2);
        assert_eq!(decoded.total_payload_bytes(), payload_bytes);
        for selected_target in &selected_ids {
            assert!(matches!(
                export_candidate_branch_recovery_bundle_v0(history, *selected_target, &mut candidates, &mut payloads, exact),
                Err(ExportError::TargetAlreadySelected { block_id }) if block_id == *selected_target
            ));
        }
        for (old_target, old_anchor) in &old_targets {
            assert!(matches!(
                export_candidate_branch_recovery_bundle_v0(history, *old_target, &mut candidates, &mut payloads, exact),
                Err(ExportError::DivergentAncestry { expected_anchor, encountered })
                    if expected_anchor == current_head && encountered == *old_anchor
            ));
        }
        for (index, bound) in [
            CandidateBranchRecoveryBundleLimits::new(1, payload_bytes, bundle_bytes).unwrap(),
            CandidateBranchRecoveryBundleLimits::new(2, payload_bytes - 1, bundle_bytes).unwrap(),
            CandidateBranchRecoveryBundleLimits::new(2, payload_bytes, bundle_bytes - 1).unwrap(),
        ]
        .into_iter()
        .enumerate()
        {
            let error = export_candidate_branch_recovery_bundle_v0(
                history,
                target,
                &mut candidates,
                &mut payloads,
                bound,
            )
            .unwrap_err();
            assert!(matches!(
                (index, error),
                (0, ExportError::BlockLimitExceeded { .. })
                    | (1, ExportError::PayloadByteLimitExceeded { .. })
                    | (2, ExportError::BundleByteLimitExceeded { .. })
            ));
        }
        assert_eq!(history.selected_head_block_id().unwrap(), current_head);
        assert_eq!(history.selected_artifact_set_root().unwrap(), current_root);
        assert_eq!(images(), before);
    }
    assert_eq!(raw.state_id().unwrap(), state);
    assert_eq!(anchored.state_id().unwrap(), state);
    assert_eq!(raw.finalized_len().unwrap(), 2);
    assert_eq!(anchored.finalized_len().unwrap(), 2);
    assert_eq!(artifact.head_block_id().unwrap(), current_head);
    assert_eq!(artifact.artifact_set_root().unwrap(), current_root);
    assert_eq!(artifact.len().unwrap(), 2);
}

#[test]
fn history_export_rejects_chain_then_halt_or_poison_before_source_integrity_reads() {
    let fixture = Fixture::new();
    let raw_directory = TestDirectory::new("bundle-export-halted-raw");
    let anchored_directory = TestDirectory::new("bundle-export-halted-anchored");
    let anchor_directory = TestDirectory::new("bundle-export-halted-anchor");
    let sources = TestDirectory::new("bundle-export-halted-sources");
    let foreign_sources = TestDirectory::new("bundle-export-foreign-sources");
    let mut raw = fixture.create(&raw_directory);
    let mut anchored = fixture.create_anchored(&anchored_directory, &anchor_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(raw.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let conflict = fixture.transition(raw.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let anchored_first = fixture.transition(
        anchored.head().unwrap(),
        &mut selected,
        ZfcAxiom::Pairing,
        0,
    );
    let anchored_conflict =
        fixture.transition(anchored.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let mut candidates = create_candidate_store(&sources, fixture.definition);
    let mut payloads = create_payload_store(&sources);
    retain_transition_inputs(&mut candidates, &mut payloads, raw.head().unwrap(), &first);
    let target = first.value().artifact_block().id();
    let foreign = ArtifactChainDefinition::new([0x89; 32]);
    let mut foreign_candidates = create_candidate_store(&foreign_sources, foreign);
    foreign_candidates.poison_after_injected_ambiguous_commit();
    // Corrupt retained addresses without reading them: a health-gate error must
    // leave the source handles unpoisoned, proving their entries were not read.
    flip_byte(
        sources.0.join("artifact-block-candidate-store.log"),
        b"naome:artifact-block-candidate-store:v0\0".len() as u64
            + ArtifactChainId::BYTE_LENGTH as u64,
    );
    flip_byte(
        sources.0.join("artifact-payload-store.log"),
        b"naome:artifact-payload-store:v1\0".len() as u64
            + FOUNDATION_ID.len() as u64
            + 4
            + ArtifactId::BYTE_LENGTH as u64,
    );
    let _ = raw.commit_verified(first).unwrap();
    let _ = anchored.commit_verified(anchored_first).unwrap();
    assert!(matches!(
        raw.commit_verified(conflict).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Halted(_)
    ));
    assert!(matches!(
        anchored.commit_verified(anchored_conflict).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Halted(_)
    ));
    let state = raw.state_id().unwrap();
    let halt = raw.halt().unwrap();
    assert_eq!(anchored.state_id().unwrap(), state);
    assert_eq!(anchored.halt().unwrap(), halt);
    let images = || {
        (
            fs::read(raw_directory.journal()).unwrap(),
            fs::read(anchored_directory.journal()).unwrap(),
            fs::read(anchor_directory.finality_anchor()).unwrap(),
            candidate_image(&sources),
            payload_image(&sources),
            candidate_image(&foreign_sources),
        )
    };
    let before = images();
    let mut check = |history: &dyn SelectedArtifactHistory, poisoned: bool| {
        assert!(matches!(export_candidate_branch_recovery_bundle_v0(
            history, target, &mut foreign_candidates, &mut payloads, limits()),
            Err(ExportError::ChainIdMismatch { selected, candidates })
                if selected == fixture.definition.id() && candidates == foreign.id()
        ));
        let error = export_candidate_branch_recovery_bundle_v0(
            history,
            target,
            &mut candidates,
            &mut payloads,
            limits(),
        )
        .unwrap_err();
        match error {
            ExportError::SelectedHistoryState { source } => match *source {
                SelectedArtifactHistoryError::FixedValidatorFinalityJournal { source } => {
                    assert!(matches!(
                        (poisoned, *source),
                        (
                            false,
                            FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. }
                        ) | (true, FixedValidatorFinalityJournalErrorV0::Poisoned)
                    ));
                }
                other => panic!("unexpected history source: {other:?}"),
            },
            other => panic!("unexpected export error: {other:?}"),
        }
        assert_eq!(candidates.len().unwrap(), 1);
        assert_eq!(payloads.len().unwrap(), 1);
        assert_eq!(images(), before);
    };
    check(&raw, false);
    check(&anchored, false);
    drop(raw);
    drop(anchored);
    let mut raw = fixture.open(&raw_directory, state).unwrap();
    let mut anchored = fixture
        .open_anchored(&anchored_directory, &anchor_directory)
        .unwrap();
    check(&raw, false);
    check(&anchored, false);
    assert_eq!(raw.state_id().unwrap(), state);
    assert_eq!(anchored.state_id().unwrap(), state);
    assert_eq!(raw.halt().unwrap(), halt);
    assert_eq!(anchored.halt().unwrap(), halt);
    // Exercise the established poison gate directly; this is not an I/O-fault
    // or crash-durability claim.
    raw.core.poisoned = true;
    anchored.journal.core.poisoned = true;
    check(&raw, true);
    check(&anchored, true);
}

#[test]
fn history_export_integrity_failure_poisons_only_the_corrupted_source() {
    for corrupt_candidate in [true, false] {
        let fixture = Fixture::new();
        let directory = TestDirectory::new("bundle-export-corrupt-finality");
        let sources = TestDirectory::new("bundle-export-corrupt-sources");
        let journal = fixture.create(&directory);
        let mut selected = ArtifactChainState::new(fixture.definition);
        let transition =
            fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
        let block = transition.value().artifact_block();
        let mut candidates = create_candidate_store(&sources, fixture.definition);
        let mut payloads = create_payload_store(&sources);
        retain_transition_inputs(
            &mut candidates,
            &mut payloads,
            journal.head().unwrap(),
            &transition,
        );
        let state = journal.state_id().unwrap();
        let head = journal.artifact_head_block_id().unwrap();
        let root = journal.artifact_set_root().unwrap();
        let journal_before = fs::read(directory.journal()).unwrap();
        if corrupt_candidate {
            flip_byte(
                sources.0.join("artifact-block-candidate-store.log"),
                b"naome:artifact-block-candidate-store:v0\0".len() as u64
                    + ArtifactChainId::BYTE_LENGTH as u64,
            );
        } else {
            flip_byte(
                sources.0.join("artifact-payload-store.log"),
                b"naome:artifact-payload-store:v1\0".len() as u64
                    + FOUNDATION_ID.len() as u64
                    + 4
                    + ArtifactId::BYTE_LENGTH as u64,
            );
        }
        let before = (candidate_image(&sources), payload_image(&sources));
        let error = export_candidate_branch_recovery_bundle_v0(
            &journal,
            block.id(),
            &mut candidates,
            &mut payloads,
            limits(),
        )
        .unwrap_err();
        if corrupt_candidate {
            assert!(
                matches!(error, ExportError::CandidateStoreRead { block_id, .. } if block_id == block.id())
            );
            assert!(matches!(
                candidates.get(block.id()),
                Err(ArtifactBlockCandidateStoreError::Poisoned)
            ));
            assert!(payloads.get(block.artifact_id()).unwrap().is_some());
        } else {
            assert!(
                matches!(error, ExportError::PayloadStoreRead { block_id, artifact_id, .. }
                if block_id == block.id() && artifact_id == block.artifact_id())
            );
            assert_eq!(candidates.get(block.id()).unwrap(), Some(block));
            assert!(matches!(
                payloads.get(block.artifact_id()),
                Err(CanonicalArtifactPayloadStoreError::Poisoned)
            ));
        }
        assert_eq!((candidate_image(&sources), payload_image(&sources)), before);
        assert_eq!(fs::read(directory.journal()).unwrap(), journal_before);
        assert_eq!(journal.state_id().unwrap(), state);
        assert_eq!(journal.artifact_head_block_id().unwrap(), head);
        assert_eq!(journal.artifact_set_root().unwrap(), root);
        assert_eq!(journal.finalized_len().unwrap(), 0);
    }
}
