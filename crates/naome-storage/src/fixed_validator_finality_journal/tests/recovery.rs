use super::*;

#[test]
fn finalizes_two_heights_and_reopens_exact_head() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("two-heights");
    let mut journal = fixture.create(&directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let expected_head = second.value().ancestry_id();
    let _ = journal.commit_verified(second).unwrap();
    let state = journal.state_id().unwrap();
    drop(journal);
    let reopened = fixture.open(&directory, state).unwrap();
    assert_eq!(reopened.finalized_len().unwrap(), 2);
    assert_eq!(reopened.head().unwrap().ancestry_id(), expected_head);
}

#[cfg(unix)]
#[test]
fn anchored_finality_advances_before_publication_and_reopens_exactly() {
    let fixture = Fixture::new();
    let journal_directory = TestDirectory::new("anchored-finality-journal");
    let anchor_directory = TestDirectory::new("anchored-finality-anchor");
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    assert_eq!(journal.journal.core.record_sequence, 0);
    let genesis_anchor = fs::read(anchor_directory.finality_anchor()).unwrap();
    assert_eq!(genesis_anchor.len(), 221);
    assert_eq!(&genesis_anchor[149..157], &0_u64.to_be_bytes());
    assert_eq!(
        &genesis_anchor[157..189],
        journal.state_id().unwrap().as_bytes()
    );

    let mut selected = ArtifactChainState::new(fixture.definition);
    let parent = journal.head().unwrap().clone();
    let first = fixture.transition(&parent, &mut selected, ZfcAxiom::Pairing, 0);
    let duplicate = fixture.transition(&parent, &mut selected, ZfcAxiom::Pairing, 0);
    let expected_head = first.value().artifact_block().id();
    let expected_state = match journal.commit_verified(first).unwrap() {
        FixedValidatorFinalityCommitOutcomeV0::Finalized { state_id, .. } => state_id,
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { .. }
        | FixedValidatorFinalityCommitOutcomeV0::Halted(_) => {
            panic!("the first direct child must finalize")
        }
    };
    assert_eq!(journal.journal.core.record_sequence, 1);
    let committed_anchor = fs::read(anchor_directory.finality_anchor()).unwrap();
    assert_ne!(committed_anchor, genesis_anchor);
    assert_eq!(&committed_anchor[149..157], &1_u64.to_be_bytes());
    assert_eq!(&committed_anchor[157..189], expected_state.as_bytes());

    assert!(matches!(
        journal.commit_verified(duplicate).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized { state_id, .. }
            if state_id == expected_state
    ));
    assert_eq!(journal.journal.core.record_sequence, 1);
    assert_eq!(
        fs::read(anchor_directory.finality_anchor()).unwrap(),
        committed_anchor
    );

    drop(journal);
    let reopened = fixture
        .open_anchored(&journal_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.journal.core.record_sequence, 1);
    assert_eq!(reopened.state_id().unwrap(), expected_state);
    assert_eq!(
        reopened.head().unwrap().artifact_snapshot().head_block_id(),
        expected_head
    );
}

#[cfg(unix)]
#[test]
fn anchored_finality_classifies_old_ahead_and_divergent_anchor_images() {
    let fixture = Fixture::new();

    let behind_journal = TestDirectory::new("anchor-behind-journal");
    let behind_anchor = TestDirectory::new("anchor-behind-anchor");
    let mut journal = fixture.create_anchored(&behind_journal, &behind_anchor);
    let genesis_anchor = fs::read(behind_anchor.finality_anchor()).unwrap();
    let genesis_journal = fs::read(behind_journal.journal()).unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(transition).unwrap();
    let current_anchor = fs::read(behind_anchor.finality_anchor()).unwrap();
    let current_journal = fs::read(behind_journal.journal()).unwrap();
    drop(journal);
    fs::write(behind_anchor.finality_anchor(), &genesis_anchor).unwrap();
    assert!(matches!(
        fixture.open_anchored(&behind_journal, &behind_anchor),
        Err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
            FixedValidatorFinalityJournalErrorV0::AnchorBehind {
                anchored_sequence: 0,
                journal_sequence: 1,
            }
        ))
    ));
    assert_eq!(fs::read(behind_journal.journal()).unwrap(), current_journal);

    fs::write(behind_anchor.finality_anchor(), &current_anchor).unwrap();
    fs::write(behind_journal.journal(), &genesis_journal).unwrap();
    assert!(matches!(
        fixture.open_anchored(&behind_journal, &behind_anchor),
        Err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
            FixedValidatorFinalityJournalErrorV0::AnchorAhead {
                anchored_sequence: 1,
                journal_sequence: 0,
            }
        ))
    ));

    let left_journal = TestDirectory::new("anchor-divergent-left-journal");
    let left_anchor = TestDirectory::new("anchor-divergent-left-anchor");
    let right_journal = TestDirectory::new("anchor-divergent-right-journal");
    let right_anchor = TestDirectory::new("anchor-divergent-right-anchor");
    let mut left = fixture.create_anchored(&left_journal, &left_anchor);
    let mut right = fixture.create_anchored(&right_journal, &right_anchor);
    let mut left_selected = ArtifactChainState::new(fixture.definition);
    let mut right_selected = ArtifactChainState::new(fixture.definition);
    let left_transition = fixture.transition(
        left.head().unwrap(),
        &mut left_selected,
        ZfcAxiom::Pairing,
        0,
    );
    let right_transition = fixture.transition(
        right.head().unwrap(),
        &mut right_selected,
        ZfcAxiom::Union,
        0,
    );
    let _ = left.commit_verified(left_transition).unwrap();
    let _ = right.commit_verified(right_transition).unwrap();
    let divergent_anchor = fs::read(right_anchor.finality_anchor()).unwrap();
    drop(left);
    drop(right);
    fs::write(left_anchor.finality_anchor(), divergent_anchor).unwrap();
    assert!(matches!(
        fixture.open_anchored(&left_journal, &left_anchor),
        Err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
            FixedValidatorFinalityJournalErrorV0::AnchorStateMismatch { sequence: 1 }
        ))
    ));
}

#[test]
fn signer_handoff_requires_retained_finality_and_exact_current_anchor() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("signer-handoff-anchor");
    let mut journal = fixture.create(&directory);
    let genesis_state = journal.state_id().unwrap();
    assert!(matches!(
        journal.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(0),
            genesis_state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::SignerHandoffUnavailable {
            height,
        }) if height == ConsensusHeight::new(0)
    ));
    assert!(matches!(
        journal.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            genesis_state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::SignerHandoffUnavailable {
            height,
        }) if height == ConsensusHeight::new(1)
    ));

    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_position = first.position();
    let first_ancestry = first.value().ancestry_id();
    let first_envelope = first.envelope_id();
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    let first_state = journal.state_id().unwrap();

    assert!(matches!(
        journal.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            genesis_state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
            required,
            acknowledged,
        }) if required == first_state && acknowledged == genesis_state
    ));
    let durable = journal
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            first_state,
        )
        .unwrap();
    assert_eq!(durable.transition.position(), first_position);
    assert_eq!(durable.transition.value().ancestry_id(), first_ancestry);
    assert_eq!(durable.transition.envelope_id(), first_envelope);
    drop(durable);

    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let _ = journal.commit_verified(second).unwrap();
    let second_state = journal.state_id().unwrap();
    assert!(matches!(
        journal.acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            first_state,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
            required,
            acknowledged,
        }) if required == second_state && acknowledged == first_state
    ));
    let historical = journal
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            second_state,
        )
        .unwrap();
    assert_eq!(historical.transition.value().ancestry_id(), first_ancestry);
}

#[test]
fn reopened_finality_history_reconstructs_current_and_historical_candidate_anchors_read_only() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("candidate-recovery");
    let mut journal = fixture.create(&directory);
    let genesis = fixture.definition.id().virtual_genesis_block_id();
    let mut selected = ArtifactChainState::new(fixture.definition);

    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();
    let mut historical_branch = selected.clone();

    let second = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let second_block = second.value().artifact_block();
    let second_payload = second.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(second).unwrap();
    selected.apply_block(&second_block, second_payload).unwrap();

    let (historical_payloads, historical_artifact_ids) = dependency_payloads(ZfcAxiom::PowerSet);
    let premature_dependency = historical_branch
        .prepare_block(historical_artifact_ids[1])
        .unwrap();
    let historical_root = historical_branch
        .prepare_block(historical_artifact_ids[0])
        .unwrap();
    historical_branch
        .apply_block(&historical_root, historical_payloads[0].clone())
        .unwrap();
    let historical_target = historical_branch
        .prepare_block(historical_artifact_ids[1])
        .unwrap();
    historical_branch
        .apply_block(&historical_target, historical_payloads[1].clone())
        .unwrap();
    let historical_target_root = historical_branch.artifact_dag().artifact_set_root();

    let current_payload = proof_payload(ZfcAxiom::Choice);
    let current_target = selected
        .prepare_block(artifact_id(&current_payload))
        .unwrap();
    let current_successor = selected
        .branch_snapshot()
        .validate_child(&current_target, current_payload.clone())
        .unwrap();

    let expected_state = journal.state_id().unwrap();
    let expected_head = journal.artifact_head_block_id().unwrap();
    let expected_root = journal.artifact_set_root().unwrap();
    let journal_image = fs::read(directory.journal()).unwrap();
    drop(journal);

    let reopened = fixture.open(&directory, expected_state).unwrap();
    assert_eq!(
        reopened.artifact_chain_id().unwrap(),
        fixture.definition.id()
    );
    assert_eq!(reopened.artifact_head_block_id().unwrap(), expected_head);
    assert_eq!(reopened.artifact_set_root().unwrap(), expected_root);
    assert_eq!(reopened.core.snapshot_index.len(), 3);
    assert_eq!(reopened.core.snapshot_index.get(&genesis), Some(&0));
    assert_eq!(
        reopened.core.snapshot_index.get(&first_block.id()),
        Some(&1)
    );
    assert_eq!(
        reopened.core.snapshot_index.get(&second_block.id()),
        Some(&2)
    );
    assert!(
        reopened
            .artifact_branch_snapshot_at(genesis)
            .unwrap()
            .unwrap()
            .is_virtual_genesis()
    );
    let historical_snapshot = reopened
        .artifact_branch_snapshot_at(first_block.id())
        .unwrap()
        .unwrap();
    let current_snapshot = reopened
        .artifact_branch_snapshot_at(second_block.id())
        .unwrap()
        .unwrap();
    assert_eq!(current_snapshot.head_block_id(), expected_head);
    assert!(
        reopened
            .artifact_branch_snapshot_at(ArtifactBlockId::from_bytes([0xee; 32]))
            .unwrap()
            .is_none()
    );
    assert!(
        historical_snapshot
            .validate_child(&premature_dependency, historical_payloads[1].clone())
            .is_err(),
        "the historical snapshot must not resolve a dependency absent from that branch"
    );

    let candidate_limits = ArtifactBlockCandidateStoreLimits::new(4).unwrap();
    let mut candidates =
        ArtifactBlockCandidateStore::create(&directory.0, fixture.definition, candidate_limits)
            .unwrap();
    for block in [historical_root, historical_target, current_target] {
        let _ = candidates.insert(&block).unwrap();
    }
    let payload_byte_limit = historical_payloads
        .iter()
        .map(|payload| u64::try_from(payload.len()).unwrap())
        .sum::<u64>()
        + u64::try_from(current_payload.len()).unwrap();
    let payload_limits = ArtifactPayloadStoreLimits::new(3, payload_byte_limit).unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(&directory.0, payload_limits).unwrap();
    let historical_root_outcome = payloads
        .validate_and_insert_branch_payload(
            &historical_snapshot,
            &historical_root,
            historical_payloads[0].clone(),
        )
        .unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(
            historical_root_outcome.successor(),
            &historical_target,
            historical_payloads[1].clone(),
        )
        .unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(&current_snapshot, &current_target, current_payload)
        .unwrap();
    let payload_image = fs::read(directory.0.join("artifact-payload-store.log")).unwrap();

    let historical = reopened
        .reconstruct_candidate_branch(
            historical_target.id(),
            &mut candidates,
            &mut payloads,
            CandidateBranchReconstructionLimits::new(2).unwrap(),
        )
        .unwrap();
    assert_eq!(historical.anchor_block_id(), first_block.id());
    assert_eq!(historical.block_count(), 2);
    assert_eq!(
        historical.snapshot().artifact_set_root(),
        historical_target_root
    );

    let current = reopened
        .reconstruct_candidate_branch(
            current_target.id(),
            &mut candidates,
            &mut payloads,
            CandidateBranchReconstructionLimits::new(1).unwrap(),
        )
        .unwrap();
    assert_eq!(current.anchor_block_id(), second_block.id());
    assert_eq!(current.block_count(), 1);
    assert_eq!(
        current.snapshot().artifact_set_root(),
        current_successor.artifact_set_root()
    );

    let unknown_parent = ArtifactBlockId::from_bytes([0xdd; 32]);
    let unknown_anchor = ArtifactBlock::new(
        unknown_parent,
        current_target.previous_artifact_set_root(),
        current_target.resulting_artifact_set_root(),
        current_target.artifact_id(),
    );
    let _ = candidates.insert(&unknown_anchor).unwrap();
    let candidate_image = fs::read(directory.0.join("artifact-block-candidate-store.log")).unwrap();
    assert!(matches!(
        reopened.reconstruct_candidate_branch(
            unknown_anchor.id(),
            &mut candidates,
            &mut payloads,
            CandidateBranchReconstructionLimits::new(2).unwrap(),
        ),
        Err(CandidateBranchReconstructionError::CandidateNotRetained { block_id })
            if block_id == unknown_parent
    ));

    let mismatch_directory = TestDirectory::new("candidate-recovery-mismatch");
    let mismatch_definition = ArtifactChainDefinition::new([0x99; 32]);
    let mut mismatch_candidates = ArtifactBlockCandidateStore::create(
        &mismatch_directory.0,
        mismatch_definition,
        ArtifactBlockCandidateStoreLimits::new(1).unwrap(),
    )
    .unwrap();
    let mut mismatch_payloads = CanonicalArtifactPayloadStore::create(
        &mismatch_directory.0,
        ArtifactPayloadStoreLimits::new(1, 1).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        reopened.reconstruct_candidate_branch(
            ArtifactBlockId::from_bytes([0xcc; 32]),
            &mut mismatch_candidates,
            &mut mismatch_payloads,
            CandidateBranchReconstructionLimits::new(1).unwrap(),
        ),
        Err(CandidateBranchReconstructionError::ChainIdMismatch {
            selected: actual_selected,
            candidates: actual_candidates,
        }) if actual_selected == fixture.definition.id()
            && actual_candidates == mismatch_definition.id()
    ));

    assert_eq!(reopened.state_id().unwrap(), expected_state);
    assert_eq!(reopened.finalized_len().unwrap(), 2);
    assert_eq!(reopened.artifact_head_block_id().unwrap(), expected_head);
    assert_eq!(reopened.artifact_set_root().unwrap(), expected_root);
    assert_eq!(fs::read(directory.journal()).unwrap(), journal_image);
    assert_eq!(
        fs::read(directory.0.join("artifact-block-candidate-store.log")).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(directory.0.join("artifact-payload-store.log")).unwrap(),
        payload_image
    );
}

#[test]
fn trusted_anchor_controls_incomplete_tail_recovery_and_suffix_rollback() {
    let fixture = Fixture::new();
    let directory = TestDirectory::new("anchor");
    let mut journal = fixture.create(&directory);
    let genesis = journal.state_id().unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(first).unwrap();
    let committed = fs::read(directory.journal()).unwrap();
    let first_state = journal.state_id().unwrap();
    drop(journal);

    let cut = committed.len() - 7;
    fs::write(directory.journal(), &committed[..cut]).unwrap();
    assert!(matches!(
        fixture.open(&directory, first_state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), &committed[..cut]);
    let recovered = fixture.open(&directory, genesis).unwrap();
    drop(recovered);
    assert_eq!(
        fs::read(directory.journal()).unwrap().len(),
        JOURNAL_PREFIX_BYTES
    );

    fs::write(directory.journal(), &committed).unwrap();
    assert!(matches!(
        fixture.open(&directory, genesis),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
    assert_eq!(fs::read(directory.journal()).unwrap(), committed);
    fs::write(directory.journal(), &committed[..JOURNAL_PREFIX_BYTES]).unwrap();
    assert!(matches!(
        fixture.open(&directory, first_state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
}

#[test]
fn every_incomplete_first_entry_cut_obeys_the_trusted_anchor() {
    let fixture = Fixture::new();
    let source = TestDirectory::new("all-cuts-source");
    let mut journal = fixture.create(&source);
    let genesis = journal.state_id().unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(transition).unwrap();
    let committed = fs::read(source.journal()).unwrap();
    let finalized = journal.state_id().unwrap();
    drop(journal);

    for cut in JOURNAL_PREFIX_BYTES + 1..committed.len() {
        let directory = TestDirectory::new("all-cuts");
        fs::write(directory.journal(), &committed[..cut]).unwrap();
        assert!(
            matches!(
                fixture.open(&directory, finalized),
                Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
            ),
            "cut={cut}"
        );
        assert_eq!(
            fs::read(directory.journal()).unwrap(),
            &committed[..cut],
            "cut={cut}"
        );
        let recovered = fixture.open(&directory, genesis).unwrap();
        assert_eq!(recovered.finalized_len().unwrap(), 0, "cut={cut}");
        drop(recovered);
        assert_eq!(
            fs::read(directory.journal()).unwrap().len(),
            JOURNAL_PREFIX_BYTES,
            "cut={cut}"
        );
    }
}
