use super::*;

#[test]
fn candidate_backed_finality_installs_one_exact_direct_child_without_mutating_sources() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-success-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-success-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-success-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);

    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();

    let second = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Union,
        fixture.limit.max_round(),
    );
    let block = second.value().artifact_block();
    let target = block.id();
    let envelope = second.canonical_envelope_bytes().to_vec();
    let artifact_bytes = second.canonical_artifact_bytes().to_vec();
    let expected_position = second.position();
    let expected_ancestry = second.value().ancestry_id();
    let expected_envelope_id = second.envelope_id();
    retain_transition_inputs(
        &mut candidates,
        &mut payloads,
        journal.head().unwrap(),
        &second,
    );

    let old_state = journal.state_id().unwrap();
    let old_finality = fs::read(finality_directory.journal()).unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);
    let body = canonical_record_body(FINALIZE_RECORD, &second, 1).unwrap();
    let body_length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let expected_state = step_state_id(old_state, body_length, &body);

    let outcome = commit_candidate_backed_finality_v0(
        &mut journal,
        &mut candidates,
        &mut payloads,
        target,
        &envelope,
        ConsensusRound::new(fixture.limit.max_round()),
    )
    .unwrap();

    assert_eq!(outcome.target(), target);
    assert_eq!(outcome.position(), expected_position);
    assert_eq!(outcome.ancestry_id(), expected_ancestry);
    assert_eq!(outcome.envelope_id(), expected_envelope_id);
    assert_eq!(outcome.state_id(), expected_state);
    assert_eq!(journal.state_id().unwrap(), expected_state);
    assert_eq!(journal.finalized_len().unwrap(), 2);
    assert_eq!(
        journal.head().unwrap().artifact_snapshot().head_block_id(),
        target
    );
    let record = journal
        .finality_record(expected_position.height())
        .unwrap()
        .unwrap();
    assert_eq!(record.position(), expected_position);
    assert_eq!(record.canonical_envelope_bytes(), envelope);
    assert_eq!(record.canonical_artifact_bytes(), artifact_bytes);

    let mut expected_finality = old_finality;
    expected_finality.extend_from_slice(&body_length);
    expected_finality.extend_from_slice(&body);
    expected_finality.extend_from_slice(expected_state.as_bytes());
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        expected_finality
    );
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
    assert_eq!(candidates.get(target).unwrap(), Some(block));
    let retained_payload = payloads.get(block.artifact_id()).unwrap().unwrap();
    assert_eq!(retained_payload.canonical_artifact_bytes(), artifact_bytes);

    drop(journal);
    assert!(matches!(
        fixture.open(&finality_directory, old_state),
        Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
    ));
    let reopened = fixture.open(&finality_directory, expected_state).unwrap();
    assert_eq!(reopened.finalized_len().unwrap(), 2);
    assert_eq!(
        reopened.head().unwrap().artifact_snapshot().head_block_id(),
        target
    );
}

#[cfg(unix)]
#[test]
fn candidate_backed_anchored_finality_keeps_the_safe_product_path_composable() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("anchored-candidate-finality");
    let anchor_directory = TestDirectory::new("anchored-candidate-anchor");
    let candidate_directory = TestDirectory::new("anchored-candidate-store");
    let payload_directory = TestDirectory::new("anchored-candidate-payloads");
    let mut journal = fixture.create_anchored(&finality_directory, &anchor_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let target = transition.value().artifact_block().id();
    let envelope = transition.canonical_envelope_bytes().to_vec();
    retain_transition_inputs(
        &mut candidates,
        &mut payloads,
        journal.head().unwrap(),
        &transition,
    );
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);

    let outcome = commit_candidate_backed_anchored_finality_v0(
        &mut journal,
        &mut candidates,
        &mut payloads,
        target,
        &envelope,
        ConsensusRound::new(0),
    )
    .unwrap();
    assert_eq!(outcome.target(), target);
    assert_eq!(journal.journal.core.record_sequence, 1);
    assert_eq!(journal.state_id().unwrap(), outcome.state_id());
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);

    drop(journal);
    let reopened = fixture
        .open_anchored(&finality_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.journal.core.record_sequence, 1);
    assert_eq!(
        SelectedArtifactHistory::selected_head_block_id(&reopened).unwrap(),
        target
    );
}

#[cfg(unix)]
fn candidate_backed_historical_sibling_terminal_case(
    label: &str,
    use_vote_batch: bool,
) -> (FixedValidatorFinalityHaltV0, [Vec<u8>; 4]) {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new(&format!("{label}-finality"));
    let anchor_directory = TestDirectory::new(&format!("{label}-anchor"));
    let candidate_directory = TestDirectory::new(&format!("{label}-candidates"));
    let payload_directory = TestDirectory::new(&format!("{label}-payloads"));
    let mut journal = fixture.create_anchored(&finality_directory, &anchor_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let genesis = journal.head().unwrap().clone();

    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(&genesis, &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();

    let mut sibling_state = ArtifactChainState::new(fixture.definition);
    let sibling = fixture.transition(&genesis, &mut sibling_state, ZfcAxiom::Union, 2);
    let sibling_target = sibling.value().artifact_block().id();
    let sibling_envelope = sibling.canonical_envelope_bytes().to_vec();
    let sibling_control =
        proposal_control_bytes(sibling.value(), sibling.position(), &fixture.proposer);
    let sibling_precommit = signed_precommit_bytes(
        fixture.context,
        sibling.position(),
        sibling.value().proposal_signing_root(),
        &fixture.proposer,
    );
    let sibling_batch = [sibling_precommit.as_slice()];
    retain_transition_inputs(&mut candidates, &mut payloads, &genesis, &sibling);

    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::PowerSet,
        0,
    );
    let _ = journal.commit_verified(second).unwrap();
    let sources_before = [
        candidate_image(&candidate_directory),
        payload_image(&payload_directory),
    ];

    let conflict = if use_vote_batch {
        commit_candidate_backed_anchored_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_control,
            &sibling_batch,
            ConsensusRound::new(2),
            ConsensusRound::new(2),
        )
        .unwrap()
    } else {
        commit_candidate_backed_anchored_finality_conflict_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_envelope,
            ConsensusRound::new(2),
        )
        .unwrap()
    };
    let halt = conflict.halt();
    assert_eq!(conflict.target(), sibling_target);
    assert_eq!(
        [
            candidate_image(&candidate_directory),
            payload_image(&payload_directory),
        ],
        sources_before
    );
    let images = [
        fs::read(finality_directory.journal()).unwrap(),
        fs::read(anchor_directory.finality_anchor()).unwrap(),
        candidate_image(&candidate_directory),
        payload_image(&payload_directory),
    ];
    drop(journal);
    let reopened = fixture
        .open_anchored(&finality_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.halt().unwrap(), Some(halt));
    assert_eq!(reopened.state_id().unwrap(), halt.state_id());
    (halt, images)
}

#[cfg(unix)]
#[test]
fn candidate_backed_historical_sibling_batch_matches_envelope_terminal_evidence() {
    let (envelope_halt, envelope_images) =
        candidate_backed_historical_sibling_terminal_case("candidate-conflict-envelope", false);
    let (batch_halt, batch_images) =
        candidate_backed_historical_sibling_terminal_case("candidate-conflict-batch", true);
    assert_eq!(batch_halt, envelope_halt);
    assert_eq!(batch_images, envelope_images);
}

#[cfg(unix)]
#[test]
fn candidate_backed_historical_sibling_halts_anchored_finality_without_mutating_sources() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-conflict-finality");
    let anchor_directory = TestDirectory::new("candidate-conflict-anchor");
    let candidate_directory = TestDirectory::new("candidate-conflict-candidates");
    let payload_directory = TestDirectory::new("candidate-conflict-payloads");
    let mut journal = fixture.create_anchored(&finality_directory, &anchor_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let genesis = journal.head().unwrap().clone();

    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(&genesis, &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let selected_ancestry = first.value().ancestry_id();
    let selected_envelope_id = first.envelope_id();

    let mut sibling_state = ArtifactChainState::new(fixture.definition);
    let sibling = fixture.transition(&genesis, &mut sibling_state, ZfcAxiom::Union, 2);
    let sibling_target = sibling.value().artifact_block().id();
    let sibling_ancestry = sibling.value().ancestry_id();
    let sibling_envelope_id = sibling.envelope_id();
    let sibling_envelope = sibling.canonical_envelope_bytes().to_vec();
    retain_transition_inputs(&mut candidates, &mut payloads, &genesis, &sibling);

    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();
    let second = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::PowerSet,
        0,
    );
    let selected_head = second.value().artifact_block().id();
    let _ = journal.commit_verified(second).unwrap();
    assert_eq!(journal.journal.core.record_sequence, 2);
    assert_eq!(
        journal.head().unwrap().artifact_snapshot().head_block_id(),
        selected_head
    );

    let finality_before = fs::read(finality_directory.journal()).unwrap();
    let anchor_before = fs::read(anchor_directory.finality_anchor()).unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);
    let conflict = commit_candidate_backed_anchored_finality_conflict_v0(
        &mut journal,
        &mut candidates,
        &mut payloads,
        sibling_target,
        &sibling_envelope,
        ConsensusRound::new(2),
    )
    .unwrap();
    let halt = conflict.halt();

    assert_eq!(conflict.target(), sibling_target);
    assert_eq!(halt.height(), ConsensusHeight::new(1));
    assert_eq!(
        halt.kind(),
        FixedValidatorFinalityHaltKindV0::SelectedSibling
    );
    assert_eq!(halt.first_ancestry(), selected_ancestry);
    assert_eq!(halt.first_envelope_id(), selected_envelope_id);
    assert_eq!(halt.second_ancestry(), sibling_ancestry);
    assert_eq!(halt.second_envelope_id(), sibling_envelope_id);
    assert_eq!(journal.halt().unwrap(), Some(halt));
    assert_eq!(journal.state_id().unwrap(), halt.state_id());
    assert_eq!(journal.journal.core.record_sequence, 3);
    assert_ne!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );
    assert_ne!(
        fs::read(anchor_directory.finality_anchor()).unwrap(),
        anchor_before
    );
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
    assert!(matches!(
        journal.head(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { height })
            if height == ConsensusHeight::new(1)
    ));

    drop(journal);
    let reopened = fixture
        .open_anchored(&finality_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.halt().unwrap(), Some(halt));
    assert_eq!(reopened.state_id().unwrap(), halt.state_id());
    assert_eq!(reopened.journal.core.record_sequence, 3);
}

#[test]
fn candidate_backed_conflict_rejects_nonselected_or_same_values_before_source_reads() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-conflict-preflight-finality");
    let candidate_directory = TestDirectory::new("candidate-conflict-preflight-candidates");
    let payload_directory = TestDirectory::new("candidate-conflict-preflight-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let genesis = journal.head().unwrap().clone();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(&genesis, &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let first_target = first_block.id();
    let first_envelope = first.canonical_envelope_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();

    let journal_before = fs::read(finality_directory.journal()).unwrap();
    let state_before = journal.state_id().unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);
    assert!(matches!(
        commit_candidate_backed_finality_conflict_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            first_target,
            &first_envelope,
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::SelectedValueNotDistinct { height })
            if height == ConsensusHeight::new(1)
    ));

    let next = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let next_target = next.value().artifact_block().id();
    assert!(matches!(
        commit_candidate_backed_finality_conflict_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            next_target,
            next.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::SelectedHeightUnavailable { height })
            if height == ConsensusHeight::new(2)
    ));
    assert_eq!(journal.state_id().unwrap(), state_before);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        journal_before
    );
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
}

#[test]
fn candidate_backed_conflict_vote_batch_rejects_routes_sources_and_votes_without_finality_write() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-conflict-batch-rejections-finality");
    let candidate_directory = TestDirectory::new("candidate-conflict-batch-rejections-candidates");
    let payload_directory = TestDirectory::new("candidate-conflict-batch-rejections-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let genesis = journal.head().unwrap().clone();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(&genesis, &mut selected, ZfcAxiom::Pairing, 0);
    let first_target = first.value().artifact_block().id();
    let first_control = proposal_control_bytes(first.value(), first.position(), &fixture.proposer);
    let first_block = first.value().artifact_block();
    let first_payload = first.canonical_artifact_bytes().to_vec();
    let _ = journal.commit_verified(first).unwrap();
    selected.apply_block(&first_block, first_payload).unwrap();

    let mut sibling_state = ArtifactChainState::new(fixture.definition);
    let sibling = fixture.transition(&genesis, &mut sibling_state, ZfcAxiom::Union, 2);
    let sibling_block = sibling.value().artifact_block();
    let sibling_target = sibling_block.id();
    let sibling_control =
        proposal_control_bytes(sibling.value(), sibling.position(), &fixture.proposer);
    let sibling_precommit = signed_precommit_bytes(
        fixture.context,
        sibling.position(),
        sibling.value().proposal_signing_root(),
        &fixture.proposer,
    );
    let sibling_batch = [sibling_precommit.as_slice()];
    let journal_before = fs::read(finality_directory.journal()).unwrap();
    let state_before = journal.state_id().unwrap();
    let empty_sources = [
        candidate_image(&candidate_directory),
        payload_image(&payload_directory),
    ];

    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &[0_u8],
            &[],
            ConsensusRound::new(10),
            ConsensusRound::new(9),
        ),
        Err(
            CandidateBackedFinalityErrorV0::RoundWorkLimitExceedsJournal {
                requested: 9,
                journal: 8
            }
        )
    ));
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &[0_u8],
            &[],
            ConsensusRound::new(2),
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::EvidenceRoundWorkLimitExceeded {
            required,
            maximum
        }) if required == ConsensusRound::new(2) && maximum == ConsensusRound::new(1)
    ));
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            first_target,
            &sibling_control,
            &[],
            ConsensusRound::new(2),
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::ProposalTargetMismatch {
            expected,
            actual
        }) if expected == first_target && actual == sibling_target
    ));
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            first_target,
            &first_control,
            &[],
            ConsensusRound::new(0),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::SelectedValueNotDistinct { height })
            if height == ConsensusHeight::new(1)
    ));
    let next = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::PowerSet,
        0,
    );
    let next_control = proposal_control_bytes(next.value(), next.position(), &fixture.proposer);
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            next.value().artifact_block().id(),
            &next_control,
            &[],
            ConsensusRound::new(0),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::SelectedHeightUnavailable { height })
            if height == ConsensusHeight::new(2)
    ));
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_control,
            &sibling_batch,
            ConsensusRound::new(2),
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::CandidateUnavailable { target })
            if target == sibling_target
    ));
    assert_eq!(
        [
            candidate_image(&candidate_directory),
            payload_image(&payload_directory),
        ],
        empty_sources
    );

    let _ = candidates.insert(&sibling_block).unwrap();
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_control,
            &sibling_batch,
            ConsensusRound::new(2),
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::PayloadUnavailable { artifact_id })
            if artifact_id == sibling_block.artifact_id()
    ));
    let _ = payloads
        .validate_and_insert_branch_payload(
            genesis.artifact_snapshot(),
            &sibling_block,
            sibling.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let complete_sources = [
        candidate_image(&candidate_directory),
        payload_image(&payload_directory),
    ];

    let mut invalid_proposal = sibling_control.clone();
    *invalid_proposal.last_mut().unwrap() ^= 0xff;
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &invalid_proposal,
            &[],
            ConsensusRound::new(2),
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::Proposal(_))
    ));
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_control,
            &[],
            ConsensusRound::new(2),
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::PrecommitBatch(
            FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                QuorumCertificateBuildError::EmptyVoteBatch
            )
        ))
    ));
    let duplicate_batch = [sibling_precommit.as_slice(), sibling_precommit.as_slice()];
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_control,
            &duplicate_batch,
            ConsensusRound::new(2),
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::PrecommitBatch(
            FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                QuorumCertificateBuildError::DuplicateSigner { .. }
            )
        ))
    ));
    let inactive = signing_key(2);
    let inactive_precommit = signed_precommit_bytes(
        fixture.context,
        sibling.position(),
        sibling.value().proposal_signing_root(),
        &inactive,
    );
    let inactive_batch = [inactive_precommit.as_slice()];
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_control,
            &inactive_batch,
            ConsensusRound::new(2),
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::PrecommitBatch(
            FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                QuorumCertificateBuildError::UnknownSigner { .. }
            )
        ))
    ));
    let mut invalid_precommit = sibling_precommit.clone();
    *invalid_precommit.last_mut().unwrap() ^= 0xff;
    let invalid_batch = [invalid_precommit.as_slice()];
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_control,
            &invalid_batch,
            ConsensusRound::new(2),
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::PrecommitBatch(
            FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                QuorumCertificateBuildError::Vote { .. }
            )
        ))
    ));
    let wrong_round_precommit = signed_precommit_bytes(
        fixture.context,
        ConsensusPosition::new(sibling.position().height(), ConsensusRound::new(1)),
        sibling.value().proposal_signing_root(),
        &fixture.proposer,
    );
    let wrong_round_batch = [wrong_round_precommit.as_slice()];
    assert!(matches!(
        commit_candidate_backed_finality_conflict_vote_batch_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_control,
            &wrong_round_batch,
            ConsensusRound::new(2),
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::PrecommitBatch(
            FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                QuorumCertificateBuildError::PositionMismatch { .. }
            )
        ))
    ));
    assert_eq!(journal.state_id().unwrap(), state_before);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        journal_before
    );
    assert_eq!(
        [
            candidate_image(&candidate_directory),
            payload_image(&payload_directory),
        ],
        complete_sources
    );
}

#[test]
fn candidate_backed_conflict_requires_complete_distinct_sibling_inputs_before_halt() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-conflict-verify-finality");
    let candidate_directory = TestDirectory::new("candidate-conflict-verify-candidates");
    let payload_directory = TestDirectory::new("candidate-conflict-verify-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let genesis = journal.head().unwrap().clone();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(&genesis, &mut selected, ZfcAxiom::Pairing, 0);
    let _ = journal.commit_verified(first).unwrap();

    let mut sibling_state = ArtifactChainState::new(fixture.definition);
    let sibling = fixture.transition(&genesis, &mut sibling_state, ZfcAxiom::Union, 2);
    let sibling_block = sibling.value().artifact_block();
    let sibling_target = sibling_block.id();
    let sibling_envelope = sibling.canonical_envelope_bytes().to_vec();
    let journal_before = fs::read(finality_directory.journal()).unwrap();
    let state_before = journal.state_id().unwrap();

    assert!(matches!(
        commit_candidate_backed_finality_conflict_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_envelope,
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::CandidateUnavailable { target })
            if target == sibling_target
    ));
    let _ = candidates.insert(&sibling_block).unwrap();
    assert!(matches!(
        commit_candidate_backed_finality_conflict_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_envelope,
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::PayloadUnavailable { artifact_id })
            if artifact_id == sibling_block.artifact_id()
    ));
    let _ = payloads
        .validate_and_insert_branch_payload(
            genesis.artifact_snapshot(),
            &sibling_block,
            sibling.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);

    let mut invalid_signature = sibling_envelope.clone();
    *invalid_signature.last_mut().unwrap() ^= 0xff;
    assert!(matches!(
        commit_candidate_backed_finality_conflict_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &invalid_signature,
            ConsensusRound::new(2),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(
                ConsensusEnvelopeVerifyError::PrecommitCertificate(
                    PrecommitCertificateVerifyError::InvalidSignature { .. }
                )
            )
        ))
    ));
    assert!(matches!(
        commit_candidate_backed_finality_conflict_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            sibling_target,
            &sibling_envelope,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::RoundLimitExceeded { round, maximum }
        )) if round == ConsensusRound::new(2) && maximum == ConsensusRound::new(1)
    ));
    assert_eq!(journal.state_id().unwrap(), state_before);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        journal_before
    );
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
}

#[test]
fn candidate_backed_finality_rejects_missing_misdirected_and_unbounded_inputs_without_writes() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-reject-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-reject-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-reject-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 1);
    let block = transition.value().artifact_block();
    let target = block.id();
    let envelope = transition.canonical_envelope_bytes().to_vec();
    let finality_before = fs::read(finality_directory.journal()).unwrap();

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &envelope,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::CandidateUnavailable { target: actual })
            if actual == target
    ));
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );

    let _ = candidates.insert(&block).unwrap();
    let candidate_only = candidate_image(&candidate_directory);
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &envelope,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::PayloadUnavailable { artifact_id })
            if artifact_id == block.artifact_id()
    ));
    assert_eq!(candidate_image(&candidate_directory), candidate_only);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );

    let _ = payloads
        .validate_and_insert_branch_payload(
            journal.head().unwrap().artifact_snapshot(),
            &block,
            transition.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);

    let wrong_target = ArtifactBlockId::from_bytes([0x99; 32]);
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            wrong_target,
            &envelope,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::EnvelopeTargetMismatch {
            expected,
            actual,
        }) if expected == wrong_target && actual == target
    ));

    let mut trailing = envelope.clone();
    trailing.push(0);
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &trailing,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(_))
    ));

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &envelope,
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::RoundLimitExceeded { round, maximum }
        )) if round == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
    ));

    let mut attacker_round = envelope.clone();
    let round_offset =
        ConsensusValueV0::BYTE_LENGTH + VerifiedProducerAuthorizationV0::BYTE_LENGTH + 77;
    attacker_round[round_offset..round_offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &attacker_round,
            ConsensusRound::new(fixture.limit.max_round()),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::RoundLimitExceeded { round, maximum }
        )) if round == ConsensusRound::new(u64::MAX)
            && maximum == ConsensusRound::new(fixture.limit.max_round())
    ));

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &envelope,
            ConsensusRound::new(fixture.limit.max_round() + 1),
        ),
        Err(CandidateBackedFinalityErrorV0::RoundWorkLimitExceedsJournal {
            requested,
            journal,
        }) if requested == fixture.limit.max_round() + 1
            && journal == fixture.limit.max_round()
    ));

    assert_eq!(journal.finalized_len().unwrap(), 0);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
}

#[test]
fn candidate_backed_finality_requires_one_independent_certificate_per_height() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-sequential-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-sequential-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-sequential-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);

    let first_for_child =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let child = first_for_child.into_branch();
    let first = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let first_block = first.value().artifact_block();
    selected
        .apply_block(&first_block, first.canonical_artifact_bytes().to_vec())
        .unwrap();
    let second = fixture.transition(&child, &mut selected, ZfcAxiom::Union, 0);
    let second_block = second.value().artifact_block();

    let _ = candidates.insert(&first_block).unwrap();
    let _ = candidates.insert(&second_block).unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(
            journal.head().unwrap().artifact_snapshot(),
            &first_block,
            first.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(
            child.artifact_snapshot(),
            &second_block,
            second.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);
    let genesis_finality = fs::read(finality_directory.journal()).unwrap();

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            second_block.id(),
            second.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::ValueHeightMismatch { expected, actual }
        )) if expected == ConsensusHeight::new(1) && actual == ConsensusHeight::new(2)
    ));
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        genesis_finality
    );

    let first_outcome = commit_candidate_backed_finality_v0(
        &mut journal,
        &mut candidates,
        &mut payloads,
        first_block.id(),
        first.canonical_envelope_bytes(),
        ConsensusRound::new(0),
    )
    .unwrap();
    assert_eq!(first_outcome.position().height(), ConsensusHeight::new(1));
    let second_outcome = commit_candidate_backed_finality_v0(
        &mut journal,
        &mut candidates,
        &mut payloads,
        second_block.id(),
        second.canonical_envelope_bytes(),
        ConsensusRound::new(0),
    )
    .unwrap();
    assert_eq!(second_outcome.position().height(), ConsensusHeight::new(2));
    assert_eq!(journal.finalized_len().unwrap(), 2);
    assert_eq!(
        journal.head().unwrap().artifact_snapshot().head_block_id(),
        second_block.id()
    );
    assert_eq!(candidate_image(&candidate_directory), candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
}

#[test]
fn candidate_backed_finality_reauthenticates_evidence_and_artifact_parent() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-verify-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-verify-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-verify-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 1);
    retain_transition_inputs(
        &mut candidates,
        &mut payloads,
        journal.head().unwrap(),
        &transition,
    );
    let block = transition.value().artifact_block();
    let target = block.id();
    let envelope = transition.canonical_envelope_bytes();
    let finality_before = fs::read(finality_directory.journal()).unwrap();
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);

    let mut invalid_authorization = envelope.to_vec();
    let signature_offset =
        ConsensusValueV0::BYTE_LENGTH + AUTHORIZATION_BODY_BYTES + CONSENSUS_KEY_BYTES;
    invalid_authorization[signature_offset] ^= 0xff;
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &invalid_authorization,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(
                ConsensusEnvelopeVerifyError::ProducerAuthorization(_)
            )
        ))
    ));

    let mut wrong_role = envelope.to_vec();
    let certificate_offset =
        ConsensusValueV0::BYTE_LENGTH + VerifiedProducerAuthorizationV0::BYTE_LENGTH;
    wrong_role[certificate_offset] = 1;
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &wrong_role,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(
                ConsensusEnvelopeVerifyError::PrecommitCertificate(_)
            )
        ))
    ));

    let mut wrong_certificate_height = envelope.to_vec();
    wrong_certificate_height[certificate_offset + 69..certificate_offset + 77]
        .copy_from_slice(&2_u64.to_be_bytes());
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &wrong_certificate_height,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::CertificateHeightMismatch {
                expected,
                actual,
            }
        )) if expected == ConsensusHeight::new(1) && actual == ConsensusHeight::new(2)
    ));

    let mut foreign_context = envelope.to_vec();
    foreign_context[0] ^= 0xff;
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            target,
            &foreign_context,
            ConsensusRound::new(1),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(
                ConsensusEnvelopeVerifyError::ChainIdMismatch { .. }
            )
        ))
    ));

    let wrong_parent = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0xa7; 32]),
        block.previous_artifact_set_root(),
        block.resulting_artifact_set_root(),
        block.artifact_id(),
    );
    let round = journal.head().unwrap().begin_round_zero().unwrap();
    let wrong_parent_value = round.value_for_artifact_block(wrong_parent);
    let wrong_parent_envelope =
        envelope_bytes(wrong_parent_value, round.position(), &fixture.proposer);
    let _ = candidates.insert(&wrong_parent).unwrap();
    let candidate_with_wrong_parent = candidate_image(&candidate_directory);
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            wrong_parent.id(),
            &wrong_parent_envelope,
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::Envelope(
                ConsensusEnvelopeVerifyError::ArtifactValidation(_)
            )
        ))
    ));

    assert_eq!(journal.finalized_len().unwrap(), 0);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );
    assert_eq!(
        candidate_image(&candidate_directory),
        candidate_with_wrong_parent
    );
    assert_ne!(candidate_with_wrong_parent, candidate_before);
    assert_eq!(payload_image(&payload_directory), payload_before);
}

#[test]
fn candidate_backed_finality_rejects_foreign_candidate_store_before_source_reads() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-foreign-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-foreign-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-foreign-payloads");
    let mut journal = fixture.create(&finality_directory);
    let foreign_definition = ArtifactChainDefinition::new([0x91; 32]);
    let mut candidates = create_candidate_store(&candidate_directory, foreign_definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);
    let transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    let finality_before = fs::read(finality_directory.journal()).unwrap();
    candidates.poison_after_injected_ambiguous_commit();
    payloads.poison_after_injected_ambiguous_commit();

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            transition.value().artifact_block().id(),
            transition.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::CandidateChainMismatch {
            expected,
            actual,
        }) if expected == fixture.definition.id() && actual == foreign_definition.id()
    ));
    assert_eq!(journal.finalized_len().unwrap(), 0);
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before
    );
}

#[test]
fn candidate_backed_finality_rejects_stale_and_halted_journals_before_selection() {
    let fixture = Fixture::new();
    let finality_directory = TestDirectory::new("candidate-backed-stale-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-stale-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-stale-payloads");
    let mut journal = fixture.create(&finality_directory);
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let mut selected = ArtifactChainState::new(fixture.definition);

    let stale = fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
    retain_transition_inputs(
        &mut candidates,
        &mut payloads,
        journal.head().unwrap(),
        &stale,
    );
    let selected_transition =
        fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Union, 0);
    let conflicting_transition = fixture.transition(
        journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::PowerSet,
        0,
    );
    let _ = journal.commit_verified(selected_transition).unwrap();
    let finality_before_stale = fs::read(finality_directory.journal()).unwrap();
    let stale_target = stale.value().artifact_block().id();
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            stale_target,
            stale.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::Envelope(
            FixedConsensusBoundedEnvelopeVerifyError::ValueHeightMismatch { expected, actual }
        )) if expected == ConsensusHeight::new(2) && actual == ConsensusHeight::new(1)
    ));
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        finality_before_stale
    );
    assert_eq!(journal.finalized_len().unwrap(), 1);
    assert!(journal.halt().unwrap().is_none());

    assert!(matches!(
        journal.commit_verified(conflicting_transition).unwrap(),
        FixedValidatorFinalityCommitOutcomeV0::Halted(_)
    ));
    let halted_image = fs::read(finality_directory.journal()).unwrap();
    candidates.poison_after_injected_ambiguous_commit();
    payloads.poison_after_injected_ambiguous_commit();
    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut journal,
            &mut candidates,
            &mut payloads,
            stale_target,
            stale.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::FinalityJournal(
            FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. }
        ))
    ));
    assert_eq!(
        fs::read(finality_directory.journal()).unwrap(),
        halted_image
    );
}

#[test]
fn candidate_backed_finality_store_integrity_failures_poison_only_the_owning_source() {
    let fixture = Fixture::new();
    let mut selected = ArtifactChainState::new(fixture.definition);

    let candidate_finality_directory =
        TestDirectory::new("candidate-backed-corrupt-candidate-finality");
    let candidate_directory = TestDirectory::new("candidate-backed-corrupt-candidate-store");
    let candidate_payload_directory =
        TestDirectory::new("candidate-backed-corrupt-candidate-payloads");
    let mut candidate_journal = fixture.create(&candidate_finality_directory);
    let mut corrupt_candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut healthy_payloads = create_payload_store(&candidate_payload_directory);
    let transition = fixture.transition(
        candidate_journal.head().unwrap(),
        &mut selected,
        ZfcAxiom::Pairing,
        0,
    );
    retain_transition_inputs(
        &mut corrupt_candidates,
        &mut healthy_payloads,
        candidate_journal.head().unwrap(),
        &transition,
    );
    let block = transition.value().artifact_block();
    let target = block.id();
    let candidate_finality_before = fs::read(candidate_finality_directory.journal()).unwrap();
    let candidate_payload_before = payload_image(&candidate_payload_directory);
    let candidate_path = candidate_directory
        .0
        .join("artifact-block-candidate-store.log");
    let candidate_body_offset = b"naome:artifact-block-candidate-store:v0\0".len() as u64
        + ArtifactChainId::BYTE_LENGTH as u64;
    flip_byte(candidate_path, candidate_body_offset);
    let corrupted_candidate_image = candidate_image(&candidate_directory);

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut candidate_journal,
            &mut corrupt_candidates,
            &mut healthy_payloads,
            target,
            transition.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::CandidateStore(_))
    ));
    assert!(matches!(
        corrupt_candidates.get(target),
        Err(ArtifactBlockCandidateStoreError::Poisoned)
    ));
    assert!(healthy_payloads.get(block.artifact_id()).unwrap().is_some());
    assert_eq!(
        fs::read(candidate_finality_directory.journal()).unwrap(),
        candidate_finality_before
    );
    assert_eq!(
        candidate_image(&candidate_directory),
        corrupted_candidate_image
    );
    assert_eq!(
        payload_image(&candidate_payload_directory),
        candidate_payload_before
    );

    let payload_finality_directory =
        TestDirectory::new("candidate-backed-corrupt-payload-finality");
    let payload_candidate_directory =
        TestDirectory::new("candidate-backed-corrupt-payload-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-corrupt-payload-store");
    let mut payload_journal = fixture.create(&payload_finality_directory);
    let mut healthy_candidates =
        create_candidate_store(&payload_candidate_directory, fixture.definition);
    let mut corrupt_payloads = create_payload_store(&payload_directory);
    retain_transition_inputs(
        &mut healthy_candidates,
        &mut corrupt_payloads,
        payload_journal.head().unwrap(),
        &transition,
    );
    let payload_finality_before = fs::read(payload_finality_directory.journal()).unwrap();
    let payload_candidate_before = candidate_image(&payload_candidate_directory);
    let payload_path = payload_directory.0.join("artifact-payload-store.log");
    let payload_body_offset = b"naome:artifact-payload-store:v1\0".len() as u64
        + FOUNDATION_ID.len() as u64
        + 4
        + ArtifactId::BYTE_LENGTH as u64;
    flip_byte(payload_path, payload_body_offset);
    let corrupted_payload_image = payload_image(&payload_directory);

    assert!(matches!(
        commit_candidate_backed_finality_v0(
            &mut payload_journal,
            &mut healthy_candidates,
            &mut corrupt_payloads,
            target,
            transition.canonical_envelope_bytes(),
            ConsensusRound::new(0),
        ),
        Err(CandidateBackedFinalityErrorV0::PayloadStore(_))
    ));
    assert_eq!(healthy_candidates.get(target).unwrap(), Some(block));
    assert!(matches!(
        corrupt_payloads.get(block.artifact_id()),
        Err(CanonicalArtifactPayloadStoreError::Poisoned)
    ));
    assert_eq!(
        fs::read(payload_finality_directory.journal()).unwrap(),
        payload_finality_before
    );
    assert_eq!(
        candidate_image(&payload_candidate_directory),
        payload_candidate_before
    );
    assert_eq!(payload_image(&payload_directory), corrupted_payload_image);
}
