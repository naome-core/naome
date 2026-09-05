use super::*;

#[test]
fn initial_signing_lineage_requires_an_exact_external_anchor_and_reopens_exactly() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("initial-signing-lineage");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let child = fixture.owned_transition().into_branch();
    let child_round = child.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let genesis = journal.state_id().unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let activated = activate_proposal_authoring(&mut journal);

    assert!(matches!(
        journal.issue_signing_session(&round, activated),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)
    ));
    let bound = journal.bind_signing_lineage(&round).unwrap();
    assert_ne!(bound, genesis);
    let bound_image = fs::read(&journal_path).unwrap();
    assert_eq!(journal.bind_signing_lineage(&round).unwrap(), bound);
    assert_eq!(fs::read(&journal_path).unwrap(), bound_image);
    assert!(matches!(
        journal.bind_signing_lineage(&child_round),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageMismatch {
            expected_height,
            actual_height,
        }) if expected_height == ConsensusHeight::new(1)
            && actual_height == ConsensusHeight::new(2)
    ));
    assert_eq!(journal.state_id().unwrap(), bound);
    assert_eq!(fs::read(&journal_path).unwrap(), bound_image);
    drop(journal);

    assert!(matches!(
        fixture.open(&directory, genesis),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
            expected,
            actual,
        }) if expected == genesis && actual == bound
    ));
    let mut reopened = fixture.open(&directory, bound).unwrap();
    assert!(matches!(
        reopened.issue_signing_session(&round, genesis),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExternalSessionAnchorMismatch {
            required,
            acknowledged,
        }) if required == bound && acknowledged == genesis
    ));
    assert!(matches!(
        reopened.issue_signing_session(&child_round, bound),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageMismatch {
            expected_height,
            actual_height,
        }) if expected_height == ConsensusHeight::new(1)
            && actual_height == ConsensusHeight::new(2)
    ));
    let session = reopened.issue_signing_session(&round, bound).unwrap();
    assert_eq!(session.position(), round.position());
}

#[cfg(unix)]
#[test]
fn anchored_vote_journal_persists_lineage_prepare_and_completion_before_release() {
    let fixture = Fixture::new(2);
    let journal_directory = TestDirectory::new("anchored-vote-journal");
    let anchor_directory = TestDirectory::new("anchored-vote-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let anchor_path = anchor_directory.vote_anchor(fixture.signer());
    let (_, journal_path) = keyed_paths(&journal_directory.0, fixture.signer()).unwrap();
    let genesis_anchor = fs::read(&anchor_path).unwrap();
    assert_eq!(genesis_anchor.len(), 256);
    assert_eq!(&genesis_anchor[184..192], &0_u64.to_be_bytes());
    assert_eq!(
        &genesis_anchor[192..224],
        journal.state_id().unwrap().as_bytes()
    );

    let _ = activate_anchored_proposal_authoring(&mut journal);
    let lineage_state = journal.bind_signing_lineage(&round).unwrap();
    assert_eq!(journal.journal.core.record_sequence, 2);
    let lineage_anchor = fs::read(&anchor_path).unwrap();
    assert_eq!(&lineage_anchor[184..192], &2_u64.to_be_bytes());
    assert_eq!(&lineage_anchor[192..224], lineage_state.as_bytes());
    let lineage_journal = fs::read(&journal_path).unwrap();
    assert_eq!(journal.bind_signing_lineage(&round).unwrap(), lineage_state);
    assert_eq!(journal.journal.core.record_sequence, 2);
    assert_eq!(fs::read(&anchor_path).unwrap(), lineage_anchor);
    assert_eq!(fs::read(&journal_path).unwrap(), lineage_journal);

    let mut session = journal.issue_signing_session(&round).unwrap();
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
    assert_eq!(
        &fs::read(&anchor_path).unwrap()[184..192],
        &3_u64.to_be_bytes()
    );
    assert_eq!(
        &fs::read(&anchor_path).unwrap()[192..224],
        prepared.state_id().as_bytes()
    );
    let acknowledgement = session.acknowledge_prepared_vote(prepared).unwrap();
    let signed = session.sign_prepared_vote(acknowledgement).unwrap();
    assert_eq!(
        &fs::read(&anchor_path).unwrap()[184..192],
        &4_u64.to_be_bytes()
    );
    assert_eq!(
        &fs::read(&anchor_path).unwrap()[192..224],
        signed.state_id().as_bytes()
    );
    drop(session);
    assert_eq!(journal.journal.core.record_sequence, 4);
    drop(journal);

    let mut reopened = fixture
        .open_anchored(&journal_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.journal.core.record_sequence, 4);
    assert_eq!(reopened.state_id().unwrap(), signed.state_id());
    assert_eq!(
        reopened
            .retained_signed_vote(round.position(), ConsensusVoteRole::Prevote)
            .unwrap(),
        Some(signed)
    );
    let resumed = reopened.issue_signing_session(&round).unwrap();
    assert_eq!(resumed.position(), round.position());
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
}

#[cfg(unix)]
#[test]
fn anchored_vote_reopen_classifies_old_ahead_and_divergent_anchor_images() {
    let fixture = Fixture::new(2);
    let journal_directory = TestDirectory::new("vote-anchor-classification-journal");
    let anchor_directory = TestDirectory::new("vote-anchor-classification-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let anchor_path = anchor_directory.vote_anchor(fixture.signer());
    let (_, journal_path) = keyed_paths(&journal_directory.0, fixture.signer()).unwrap();
    let genesis_anchor = fs::read(&anchor_path).unwrap();
    let genesis_journal = fs::read(&journal_path).unwrap();
    let _ = journal.bind_signing_lineage(&round).unwrap();
    let current_anchor = fs::read(&anchor_path).unwrap();
    let current_journal = fs::read(&journal_path).unwrap();
    drop(journal);

    fs::write(&anchor_path, &genesis_anchor).unwrap();
    assert!(matches!(
        fixture.open_anchored(&journal_directory, &anchor_directory),
        Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind {
                anchored_sequence: 0,
                journal_sequence: 1,
                }
            )
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), current_journal);

    fs::write(&anchor_path, &current_anchor).unwrap();
    fs::write(&journal_path, &genesis_journal).unwrap();
    assert!(matches!(
        fixture.open_anchored(&journal_directory, &anchor_directory),
        Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::AnchorAhead {
                anchored_sequence: 1,
                journal_sequence: 0,
                }
            )
    ));

    let left_journal = TestDirectory::new("vote-anchor-divergent-left-journal");
    let left_anchor = TestDirectory::new("vote-anchor-divergent-left-anchor");
    let right_journal = TestDirectory::new("vote-anchor-divergent-right-journal");
    let right_anchor = TestDirectory::new("vote-anchor-divergent-right-anchor");
    let mut left = fixture.create_anchored(&left_journal, &left_anchor);
    let mut right = fixture.create_anchored(&right_journal, &right_anchor);
    let left_branch = fixture.branch();
    let left_round = left_branch.begin_round_zero().unwrap();
    let right_branch = fixture.branch();
    let right_round = right_branch.begin_round_zero().unwrap();
    let _ = activate_anchored_proposal_authoring(&mut left);
    let _ = activate_anchored_proposal_authoring(&mut right);
    let _ = left.bind_signing_lineage(&left_round).unwrap();
    let _ = right.bind_signing_lineage(&right_round).unwrap();
    let mut left_session = left.issue_signing_session(&left_round).unwrap();
    let mut right_session = right.issue_signing_session(&right_round).unwrap();
    let left_effect = left_session.decide_prevote_without_proposal().unwrap();
    let left_prepared = prepared(left_session.prepare_vote(&left_round, left_effect).unwrap());
    let right_payload = proof_payload();
    let right_artifact_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(right_payload.clone())
        .unwrap()
        .artifact_id();
    let right_block = ArtifactChainState::new(fixture.definition)
        .prepare_block(right_artifact_id)
        .unwrap();
    let right_value = right_round.value_for_artifact_block(right_block);
    let mut right_proposal_bytes = right_value.to_canonical_bytes().to_vec();
    right_proposal_bytes.extend_from_slice(&authorization_bytes(
        fixture.context,
        right_round.position(),
        right_value.proposal_signing_root(),
        &fixture.signing_key(),
    ));
    right_proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    let right_proposal = right_round
        .decode_and_verify_proposal_control(&right_proposal_bytes, right_payload)
        .unwrap();
    let right_effect = right_session
        .decide_prevote_for_proposal(&right_proposal)
        .unwrap();
    let right_prepared = prepared(
        right_session
            .prepare_vote(&right_round, right_effect)
            .unwrap(),
    );
    assert_ne!(left_prepared.state_id(), right_prepared.state_id());
    let divergent_anchor = fs::read(right_anchor.vote_anchor(fixture.signer())).unwrap();
    drop(left_session);
    drop(right_session);
    drop(left);
    drop(right);
    fs::write(left_anchor.vote_anchor(fixture.signer()), divergent_anchor).unwrap();
    assert!(matches!(
        fixture.open_anchored(&left_journal, &left_anchor),
        Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::AnchorStateMismatch { sequence: 3 }
            )
    ));
}

#[test]
fn recovered_signer_session_replays_latest_completed_round_with_bounded_work() {
    let fixture = Fixture::new(8);
    let directory = TestDirectory::new("completed-round-recovery");
    let parent = fixture.branch();
    let parent_round = parent.begin_round_zero().unwrap();

    let mut finality = fixture.create_finality(&directory);
    let first_transition = fixture.owned_transition();
    let first_artifact_block = first_transition.value().artifact_block();
    let _ = finality.commit_verified(first_transition).unwrap();
    let finality_state = finality.state_id().unwrap();
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    let mut vote_journal = fixture.create(&directory);
    let mut session = issue_session(&mut vote_journal, &parent_round);
    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let child_lineage_state = prepared_height.state_id();
    let child = session
        .acknowledge_prepared_height_is_externally_durable(prepared_height, child_lineage_state)
        .unwrap();
    let child_coordinate = child.coordinate();
    let child_round_zero = child.begin_round_zero().unwrap();
    let child_round_one = child.begin_round_zero().unwrap().advance_round().unwrap();

    let mut child_artifact_state = ArtifactChainState::new(fixture.definition);
    child_artifact_state
        .apply_block(&first_artifact_block, proof_payload())
        .unwrap();
    let second_payload = proof_payload_for(ZfcAxiom::Union);
    let second_artifact_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(second_payload.clone())
        .unwrap()
        .artifact_id();
    let second_artifact_block = child_artifact_state
        .prepare_block(second_artifact_id)
        .unwrap();
    let proposal_value = child_round_zero.value_for_artifact_block(second_artifact_block);
    let proposal_root = proposal_value.proposal_signing_root();
    let mut proposal_bytes = proposal_value.to_canonical_bytes().to_vec();
    proposal_bytes.extend_from_slice(&authorization_bytes(
        fixture.context,
        child_round_zero.position(),
        proposal_root,
        &fixture.signing_key(),
    ));
    proposal_bytes.push(VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG);
    let proposal = child_round_zero
        .decode_and_verify_proposal_control(&proposal_bytes, second_payload)
        .unwrap();

    let effect = session.decide_prevote_for_proposal(&proposal).unwrap();
    let prepared_vote = prepared(session.prepare_vote(&child_round_zero, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared_vote, prepared_vote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    let prevote_quorum = certificate_bytes(
        fixture.context,
        child_round_zero.position(),
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(proposal_root),
        &fixture.signing_key(),
    );
    let effect = session
        .decide_precommit_for_proposal_quorum(&child_round_zero, &proposal, &prevote_quorum)
        .unwrap();
    let prepared_vote = prepared(session.prepare_vote(&child_round_zero, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared_vote, prepared_vote.state_id())
        .unwrap();
    let _ = session.sign_prepared_vote(acknowledgement).unwrap();
    session.advance_round(&child_round_one).unwrap();
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared_vote = prepared(session.prepare_vote(&child_round_one, effect).unwrap());
    let acknowledgement = session
        .acknowledge_prepared_vote_is_externally_durable(prepared_vote, prepared_vote.state_id())
        .unwrap();
    let vote_state = session
        .sign_prepared_vote(acknowledgement)
        .unwrap()
        .state_id();
    let expected_locked = session.locked_value();
    let expected_valid = session.valid_value().cloned();
    assert!(expected_locked.is_some());
    assert!(expected_valid.is_some());

    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let finality_image = fs::read(&finality_path).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    drop(session);
    drop(vote_journal);
    drop(child_round_one);
    drop(child_round_zero);
    drop(child);
    drop(parent_round);
    drop(parent);
    drop(finality);

    let finality = fixture.open_finality(&directory, finality_state);
    let mut vote_journal = fixture.open(&directory, vote_state).unwrap();
    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    let recovered_branch = finality.recover_anchored_signer_branch(recovery).unwrap();
    assert!(matches!(
        vote_journal.issue_recovered_signing_session(
            recovered_branch,
            vote_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        ),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::SignerRecoveryRoundLimitExceeded {
                required: 1,
                maximum: 0,
            }
        )
    ));
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);

    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    let recovered_branch = finality.recover_anchored_signer_branch(recovery).unwrap();
    let recovered = vote_journal
        .issue_recovered_signing_session(
            recovered_branch,
            vote_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(1),
        )
        .unwrap();
    assert_eq!(recovered.branch().coordinate(), child_coordinate);
    assert_eq!(
        recovered.session().position(),
        ConsensusPosition::new(ConsensusHeight::new(2), ConsensusRound::new(1))
    );
    assert_eq!(
        recovered.session().phase(),
        FixedValidatorLockPhaseV0::Prevote
    );
    assert_eq!(recovered.session().locked_value(), expected_locked);
    assert_eq!(recovered.session().valid_value(), expected_valid.as_ref());
    assert_eq!(fs::read(finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(vote_path).unwrap(), vote_image);
}

#[test]
fn signer_recovery_rejects_mismatched_history_and_foreign_handle_provenance() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("recovery-provenance");
    let missing_directory = TestDirectory::new("recovery-missing");
    let mismatch_directory = TestDirectory::new("recovery-mismatch");
    let equivalent_directory = TestDirectory::new("recovery-equivalent");
    let parent = fixture.branch();
    let parent_round = parent.begin_round_zero().unwrap();

    let mut finality = fixture.create_finality(&directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let finality_state = finality.state_id().unwrap();
    let finality_coordinate = finality.head().unwrap().coordinate();
    let durable = finality
        .acknowledge_signer_height_transition_is_externally_durable(
            ConsensusHeight::new(1),
            finality_state,
        )
        .unwrap();
    let mut vote_journal = fixture.create(&directory);
    let mut session = issue_session(&mut vote_journal, &parent_round);
    let prepared_height = session
        .prepare_height_with_durable_finality(durable)
        .unwrap();
    let vote_state = prepared_height.state_id();
    drop(prepared_height);
    drop(session);
    drop(vote_journal);
    drop(parent_round);
    drop(parent);
    drop(finality);

    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let finality_image = fs::read(&finality_path).unwrap();
    let mut equivalent_finality = fixture.create_finality(&equivalent_directory);
    let _ = equivalent_finality
        .commit_verified(fixture.owned_transition_for_round(ZfcAxiom::Pairing, 1))
        .unwrap();
    let equivalent_state = equivalent_finality.state_id().unwrap();
    assert_ne!(equivalent_state, finality_state);
    assert_eq!(
        equivalent_finality.head().unwrap().coordinate(),
        finality_coordinate
    );
    let equivalent_path = equivalent_directory.0.join(crate::JOURNAL_FILE_NAME);
    let equivalent_image = fs::read(&equivalent_path).unwrap();
    assert_ne!(equivalent_image, finality_image);
    drop(equivalent_finality);
    let equivalent_finality = fixture.open_finality(&equivalent_directory, equivalent_state);

    let missing_finality = fixture.create_finality(&missing_directory);
    let missing_state = missing_finality.state_id().unwrap();
    let missing_path = missing_directory.0.join(crate::JOURNAL_FILE_NAME);
    let missing_image = fs::read(&missing_path).unwrap();

    let mut mismatched_finality = fixture.create_finality(&mismatch_directory);
    let _ = mismatched_finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap();
    let mismatched_state = mismatched_finality.state_id().unwrap();
    let mismatched_image = fs::read(mismatch_directory.0.join(crate::JOURNAL_FILE_NAME)).unwrap();

    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    let vote_journal = fixture.open(&directory, vote_state).unwrap();
    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    assert!(matches!(
        missing_finality.recover_anchored_signer_branch(recovery),
        Err(FixedValidatorFinalityJournalErrorV0::SignerRecoveryUnavailable {
            height,
        }) if height == ConsensusHeight::new(2)
    ));
    assert_eq!(vote_journal.state_id().unwrap(), vote_state);
    assert_eq!(missing_finality.state_id().unwrap(), missing_state);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);
    assert_eq!(fs::read(&missing_path).unwrap(), missing_image);

    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    assert!(matches!(
        mismatched_finality.recover_anchored_signer_branch(recovery),
        Err(FixedValidatorFinalityJournalErrorV0::SignerRecoveryLineageMismatch {
            height,
        }) if height == ConsensusHeight::new(2)
    ));
    assert_eq!(vote_journal.state_id().unwrap(), vote_state);
    assert_eq!(mismatched_finality.state_id().unwrap(), mismatched_state);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);
    assert_eq!(
        fs::read(mismatch_directory.0.join(crate::JOURNAL_FILE_NAME)).unwrap(),
        mismatched_image
    );

    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    let recovered_branch = equivalent_finality
        .recover_anchored_signer_branch(recovery)
        .unwrap();
    drop(vote_journal);
    let mut reopened = fixture.open(&directory, vote_state).unwrap();
    assert!(matches!(
        reopened.issue_recovered_signing_session(
            recovered_branch,
            vote_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ForeignSignerRecovery)
    ));
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);
    assert_eq!(fs::read(&equivalent_path).unwrap(), equivalent_image);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);

    let recovery = reopened
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    let recovered_branch = equivalent_finality
        .recover_anchored_signer_branch(recovery)
        .unwrap();
    let recovered = reopened
        .issue_recovered_signing_session(
            recovered_branch,
            vote_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        )
        .unwrap();
    assert_eq!(
        recovered.session().position().height(),
        ConsensusHeight::new(2)
    );
    assert_eq!(fs::read(vote_path).unwrap(), vote_image);
    assert_eq!(fs::read(equivalent_path).unwrap(), equivalent_image);
    assert_eq!(fs::read(finality_path).unwrap(), finality_image);
}

#[test]
fn signer_recovery_capability_requires_a_live_exact_anchored_lineage() {
    let fixture = Fixture::new(2);
    let unbound_directory = TestDirectory::new("recovery-unbound");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut unbound = fixture.create(&unbound_directory);
    let (_, unbound_path) = keyed_paths(&unbound_directory.0, fixture.signer()).unwrap();
    let activated = activate_proposal_authoring(&mut unbound);
    let activated_image = fs::read(&unbound_path).unwrap();
    assert!(matches!(
        unbound.acknowledge_signer_recovery_is_externally_durable(
            FixedValidatorVoteSafetyJournalStateIdV0::from_bytes([0xee; 32]),
        ),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ExternalSessionAnchorMismatch { .. })
    ));
    assert!(matches!(
        unbound.acknowledge_signer_recovery_is_externally_durable(activated),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningLineageRequired)
    ));
    assert_eq!(unbound.state_id().unwrap(), activated);
    assert_eq!(fs::read(&unbound_path).unwrap(), activated_image);
    let bound = unbound.bind_signing_lineage(&round).unwrap();
    let session = unbound.issue_signing_session(&round, bound).unwrap();
    drop(session);
    let bound_image = fs::read(&unbound_path).unwrap();
    assert!(matches!(
        unbound.acknowledge_signer_recovery_is_externally_durable(bound),
        Err(FixedValidatorVoteSafetyJournalErrorV0::SigningSessionAlreadyIssued)
    ));
    assert_eq!(unbound.state_id().unwrap(), bound);
    assert_eq!(fs::read(&unbound_path).unwrap(), bound_image);

    let pending_directory = TestDirectory::new("recovery-pending");
    let mut pending = fixture.create(&pending_directory);
    let mut session = issue_session(&mut pending, &round);
    let effect = session.decide_prevote_without_proposal().unwrap();
    let pending_vote = prepared(session.prepare_vote(&round, effect).unwrap());
    let prepared_state = pending_vote.state_id();
    drop(session);
    drop(pending);
    let pending = fixture.open(&pending_directory, prepared_state).unwrap();
    let (_, pending_path) = keyed_paths(&pending_directory.0, fixture.signer()).unwrap();
    let pending_image = fs::read(&pending_path).unwrap();
    assert!(matches!(
        pending.acknowledge_signer_recovery_is_externally_durable(prepared_state),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingRecoveryDenied { .. })
    ));
    assert_eq!(pending.state_id().unwrap(), prepared_state);
    assert_eq!(fs::read(&pending_path).unwrap(), pending_image);

    let halted_directory = TestDirectory::new("recovery-vote-halt");
    let mut halted = fixture.create(&halted_directory);
    let _ = halted.bind_signing_lineage(&round).unwrap();
    let prepared = prepared(halted.prepare_vote(fixture.nil_prevote_intent()).unwrap());
    let _ = halted.sign_prepared_vote(prepared).unwrap();
    let halt = match halted
        .prepare_vote(fixture.proposal_prevote_intent())
        .unwrap()
    {
        FixedValidatorVotePrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected terminal halt, got {other:?}"),
    };
    let (_, halted_path) = keyed_paths(&halted_directory.0, fixture.signer()).unwrap();
    let halted_image = fs::read(&halted_path).unwrap();
    assert!(matches!(
        halted.acknowledge_signer_recovery_is_externally_durable(halt.state_id()),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt { .. })
    ));
    assert_eq!(halted.state_id().unwrap(), halt.state_id());
    assert_eq!(halted.halt().unwrap(), Some(halt));
    assert_eq!(fs::read(halted_path).unwrap(), halted_image);
}

#[test]
fn initial_lineage_recovery_reproduces_exact_configured_virtual_genesis() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("recovery-initial-lineage");
    let mismatch_directory = TestDirectory::new("recovery-initial-mismatch");
    let finality = fixture.create_finality(&directory);
    let finality_state = finality.state_id().unwrap();
    let mismatched_context = ConsensusContextV0::new(
        fixture.context.chain_id(),
        ConsensusGenesisId::from_bytes([0x43; 32]),
        fixture.context.protocol_version(),
    );
    let mismatched_finality = FixedValidatorFinalityJournalV0::create(
        &mismatch_directory.0,
        fixture.definition,
        mismatched_context,
        &fixture.entries(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
    )
    .unwrap();
    let mismatched_state = mismatched_finality.state_id().unwrap();
    let branch = fixture.branch();
    let expected_coordinate = branch.coordinate();
    let round = branch.begin_round_zero().unwrap();
    let mut vote_journal = fixture.create(&directory);
    let _ = activate_proposal_authoring(&mut vote_journal);
    let vote_state = vote_journal.bind_signing_lineage(&round).unwrap();
    let finality_path = directory.0.join(crate::JOURNAL_FILE_NAME);
    let mismatched_path = mismatch_directory.0.join(crate::JOURNAL_FILE_NAME);
    let (_, vote_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let finality_image = fs::read(&finality_path).unwrap();
    let mismatched_image = fs::read(&mismatched_path).unwrap();
    let vote_image = fs::read(&vote_path).unwrap();
    drop(vote_journal);
    drop(round);
    drop(branch);
    drop(finality);
    drop(mismatched_finality);

    let finality = fixture.open_finality(&directory, finality_state);
    let mismatched_finality = FixedValidatorFinalityJournalV0::open_verified(
        &mismatch_directory.0,
        fixture.definition,
        mismatched_context,
        &fixture.entries(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        mismatched_state,
    )
    .unwrap();
    let mut vote_journal = fixture.open(&directory, vote_state).unwrap();
    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    assert!(matches!(
        mismatched_finality.recover_anchored_signer_branch(recovery),
        Err(FixedValidatorFinalityJournalErrorV0::SignerRecoveryLineageMismatch {
            height,
        }) if height == ConsensusHeight::new(1)
    ));
    assert_eq!(mismatched_finality.state_id().unwrap(), mismatched_state);
    assert_eq!(vote_journal.state_id().unwrap(), vote_state);
    assert_eq!(fs::read(&mismatched_path).unwrap(), mismatched_image);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);

    let recovery = vote_journal
        .acknowledge_signer_recovery_is_externally_durable(vote_state)
        .unwrap();
    let recovered_branch = finality.recover_anchored_signer_branch(recovery).unwrap();
    let recovered = vote_journal
        .issue_recovered_signing_session(
            recovered_branch,
            vote_state,
            FixedValidatorSignerRecoveryRoundLimitV0::new(0),
        )
        .unwrap();
    assert_eq!(recovered.branch().coordinate(), expected_coordinate);
    assert_eq!(
        recovered.session().position(),
        ConsensusPosition::new(ConsensusHeight::new(1), ConsensusRound::new(0))
    );
    assert_eq!(finality.state_id().unwrap(), finality_state);
    assert_eq!(fs::read(&finality_path).unwrap(), finality_image);
    assert_eq!(fs::read(&mismatched_path).unwrap(), mismatched_image);
    assert_eq!(fs::read(&vote_path).unwrap(), vote_image);
}

#[test]
fn exact_intent_is_idempotent_and_completed_bytes_reopen_and_release() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("idempotent");
    let mut journal = fixture.create(&directory);
    let intent = fixture.nil_prevote_intent();
    let prepared = prepared(journal.prepare_vote(intent.clone()).unwrap());
    assert!(matches!(
        journal.prepare_vote(intent.clone()).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::AlreadyPrepared(actual) if actual == prepared
    ));
    let first = signed(journal.sign_prepared_vote(prepared).unwrap());
    let second = signed(journal.sign_prepared_vote(prepared).unwrap());
    assert_eq!(second, first);
    assert!(matches!(
        journal.prepare_vote(intent.clone()).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::AlreadySigned(ref actual) if actual == &first
    ));
    let completed_state = first.state_id();
    drop(journal);

    let mut reopened = fixture.open(&directory, completed_state).unwrap();
    assert_eq!(
        reopened
            .retained_signed_vote(first.position(), first.role())
            .unwrap(),
        Some(first.clone())
    );
    assert!(matches!(
        reopened.prepare_vote(intent).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::AlreadySigned(actual) if actual == first
    ));
}

#[test]
fn anchored_pending_reopen_is_diagnostic_but_never_signable() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("pending-restart");
    let mut journal = fixture.create(&directory);
    let intent = fixture.nil_prevote_intent();
    let prepared = prepared(journal.prepare_vote(intent.clone()).unwrap());
    let prepared_state = prepared.state_id();
    drop(journal);

    let mut reopened = fixture.open(&directory, prepared_state).unwrap();
    let pending = reopened.pending_vote().unwrap().unwrap();
    assert_eq!(pending.position(), prepared.position());
    assert_eq!(pending.role(), prepared.role());
    assert_eq!(pending.target(), prepared.target());
    assert_eq!(pending.state_id(), prepared_state);
    assert!(matches!(
        reopened.pending_prepared_vote(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RestartedPending { .. })
    ));
    assert!(matches!(
        reopened.sign_prepared_vote(prepared),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RestartedPending { .. })
    ));
    assert!(matches!(
        reopened.prepare_vote(intent),
        Err(FixedValidatorVoteSafetyJournalErrorV0::RestartedPending { .. })
    ));
}

#[test]
fn completed_state_recovery_returns_only_the_latest_slot() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("latest-completed-recovery");
    let (prevote, precommit) = fixture.round_zero_nil_intents();
    let prevote_bytes = prevote.canonical_state_and_vote_intent_bytes().to_vec();
    let precommit_bytes = precommit.canonical_state_and_vote_intent_bytes().to_vec();
    let mut journal = fixture.create(&directory);

    let prevote_prepared = prepared(journal.prepare_vote(prevote).unwrap());
    let _ = journal.sign_prepared_vote(prevote_prepared).unwrap();
    let precommit_prepared = prepared(journal.prepare_vote(precommit).unwrap());
    let completed = signed(journal.sign_prepared_vote(precommit_prepared).unwrap());
    let completed_state = completed.state_id();

    let retained = journal
        .latest_completed_state_and_vote_intent_bytes()
        .unwrap()
        .unwrap();
    assert_eq!(retained, precommit_bytes);
    assert_ne!(retained, prevote_bytes);
    drop(journal);

    let reopened = fixture.open(&directory, completed_state).unwrap();
    let retained = reopened
        .latest_completed_state_and_vote_intent_bytes()
        .unwrap()
        .unwrap();
    assert_eq!(retained, precommit_bytes);
    assert_ne!(retained, prevote_bytes);
}

#[test]
fn completed_intent_restores_typed_lock_state_but_pending_and_halt_deny_recovery() {
    let fixture = Fixture::new(4);
    let directory = TestDirectory::new("typed-recovery");
    let intent = fixture.proposal_precommit_intent();
    let position = intent.position();
    let mut journal = fixture.create(&directory);
    let completed_prepared = prepared(journal.prepare_vote(intent).unwrap());
    let _ = journal.sign_prepared_vote(completed_prepared).unwrap();
    let retained = journal
        .latest_completed_state_and_vote_intent_bytes()
        .unwrap()
        .unwrap()
        .to_vec();
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let replay = VerifiedReplayFixedValidatorVoteIntentV0::decode_and_verify_for_round(
        &retained,
        &round,
        fixture.signer(),
    )
    .unwrap();
    let mut recovered = replay.into_lock_state();
    assert_eq!(recovered.position(), position);
    assert_eq!(recovered.phase(), FixedValidatorLockPhaseV0::Precommit);
    assert!(recovered.locked_value().is_some());
    assert!(recovered.valid_value().is_some());

    let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
    recovered.advance_round(&round_one).unwrap();
    let pending_effect = recovered.decide_prevote_without_proposal().unwrap();
    let pending_intent = recovered
        .prepare_vote_intent(&round_one, pending_effect, fixture.signer())
        .unwrap();
    let pending = prepared(journal.prepare_vote(pending_intent).unwrap());
    assert!(matches!(
        journal.latest_completed_state_and_vote_intent_bytes(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingRecoveryDenied { .. })
    ));
    let pending_state = pending.state_id();
    drop(journal);
    let reopened = fixture.open(&directory, pending_state).unwrap();
    assert!(matches!(
        reopened.latest_completed_state_and_vote_intent_bytes(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingRecoveryDenied { .. })
    ));

    let halt_directory = TestDirectory::new("typed-recovery-halt");
    let mut halted = fixture.create(&halt_directory);
    let nil = fixture.nil_prevote_intent();
    let conflict = fixture.proposal_prevote_intent();
    let prepared = prepared(halted.prepare_vote(nil).unwrap());
    let _ = halted.sign_prepared_vote(prepared).unwrap();
    assert!(matches!(
        halted.prepare_vote(conflict).unwrap(),
        FixedValidatorVotePrepareOutcomeV0::Halted(_)
    ));
    assert!(matches!(
        halted.latest_completed_state_and_vote_intent_bytes(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalHalt { .. })
    ));
}
