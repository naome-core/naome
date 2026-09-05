use super::*;

#[test]
fn session_and_recovery_issuance_require_proposal_authoring_activation() {
    let fixture = Fixture::new(2);
    let directory = TestDirectory::new("session-requires-proposal-activation");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create(&directory);
    let bound = journal.bind_signing_lineage(&round).unwrap();
    let (_, journal_path) = keyed_paths(&directory.0, fixture.signer()).unwrap();
    let unactivated_image = fs::read(&journal_path).unwrap();

    assert!(matches!(
        journal.issue_signing_session(&round, bound),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ProposalAuthoringNotActivated)
    ));
    assert!(matches!(
        journal.acknowledge_signer_recovery_is_externally_durable(bound),
        Err(FixedValidatorVoteSafetyJournalErrorV0::ProposalAuthoringNotActivated)
    ));
    assert_eq!(fs::read(&journal_path).unwrap(), unactivated_image);

    let activated = activate_proposal_authoring(&mut journal);
    let recovery = journal
        .acknowledge_signer_recovery_is_externally_durable(activated)
        .unwrap();
    drop(recovery);
    let session = journal.issue_signing_session(&round, activated).unwrap();
    assert_eq!(session.position(), round.position());
}

#[cfg(unix)]
#[test]
fn anchored_proposal_authoring_activates_signs_replays_and_recovers_exactly() {
    let fixture = Fixture::new(4);
    let journal_directory = TestDirectory::new("anchored-proposal-journal");
    let anchor_directory = TestDirectory::new("anchored-proposal-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let proposal_limit = FixedValidatorProposalReplayLimitV0::new(2).unwrap();
    let activation = journal.activate_proposal_authoring(proposal_limit).unwrap();
    let activated_images = (
        fs::read(
            keyed_paths(&journal_directory.0, fixture.signer())
                .unwrap()
                .1,
        )
        .unwrap(),
        fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
    );
    assert_eq!(journal.proposal_replay_limit(), Some(proposal_limit));
    assert_eq!(
        journal.activate_proposal_authoring(proposal_limit).unwrap(),
        activation
    );
    assert_eq!(
        activated_images,
        (
            fs::read(
                keyed_paths(&journal_directory.0, fixture.signer())
                    .unwrap()
                    .1
            )
            .unwrap(),
            fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
        )
    );
    assert!(matches!(
        journal.activate_proposal_authoring(FixedValidatorProposalReplayLimitV0::new(3).unwrap()),
        Err(
            FixedValidatorVoteSafetyJournalErrorV0::ProposalReplayLimitMismatch {
                retained: 2,
                supplied: 3,
            }
        )
    ));

    let _ = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round).unwrap();
    let (artifact_block, payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let prepared = prepared_proposal(
        session
            .prepare_proposal(
                &round,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block,
                    canonical_artifact_bytes: payload.clone(),
                },
            )
            .unwrap(),
    );
    let acknowledgement = session.acknowledge_prepared_proposal(prepared).unwrap();
    let signed = session.sign_prepared_proposal(acknowledgement).unwrap();
    let verified = round
        .decode_and_verify_proposal_control(
            signed.canonical_proposal_control_bytes(),
            payload.clone(),
        )
        .unwrap();
    assert_eq!(
        verified.proposal_signing_root(),
        signed.proposal_signing_root()
    );
    let completed_images = (
        fs::read(
            keyed_paths(&journal_directory.0, fixture.signer())
                .unwrap()
                .1,
        )
        .unwrap(),
        fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
    );
    assert!(matches!(
        session
            .prepare_proposal(
                &round,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block,
                    canonical_artifact_bytes: payload,
                },
            )
            .unwrap(),
        FixedValidatorProposalPrepareOutcomeV0::AlreadySigned(ref replay)
            if replay == &signed
    ));
    assert_eq!(
        completed_images,
        (
            fs::read(
                keyed_paths(&journal_directory.0, fixture.signer())
                    .unwrap()
                    .1
            )
            .unwrap(),
            fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
        )
    );
    drop(session);
    drop(journal);

    let mut reopened = fixture
        .open_anchored(&journal_directory, &anchor_directory)
        .unwrap();
    assert_eq!(reopened.proposal_replay_limit(), Some(proposal_limit));
    assert_eq!(
        reopened.retained_signed_proposal(round.position()).unwrap(),
        Some(signed)
    );
    let resumed = reopened.issue_signing_session(&round).unwrap();
    assert_eq!(resumed.position(), round.position());
    assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Proposal);
}

#[cfg(unix)]
#[test]
fn anchored_pending_proposal_is_diagnostic_only_after_restart() {
    let fixture = Fixture::new(4);
    let journal_directory = TestDirectory::new("pending-proposal-journal");
    let anchor_directory = TestDirectory::new("pending-proposal-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let _ = journal
        .activate_proposal_authoring(FixedValidatorProposalReplayLimitV0::new(2).unwrap())
        .unwrap();
    let _ = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round).unwrap();
    let (artifact_block, payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let prepared = prepared_proposal(
        session
            .prepare_proposal(
                &round,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block,
                    canonical_artifact_bytes: payload,
                },
            )
            .unwrap(),
    );
    drop(session);
    drop(journal);

    let mut reopened = fixture
        .open_anchored(&journal_directory, &anchor_directory)
        .unwrap();
    let pending = reopened.pending_proposal().unwrap().unwrap();
    assert_eq!(pending.position(), prepared.position());
    assert_eq!(pending.state_id(), prepared.state_id());
    assert!(matches!(
        reopened.issue_signing_session(&round),
        Err(FixedValidatorVoteSafetyJournalErrorV0::PendingProposalRecoveryDenied {
            position,
        }) if position == round.position()
    ));
}

#[cfg(unix)]
#[test]
fn conflicting_same_slot_proposal_intent_terminally_stops_only_the_signer() {
    let fixture = Fixture::new(4);
    let journal_directory = TestDirectory::new("proposal-conflict-journal");
    let anchor_directory = TestDirectory::new("proposal-conflict-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let _ = journal
        .activate_proposal_authoring(FixedValidatorProposalReplayLimitV0::new(1).unwrap())
        .unwrap();
    let _ = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round).unwrap();
    let (first_block, first_payload) = fixture.proposal_candidate_for(ZfcAxiom::Pairing);
    let first = prepared_proposal(
        session
            .prepare_proposal(
                &round,
                FixedValidatorProposalSourceV0::Fresh {
                    artifact_block: first_block,
                    canonical_artifact_bytes: first_payload,
                },
            )
            .unwrap(),
    );
    let acknowledgement = session.acknowledge_prepared_proposal(first).unwrap();
    let _ = session.sign_prepared_proposal(acknowledgement).unwrap();

    let (second_block, second_payload) = fixture.proposal_candidate_for(ZfcAxiom::Union);
    let halt = match session
        .prepare_proposal(
            &round,
            FixedValidatorProposalSourceV0::Fresh {
                artifact_block: second_block,
                canonical_artifact_bytes: second_payload,
            },
        )
        .unwrap()
    {
        FixedValidatorProposalPrepareOutcomeV0::Halted(halt) => halt,
        other => panic!("expected proposal halt, got {other:?}"),
    };
    assert_eq!(halt.position(), round.position());
    assert_ne!(halt.retained_root(), halt.conflicting_root());
    assert!(matches!(
        session.decide_prevote_without_proposal(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::TerminalProposalHalt {
            position,
        }) if position == round.position()
    ));
}
