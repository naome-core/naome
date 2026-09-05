use super::*;

#[test]
fn fresh_driver_lineage_rejects_a_previous_driver_ticket_after_restart() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-ticket-restart");
    let branch = fixed_branch(&fixture);
    let (_, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let old_timeout = ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 4, 2));
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit_due(driver, timeout);
            assert_eq!(driver.inbox_len(), 1);
            assert!(driver.timeout_is_due());
            assert!(!driver.has_pending_command());
            drop(driver);
            timeout
        })
        .unwrap();
    let before_vote = layout.images();

    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    let superseded_timeout = ready
        .run_with_signing_session(|scope| {
            let (driver, new_timeout) = step_arm(driver(scope, 4, 2));
            assert_eq!(driver.inbox_len(), 0);
            assert!(!driver.timeout_is_due());
            assert_eq!(old_timeout.context(), new_timeout.context());
            assert_eq!(old_timeout.position(), new_timeout.position());
            assert_eq!(old_timeout.phase(), new_timeout.phase());
            assert_eq!(old_timeout.generation(), new_timeout.generation());
            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(old_timeout))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver, rejection, ..
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                    ));
                    *driver
                }
                _ => panic!("old driver lineage must not authorize a fresh driver"),
            };
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, disposition) = admit_due(driver, new_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
            );
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.inbox_len(), 1);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());
            assert_ne!(layout.images(), before_vote);
            drop(driver);
            new_timeout
        })
        .unwrap();

    let durable_vote = layout.images();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 4, 2);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.inbox_len(), 0);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());

            let (driver, fresh_timeout) = step_arm(driver);
            assert_eq!(fresh_timeout.generation(), 0);
            assert_eq!(fresh_timeout.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(layout.images(), durable_vote);
            let driver = match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(
                    superseded_timeout,
                ))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::TimeoutDue(returned)
                            if returned == superseded_timeout
                    ));
                    *driver
                }
                _ => panic!("restart must not reconstruct the dropped publication or timer"),
            };
            let (_, disposition) = admit_due(driver, fresh_timeout);
            assert_eq!(
                disposition,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue
            );
        })
        .unwrap();
}

#[test]
fn evidence_pending_publication_is_not_reconstructed_after_strict_restart() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-evidence-pending-restart");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 2, ZfcAxiom::Pairing);
    let position = round_at(&branch, 2).position();
    let root = value.proposal_signing_root();
    let prevote = signed_vote_bytes(
        fixture.context,
        position,
        ConsensusVoteRole::Prevote,
        ConsensusVoteTarget::Proposal(root),
        &fixture.signing_key(),
    );
    let expected_certificate = round_at(&branch, 2)
        .build_quorum_certificate_from_signed_votes(
            &[prevote.as_slice()],
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Proposal(root),
        )
        .unwrap()
        .to_canonical_bytes();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    let dropped_timeout = ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, timeout);
            let (driver, _) = admit(driver, proposal_event(2, &control, &payload));
            let (driver, _) = admit(driver, prevote_event(&prevote));
            let driver = step_transition(driver);

            assert_eq!(driver.position(), position);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(driver.inbox_len(), 1);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());
            assert_ne!(layout.images(), before);
            drop(driver);
            timeout
        })
        .unwrap();

    let durable = layout.images();
    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|mut scope| {
            let signing = scope.signing_session();
            assert_eq!(signing.position(), position);
            assert_eq!(signing.phase(), FixedValidatorLockPhaseV0::Precommit);
            let locked = signing
                .locked_value()
                .expect("higher-round precommit must recover its exact lock");
            assert_eq!(locked.round(), ConsensusRound::new(2));
            assert_eq!(locked.proposal_signing_root(), root);
            let valid = signing
                .valid_value()
                .expect("higher-round precommit must recover its valid evidence");
            assert_eq!(valid.round(), ConsensusRound::new(2));
            assert_eq!(valid.value().proposal_signing_root(), root);
            assert_eq!(
                valid.canonical_prevote_certificate(),
                expected_certificate.as_slice()
            );

            let driver = driver(scope, 8, 4);
            assert_eq!(driver.inbox_len(), 0);
            assert!(!driver.timeout_is_due());
            assert!(driver.has_pending_command());
            let (driver, fresh_timeout) = step_arm(driver);
            assert_eq!(fresh_timeout.position(), position);
            assert_eq!(fresh_timeout.phase(), FixedValidatorLockPhaseV0::Precommit);
            assert_eq!(fresh_timeout.generation(), 0);
            assert_eq!(layout.images(), durable);

            match driver
                .admit_event(FixedValidatorNodeDriverEventV0::TimeoutDue(dropped_timeout))
                .unwrap()
            {
                FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
                    driver,
                    event,
                    rejection,
                } => {
                    assert!(matches!(
                        *rejection,
                        FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch
                    ));
                    assert!(matches!(
                        *event,
                        FixedValidatorNodeDriverEventV0::TimeoutDue(returned)
                            if returned == dropped_timeout
                    ));
                    assert_eq!(driver.inbox_len(), 0);
                    assert!(!driver.timeout_is_due());
                }
                _ => panic!("strict restart must not reconstruct the dropped publication"),
            }
        })
        .unwrap();
}

#[test]
fn fatal_vote_anchor_failure_returns_no_driver_command_and_reopens_strictly() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-vote-anchor-failure");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let collision = next_anchor_collision(&layout.vote_anchor, 3);

    let error = ready
        .run_with_signing_session(|scope| {
            let (driver, timeout) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit_due(driver, timeout);
            match driver.step() {
                Err(error) => error,
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Command { .. }) => {
                    panic!("fatal anchored-vote failure must emit no command")
                }
                Ok(_) => panic!("fatal anchored-vote failure must return no live driver"),
            }
        })
        .unwrap();
    assert!(matches!(
        error,
        FixedValidatorNodeDriverStepErrorV0::Vote(source)
            if matches!(
                source.as_ref(),
                FixedValidatorNodeVoteExecutionErrorV0::Prepare(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::Commit { .. }
                    )
            )
    ));

    fs::remove_file(collision).unwrap();
    assert!(matches!(
        fixture.provision(&layout, 8).open(fixture.signing_key()),
        Err(FixedValidatorNodeStartupErrorV0::VotePair(source))
            if matches!(
                source.as_ref(),
                FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                    if matches!(
                        inner.as_ref(),
                        FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. }
                    )
            )
    ));
}

#[test]
fn current_evidence_is_volatile_and_can_be_readmitted_after_strict_restart() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-current-restart-readmission");
    let branch = fixed_branch(&fixture);
    let (value, control, payload) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let root = value.proposal_signing_root();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();

    let canonical_prevote = ready
        .run_with_signing_session(|scope| {
            let (driver, _) = step_arm(driver(scope, 8, 4));
            let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
            let driver = step_transition(driver);
            let (driver, prevote, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(prevote.target(), ConsensusVoteTarget::Proposal(root));
            let canonical_prevote = prevote.canonical_bytes().to_vec();
            let (driver, _) = step_arm(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(driver.current_inbox_len(), 1);
            drop(driver);
            canonical_prevote
        })
        .unwrap();

    let ready = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    ready
        .run_with_signing_session(|mut scope| {
            assert_eq!(
                scope.signing_session().position(),
                round_at(&branch, 0).position()
            );
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
            let driver = driver(scope, 8, 4);
            assert_eq!(driver.current_inbox_len(), 0);
            let (driver, _) = step_arm(driver);
            let (driver, _) = admit(driver, current_proposal_event(&control, &payload));
            let (driver, _) = admit(driver, current_prevote_event(&canonical_prevote));
            let driver = step_transition(driver);
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
            let (driver, precommit, released_proposal) = step_publish(driver);
            assert!(released_proposal.is_none());
            assert_eq!(precommit.role(), ConsensusVoteRole::Precommit);
            assert_eq!(precommit.target(), ConsensusVoteTarget::Proposal(root));
            assert_eq!(driver.current_inbox_len(), 2);
        })
        .unwrap();
}
