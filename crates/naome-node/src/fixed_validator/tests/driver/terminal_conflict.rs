use super::*;

#[test]
fn pending_commands_precede_candidate_backed_terminal_conflict_processing() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-candidate-conflict-command-pending");
    let branch = fixed_branch(&fixture);
    let (value, control, _) = proposal_inputs(&fixture, &branch, 0, ZfcAxiom::Pairing);
    let target = value.artifact_block().id();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);

    ready
        .run_with_signing_session(|scope| {
            let driver = driver(scope, 8, 0);
            let authority_before_arm_gate = layout.images();
            let sources_before_arm_gate = layout.source_images();
            let driver = match driver
                .commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[],
                    ConsensusRound::new(1),
                )
                .unwrap()
            {
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::CommandPending {
                    driver,
                } => *driver,
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::FinalityStopped(
                    _,
                ) => panic!("a pending arm must prevent terminal conflict processing"),
            };
            assert_eq!(layout.images(), authority_before_arm_gate);
            assert_eq!(layout.source_images(), sources_before_arm_gate);
            assert!(driver.has_pending_command());

            let (driver, proposal_timeout) = step_arm(driver);
            assert_eq!(proposal_timeout.position(), driver.position());
            assert_eq!(
                proposal_timeout.phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            let (driver, _) = admit_due(driver, proposal_timeout);
            let driver = step_transition(driver);
            assert!(driver.has_pending_command());
            assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);

            let authority_before_publish_gate = layout.images();
            let sources_before_publish_gate = layout.source_images();
            let driver = match driver
                .commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[],
                    ConsensusRound::new(1),
                )
                .unwrap()
            {
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::CommandPending {
                    driver,
                } => *driver,
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::FinalityStopped(
                    _,
                ) => panic!("a pending publication must prevent terminal conflict processing"),
            };
            assert_eq!(layout.images(), authority_before_publish_gate);
            assert_eq!(layout.source_images(), sources_before_publish_gate);
            assert!(driver.has_pending_command());

            let (driver, vote, released_proposal) = step_publish(driver);
            assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
            assert_eq!(vote.target(), ConsensusVoteTarget::Nil);
            assert!(released_proposal.is_none());
            drop(driver);
        })
        .unwrap();
}

#[test]
fn candidate_backed_terminal_conflict_uses_the_driver_round_ceiling() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-candidate-conflict-round-ceiling");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let expected_position = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let (transition, control, precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                scope.branch(),
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::Pairing,
                0,
            );
            let target = transition.value().artifact_block().id();
            let (scope, _) =
                expect_continuation(scope.commit_verified_finality(transition).unwrap());
            let driver = driver(scope, 8, 1);
            let (driver, _) = step_arm(driver);
            let expected_position = driver.position();
            let authority_before = layout.images();
            let sources_before = layout.source_images();
            assert!(matches!(
                driver.commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[precommit.as_slice()],
                    ConsensusRound::new(2),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::EvidenceRoundWorkLimitExceeded {
                            required,
                            maximum,
                        } if *required == ConsensusRound::new(2)
                            && *maximum == ConsensusRound::new(1)
                    )
            ));
            assert_eq!(layout.images(), authority_before);
            assert_eq!(layout.source_images(), sources_before);
            expected_position
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    let reopened = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position(), expected_position);
        })
        .unwrap();
}

#[test]
fn selected_value_conflict_attempt_consumes_driver_without_source_or_authority_writes() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-candidate-conflict-selected-value");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let expected_position = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let (transition, control, precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                scope.branch(),
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::Pairing,
                0,
            );
            let target = transition.value().artifact_block().id();
            let (scope, _) =
                expect_continuation(scope.commit_verified_finality(transition).unwrap());
            let driver = driver(scope, 8, 0);
            let (driver, _) = step_arm(driver);
            let expected_position = driver.position();
            let authority_before = layout.images();
            let sources_before = layout.source_images();

            assert!(matches!(
                driver.commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[precommit.as_slice()],
                    ConsensusRound::new(0),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::SelectedValueNotDistinct { height }
                            if height.value() == 1
                    )
            ));
            assert_eq!(layout.images(), authority_before);
            assert_eq!(layout.source_images(), sources_before);
            expected_position
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    let reopened = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position(), expected_position);
        })
        .unwrap();
}

#[test]
fn candidate_backed_historical_conflict_stops_driver_and_strictly_reopens() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-candidate-conflict-terminal");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let (stopped, authority_after) = ready
        .run_with_signing_session(|scope| {
            let genesis = scope.branch().clone();
            let mut selected = ArtifactChainState::new(fixture.definition);
            let first = fixture.transition(&genesis, &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let selected_ancestry = first.value().ancestry_id();
            let (sibling, control, precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                &genesis,
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::Union,
                2,
            );
            let target = sibling.value().artifact_block().id();
            let sibling_ancestry = sibling.value().ancestry_id();
            let sibling_envelope_id = sibling.envelope_id();

            let (scope, _) = expect_continuation(scope.commit_verified_finality(first).unwrap());
            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::PowerSet, 0);
            let (scope, _) = expect_continuation(scope.commit_verified_finality(second).unwrap());
            let driver = driver(scope, 8, 2);
            let (driver, timeout) = step_arm(driver);
            let (driver, _) = admit_due(driver, timeout);
            assert!(driver.timeout_is_due());

            let authority_before = layout.images();
            let sources_before = layout.source_images();
            let stopped = match driver
                .commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[precommit.as_slice()],
                    ConsensusRound::new(2),
                )
                .unwrap()
            {
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::FinalityStopped(
                    stopped,
                ) => *stopped,
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::CommandPending {
                    ..
                } => panic!("the transferred arm must not block terminal conflict processing"),
            };
            let authority_after = layout.images();
            for (index, (before, after)) in
                authority_before.iter().zip(&authority_after).enumerate()
            {
                assert_ne!(before, after, "authority image {index} did not advance");
            }
            assert_eq!(layout.source_images(), sources_before);
            assert_eq!(
                stopped.finality_halt().kind(),
                naome_storage::FixedValidatorFinalityHaltKindV0::SelectedSibling
            );
            assert_eq!(stopped.finality_halt().height().value(), 1);
            assert_eq!(stopped.finality_halt().first_ancestry(), selected_ancestry);
            assert_eq!(stopped.finality_halt().second_ancestry(), sibling_ancestry);
            assert_eq!(
                stopped.finality_halt().second_envelope_id(),
                sibling_envelope_id
            );
            assert_eq!(
                stopped.signer_stop().finality_state_id(),
                stopped.finality_halt().state_id()
            );
            (stopped, authority_after)
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    match fixture
        .provision(&layout, 8)
        .open(fixture.signing_key())
        .unwrap()
    {
        FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
            assert_eq!(reopened, stopped);
        }
        _ => panic!("strict restart must recover the driver-routed terminal conflict"),
    }
    assert_eq!(layout.images(), authority_after);
}

#[test]
fn candidate_corruption_consumes_terminal_driver_and_poisons_only_its_source() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("driver-candidate-conflict-corrupt-source");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut candidates = create_candidate_store(&layout, fixture.definition);
    let mut payloads = create_payload_store(&layout);
    let expected_position = ready
        .run_with_signing_session(|scope| {
            let genesis = scope.branch().clone();
            let mut selected = ArtifactChainState::new(fixture.definition);
            let first = fixture.transition(&genesis, &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let (sibling, control, precommit) = candidate_backed_batch_finality_inputs(
                &fixture,
                &genesis,
                &selected,
                &mut candidates,
                &mut payloads,
                ZfcAxiom::Union,
                2,
            );
            let target = sibling.value().artifact_block().id();
            let artifact_id = sibling.value().artifact_block().artifact_id();

            let (scope, _) = expect_continuation(scope.commit_verified_finality(first).unwrap());
            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::PowerSet, 0);
            let (scope, _) = expect_continuation(scope.commit_verified_finality(second).unwrap());
            let driver = driver(scope, 8, 2);
            let (driver, _) = step_arm(driver);
            let expected_position = driver.position();
            flip_last_store_byte(&layout.candidate_store);
            let authority_before = layout.images();
            let sources_before = layout.source_images();

            assert!(matches!(
                driver.commit_candidate_backed_finality_conflict_vote_batch(
                    &mut candidates,
                    &mut payloads,
                    target,
                    &control,
                    &[precommit.as_slice()],
                    ConsensusRound::new(2),
                ),
                Err(FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(source))
                    if matches!(
                        source.as_ref(),
                        CandidateBackedFinalityErrorV0::CandidateStore(
                            ArtifactBlockCandidateStoreError::StoredEntryChanged { block_id }
                        ) if *block_id == target
                    )
            ));
            assert_eq!(layout.images(), authority_before);
            assert_eq!(layout.source_images(), sources_before);
            assert!(matches!(
                candidates.contains(target),
                Err(ArtifactBlockCandidateStoreError::Poisoned)
            ));
            assert!(payloads.contains(artifact_id).unwrap());
            expected_position
        })
        .unwrap();

    drop(candidates);
    drop(payloads);
    let reopened = expect_ready(
        fixture
            .provision(&layout, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position(), expected_position);
        })
        .unwrap();
}
