use super::*;

#[test]
fn new_finality_advances_both_anchors_before_returning_the_next_signer() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-success");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|scope| {
            let original_branch = scope.branch().clone();
            let before_first = layout.images();
            let first = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let first_block = first.value().artifact_block();
            let first_payload = first.canonical_artifact_bytes().to_vec();
            let (scope, selection) =
                expect_continuation(scope.commit_verified_finality(first).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 1
            ));
            assert_eq!(scope.signing_session.position().height().value(), 2);
            assert_eq!(scope.signing_session.position().round().value(), 0);
            assert_eq!(
                scope.finality.head().unwrap().coordinate(),
                scope.branch.coordinate()
            );
            let after_first = layout.images();
            for (index, (before, after)) in before_first.iter().zip(&after_first).enumerate() {
                assert_ne!(before, after, "durable image {index} did not advance");
            }

            selected.apply_block(&first_block, first_payload).unwrap();
            let second = fixture.transition(scope.branch(), &selected, ZfcAxiom::Union, 1);
            let (mut scope, selection) =
                expect_continuation(scope.commit_verified_finality(second).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 2 && position.round().value() == 1
            ));
            assert_eq!(scope.signing_session().position().height().value(), 3);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.finality().head().unwrap().coordinate(),
                scope.branch().coordinate()
            );
            let after_second = layout.images();
            for (index, (before, after)) in after_first.iter().zip(&after_second).enumerate() {
                assert_ne!(before, after, "durable image {index} did not advance");
            }

            let stale_round = original_branch.begin_round_zero().unwrap();
            let current_branch = scope.branch().clone();
            let current_round = current_branch.begin_round_zero().unwrap();
            let session = scope.signing_session_mut();
            let stale_effect = session.decide_prevote_without_proposal().unwrap();
            assert!(session.prepare_vote(&stale_round, stale_effect).is_err());
            let current_effect = session.decide_precommit_without_quorum().unwrap();
            let prepared = match session
                .prepare_vote(&current_round, current_effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the child-height precommit must prepare exactly once"),
            };
            prepare_and_sign(session, &current_round, prepared);
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();
    assert_eq!(signer_position.height().value(), 3);

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
        })
        .unwrap();
}

#[test]
fn one_child_continuation_strictly_reopens_without_signer_catch_up() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("live-finality-one-child-reopen");
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|scope| {
            let selected = ArtifactChainState::new(fixture.definition);
            let transition = fixture.transition(scope.branch(), &selected, ZfcAxiom::Pairing, 0);
            let (mut scope, selection) =
                expect_continuation(scope.commit_verified_finality(transition).unwrap());
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized { position, .. }
                    if position.height().value() == 1
            ));
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(old, new, "durable image {index} did not advance");
            }
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
        })
        .unwrap();
}

#[test]
fn current_round_finality_at_nonzero_round_advances_all_four_files_and_strictly_reopens() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-success");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();
    let selected = ArtifactChainState::new(fixture.definition);
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            assert_eq!(layout.images(), before);

            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                1,
                &proposer,
                &[&proposer],
            );
            let expected_envelope_id = round_one
                .decode_and_verify_proposal_control(&control, payload.clone())
                .unwrap()
                .seal_with_precommit_certificate(&certificate)
                .unwrap()
                .envelope_id();
            let precommit = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &proposer,
            );
            let precommits = [precommit.as_slice()];
            let (mut scope, selection) = expect_current_round_finality(
                scope
                    .commit_current_round_finality_vote_batch(
                        &control,
                        payload,
                        &precommits,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual_position,
                    ancestry_id,
                    envelope_id,
                    ..
                } if actual_position == position
                    && ancestry_id == value.ancestry_id()
                    && envelope_id == expected_envelope_id
            ));
            assert_eq!(scope.signing_session().position().height().value(), 2);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.finality().head().unwrap().coordinate(),
                scope.branch().coordinate()
            );
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(old, new, "durable image {index} did not advance");
            }
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
        })
        .unwrap();
}

#[test]
fn current_round_finality_from_healthy_prevote_phase_returns_child_continuation() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-prevote");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let (selected_coordinate, signer_position) = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let effect = scope
                .signing_session_mut()
                .decide_prevote_without_proposal()
                .unwrap();
            let prepared = match scope
                .signing_session_mut()
                .prepare_vote(&round, effect)
                .unwrap()
            {
                FixedValidatorVotePrepareOutcomeV0::Prepared(prepared) => prepared,
                _ => panic!("the first prevote must prepare"),
            };
            prepare_and_sign(scope.signing_session_mut(), &round, prepared);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );

            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                0,
                &proposer,
                &[&proposer],
            );
            let (mut scope, selection) = expect_current_round_finality(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload,
                        &certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual_position,
                    ancestry_id,
                    ..
                } if actual_position == position && ancestry_id == value.ancestry_id()
            ));
            assert_eq!(scope.signing_session().position().height().value(), 2);
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
            (
                scope.branch().coordinate(),
                scope.signing_session().position(),
            )
        })
        .unwrap();

    let reopened = expect_ready(
        fixture
            .provision_with_catch_up_limit(&layout, 8, 0)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.branch().coordinate(), selected_coordinate);
            assert_eq!(scope.signing_session().position(), signer_position);
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
        })
        .unwrap();
}

#[test]
fn current_round_finality_input_rejections_preserve_all_files_and_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-rejections");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();

    ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
            let (control, payload, certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                1,
                &proposer,
                &[&proposer],
            );
            let root = value.proposal_signing_root();
            let expected_diagnostics = signing_scope_diagnostics(&mut scope);

            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &[0_u8],
                        payload.clone(),
                        &certificate,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::InvalidLength { .. }
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let mismatching_payload = proof_payload(ZfcAxiom::Union);
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        mismatching_payload,
                        &certificate,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::Proposal(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusProposalVerifyError::ArtifactValidation(_)
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &[0_u8],
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::InvalidLength { .. }
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let prevote = quorum_certificate_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(root),
                &[&proposer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &prevote,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::WrongVoteRole {
                                actual: ConsensusVoteRole::Prevote,
                            }
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let nil_precommit = quorum_certificate_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &[&proposer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &nil_precommit,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::NilCertificateTarget
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let wrong_root = ProposalSigningRoot::from_bytes([0x5a; 32]);
            assert_ne!(wrong_root, root);
            let wrong_root_precommit = quorum_certificate_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(wrong_root),
                &[&proposer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &wrong_root_precommit,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificateRootMismatch {
                            expected,
                            actual,
                        } if *expected == root && *actual == wrong_root
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let other_position = ConsensusPosition::new(position.height(), ConsensusRound::new(2));
            let other_round_precommit = quorum_certificate_bytes(
                fixture.context,
                other_position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(root),
                &[&proposer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &other_round_precommit,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::SnapshotPositionMismatch {
                                certificate,
                                snapshot,
                            }
                        ) if *certificate == other_position && *snapshot == position
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let wrong_context = ConsensusContextV0::new(
                fixture.context.chain_id(),
                ConsensusGenesisId::from_bytes([0x93; 32]),
                fixture.context.protocol_version(),
            );
            let wrong_context_precommit = quorum_certificate_bytes(
                wrong_context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(root),
                &[&proposer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &wrong_context_precommit,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::GenesisIdMismatch {
                                expected,
                                actual,
                            }
                        ) if *expected == fixture.context.genesis_id()
                            && *actual == wrong_context.genesis_id()
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let foreign_signer = SigningKey::from_bytes(&signing_seed(93));
            let foreign_set_precommit = quorum_certificate_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(root),
                &[&foreign_signer],
            );
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &foreign_set_precommit,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::UnknownSigner { signer }
                        ) if *signer == consensus_key(&foreign_signer)
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let mut invalid_signature = certificate.clone();
            *invalid_signature
                .last_mut()
                .expect("one-signer certificate has a signature") ^= 0x80;
            let (next, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload.clone(),
                        &invalid_signature,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(source)
                    if matches!(
                        source.as_ref(),
                        ConsensusEnvelopeVerifyError::PrecommitCertificate(
                            PrecommitCertificateVerifyError::InvalidSignature { signer }
                        ) if *signer == consensus_key(&proposer)
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (_scope, selection) = expect_current_round_finality(
                scope
                    .commit_current_round_finality(
                        &control,
                        payload,
                        &certificate,
                        ConsensusRound::new(1),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual,
                    ..
                } if actual == position
            ));
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(old, new, "retry did not advance durable image {index}");
            }
        })
        .unwrap();
}

#[test]
fn insufficient_current_round_precommits_preserve_scope_before_a_quorum_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-insufficient");
    let local_seed = signing_seed(41);
    let local = SigningKey::from_bytes(&local_seed);
    let other = SigningKey::from_bytes(&signing_seed(42));
    let entries = [
        ActiveAgreementEntry::new(consensus_key(&local), AgreementWeight::new(1)),
        ActiveAgreementEntry::new(consensus_key(&other), AgreementWeight::new(2)),
    ];
    let ready = FixedValidatorNodeProvisionV0::new(
        fixture.definition,
        fixture.context,
        &entries,
        layout.directories(),
        FixedValidatorFinalityReplayLimitV0::new(8).unwrap(),
        FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
        FixedValidatorProposalReplayLimitV0::new(32).unwrap(),
        FixedValidatorSignerRecoveryRoundLimitV0::new(8),
        FixedValidatorSignerCatchUpHeightLimitV0::new(8),
    )
    .create(SigningKey::from_bytes(&local_seed))
    .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();

    ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round = branch.begin_round_zero().unwrap();
            let proposer = if round.proposer() == consensus_key(&local) {
                &local
            } else {
                assert_eq!(round.proposer(), consensus_key(&other));
                &other
            };
            let (control, payload, _certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                0,
                proposer,
                &[&local],
            );
            let insufficient = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &local,
            );
            let insufficient_batch = [insufficient.as_slice()];
            let expected_diagnostics = signing_scope_diagnostics(&mut scope);
            let (mut scope, rejection) = expect_current_round_finality_rejection(
                scope
                    .commit_current_round_finality_vote_batch(
                        &control,
                        payload.clone(),
                        &insufficient_batch,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitBatch(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                            QuorumCertificateBuildError::InsufficientAgreementWeight {
                                signed,
                                total,
                            }
                        ) if *signed == AgreementWeight::new(1)
                            && *total == AgreementWeight::new(3)
                    )
            ));
            assert_eq!(layout.images(), before);
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let local_vote = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &local,
            );
            let other_vote = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &other,
            );
            let sufficient = [other_vote.as_slice(), local_vote.as_slice()];
            let (_scope, selection) = expect_current_round_finality(
                scope
                    .commit_current_round_finality_vote_batch(
                        &control,
                        payload,
                        &sufficient,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual,
                    ..
                } if actual == position
            ));
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(
                    old, new,
                    "quorum retry did not advance durable image {index}"
                );
            }
        })
        .unwrap();
}

#[test]
fn persisted_finality_round_ceiling_is_fatal_before_input_parsing() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-finality-persisted-ceiling");
    let ready = provision_with_finality_round_limit(&fixture, &layout, 1, 8)
        .create(fixture.signing_key())
        .unwrap();
    let before = layout.images();

    ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let round_one = round_at(&branch, 1);
            let round_two = round_at(&branch, 2);
            advance_signer_round_without_writing(&mut scope, &round_one);
            advance_signer_round_without_writing(&mut scope, &round_two);
            assert!(matches!(
                scope.commit_current_round_finality(
                    &[0_u8],
                    Vec::new(),
                    &[0_u8],
                    ConsensusRound::new(0),
                ),
                Err(
                    FixedValidatorNodeCurrentRoundFinalityErrorV0::FinalityRoundLimitExceeded {
                        required,
                        maximum,
                    }
                ) if required == ConsensusRound::new(2)
                    && maximum == ConsensusRound::new(1)
            ));
            assert_eq!(layout.images(), before);
        })
        .unwrap();

    let reopened = expect_ready(
        provision_with_finality_round_limit(&fixture, &layout, 1, 8)
            .open(fixture.signing_key())
            .unwrap(),
    );
    reopened
        .run_with_signing_session(|mut scope| {
            assert_eq!(scope.signing_session().position().round().value(), 0);
            assert_eq!(layout.images(), before);
        })
        .unwrap();
}
