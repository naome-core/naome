use super::*;

#[test]
fn nonzero_lower_round_finality_ignores_later_local_phase_and_strictly_reopens() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-success");
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
            let round_two = round_at(&branch, 2);
            advance_signer_round_without_writing(&mut scope, &round_two);
            let _ = scope
                .signing_session_mut()
                .decide_prevote_without_proposal()
                .unwrap();
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Prevote
            );
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
            let (mut scope, selection) = expect_lower_round_finality(
                scope
                    .commit_lower_round_finality_vote_batch(
                        &control,
                        payload,
                        &precommits,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
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
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
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
            assert_eq!(
                scope.signing_session().phase(),
                FixedValidatorLockPhaseV0::Proposal
            );
        })
        .unwrap();
}

#[test]
fn lower_round_batch_routing_precedes_input_work_and_must_match_proposal_and_every_vote() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-batch-routing");
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
            let round_two = round_at(&branch, 2);
            advance_signer_round_without_writing(&mut scope, &round_one);
            advance_signer_round_without_writing(&mut scope, &round_two);
            let expected_diagnostics = signing_scope_diagnostics(&mut scope);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality_vote_batch(
                        &[0_u8],
                        Vec::new(),
                        &[],
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(2),
                            ConsensusRound::new(0),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                    evidence,
                    signer,
                } if evidence == ConsensusRound::new(2) && signer == ConsensusRound::new(2)
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality_vote_batch(
                        &[0_u8],
                        Vec::new(),
                        &[],
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(0),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1)
                    && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (control, payload, _certificate, position, value) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Pairing,
                1,
                &proposer,
                &[&proposer],
            );
            let wrong_position = ConsensusPosition::new(position.height(), ConsensusRound::new(0));
            let routed_precommit = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &proposer,
            );
            let routed_batch = [routed_precommit.as_slice()];
            let wrong_round_control = proposal_control_bytes(value, wrong_position, &proposer);
            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality_vote_batch(
                        &wrong_round_control,
                        payload.clone(),
                        &routed_batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                            ConsensusProposalVerifyError::ProducerAuthorization(
                                ProducerAuthorizationVerifyError::SnapshotPositionMismatch {
                                    authorization,
                                    snapshot,
                                }
                            )
                        ) if *authorization == wrong_position && *snapshot == position
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let wrong_round_vote = signed_vote_bytes(
                fixture.context,
                wrong_position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value.proposal_signing_root()),
                &proposer,
            );
            let wrong_round_batch = [wrong_round_vote.as_slice()];
            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality_vote_batch(
                        &control,
                        payload.clone(),
                        &wrong_round_batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::PrecommitBatch(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                            QuorumCertificateBuildError::PositionMismatch {
                                index: 0,
                                expected,
                                actual,
                            }
                        ) if *expected == position && *actual == wrong_position
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (_scope, selection) = expect_lower_round_finality(
                scope
                    .commit_lower_round_finality_vote_batch(
                        &control,
                        payload,
                        &routed_batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(1),
                            ConsensusRound::new(1),
                        ),
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
        })
        .unwrap();
}

#[test]
fn lower_round_finality_rejections_preserve_scope_files_and_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-rejections");
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
            let round_two = round_at(&branch, 2);
            advance_signer_round_without_writing(&mut scope, &round_two);
            let (control_zero, payload_zero, certificate_zero, position_zero, value_zero) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Pairing,
                    0,
                    &proposer,
                    &[&proposer],
                );
            let (_control_one, payload_one, certificate_one, _, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Union,
                    1,
                    &proposer,
                    &[&proposer],
                );
            let (_, payload_two, certificate_two, _, _) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Infinity,
                2,
                &proposer,
                &[&proposer],
            );
            let (_, payload_three, certificate_three, _, _) = current_round_finality_inputs(
                &branch,
                &selected,
                ZfcAxiom::Extensionality,
                3,
                &proposer,
                &[&proposer],
            );
            let expected_diagnostics = signing_scope_diagnostics(&mut scope);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &[0_u8],
                        payload_one,
                        &certificate_one,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                } if required == ConsensusRound::new(1) && maximum == ConsensusRound::new(0)
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &[0_u8],
                        payload_two,
                        &certificate_two,
                        ConsensusRound::new(8),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                    evidence,
                    signer,
                } if evidence == ConsensusRound::new(2) && signer == ConsensusRound::new(2)
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &[0_u8],
                        payload_three,
                        &certificate_three,
                        ConsensusRound::new(8),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                    evidence,
                    signer,
                } if evidence == ConsensusRound::new(3) && signer == ConsensusRound::new(2)
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let wrong_height = ConsensusPosition::new(
                ConsensusHeight::new(position_zero.height().value() + 1),
                ConsensusRound::new(0),
            );
            let wrong_height_certificate = quorum_certificate_bytes(
                fixture.context,
                wrong_height,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(value_zero.proposal_signing_root()),
                &[&proposer],
            );
            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &[0_u8],
                        payload_zero.clone(),
                        &wrong_height_certificate,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::CertificateHeightMismatch {
                            expected,
                            actual,
                        } if *expected == position_zero.height() && *actual == wrong_height.height()
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        payload_zero.clone(),
                        &[0_u8],
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::EmbeddedCertificatePosition(_)
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &[0_u8],
                        payload_zero.clone(),
                        &certificate_zero,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                            ConsensusProposalVerifyError::InvalidLength { .. }
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        proof_payload(ZfcAxiom::Union),
                        &certificate_zero,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                            ConsensusProposalVerifyError::ArtifactValidation(_)
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let mut invalid_signature = certificate_zero.clone();
            *invalid_signature
                .last_mut()
                .expect("one-signer certificate has a signature") ^= 0x80;
            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        payload_zero.clone(),
                        &invalid_signature,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::PrecommitCertificate(
                            ConsensusEnvelopeVerifyError::PrecommitCertificate(
                                PrecommitCertificateVerifyError::InvalidSignature { signer }
                            )
                        ) if *signer == consensus_key(&proposer)
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let prevote = quorum_certificate_bytes(
                fixture.context,
                position_zero,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(value_zero.proposal_signing_root()),
                &[&proposer],
            );
            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        payload_zero.clone(),
                        &prevote,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::PrecommitCertificate(
                            ConsensusEnvelopeVerifyError::PrecommitCertificate(
                                PrecommitCertificateVerifyError::WrongVoteRole {
                                    actual: ConsensusVoteRole::Prevote,
                                }
                            )
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let nil_precommit = quorum_certificate_bytes(
                fixture.context,
                position_zero,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Nil,
                &[&proposer],
            );
            let (next, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        payload_zero.clone(),
                        &nil_precommit,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(source)
                    if matches!(
                        source.as_ref(),
                        FixedConsensusBoundedSeparateFinalityVerifyError::PrecommitCertificate(
                            ConsensusEnvelopeVerifyError::PrecommitCertificate(
                                PrecommitCertificateVerifyError::NilCertificateTarget
                            )
                        )
                    )
            ));
            assert_eq!(layout.images(), before);
            scope = next;
            assert_eq!(signing_scope_diagnostics(&mut scope), expected_diagnostics);

            let (_scope, selection) = expect_lower_round_finality(
                scope
                    .commit_lower_round_finality(
                        &control_zero,
                        payload_zero,
                        &certificate_zero,
                        ConsensusRound::new(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                selection,
                FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position: actual,
                    ..
                } if actual == position_zero
            ));
            let after = layout.images();
            for (index, (old, new)) in before.iter().zip(&after).enumerate() {
                assert_ne!(old, new, "retry did not advance durable image {index}");
            }
        })
        .unwrap();
}

#[test]
fn insufficient_lower_round_precommits_preserve_scope_before_a_quorum_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-insufficient");
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
            let round_zero = branch.begin_round_zero().unwrap();
            let proposer = if round_zero.proposer() == consensus_key(&local) {
                &local
            } else {
                assert_eq!(round_zero.proposer(), consensus_key(&other));
                &other
            };
            let round_one = round_at(&branch, 1);
            advance_signer_round_without_writing(&mut scope, &round_one);
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
            let (mut scope, rejection) = expect_lower_round_finality_rejection(
                scope
                    .commit_lower_round_finality_vote_batch(
                        &control,
                        payload.clone(),
                        &insufficient_batch,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(0),
                            ConsensusRound::new(0),
                        ),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::PrecommitBatch(source)
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
            let (_scope, selection) = expect_lower_round_finality(
                scope
                    .commit_lower_round_finality_vote_batch(
                        &control,
                        payload,
                        &sufficient,
                        FixedValidatorNodeFinalityRoundRouteV0::new(
                            ConsensusRound::new(0),
                            ConsensusRound::new(0),
                        ),
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
fn lower_round_finality_checks_persisted_signer_ceiling_before_input_parsing() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-finality-persisted-ceiling");
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
                scope.commit_lower_round_finality(
                    &[0_u8],
                    Vec::new(),
                    &[0_u8],
                    ConsensusRound::new(0),
                ),
                Err(
                    FixedValidatorNodeLowerRoundFinalityErrorV0::FinalityRoundLimitExceeded {
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
