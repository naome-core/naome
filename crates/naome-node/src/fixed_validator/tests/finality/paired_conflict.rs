use super::*;

#[test]
fn current_round_preselection_batch_pair_matches_certificate_pair_in_both_orders() {
    let fixture = Fixture::new();
    let certificate = run_current_round_preselection_pair(
        &fixture,
        "current-round-preselection-batch-certificate",
        false,
        false,
    );
    let batch = run_current_round_preselection_pair(
        &fixture,
        "current-round-preselection-batch-forward",
        false,
        true,
    );
    let reversed = run_current_round_preselection_pair(
        &fixture,
        "current-round-preselection-batch-reversed",
        true,
        true,
    );

    assert_eq!(batch, certificate);
    assert_eq!(reversed, certificate);
}

#[test]
fn current_round_preselection_batch_pair_rejections_preserve_scope_files_and_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-preselection-batch-rejections");
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
            let (first_control, first_payload, _, position, first_value) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Pairing,
                    1,
                    &proposer,
                    &[&proposer],
                );
            let (second_control, second_payload, _, second_position, second_value) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Union,
                    1,
                    &proposer,
                    &[&proposer],
                );
            assert_eq!(second_position, position);
            let first_precommit = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
                &proposer,
            );
            let second_precommit = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
                &proposer,
            );
            let first_batch = [first_precommit.as_slice()];
            let second_batch = [second_precommit.as_slice()];
            let second_duplicate_batch = [second_precommit.as_slice(), second_precommit.as_slice()];
            let empty_batch: [&[u8]; 0] = [];
            let mut invalid_first_control = first_control.clone();
            invalid_first_control.pop();
            let mut invalid_second_control = second_control.clone();
            invalid_second_control.pop();
            let diagnostics = signing_scope_diagnostics(&mut scope);

            macro_rules! reject_batch_pair {
                (
                    $first_control:expr,
                    $first_payload:expr,
                    $first_batch:expr,
                    $second_control:expr,
                    $second_payload:expr,
                    $second_batch:expr,
                    $maximum:expr,
                    $check:expr
                ) => {{
                    let (mut next, rejection) =
                        expect_current_round_preselection_conflict_rejection(
                            scope
                                .commit_current_round_preselection_conflict_vote_batches(
                                    $first_control,
                                    $first_payload,
                                    $first_batch,
                                    $second_control,
                                    $second_payload,
                                    $second_batch,
                                    $maximum,
                                )
                                .unwrap(),
                        );
                    let check = $check;
                    assert!(check(&rejection), "unexpected rejection: {rejection}");
                    assert_eq!(signing_scope_diagnostics(&mut next), diagnostics);
                    assert_eq!(layout.images(), before);
                    scope = next;
                }};
            }

            reject_batch_pair!(
                &[0_u8],
                Vec::new(),
                &empty_batch,
                &[0_u8],
                Vec::new(),
                &empty_batch,
                ConsensusRound::new(0),
                |rejection: &FixedValidatorNodeCurrentRoundFinalityRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeCurrentRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                            required,
                            maximum,
                        } if *required == ConsensusRound::new(1)
                            && *maximum == ConsensusRound::new(0)
                    )
                }
            );
            reject_batch_pair!(
                &invalid_first_control,
                first_payload.clone(),
                &first_batch,
                &second_control,
                second_payload.clone(),
                &second_batch,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeCurrentRoundFinalityRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeCurrentRoundFinalityRejectionV0::FirstProposal(_)
                    )
                }
            );
            reject_batch_pair!(
                &first_control,
                first_payload.clone(),
                &empty_batch,
                &second_control,
                second_payload.clone(),
                &second_batch,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeCurrentRoundFinalityRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeCurrentRoundFinalityRejectionV0::FirstPrecommitBatch(
                            source
                        ) if matches!(
                            source.as_ref(),
                            FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                                QuorumCertificateBuildError::EmptyVoteBatch
                            )
                        )
                    )
                }
            );
            reject_batch_pair!(
                &first_control,
                first_payload.clone(),
                &first_batch,
                &invalid_second_control,
                second_payload.clone(),
                &second_batch,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeCurrentRoundFinalityRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeCurrentRoundFinalityRejectionV0::SecondProposal(_)
                    )
                }
            );
            reject_batch_pair!(
                &first_control,
                first_payload.clone(),
                &first_batch,
                &second_control,
                second_payload.clone(),
                &second_duplicate_batch,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeCurrentRoundFinalityRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeCurrentRoundFinalityRejectionV0::SecondPrecommitBatch(
                            source
                        ) if matches!(
                            source.as_ref(),
                            FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                                QuorumCertificateBuildError::DuplicateSigner { .. }
                            )
                        )
                    )
                }
            );

            match scope
                .commit_current_round_preselection_conflict_vote_batches(
                    &first_control,
                    first_payload,
                    &first_batch,
                    &second_control,
                    second_payload,
                    &second_batch,
                    ConsensusRound::new(1),
                )
                .unwrap()
            {
                FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::FinalityStopped(_) => {
                }
                FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::Rejected {
                    ..
                } => {
                    panic!("the intact exact-current batch pair must succeed after rejections")
                }
            }
        })
        .unwrap();
}

#[test]
fn paired_current_round_rejections_restore_the_exact_scope_and_all_files_before_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-preselection-pair-rejections");
    let proposer = fixture.signing_key();
    let ready = fixture
        .provision(&layout, 8)
        .create(fixture.signing_key())
        .unwrap();
    let selected = ArtifactChainState::new(fixture.definition);
    let before = layout.images();

    let stopped = ready
        .run_with_signing_session(|mut scope| {
            let branch = scope.branch().clone();
            let (first_control, first_payload, first_certificate, first_position, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Pairing,
                    0,
                    &proposer,
                    &[&proposer],
                );
            let (second_control, second_payload, second_certificate, second_position, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Union,
                    0,
                    &proposer,
                    &[&proposer],
                );
            assert_eq!(first_position, second_position);
            let diagnostics = signing_scope_diagnostics(&mut scope);

            let mut invalid_first_control = first_control.clone();
            invalid_first_control.pop();
            let (mut next, rejection) = expect_current_round_preselection_conflict_rejection(
                scope
                    .commit_current_round_preselection_conflict(
                        &invalid_first_control,
                        first_payload.clone(),
                        &first_certificate,
                        &second_control,
                        second_payload.clone(),
                        &second_certificate,
                        ConsensusRound::new(8),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::FirstProposal(_)
            ));
            assert_eq!(signing_scope_diagnostics(&mut next), diagnostics);
            assert_eq!(layout.images(), before);
            scope = next;

            let (mut next, rejection) = expect_current_round_preselection_conflict_rejection(
                scope
                    .commit_current_round_preselection_conflict(
                        &first_control,
                        first_payload.clone(),
                        &[],
                        &second_control,
                        second_payload.clone(),
                        &second_certificate,
                        ConsensusRound::new(8),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::FirstPrecommitCertificate(_)
            ));
            assert_eq!(signing_scope_diagnostics(&mut next), diagnostics);
            assert_eq!(layout.images(), before);
            scope = next;

            let mut invalid_second_control = second_control.clone();
            invalid_second_control.pop();
            let (mut next, rejection) = expect_current_round_preselection_conflict_rejection(
                scope
                    .commit_current_round_preselection_conflict(
                        &first_control,
                        first_payload.clone(),
                        &first_certificate,
                        &invalid_second_control,
                        second_payload.clone(),
                        &second_certificate,
                        ConsensusRound::new(8),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::SecondProposal(_)
            ));
            assert_eq!(signing_scope_diagnostics(&mut next), diagnostics);
            assert_eq!(layout.images(), before);
            scope = next;

            let (mut next, rejection) = expect_current_round_preselection_conflict_rejection(
                scope
                    .commit_current_round_preselection_conflict(
                        &first_control,
                        first_payload.clone(),
                        &first_certificate,
                        &second_control,
                        second_payload.clone(),
                        &[],
                        ConsensusRound::new(8),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                rejection,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::SecondPrecommitCertificate(_)
            ));
            assert_eq!(signing_scope_diagnostics(&mut next), diagnostics);
            assert_eq!(layout.images(), before);

            match next
                .commit_current_round_preselection_conflict(
                    &first_control,
                    first_payload,
                    &first_certificate,
                    &second_control,
                    second_payload,
                    &second_certificate,
                    ConsensusRound::new(8),
                )
                .unwrap()
            {
                FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::FinalityStopped(
                    stop,
                ) => *stop,
                FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::Rejected {
                    ..
                } => {
                    panic!("the intact pair must succeed after no-effect rejections")
                }
            }
        })
        .unwrap();
    assert_eq!(
        stopped.finality_halt().kind(),
        naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    assert_eq!(
        stopped.signer_stop().kind(),
        naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    let after = layout.images();
    for index in 0..after.len() {
        assert_ne!(after[index], before[index], "durable image index {index}");
    }
}

#[test]
fn lower_round_preselection_pair_is_canonical_and_strictly_restarts_terminal() {
    let fixture = Fixture::new();
    let first =
        run_lower_round_preselection_pair(&fixture, "lower-round-preselection-pair-forward", false);
    let reversed =
        run_lower_round_preselection_pair(&fixture, "lower-round-preselection-pair-reversed", true);

    assert_eq!(reversed, first);
}

#[test]
fn lower_round_preselection_batch_pair_matches_certificate_pair_in_both_orders() {
    let fixture = Fixture::new();
    let certificate = run_lower_round_preselection_pair(
        &fixture,
        "lower-round-preselection-batch-certificate",
        false,
    );
    let batch = run_lower_round_preselection_batch_pair(
        &fixture,
        "lower-round-preselection-batch-forward",
        false,
    );
    let reversed = run_lower_round_preselection_batch_pair(
        &fixture,
        "lower-round-preselection-batch-reversed",
        true,
    );

    assert_eq!(batch, certificate);
    assert_eq!(reversed, certificate);
}

#[test]
fn lower_round_preselection_batch_pair_rejections_preserve_scope_files_and_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-preselection-batch-rejections");
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
            let (first_control, first_payload, _, position, first_value) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Pairing,
                    1,
                    &proposer,
                    &[&proposer],
                );
            let (second_control, second_payload, _, second_position, second_value) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Union,
                    1,
                    &proposer,
                    &[&proposer],
                );
            assert_eq!(second_position, position);
            let first_precommit = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
                &proposer,
            );
            let second_precommit = signed_vote_bytes(
                fixture.context,
                position,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
                &proposer,
            );
            let first_batch = [first_precommit.as_slice()];
            let second_batch = [second_precommit.as_slice()];
            let second_duplicate_batch = [second_precommit.as_slice(), second_precommit.as_slice()];
            let empty_batch: [&[u8]; 0] = [];
            let mut invalid_first_control = first_control.clone();
            invalid_first_control.pop();
            let mut invalid_second_control = second_control.clone();
            invalid_second_control.pop();
            let diagnostics = signing_scope_diagnostics(&mut scope);

            macro_rules! reject_batch_pair {
                (
                    $first_control:expr,
                    $first_payload:expr,
                    $first_batch:expr,
                    $second_control:expr,
                    $second_payload:expr,
                    $second_batch:expr,
                    $route:expr,
                    $check:expr
                ) => {{
                    let (mut next, rejection) =
                        expect_lower_round_preselection_conflict_rejection(
                            scope
                                .commit_lower_round_preselection_conflict_vote_batches(
                                    $first_control,
                                    $first_payload,
                                    $first_batch,
                                    $second_control,
                                    $second_payload,
                                    $second_batch,
                                    $route,
                                )
                                .unwrap(),
                        );
                    let check = $check;
                    assert!(check(&rejection), "unexpected rejection: {rejection}");
                    assert_eq!(signing_scope_diagnostics(&mut next), diagnostics);
                    assert_eq!(layout.images(), before);
                    scope = next;
                }};
            }

            reject_batch_pair!(
                &[0_u8],
                Vec::new(),
                &empty_batch,
                &[0_u8],
                Vec::new(),
                &empty_batch,
                FixedValidatorNodeFinalityRoundRouteV0::new(
                    ConsensusRound::new(2),
                    ConsensusRound::new(0),
                ),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Route(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                                    evidence,
                                    signer,
                                } if *evidence == ConsensusRound::new(2)
                                    && *signer == ConsensusRound::new(2)
                            )
                    )
                }
            );
            reject_batch_pair!(
                &[0_u8],
                Vec::new(),
                &empty_batch,
                &[0_u8],
                Vec::new(),
                &empty_batch,
                FixedValidatorNodeFinalityRoundRouteV0::new(
                    ConsensusRound::new(1),
                    ConsensusRound::new(0),
                ),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Route(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                                    required,
                                    maximum,
                                } if *required == ConsensusRound::new(1)
                                    && *maximum == ConsensusRound::new(0)
                            )
                    )
                }
            );
            reject_batch_pair!(
                &invalid_first_control,
                first_payload.clone(),
                &first_batch,
                &second_control,
                second_payload.clone(),
                &second_batch,
                FixedValidatorNodeFinalityRoundRouteV0::new(
                    ConsensusRound::new(1),
                    ConsensusRound::new(1),
                ),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                                            ConsensusProposalVerifyError::InvalidLength { .. }
                                        )
                                    )
                            )
                    )
                }
            );
            reject_batch_pair!(
                &first_control,
                first_payload.clone(),
                &first_batch,
                &invalid_second_control,
                second_payload.clone(),
                &second_batch,
                FixedValidatorNodeFinalityRoundRouteV0::new(
                    ConsensusRound::new(1),
                    ConsensusRound::new(1),
                ),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Second(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                                            ConsensusProposalVerifyError::InvalidLength { .. }
                                        )
                                    )
                            )
                    )
                }
            );
            reject_batch_pair!(
                &first_control,
                first_payload.clone(),
                &empty_batch,
                &second_control,
                second_payload.clone(),
                &second_batch,
                FixedValidatorNodeFinalityRoundRouteV0::new(
                    ConsensusRound::new(1),
                    ConsensusRound::new(1),
                ),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::PrecommitBatch(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                                            QuorumCertificateBuildError::EmptyVoteBatch
                                        )
                                    )
                            )
                    )
                }
            );
            reject_batch_pair!(
                &first_control,
                first_payload.clone(),
                &first_batch,
                &second_control,
                second_payload.clone(),
                &second_duplicate_batch,
                FixedValidatorNodeFinalityRoundRouteV0::new(
                    ConsensusRound::new(1),
                    ConsensusRound::new(1),
                ),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Second(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::PrecommitBatch(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusPrecommitBatchSealErrorV0::QuorumConstruction(
                                            QuorumCertificateBuildError::DuplicateSigner { .. }
                                        )
                                    )
                            )
                    )
                }
            );

            match scope
                .commit_lower_round_preselection_conflict_vote_batches(
                    &first_control,
                    first_payload,
                    &first_batch,
                    &second_control,
                    second_payload,
                    &second_batch,
                    FixedValidatorNodeFinalityRoundRouteV0::new(
                        ConsensusRound::new(1),
                        ConsensusRound::new(1),
                    ),
                )
                .unwrap()
            {
                FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::FinalityStopped(_) => {}
                FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::Rejected { .. } => {
                    panic!("the intact lower-round batch pair must succeed after rejections")
                }
            }
        })
        .unwrap();
}

#[test]
fn lower_round_preselection_pair_rejections_preserve_scope_files_and_retry() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-preselection-pair-rejections");
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

            let (first_control, first_payload, first_certificate, position_one, first_value) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Pairing,
                    1,
                    &proposer,
                    &[&proposer],
                );
            let (second_control, second_payload, second_certificate, second_position, second_value) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Union,
                    1,
                    &proposer,
                    &[&proposer],
                );
            assert_eq!(second_position, position_one);
            let (zero_control, zero_payload, zero_certificate, position_zero, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Infinity,
                    0,
                    &proposer,
                    &[&proposer],
                );
            let (current_control, current_payload, current_certificate, current_position, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::Extensionality,
                    2,
                    &proposer,
                    &[&proposer],
                );
            let (future_control, future_payload, future_certificate, future_position, _) =
                current_round_finality_inputs(
                    &branch,
                    &selected,
                    ZfcAxiom::PowerSet,
                    3,
                    &proposer,
                    &[&proposer],
                );
            let wrong_height = ConsensusPosition::new(
                ConsensusHeight::new(position_one.height().value() + 1),
                position_one.round(),
            );
            let wrong_first_height_certificate = quorum_certificate_bytes(
                fixture.context,
                wrong_height,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(first_value.proposal_signing_root()),
                &[&proposer],
            );
            let wrong_second_height_certificate = quorum_certificate_bytes(
                fixture.context,
                wrong_height,
                ConsensusVoteRole::Precommit,
                ConsensusVoteTarget::Proposal(second_value.proposal_signing_root()),
                &[&proposer],
            );
            let mut invalid_first_certificate = first_certificate.clone();
            *invalid_first_certificate.last_mut().unwrap() ^= 0x80;
            let mut invalid_second_certificate = second_certificate.clone();
            *invalid_second_certificate.last_mut().unwrap() ^= 0x80;
            let mut invalid_first_control = first_control.clone();
            invalid_first_control.pop();
            let mut invalid_second_control = second_control.clone();
            invalid_second_control.pop();
            let diagnostics = signing_scope_diagnostics(&mut scope);

            macro_rules! reject_pair {
                (
                    $first_control:expr,
                    $first_payload:expr,
                    $first_certificate:expr,
                    $second_control:expr,
                    $second_payload:expr,
                    $second_certificate:expr,
                    $maximum:expr,
                    $check:expr
                ) => {{
                    let (mut next, rejection) =
                        expect_lower_round_preselection_conflict_rejection(
                            scope
                                .commit_lower_round_preselection_conflict(
                                    $first_control,
                                    $first_payload,
                                    $first_certificate,
                                    $second_control,
                                    $second_payload,
                                    $second_certificate,
                                    $maximum,
                                )
                                .unwrap(),
                        );
                    let check = $check;
                    assert!(check(&rejection), "unexpected rejection: {rejection}");
                    assert_eq!(signing_scope_diagnostics(&mut next), diagnostics);
                    assert_eq!(layout.images(), before);
                    scope = next;
                }};
            }

            reject_pair!(
                &first_control,
                first_payload.clone(),
                &[0_u8],
                &second_control,
                second_payload.clone(),
                &second_certificate,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::EmbeddedCertificatePosition(_)
                                    )
                            )
                    )
                }
            );
            reject_pair!(
                &first_control,
                first_payload.clone(),
                &first_certificate,
                &second_control,
                second_payload.clone(),
                &[0_u8],
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Second(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::EmbeddedCertificatePosition(_)
                                    )
                            )
                    )
                }
            );
            reject_pair!(
                &first_control,
                first_payload.clone(),
                &wrong_first_height_certificate,
                &second_control,
                second_payload.clone(),
                &second_certificate,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::CertificateHeightMismatch { .. }
                                    )
                            )
                    )
                }
            );
            reject_pair!(
                &first_control,
                first_payload.clone(),
                &first_certificate,
                &second_control,
                second_payload.clone(),
                &wrong_second_height_certificate,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Second(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::CertificateHeightMismatch { .. }
                                    )
                            )
                    )
                }
            );
            reject_pair!(
                &invalid_first_control,
                first_payload.clone(),
                &first_certificate,
                &second_control,
                second_payload.clone(),
                &second_certificate,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                                            ConsensusProposalVerifyError::InvalidLength { .. }
                                        )
                                    )
                            )
                    )
                }
            );
            reject_pair!(
                &first_control,
                first_payload.clone(),
                &first_certificate,
                &invalid_second_control,
                second_payload.clone(),
                &second_certificate,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Second(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                                            ConsensusProposalVerifyError::InvalidLength { .. }
                                        )
                                    )
                            )
                    )
                }
            );
            reject_pair!(
                &first_control,
                proof_payload(ZfcAxiom::Union),
                &first_certificate,
                &second_control,
                second_payload.clone(),
                &second_certificate,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                                            ConsensusProposalVerifyError::ArtifactValidation(_)
                                        )
                                    )
                            )
                    )
                }
            );
            reject_pair!(
                &first_control,
                first_payload.clone(),
                &first_certificate,
                &second_control,
                proof_payload(ZfcAxiom::Pairing),
                &second_certificate,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Second(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(
                                            ConsensusProposalVerifyError::ArtifactValidation(_)
                                        )
                                    )
                            )
                    )
                }
            );
            reject_pair!(
                &first_control,
                first_payload.clone(),
                &invalid_first_certificate,
                &second_control,
                second_payload.clone(),
                &second_certificate,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::PrecommitCertificate(_)
                                    )
                            )
                    )
                }
            );
            reject_pair!(
                &first_control,
                first_payload.clone(),
                &first_certificate,
                &second_control,
                second_payload.clone(),
                &invalid_second_certificate,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Second(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(inner)
                                    if matches!(
                                        inner.as_ref(),
                                        FixedConsensusBoundedSeparateFinalityVerifyError::PrecommitCertificate(_)
                                    )
                            )
                    )
                }
            );
            reject_pair!(
                &zero_control,
                zero_payload,
                &zero_certificate,
                &second_control,
                second_payload.clone(),
                &second_certificate,
                ConsensusRound::new(1),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::PositionMismatch {
                            first,
                            second,
                        } if *first == position_zero && *second == position_one
                    )
                }
            );
            reject_pair!(
                &current_control,
                current_payload,
                &current_certificate,
                &second_control,
                second_payload.clone(),
                &second_certificate,
                ConsensusRound::new(8),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                                    evidence,
                                    signer,
                                } if *evidence == current_position.round()
                                    && *signer == ConsensusRound::new(2)
                            )
                    )
                }
            );
            reject_pair!(
                &first_control,
                first_payload.clone(),
                &first_certificate,
                &future_control,
                future_payload,
                &future_certificate,
                ConsensusRound::new(8),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Second(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                                    evidence,
                                    signer,
                                } if *evidence == future_position.round()
                                    && *signer == ConsensusRound::new(2)
                            )
                    )
                }
            );
            reject_pair!(
                &first_control,
                first_payload.clone(),
                &first_certificate,
                &second_control,
                second_payload.clone(),
                &second_certificate,
                ConsensusRound::new(0),
                |rejection: &FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0| {
                    matches!(
                        rejection,
                        FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(source)
                            if matches!(
                                source.as_ref(),
                                FixedValidatorNodeLowerRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                                    required,
                                    maximum,
                                } if *required == ConsensusRound::new(1)
                                    && *maximum == ConsensusRound::new(0)
                            )
                    )
                }
            );

            match scope
                .commit_lower_round_preselection_conflict(
                    &first_control,
                    first_payload,
                    &first_certificate,
                    &second_control,
                    second_payload,
                    &second_certificate,
                    ConsensusRound::new(1),
                )
                .unwrap()
            {
                FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::FinalityStopped(_) => {}
                FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::Rejected { .. } => {
                    panic!("the intact lower-round pair must succeed after no-effect rejections")
                }
            }
        })
        .unwrap();
}

#[test]
fn current_round_batch_pair_checks_persisted_ceiling_before_input_work() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("current-round-batch-pair-persisted-ceiling");
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
                scope.commit_current_round_preselection_conflict_vote_batches(
                    &[0_u8],
                    Vec::new(),
                    &[],
                    &[0_u8],
                    Vec::new(),
                    &[],
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

#[test]
fn lower_round_pair_checks_persisted_ceiling_before_input_parsing() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-pair-persisted-ceiling");
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
                scope.commit_lower_round_preselection_conflict(
                    &[0_u8],
                    Vec::new(),
                    &[0_u8],
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

#[test]
fn lower_round_batch_pair_checks_persisted_ceiling_before_route_and_input_work() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("lower-round-batch-pair-persisted-ceiling");
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
                scope.commit_lower_round_preselection_conflict_vote_batches(
                    &[0_u8],
                    Vec::new(),
                    &[],
                    &[0_u8],
                    Vec::new(),
                    &[],
                    FixedValidatorNodeFinalityRoundRouteV0::new(
                        ConsensusRound::new(2),
                        ConsensusRound::new(0),
                    ),
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
