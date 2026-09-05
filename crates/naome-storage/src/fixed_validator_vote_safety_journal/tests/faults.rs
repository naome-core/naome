use super::*;

#[cfg(unix)]
#[test]
fn anchor_update_failure_releases_no_signed_vote_and_strict_reopen_fails_behind() {
    let fixture = Fixture::new(2);
    let journal_directory = TestDirectory::new("anchor-failure-vote-journal");
    let anchor_directory = TestDirectory::new("anchor-failure-vote-anchor");
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let _ = activate_anchored_proposal_authoring(&mut journal);
    let _ = journal.bind_signing_lineage(&round).unwrap();
    let mut session = journal.issue_signing_session(&round).unwrap();
    let effect = session.decide_prevote_without_proposal().unwrap();
    let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
    assert_eq!(session.session.journal.core.record_sequence, 3);
    let anchor_before = fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap();

    fs::create_dir(anchor_directory.vote_anchor_temporary(fixture.signer(), 4)).unwrap();
    let acknowledgement = session.acknowledge_prepared_vote(prepared).unwrap();
    assert!(matches!(
        session.sign_prepared_vote(acknowledgement),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
    ));
    assert_eq!(
        fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
        anchor_before
    );
    assert!(matches!(
        session.decide_precommit_without_quorum(),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
    ));
    drop(session);
    drop(journal);

    assert!(matches!(
        fixture.open_anchored(&journal_directory, &anchor_directory),
        Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
            if matches!(
                source.as_ref(),
                FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind {
                anchored_sequence: 3,
                journal_sequence: 4,
                }
            )
    ));
}

#[cfg(unix)]
#[test]
fn anchor_operation_failures_withhold_signed_vote_until_exact_stabilized_reopen() {
    use crate::fixed_validator_anchor::faults::{Operation, REPLACEMENT_OPERATIONS, inject};

    let fixture = Fixture::new(2);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let (expected_signed, expected_images) = {
        let journal_directory = TestDirectory::new("anchor-fault-vote-control-journal");
        let anchor_directory = TestDirectory::new("anchor-fault-vote-control-anchor");
        let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
        let _ = activate_anchored_proposal_authoring(&mut journal);
        let _ = journal.bind_signing_lineage(&round).unwrap();
        let mut session = journal.issue_signing_session(&round).unwrap();
        let effect = session.decide_prevote_without_proposal().unwrap();
        let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
        let acknowledgement = session.acknowledge_prepared_vote(prepared).unwrap();
        let signed = session.sign_prepared_vote(acknowledgement).unwrap();
        (
            signed,
            (
                fs::read(
                    keyed_paths(&journal_directory.0, fixture.signer())
                        .unwrap()
                        .1,
                )
                .unwrap(),
                fs::read(anchor_directory.vote_anchor(fixture.signer())).unwrap(),
            ),
        )
    };

    for operation in REPLACEMENT_OPERATIONS {
        let journal_directory = TestDirectory::new("anchor-fault-vote-journal");
        let anchor_directory = TestDirectory::new("anchor-fault-vote-anchor");
        let anchor_path = anchor_directory.vote_anchor(fixture.signer());
        let temporary_path = anchor_directory.vote_anchor_temporary(fixture.signer(), 4);
        let journal_path = keyed_paths(&journal_directory.0, fixture.signer())
            .unwrap()
            .1;
        let images = || {
            (
                fs::read(&journal_path).unwrap(),
                fs::read(&anchor_path).unwrap(),
            )
        };
        let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
        let _ = activate_anchored_proposal_authoring(&mut journal);
        let _ = journal.bind_signing_lineage(&round).unwrap();
        let mut session = journal.issue_signing_session(&round).unwrap();
        let effect = session.decide_prevote_without_proposal().unwrap();
        let prepared = prepared(session.prepare_vote(&round, effect).unwrap());
        let acknowledgement = session.acknowledge_prepared_vote(prepared).unwrap();
        let before = images();
        let fault = inject(&anchor_path, operation);
        assert!(
            matches!(
                session.sign_prepared_vote(acknowledgement),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "{operation:?}"
        );
        fault.assert_fired();
        drop(fault);
        assert!(matches!(
            session.decide_precommit_without_quorum(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        drop(session);
        assert!(matches!(
            journal.state_id(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        assert!(matches!(
            journal.retained_signed_vote(round.position(), ConsensusVoteRole::Prevote),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        assert!(matches!(
            journal.issue_signing_session(&round),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        let after = images();
        assert_eq!(after.0, expected_images.0, "{operation:?}");
        assert_ne!(after.0, before.0);
        match operation {
            Operation::CreateTemporary | Operation::SyncReplacementDirectory => {
                assert!(!temporary_path.exists())
            }
            Operation::WriteTemporary => assert!(fs::read(&temporary_path).unwrap().is_empty()),
            Operation::SyncTemporary | Operation::Rename => {
                assert_eq!(fs::read(&temporary_path).unwrap(), expected_images.1)
            }
            Operation::StabilizeFile | Operation::StabilizeDirectory => unreachable!(),
        }
        drop(journal);

        if operation != Operation::SyncReplacementDirectory {
            assert_eq!(after.1, before.1);
            let temporary_before = fs::read(&temporary_path).ok();
            for _ in 0..2 {
                assert!(matches!(
                    fixture.open_anchored(&journal_directory, &anchor_directory),
                    Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(source))
                        if matches!(source.as_ref(), FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { anchored_sequence: 3, journal_sequence: 4 })
                ));
                assert_eq!(images(), after);
                assert_eq!(fs::read(&temporary_path).ok(), temporary_before);
            }
            continue;
        }

        assert_eq!(after, expected_images);
        for stabilization in [Operation::StabilizeFile, Operation::StabilizeDirectory] {
            let fault = inject(&anchor_path, stabilization);
            assert!(matches!(
                fixture.open_anchored(&journal_directory, &anchor_directory),
                Err(FixedValidatorAnchoredVoteSafetyJournalErrorV0::Anchor(
                    FixedValidatorAnchorErrorV0::Stabilize { .. }
                ))
            ));
            fault.assert_fired();
            drop(fault);
            assert_eq!(images(), after);
        }
        let mut reopened = fixture
            .open_anchored(&journal_directory, &anchor_directory)
            .unwrap();
        assert_eq!(reopened.state_id().unwrap(), expected_signed.state_id());
        assert_eq!(
            reopened
                .retained_signed_vote(round.position(), ConsensusVoteRole::Prevote)
                .unwrap()
                .as_ref(),
            Some(&expected_signed)
        );
        let resumed = reopened.issue_signing_session(&round).unwrap();
        assert_eq!(resumed.position(), round.position());
        assert_eq!(resumed.phase(), FixedValidatorLockPhaseV0::Prevote);
        assert_eq!(images(), after);
    }
}

#[test]
fn every_prepare_append_fault_poisons_and_reopens_only_from_durable_anchor() {
    let fixture = Fixture::new(2);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let prototype_intent = fixture.nil_prevote_intent();
    let prepare_body = tagged_record(
        PREPARE_RECORD,
        prototype_intent.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let prepared_state = step_state_id(
        genesis,
        u32::try_from(prepare_body.len()).unwrap().to_be_bytes(),
        &prepare_body,
    );
    let complete_length = prefix.len() + 4 + prepare_body.len() + 32;

    for fault in all_append_faults(4 + prepare_body.len(), 32) {
        let io = ScriptedIo::new(prefix.clone(), Some(fault.clone()));
        let mut core = fixture.scripted_core(io);
        assert!(
            matches!(
                core.prepare_vote(prototype_intent.clone()),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "fault {fault:?}"
        );
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        let durable = core.file.durable.clone();
        let replay_io = ScriptedIo::from_images(durable.clone(), durable.clone());
        if durable.len() == complete_length {
            assert!(
                matches!(
                    fixture.replay_scripted(replay_io, genesis),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual
                    }) if expected == genesis && actual == prepared_state
                ),
                "fault {fault:?}"
            );
        } else {
            let reopened = fixture.replay_scripted(replay_io, genesis).unwrap();
            assert_eq!(reopened.file.volatile.get_ref(), &prefix, "fault {fault:?}");
        }
    }
}

#[test]
fn every_signing_lineage_append_fault_poisons_and_reopens_only_from_durable_anchor() {
    let fixture = Fixture::new(1);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let lineage_id = signing_lineage_id(
        round.parent_coordinate(),
        round.position().height(),
        fixture.signer(),
    );
    let body = signing_lineage_record(round.position().height(), lineage_id, 0).unwrap();
    let state = step_state_id(
        genesis,
        u32::try_from(body.len()).unwrap().to_be_bytes(),
        &body,
    );
    let complete_length = prefix.len() + 4 + body.len() + 32;

    for fault in all_append_faults(4 + body.len(), 32) {
        let io = ScriptedIo::new(prefix.clone(), Some(fault.clone()));
        let mut core = fixture.scripted_core(io);
        assert!(
            matches!(
                core.bind_signing_lineage(&round),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "fault {fault:?}"
        );
        assert!(core.lineage.is_none(), "fault {fault:?}");
        assert_eq!(core.state_id, genesis, "fault {fault:?}");
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        let durable = core.file.durable.clone();
        if durable.len() == complete_length {
            let old_anchor_io = ScriptedIo::from_images(durable.clone(), durable.clone());
            assert!(
                matches!(
                    fixture.replay_scripted(old_anchor_io, genesis),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == genesis && actual == state
                ),
                "fault {fault:?}"
            );
            let exact_anchor_io = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(exact_anchor_io, state).unwrap();
            assert_eq!(reopened.lineage.unwrap().height, ConsensusHeight::new(1));
            assert_eq!(reopened.state_id, state);
        } else {
            let replay_io = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(replay_io, genesis).unwrap();
            assert!(reopened.lineage.is_none(), "fault {fault:?}");
            assert_eq!(reopened.file.volatile.get_ref(), &prefix, "fault {fault:?}");
        }
    }
}

#[test]
fn every_higher_round_checkpoint_append_fault_poisons_and_reopens_only_exact_prefix() {
    let fixture = Fixture::new(1);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let branch = fixture.branch();
    let round_zero = branch.begin_round_zero().unwrap();
    let lineage_id = signing_lineage_id(
        round_zero.parent_coordinate(),
        round_zero.position().height(),
        fixture.signer(),
    );
    let lineage_body =
        signing_lineage_record(round_zero.position().height(), lineage_id, 0).unwrap();
    let lineage_state = step_state_id(
        genesis,
        u32::try_from(lineage_body.len()).unwrap().to_be_bytes(),
        &lineage_body,
    );
    let mut lineage_image = prefix;
    let _ = append_test_record(&mut lineage_image, genesis, &lineage_body);
    let target_position =
        ConsensusPosition::new(round_zero.position().height(), ConsensusRound::new(3));
    let certificate = certificate_bytes(
        fixture.context,
        target_position,
        ConsensusVoteRole::Precommit,
        ConsensusVoteTarget::Nil,
        &fixture.signing_key(),
    );
    let state = FixedValidatorLockStateV0::try_from_round_zero(&round_zero).unwrap();
    let transition = state
        .prepare_higher_round_quorum_advance(&round_zero, &certificate, ConsensusRound::new(3))
        .unwrap();
    let checkpoint = transition.canonical_checkpoint_bytes().to_vec();
    let body = tagged_record(HIGHER_ROUND_CHECKPOINT_RECORD, &checkpoint, 0).unwrap();
    let checkpoint_state = step_state_id(
        lineage_state,
        u32::try_from(body.len()).unwrap().to_be_bytes(),
        &body,
    );
    let complete_length = lineage_image.len() + 4 + body.len() + 32;

    for fault in all_append_faults(4 + body.len(), 32) {
        let io = ScriptedIo::from_images(lineage_image.clone(), lineage_image.clone());
        let mut core = fixture.replay_scripted(io, lineage_state).unwrap();
        core.file.inject_fault(fault.clone());
        assert!(
            matches!(
                core.append_higher_round_checkpoint(&checkpoint),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "fault {fault:?}"
        );
        assert!(
            core.latest_current_lineage_state.is_none(),
            "fault {fault:?}"
        );
        assert_eq!(core.state_id, lineage_state, "fault {fault:?}");
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));

        let durable = core.file.durable.clone();
        if durable.len() == complete_length {
            let old_anchor = ScriptedIo::from_images(durable.clone(), durable.clone());
            assert!(
                matches!(
                    fixture.replay_scripted(old_anchor, lineage_state),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == lineage_state && actual == checkpoint_state
                ),
                "fault {fault:?}"
            );
            let exact = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(exact, checkpoint_state).unwrap();
            assert!(matches!(
                reopened.latest_current_lineage_state,
                Some(RetainedCurrentLineageStateV0::HigherRound { state_id, .. })
                    if state_id == checkpoint_state
            ));
        } else {
            let old_anchor = ScriptedIo::from_images(durable.clone(), durable.clone());
            let reopened = fixture.replay_scripted(old_anchor, lineage_state).unwrap();
            assert!(
                reopened.latest_current_lineage_state.is_none(),
                "fault {fault:?}"
            );
            assert_eq!(reopened.file.volatile.get_ref(), &lineage_image);
            let proposed = ScriptedIo::from_images(durable.clone(), durable);
            assert!(
                matches!(
                    fixture.replay_scripted(proposed, checkpoint_state),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == checkpoint_state && actual == lineage_state
                ),
                "fault {fault:?}"
            );
        }
    }
}

fn assert_every_finality_stop_append_fault(
    fixture: &Fixture,
    finality: &FixedValidatorFinalityJournalV0,
    halt: FixedValidatorFinalityHaltV0,
    expected_tag: u8,
) {
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let proposed = FixedValidatorFinalityConflictSignerStopV0 {
        kind: halt.kind(),
        finality_state_id: halt.state_id(),
        height: halt.height(),
        first_ancestry: halt.first_ancestry(),
        first_envelope_id: halt.first_envelope_id(),
        second_ancestry: halt.second_ancestry(),
        second_envelope_id: halt.second_envelope_id(),
        vote_state_id: genesis,
    };
    let body = finality_conflict_stop_record(proposed, 0).unwrap();
    assert_eq!(body[0], expected_tag);
    let stopped_state = step_state_id(
        genesis,
        u32::try_from(body.len()).unwrap().to_be_bytes(),
        &body,
    );
    let complete_length = prefix.len() + 4 + body.len() + 32;

    for fault in all_append_faults(4 + body.len(), 32) {
        let io = ScriptedIo::new(prefix.clone(), Some(fault.clone()));
        let mut core = fixture.scripted_core(io);
        let conflict = finality
            .acknowledge_signer_stop_is_externally_durable(halt.state_id())
            .unwrap();
        assert!(
            matches!(
                core.stop_after_durable_finality_conflict(conflict),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "fault {fault:?}"
        );
        assert!(core.finality_conflict_stop.is_none(), "fault {fault:?}");
        assert_eq!(core.state_id, genesis, "fault {fault:?}");
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));

        let durable = core.file.durable.clone();
        if durable.len() == complete_length {
            let stale = ScriptedIo::from_images(durable.clone(), durable.clone());
            assert!(
                matches!(
                    fixture.replay_scripted(stale, genesis),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == genesis && actual == stopped_state
                ),
                "fault {fault:?}"
            );
            let exact = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(exact, stopped_state).unwrap();
            let stop = reopened
                .finality_conflict_stop
                .expect("the exact durable stop replays");
            assert_eq!(stop.finality_state_id(), halt.state_id());
            assert_eq!(stop.vote_state_id(), stopped_state);
        } else {
            let partial = ScriptedIo::from_images(durable.clone(), durable.clone());
            let reopened = fixture.replay_scripted(partial, genesis).unwrap();
            assert!(reopened.finality_conflict_stop.is_none(), "fault {fault:?}");
            assert_eq!(reopened.file.volatile.get_ref(), &prefix, "fault {fault:?}");
            let proposed = ScriptedIo::from_images(durable.clone(), durable);
            assert!(
                matches!(
                    fixture.replay_scripted(proposed, stopped_state),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == stopped_state && actual == genesis
                ),
                "fault {fault:?}"
            );
        }
    }
}

#[test]
fn every_finality_stop_append_fault_poisons_and_reopens_only_from_exact_anchor() {
    let fixture = Fixture::new(1);
    let finality_directory = TestDirectory::new("finality-stop-fault-source");
    let mut finality = fixture.create_finality(&finality_directory);
    let _ = finality
        .commit_verified(fixture.owned_transition())
        .unwrap();
    let halt = match finality
        .commit_verified(fixture.owned_transition_for(ZfcAxiom::Union))
        .unwrap()
    {
        FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => halt,
        other => panic!("expected finality halt, got {other:?}"),
    };
    assert_every_finality_stop_append_fault(
        &fixture,
        &finality,
        halt,
        FINALITY_CONFLICT_STOP_RECORD,
    );
}

#[cfg(unix)]
#[test]
fn every_preselection_stop_append_fault_replays_only_the_exact_tag_0b_state() {
    let fixture = Fixture::new(1);
    let finality_directory = TestDirectory::new("preselection-stop-fault-source");
    let finality_anchor_directory = TestDirectory::new("preselection-stop-fault-anchor");
    let mut anchored_finality =
        fixture.create_anchored_finality(&finality_directory, &finality_anchor_directory);
    let halt = anchored_finality
        .commit_verified_preselection_conflict(
            fixture.owned_transition_for_round(ZfcAxiom::Union, 2),
            fixture.owned_transition_for_round(ZfcAxiom::Pairing, 2),
        )
        .unwrap();
    assert_eq!(
        halt.kind(),
        FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    drop(anchored_finality);
    let finality = fixture.open_finality(&finality_directory, halt.state_id());
    assert_every_finality_stop_append_fault(
        &fixture,
        &finality,
        halt,
        PRESELECTION_CONFLICT_STOP_RECORD,
    );
}

#[test]
fn every_child_lineage_append_fault_preserves_the_anchored_parent_lineage() {
    let fixture = Fixture::new(1);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let branch = fixture.branch();
    let round = branch.begin_round_zero().unwrap();
    let first_id = signing_lineage_id(
        round.parent_coordinate(),
        round.position().height(),
        fixture.signer(),
    );
    let first_body = signing_lineage_record(round.position().height(), first_id, 0).unwrap();
    let first_state = step_state_id(
        genesis,
        u32::try_from(first_body.len()).unwrap().to_be_bytes(),
        &first_body,
    );
    let mut first_image = prefix;
    let _ = append_test_record(&mut first_image, genesis, &first_body);

    let child = fixture.owned_transition().into_branch();
    let child_round = child.begin_round_zero().unwrap();
    let child_height = child_round.position().height();
    let child_id = signing_lineage_id(
        child_round.parent_coordinate(),
        child_height,
        fixture.signer(),
    );
    let child_body = signing_lineage_record(child_height, child_id, 0).unwrap();
    let child_state = step_state_id(
        first_state,
        u32::try_from(child_body.len()).unwrap().to_be_bytes(),
        &child_body,
    );
    let complete_length = first_image.len() + 4 + child_body.len() + 32;

    for fault in all_append_faults(4 + child_body.len(), 32) {
        let io = ScriptedIo::from_images(first_image.clone(), first_image.clone());
        let mut core = fixture.replay_scripted(io, first_state).unwrap();
        core.file.inject_fault(fault.clone());
        assert!(
            matches!(
                core.append_signing_lineage(child_height, child_id),
                Err(FixedValidatorVoteSafetyJournalErrorV0::Commit { .. })
            ),
            "fault {fault:?}"
        );
        assert_eq!(core.lineage.unwrap().height, ConsensusHeight::new(1));
        assert_eq!(core.state_id, first_state, "fault {fault:?}");
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        let durable = core.file.durable.clone();
        if durable.len() == complete_length {
            let old_anchor_io = ScriptedIo::from_images(durable.clone(), durable.clone());
            assert!(
                matches!(
                    fixture.replay_scripted(old_anchor_io, first_state),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual,
                    }) if expected == first_state && actual == child_state
                ),
                "fault {fault:?}"
            );
            let exact_anchor_io = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture
                .replay_scripted(exact_anchor_io, child_state)
                .unwrap();
            assert_eq!(reopened.lineage.unwrap().height, child_height);
            assert_eq!(reopened.state_id, child_state);
        } else {
            let replay_io = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(replay_io, first_state).unwrap();
            assert_eq!(
                reopened.lineage.unwrap().height,
                ConsensusHeight::new(1),
                "fault {fault:?}"
            );
            assert_eq!(reopened.file.volatile.get_ref(), &first_image);
        }
    }
}

#[test]
fn every_completion_append_fault_withholds_bytes_and_requires_exact_durable_anchor() {
    let fixture = Fixture::new(2);
    let prefix = fixture.prefix();
    let intent = fixture.nil_prevote_intent();
    let prepare_body = tagged_record(
        PREPARE_RECORD,
        intent.canonical_state_and_vote_intent_bytes(),
        0,
    )
    .unwrap();
    let prepared_state = step_state_id(
        genesis_state_id(&prefix),
        u32::try_from(prepare_body.len()).unwrap().to_be_bytes(),
        &prepare_body,
    );

    for fault in all_append_faults(4 + SIGNED_VOTE_BODY_BYTES, 32) {
        let io = ScriptedIo::new(prefix.clone(), None);
        let mut core = fixture.scripted_core(io);
        let prepared = prepared(core.prepare_vote(intent.clone()).unwrap());
        assert_eq!(prepared.state_id(), prepared_state);
        let prepared_image = core.file.durable.clone();
        core.file = ScriptedIo::new(prepared_image.clone(), Some(fault.clone()));
        let error = core
            .sign_prepared_vote(&fixture.signing_key(), prepared)
            .unwrap_err();
        let proposed_state = match error {
            FixedValidatorVoteSafetyJournalErrorV0::Commit {
                proposed_state_id, ..
            } => proposed_state_id,
            other => panic!("fault {fault:?} returned {other:?}"),
        };
        assert!(matches!(
            core.ensure_healthy(),
            Err(FixedValidatorVoteSafetyJournalErrorV0::Poisoned)
        ));
        let durable = core.file.durable.clone();
        let complete_length = prepared_image.len() + 4 + SIGNED_VOTE_BODY_BYTES + 32;
        if durable.len() == complete_length {
            let stale = ScriptedIo::from_images(durable.clone(), durable.clone());
            assert!(
                matches!(
                    fixture.replay_scripted(stale, prepared_state),
                    Err(FixedValidatorVoteSafetyJournalErrorV0::ExpectedStateIdMismatch {
                        expected,
                        actual
                    }) if expected == prepared_state && actual == proposed_state
                ),
                "fault {fault:?}"
            );
            let exact = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(exact, proposed_state).unwrap();
            assert!(reopened.pending.is_none());
        } else {
            let partial = ScriptedIo::from_images(durable.clone(), durable);
            let reopened = fixture.replay_scripted(partial, prepared_state).unwrap();
            assert!(reopened.restarted_pending().is_some());
            assert_eq!(
                reopened.file.volatile.get_ref(),
                &prepared_image,
                "fault {fault:?}"
            );
        }
    }
}

#[test]
fn recovery_and_stabilization_io_failures_are_reported_without_a_handle() {
    let fixture = Fixture::new(1);
    let prefix = fixture.prefix();
    let genesis = genesis_state_id(&prefix);
    let mut incomplete = prefix.clone();
    incomplete.extend_from_slice(&u32::try_from(MIN_RECORD_BODY_BYTES).unwrap().to_be_bytes());
    incomplete.extend_from_slice(&[PREPARE_RECORD, 0xaa]);
    let mut recovery_io = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_io.set_len_failure = true;
    assert!(matches!(
        fixture.replay_scripted(recovery_io, genesis),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Recovery { .. })
    ));

    let mut stabilize_io = ScriptedIo::from_images(prefix.clone(), prefix);
    stabilize_io.plain_sync_failure = true;
    assert!(matches!(
        fixture.replay_scripted(stabilize_io, genesis),
        Err(FixedValidatorVoteSafetyJournalErrorV0::Stabilize { .. })
    ));
}
