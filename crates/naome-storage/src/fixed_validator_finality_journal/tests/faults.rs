use super::*;

#[cfg(unix)]
#[test]
fn anchor_operation_failures_withhold_finality_until_exact_stabilized_reopen() {
    use crate::fixed_validator_anchor::faults::{Operation, REPLACEMENT_OPERATIONS, inject};

    let fixture = Fixture::new();
    let (expected_state, expected_head, expected_images) = {
        let journal_directory = TestDirectory::new("anchor-fault-finality-control-journal");
        let anchor_directory = TestDirectory::new("anchor-fault-finality-control-anchor");
        let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
        let mut selected = ArtifactChainState::new(fixture.definition);
        let transition =
            fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
        let expected_head = transition.value().ancestry_id();
        assert!(matches!(
            journal.commit_verified(transition).unwrap(),
            FixedValidatorFinalityCommitOutcomeV0::Finalized { .. }
        ));
        (
            journal.state_id().unwrap(),
            expected_head,
            (
                fs::read(journal_directory.journal()).unwrap(),
                fs::read(anchor_directory.finality_anchor()).unwrap(),
            ),
        )
    };

    for operation in REPLACEMENT_OPERATIONS {
        let journal_directory = TestDirectory::new("anchor-fault-finality-journal");
        let anchor_directory = TestDirectory::new("anchor-fault-finality-anchor");
        let anchor_path = anchor_directory.finality_anchor();
        let temporary_path = anchor_directory
            .0
            .join("fixed-validator-finality.anchor.tmp-0000000000000001");
        let images = || {
            (
                fs::read(journal_directory.journal()).unwrap(),
                fs::read(&anchor_path).unwrap(),
            )
        };
        let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
        let before = images();
        let mut selected = ArtifactChainState::new(fixture.definition);
        let transition =
            fixture.transition(journal.head().unwrap(), &mut selected, ZfcAxiom::Pairing, 0);
        let fault = inject(&anchor_path, operation);
        assert!(
            matches!(
                journal.commit_verified(transition),
                Err(FixedValidatorFinalityJournalErrorV0::Commit { .. })
            ),
            "{operation:?}"
        );
        fault.assert_fired();
        drop(fault);
        assert!(matches!(
            journal.head(),
            Err(FixedValidatorFinalityJournalErrorV0::Poisoned)
        ));
        assert!(matches!(
            journal.state_id(),
            Err(FixedValidatorFinalityJournalErrorV0::Poisoned)
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
                    Err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                        FixedValidatorFinalityJournalErrorV0::AnchorBehind {
                            anchored_sequence: 0,
                            journal_sequence: 1
                        }
                    ))
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
                Err(FixedValidatorAnchoredFinalityJournalErrorV0::Anchor(
                    FixedValidatorAnchorErrorV0::Stabilize { .. }
                ))
            ));
            fault.assert_fired();
            drop(fault);
            assert_eq!(images(), after);
        }
        let reopened = fixture
            .open_anchored(&journal_directory, &anchor_directory)
            .unwrap();
        assert_eq!(reopened.state_id().unwrap(), expected_state);
        assert_eq!(reopened.head().unwrap().ancestry_id(), expected_head);
        assert_eq!(reopened.finalized_len().unwrap(), 1);
        assert_eq!(images(), after);
    }
}

#[test]
fn every_candidate_backed_append_fault_poisons_only_finality_and_reopens_exactly() {
    let fixture = Fixture::new();
    let candidate_directory = TestDirectory::new("candidate-backed-fault-candidates");
    let payload_directory = TestDirectory::new("candidate-backed-fault-payloads");
    let mut candidates = create_candidate_store(&candidate_directory, fixture.definition);
    let mut payloads = create_payload_store(&payload_directory);
    let genesis_branch =
        fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
    let prefix = canonical_prefix(
        fixture.context,
        genesis_branch.fixed_agreement_set_id(),
        fixture.limit,
    )
    .unwrap();
    let genesis_id = genesis_state_id(&prefix);
    let genesis_block_id = fixture.definition.id().virtual_genesis_block_id();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let probe = fixture.transition(&genesis_branch, &mut selected, ZfcAxiom::Pairing, 0);
    let proposed_block_id = probe.value().artifact_block().id();
    let canonical_envelope = probe.canonical_envelope_bytes().to_vec();
    retain_transition_inputs(&mut candidates, &mut payloads, &genesis_branch, &probe);
    let candidate_before = candidate_image(&candidate_directory);
    let payload_before = payload_image(&payload_directory);
    let body = canonical_record_body(FINALIZE_RECORD, &probe, 0).unwrap();
    let body_length_bytes = u32::try_from(body.len()).unwrap().to_be_bytes();
    let proposed_state = step_state_id(genesis_id, body_length_bytes, &body);

    for fault in all_append_faults(
        RECORD_LENGTH_BYTES as usize + body.len(),
        STATE_ID_BYTES as usize,
    ) {
        let branch = fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
        let io = ScriptedIo::new(prefix.clone(), Some(fault.clone()));
        let branches = vec![branch];
        let snapshot_index = genesis_snapshot_index(&branches).unwrap();
        let mut core = FixedValidatorFinalityJournalCore::empty(
            io,
            fixture.context,
            fixture.limit,
            branches,
            snapshot_index,
            genesis_id,
        );
        assert!(
            matches!(
                commit_candidate_backed_finality_core_v0(
                    &mut core,
                    &mut candidates,
                    &mut payloads,
                    proposed_block_id,
                    &canonical_envelope,
                    ConsensusRound::new(0),
                ),
                Err(CandidateBackedFinalityErrorV0::FinalityJournal(
                    FixedValidatorFinalityJournalErrorV0::Commit {
                        envelope_id,
                        proposed_state_id,
                        ..
                    }
                )) if envelope_id == probe.envelope_id()
                    && proposed_state_id == proposed_state
            ),
            "fault={fault:?}"
        );
        assert!(core.poisoned, "fault={fault:?}");
        assert_eq!(core.state_id, genesis_id, "fault={fault:?}");
        assert_eq!(core.records.len(), 0, "fault={fault:?}");
        assert_eq!(core.branches.len(), 1, "fault={fault:?}");
        assert_eq!(core.snapshot_index.len(), 1, "fault={fault:?}");
        assert_eq!(
            core.snapshot_index.get(&genesis_block_id),
            Some(&0),
            "fault={fault:?}"
        );
        assert!(
            matches!(
                core.ensure_operational(),
                Err(FixedValidatorFinalityJournalErrorV0::Poisoned)
            ),
            "fault={fault:?}"
        );
        assert!(
            matches!(
                core.reconstruct_selected_transition(ConsensusHeight::new(1)),
                Err(FixedValidatorFinalityJournalErrorV0::Poisoned)
            ),
            "fault={fault:?}"
        );
        assert_eq!(
            candidate_image(&candidate_directory),
            candidate_before,
            "fault={fault:?}"
        );
        assert_eq!(
            payload_image(&payload_directory),
            payload_before,
            "fault={fault:?}"
        );
        assert_eq!(
            candidates.get(proposed_block_id).unwrap(),
            Some(probe.value().artifact_block()),
            "fault={fault:?}"
        );
        assert!(
            payloads
                .get(probe.value().artifact_block().artifact_id())
                .unwrap()
                .is_some(),
            "fault={fault:?}"
        );

        let durable = core.file.durable.clone();
        let durable_commit = matches!(
            fault,
            Fault::SyncAfter {
                phase: AppendPhase::Commit
            }
        );
        let old_anchor = FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(durable.clone(), durable.clone()),
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap()],
            genesis_id,
            None,
        );
        if durable_commit {
            assert!(matches!(
                old_anchor,
                Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
            ));
        } else {
            let old_anchor = old_anchor.unwrap();
            assert_eq!(old_anchor.state_id, genesis_id);
            assert_eq!(old_anchor.snapshot_index.len(), 1);
            assert_eq!(old_anchor.snapshot_index.get(&genesis_block_id), Some(&0));
        }

        let new_anchor = FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(durable.clone(), durable),
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap()],
            proposed_state,
            None,
        );
        if durable_commit {
            let new_anchor = new_anchor.unwrap();
            assert_eq!(new_anchor.state_id, proposed_state);
            assert_eq!(new_anchor.snapshot_index.len(), 2);
            assert_eq!(new_anchor.snapshot_index.get(&genesis_block_id), Some(&0));
            assert_eq!(new_anchor.snapshot_index.get(&proposed_block_id), Some(&1));
            assert!(
                new_anchor
                    .reconstruct_selected_transition(ConsensusHeight::new(1))
                    .is_ok()
            );
        } else {
            assert!(matches!(
                new_anchor,
                Err(FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch { .. })
            ));
        }
    }
}

#[test]
fn every_preselection_conflict_append_fault_poisons_and_reopens_only_from_exact_anchor() {
    let fixture = Fixture::new();
    let genesis_branch =
        fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
    let prefix = canonical_prefix(
        fixture.context,
        genesis_branch.fixed_agreement_set_id(),
        fixture.limit,
    )
    .unwrap();
    let genesis_id = genesis_state_id(&prefix);
    let genesis_block_id = fixture.definition.id().virtual_genesis_block_id();
    let (probe_left, probe_right) = fixture.preselection_conflict_pair(&genesis_branch, 2);
    let (probe_first, probe_second) = if probe_left.value().proposal_signing_root()
        < probe_right.value().proposal_signing_root()
    {
        (&probe_left, &probe_right)
    } else {
        (&probe_right, &probe_left)
    };
    let first_envelope_id = probe_first.envelope_id();
    let second_envelope_id = probe_second.envelope_id();
    let body = canonical_preselection_conflict_record_body(probe_first, probe_second, 0).unwrap();
    let body_length_bytes = u32::try_from(body.len()).unwrap().to_be_bytes();
    let proposed_state = step_state_id(genesis_id, body_length_bytes, &body);

    for fault in all_append_faults(
        RECORD_LENGTH_BYTES as usize + body.len(),
        STATE_ID_BYTES as usize,
    ) {
        let branch = fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
        let io = ScriptedIo::new(prefix.clone(), Some(fault.clone()));
        let branches = vec![branch.clone()];
        let snapshot_index = genesis_snapshot_index(&branches).unwrap();
        let mut core = FixedValidatorFinalityJournalCore::empty(
            io,
            fixture.context,
            fixture.limit,
            branches,
            snapshot_index,
            genesis_id,
        );
        let (left, right) = fixture.preselection_conflict_pair(&branch, 2);
        assert!(
            matches!(
                core.commit_verified_preselection_conflict(right, left),
                Err(FixedValidatorFinalityJournalErrorV0::PairedCommit {
                    first_envelope_id: actual_first,
                    second_envelope_id: actual_second,
                    proposed_state_id,
                    ..
                }) if actual_first == first_envelope_id
                    && actual_second == second_envelope_id
                    && proposed_state_id == proposed_state
            ),
            "fault={fault:?}"
        );
        assert!(core.poisoned, "fault={fault:?}");
        assert_eq!(core.state_id, genesis_id, "fault={fault:?}");
        assert_eq!(core.record_sequence, 0, "fault={fault:?}");
        assert_eq!(core.halt, None, "fault={fault:?}");
        assert_eq!(core.records.len(), 0, "fault={fault:?}");
        assert_eq!(core.branches.len(), 1, "fault={fault:?}");
        assert_eq!(core.snapshot_index.len(), 1, "fault={fault:?}");
        assert_eq!(
            core.snapshot_index.get(&genesis_block_id),
            Some(&0),
            "fault={fault:?}"
        );
        assert!(
            matches!(
                core.ensure_operational(),
                Err(FixedValidatorFinalityJournalErrorV0::Poisoned)
            ),
            "fault={fault:?}"
        );

        let durable = core.file.durable.clone();
        let durable_commit = matches!(
            fault,
            Fault::SyncAfter {
                phase: AppendPhase::Commit
            }
        );
        let old_anchor = FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(durable.clone(), durable.clone()),
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap()],
            genesis_id,
            Some(0),
        );
        if durable_commit {
            assert!(
                matches!(
                    old_anchor,
                    Err(FixedValidatorFinalityJournalErrorV0::AnchorBehind {
                        anchored_sequence: 0,
                        journal_sequence: 1,
                    })
                ),
                "fault={fault:?}"
            );
        } else {
            let old_anchor = old_anchor.unwrap();
            assert_eq!(old_anchor.state_id, genesis_id, "fault={fault:?}");
            assert_eq!(old_anchor.record_sequence, 0, "fault={fault:?}");
            assert_eq!(old_anchor.halt, None, "fault={fault:?}");
            assert_eq!(old_anchor.records.len(), 0, "fault={fault:?}");
            assert_eq!(old_anchor.branches.len(), 1, "fault={fault:?}");
            assert_eq!(old_anchor.snapshot_index.len(), 1, "fault={fault:?}");
            assert_eq!(old_anchor.file.durable, prefix, "fault={fault:?}");
        }

        let new_anchor = FixedValidatorFinalityJournalCore::replay(
            ScriptedIo::from_images(durable.clone(), durable),
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap()],
            proposed_state,
            Some(1),
        );
        if durable_commit {
            let new_anchor = new_anchor.unwrap();
            assert_eq!(new_anchor.state_id, proposed_state, "fault={fault:?}");
            assert_eq!(new_anchor.record_sequence, 1, "fault={fault:?}");
            assert_eq!(
                new_anchor.halt.unwrap().kind(),
                FixedValidatorFinalityHaltKindV0::PreselectionPair,
                "fault={fault:?}"
            );
            assert_eq!(new_anchor.records.len(), 0, "fault={fault:?}");
            assert_eq!(new_anchor.branches.len(), 1, "fault={fault:?}");
            assert_eq!(new_anchor.snapshot_index.len(), 1, "fault={fault:?}");
            assert_eq!(
                new_anchor.snapshot_index.get(&genesis_block_id),
                Some(&0),
                "fault={fault:?}"
            );
        } else {
            assert!(
                matches!(
                    new_anchor,
                    Err(FixedValidatorFinalityJournalErrorV0::AnchorAhead {
                        anchored_sequence: 1,
                        journal_sequence: 0,
                    })
                ),
                "fault={fault:?}"
            );
        }
    }
}

#[test]
fn replay_recovery_and_stabilization_io_fail_closed() {
    let fixture = Fixture::new();
    let branch = fixed_genesis(fixture.definition, fixture.context, &fixture.entries).unwrap();
    let prefix = canonical_prefix(
        fixture.context,
        branch.fixed_agreement_set_id(),
        fixture.limit,
    )
    .unwrap();
    let genesis = genesis_state_id(&prefix);

    let mut incomplete = prefix.clone();
    incomplete.push(0);
    let mut recovery_io = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_io.set_len_failure = true;
    assert!(matches!(
        FixedValidatorFinalityJournalCore::replay(
            recovery_io,
            fixture.context,
            fixture.limit,
            prefix.clone(),
            vec![branch.clone()],
            genesis,
            None,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::Recovery { .. })
    ));

    let mut stabilize_io = ScriptedIo::from_images(prefix.clone(), prefix.clone());
    stabilize_io.plain_sync_failure = true;
    assert!(matches!(
        FixedValidatorFinalityJournalCore::replay(
            stabilize_io,
            fixture.context,
            fixture.limit,
            prefix,
            vec![branch],
            genesis,
            None,
        ),
        Err(FixedValidatorFinalityJournalErrorV0::Stabilize { .. })
    ));
}
