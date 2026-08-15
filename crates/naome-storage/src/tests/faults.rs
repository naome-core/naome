use super::*;
use crate::fault_io::{Fault, ScriptedIo, Trace, all_append_faults};

fn scripted_io(id: ArtifactChainId, fault: Option<Fault>) -> ScriptedIo {
    ScriptedIo::new(journal_prefix(id), fault)
}

#[test]
fn block_rejection_consumes_no_journal_io_or_fault() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let (payloads, artifact_ids) = dependency_chain_with_len(1);
    let state = ArtifactChainState::new(definition);
    let block = prepared_block(&state, artifact_ids[0]);
    let stale = ArtifactBlock::new(
        ArtifactBlockId::from_bytes([0xaa; 32]),
        block.previous_artifact_set_root(),
        block.resulting_artifact_set_root(),
        block.artifact_id(),
    );
    let fault = Fault::SyncBefore {
        phase: AppendPhase::Body,
    };
    let mut core = JournalCore::empty(scripted_io(id, Some(fault.clone())), state);
    let before = core.file.volatile.get_ref().clone();

    assert!(matches!(
        core.apply_block(&stale, vec![0x00]),
        Err(ArtifactChainJournalError::BlockAdmission {
            source: ArtifactBlockApplyError::ParentBlockIdMismatch { .. }
        })
    ));
    assert!(core.file.trace.is_empty());
    assert_eq!(core.file.fault(), Some(&fault));
    assert_eq!(core.file.volatile.get_ref(), &before);
    assert_eq!(core.committed_end, JOURNAL_PREFIX_BYTES as u64);
    assert!(core.chain.artifact_dag().is_empty());
    assert!(core.blocks.is_empty());
    assert!(core.ensure_healthy().is_ok());

    core.apply_block(&block, artifact_bytes(&payloads[0]))
        .unwrap_err();
    assert!(core.file.fault().is_none());
    assert!(matches!(
        core.ensure_healthy(),
        Err(ArtifactChainJournalError::Poisoned)
    ));
}

#[test]
fn append_barriers_are_ordered_and_every_ambiguous_failure_replays_old_or_new() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let (payloads, artifact_ids) = dependency_chain_with_len(1);
    let block = one_block(definition, artifact_ids[0]);
    let block_bytes = block.to_canonical_bytes();
    let body_write_bytes = 4 + block_bytes.len() + payloads[0].len();
    let faults = all_append_faults(body_write_bytes, 32);

    for fault in faults {
        let mut core = JournalCore::empty(
            scripted_io(id, Some(fault.clone())),
            ArtifactChainState::new(definition),
        );
        assert!(
            matches!(
                core.apply_block(&block, artifact_bytes(&payloads[0])),
                Err(ArtifactChainJournalError::Commit {
                    block_id,
                    ..
                }) if block_id == block.id()
            ),
            "fault={fault:?}"
        );
        assert!(core.file.fault().is_none(), "fault={fault:?}");
        assert!(matches!(
            core.ensure_healthy(),
            Err(ArtifactChainJournalError::Poisoned)
        ));
        assert!(core.blocks.is_empty(), "fault={fault:?}");

        let durable = core.file.durable.clone();
        let replay = JournalCore::replay(
            ScriptedIo::from_images(durable.clone(), durable),
            definition,
            None,
        )
        .unwrap();
        let expected_new = matches!(
            fault,
            Fault::SyncAfter {
                phase: AppendPhase::Commit
            }
        );
        assert_eq!(
            replay.chain.artifact_dag().len(),
            usize::from(expected_new),
            "fault={fault:?}"
        );
        assert_eq!(
            replay.chain.head_block_id(),
            if expected_new {
                block.id()
            } else {
                ArtifactChainState::new(definition).head_block_id()
            },
            "fault={fault:?}"
        );
        assert_eq!(
            replay.blocks.get(&block.id()),
            expected_new.then_some(&block),
            "fault={fault:?}"
        );
    }
}

#[test]
fn successful_commit_streams_body_then_two_sync_barriers_then_footer() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let (payloads, artifact_ids) = dependency_chain_with_len(1);
    let block = one_block(definition, artifact_ids[0]);
    let block_len = block.to_canonical_bytes().len();
    let mut core = JournalCore::empty(scripted_io(id, None), ArtifactChainState::new(definition));

    core.apply_block(&block, artifact_bytes(&payloads[0]))
        .unwrap();
    assert_eq!(
        core.file.trace,
        vec![
            Trace::Write(AppendPhase::Body, 4),
            Trace::Write(AppendPhase::Body, block_len),
            Trace::Write(AppendPhase::Body, payloads[0].len()),
            Trace::Sync(AppendPhase::Body),
            Trace::Write(AppendPhase::Commit, 32),
            Trace::Sync(AppendPhase::Commit),
        ]
    );
    assert_eq!(
        core.file.durable,
        journal_image(id, &[(block, payloads[0].clone(), artifact_ids[0])])
    );
    assert_eq!(core.chain.head_block_id(), block.id());
    assert_eq!(core.blocks.get(&block.id()), Some(&block));
}

#[test]
fn replay_recovery_and_stabilization_fail_without_returning_a_handle() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let (payloads, artifact_ids) = dependency_chain_with_len(1);
    let block = one_block(definition, artifact_ids[0]);
    let complete = journal_image(id, &[(block, payloads[0].clone(), artifact_ids[0])]);

    let mut stabilization = ScriptedIo::from_images(complete.clone(), complete.clone());
    stabilization.plain_sync_failure = true;
    assert!(matches!(
        JournalCore::replay(stabilization, definition, None),
        Err(ArtifactChainJournalError::Stabilize { .. })
    ));

    let incomplete = complete[..complete.len() - 1].to_vec();
    let mut truncation = ScriptedIo::from_images(incomplete.clone(), incomplete.clone());
    truncation.set_len_failure = true;
    assert!(matches!(
        JournalCore::replay(truncation, definition, None),
        Err(ArtifactChainJournalError::Recovery { .. })
    ));

    let mut recovery_sync = ScriptedIo::from_images(incomplete.clone(), incomplete);
    recovery_sync.plain_sync_failure = true;
    assert!(matches!(
        JournalCore::replay(recovery_sync, definition, None),
        Err(ArtifactChainJournalError::Recovery { .. })
    ));
}

#[test]
fn complete_bad_footer_is_not_recovered_but_incomplete_footer_is() {
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let (payloads, artifact_ids) = dependency_chain_with_len(1);
    let block = one_block(definition, artifact_ids[0]);
    let complete = journal_image(id, &[(block, payloads[0].clone(), artifact_ids[0])]);

    let incomplete = complete[..complete.len() - 1].to_vec();
    let recovered = JournalCore::replay(
        ScriptedIo::from_images(incomplete.clone(), incomplete),
        definition,
        None,
    )
    .unwrap();
    assert!(recovered.chain.artifact_dag().is_empty());
    assert!(recovered.blocks.is_empty());
    assert_eq!(recovered.file.durable, journal_prefix(id));

    let mut corrupt = complete.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(matches!(
        JournalCore::replay(
            ScriptedIo::from_images(corrupt.clone(), corrupt),
            definition,
            None,
        ),
        Err(ArtifactChainJournalError::BlockIdMismatch { entry: 0, .. })
    ));
}

#[test]
fn poisoned_public_handle_exposes_only_chain_context_and_keeps_lock() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let id = definition.id();
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_id).unwrap();
    journal.apply_block(&block, payload.clone()).unwrap();
    let block_id = block.id();
    assert_eq!(journal.block(block_id).unwrap(), Some(&block));
    journal.core.poisoned = true;

    assert_eq!(journal.chain_id(), id);
    assert!(matches!(
        journal.block(block_id),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.head_block_id(),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.artifact(artifact_id),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.artifact_state(),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.len(),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.is_empty(),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.artifact_set_root(),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.artifact_set_proof(artifact_id),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.prepare_block(artifact_id),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.apply_block(&block, payload),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        ArtifactChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ArtifactChainJournalError::Locked)
    ));
}
