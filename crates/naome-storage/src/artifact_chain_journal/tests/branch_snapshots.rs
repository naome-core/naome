use super::*;

#[test]
fn selected_branch_snapshots_rebuild_for_genesis_and_every_block() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let genesis = definition.id().virtual_genesis_block_id();
    let (payloads, artifact_ids) = dependency_chain_with_len(3);
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();

    let genesis_snapshot = journal.branch_snapshot_at(genesis).unwrap().unwrap();
    assert_eq!(genesis_snapshot.head_block_id(), genesis);
    assert_eq!(
        genesis_snapshot.artifact_set_root(),
        journal.artifact_set_root().unwrap()
    );

    let mut expected = Vec::new();
    let mut selected_blocks = Vec::new();
    for (payload, artifact_id) in payloads.iter().zip(&artifact_ids) {
        let block = journal.prepare_block(*artifact_id).unwrap();
        let block_id = block.id();
        journal.apply_block(&block, payload.clone()).unwrap();
        let root = journal.artifact_set_root().unwrap();
        let snapshot = journal.branch_snapshot_at(block_id).unwrap().unwrap();
        assert_eq!(snapshot.head_block_id(), block_id);
        assert_eq!(snapshot.artifact_set_root(), root);
        expected.push((block_id, root));
        selected_blocks.push(block);
    }

    assert!(
        journal
            .branch_snapshot_at(ArtifactBlockId::from_bytes([0xff; 32]))
            .unwrap()
            .is_none()
    );
    let selected_head = journal.head_block_id().unwrap();
    drop(journal);

    let reopened =
        ArtifactChainJournal::open_verified(&directory.path, definition, selected_head).unwrap();
    assert_eq!(
        reopened
            .branch_snapshot_at(genesis)
            .unwrap()
            .unwrap()
            .head_block_id(),
        genesis
    );
    for (block_id, root) in &expected {
        let snapshot = reopened.branch_snapshot_at(*block_id).unwrap().unwrap();
        assert_eq!(snapshot.head_block_id(), *block_id);
        assert_eq!(snapshot.artifact_set_root(), *root);
    }

    let historical = reopened
        .branch_snapshot_at(selected_blocks[0].id())
        .unwrap()
        .unwrap();
    let advanced = historical
        .validate_child(&selected_blocks[1], payloads[1].clone())
        .unwrap();
    assert_eq!(advanced.head_block_id(), selected_blocks[1].id());

    let later_dependency_candidate = {
        let mut historical_state = ArtifactChainState::new(definition);
        historical_state
            .apply_block(&selected_blocks[0], payloads[0].clone())
            .unwrap();
        historical_state.prepare_block(artifact_ids[2]).unwrap()
    };
    assert!(matches!(
        historical.validate_child(&later_dependency_candidate, payloads[2].clone()),
        Err(ArtifactBlockApplyError::Admission {
            source: LedgerError::ProofCheck { .. }
        })
    ));
}

#[test]
fn candidate_children_are_functional_isolated_and_never_indexed_as_selected() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (payloads, artifact_ids) = dependency_chain_with_len(3);
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();

    let selected_block = journal.prepare_block(artifact_ids[0]).unwrap();
    journal
        .apply_block(&selected_block, payloads[0].clone())
        .unwrap();
    let selected_block_id = selected_block.id();
    let selected_root = journal.artifact_set_root().unwrap();
    let selected_len = journal.len().unwrap();
    let journal_bytes = fs::read(directory.journal_path()).unwrap();
    let predecessor = journal
        .branch_snapshot_at(selected_block_id)
        .unwrap()
        .unwrap();

    let mut fixture = ArtifactChainState::new(definition);
    fixture
        .apply_block(&selected_block, payloads[0].clone())
        .unwrap();
    let first_candidate = fixture.prepare_block(artifact_ids[1]).unwrap();
    fixture
        .apply_block(&first_candidate, payloads[1].clone())
        .unwrap();
    let second_candidate = fixture.prepare_block(artifact_ids[2]).unwrap();
    let sibling_candidate = {
        let mut sibling = ArtifactChainState::new(definition);
        sibling
            .apply_block(&selected_block, payloads[0].clone())
            .unwrap();
        sibling.prepare_block(artifact_ids[2]).unwrap()
    };

    let first = predecessor
        .validate_child(&first_candidate, payloads[1].clone())
        .unwrap();
    let second = first
        .validate_child(&second_candidate, payloads[2].clone())
        .unwrap();
    assert_eq!(predecessor.head_block_id(), selected_block_id);
    assert_eq!(first.head_block_id(), first_candidate.id());
    assert_eq!(second.head_block_id(), second_candidate.id());

    assert!(matches!(
        predecessor.validate_child(&sibling_candidate, payloads[2].clone()),
        Err(ArtifactBlockApplyError::Admission {
            source: LedgerError::ProofCheck { .. }
        })
    ));
    assert_eq!(predecessor.head_block_id(), selected_block_id);
    assert_eq!(journal.head_block_id().unwrap(), selected_block_id);
    assert_eq!(journal.artifact_set_root().unwrap(), selected_root);
    assert_eq!(journal.len().unwrap(), selected_len);
    assert_eq!(fs::read(directory.journal_path()).unwrap(), journal_bytes);
    assert!(
        journal
            .branch_snapshot_at(first_candidate.id())
            .unwrap()
            .is_none()
    );
    assert!(
        journal
            .branch_snapshot_at(second_candidate.id())
            .unwrap()
            .is_none()
    );

    drop(second);
    drop(first);
    drop(predecessor);
    let selected_head = journal.head_block_id().unwrap();
    drop(journal);
    let reopened =
        ArtifactChainJournal::open_verified(&directory.path, definition, selected_head).unwrap();
    assert!(
        reopened
            .branch_snapshot_at(first_candidate.id())
            .unwrap()
            .is_none()
    );
}

#[test]
fn journal_health_precedes_selected_snapshot_lookup() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    journal.core.poisoned = true;

    assert!(matches!(
        journal.branch_snapshot_at(definition.id().virtual_genesis_block_id()),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert!(matches!(
        journal.branch_snapshot_at(ArtifactBlockId::from_bytes([0xff; 32])),
        Err(ArtifactChainJournalError::Poisoned)
    ));
}
