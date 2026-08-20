use std::io::{Read, Seek, SeekFrom, Write};

use naome_chain::ARTIFACT_BLOCK_BYTES;
use naome_checker::CheckError;

use super::*;
use crate::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreLimits, ArtifactPayloadInsertOutcome, ArtifactPayloadStoreLimits,
    CandidatePayloadArchiveError, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError,
};

const CANDIDATE_STORE_FILE_NAME: &str = "artifact-block-candidate-store.log";
const PAYLOAD_STORE_FILE_NAME: &str = "artifact-payload-store.log";

fn candidate_limits(entries: usize) -> ArtifactBlockCandidateStoreLimits {
    ArtifactBlockCandidateStoreLimits::new(entries).unwrap()
}

fn payload_limits(entries: usize, payload_bytes: u64) -> ArtifactPayloadStoreLimits {
    ArtifactPayloadStoreLimits::new(entries, payload_bytes).unwrap()
}

fn archive_payloads(
    store: &mut CanonicalArtifactPayloadStore,
    payloads: &[Vec<u8>],
    expected_ids: &[ArtifactId],
) {
    assert_eq!(payloads.len(), expected_ids.len());
    let mut source = ArtifactDag::new();
    for (payload, expected_id) in payloads.iter().zip(expected_ids.iter().copied()) {
        let record = source
            .apply_canonical_artifact_bytes_with_expected_id(payload.clone(), expected_id)
            .unwrap();
        assert_eq!(
            store.insert(record).unwrap(),
            ArtifactPayloadInsertOutcome::Inserted
        );
    }
}

fn artifact_ids(payloads: &[Vec<u8>]) -> Vec<ArtifactId> {
    let mut dag = ArtifactDag::new();
    payloads
        .iter()
        .map(|payload| {
            dag.apply_canonical_artifact_bytes(payload.clone())
                .unwrap()
                .artifact_id()
        })
        .collect()
}

fn load_payload(store: &mut CanonicalArtifactPayloadStore, artifact_id: ArtifactId) -> Vec<u8> {
    let payload = store.get(artifact_id).unwrap().unwrap();
    assert_eq!(payload.artifact_id(), artifact_id);
    payload.into_canonical_artifact_bytes().into_vec()
}

fn load_block(store: &mut ArtifactBlockCandidateStore, block_id: ArtifactBlockId) -> ArtifactBlock {
    let block = store.get(block_id).unwrap().unwrap();
    assert_eq!(block.id(), block_id);
    block
}

fn assert_empty_journal_unchanged(
    journal: &ArtifactChainJournal,
    directory: &TestDirectory,
    image: &[u8],
    head: ArtifactBlockId,
    root: ArtifactSetRoot,
    artifact_ids: &[ArtifactId],
    witnesses: &[Vec<u8>],
) {
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
    assert_eq!(journal.head_block_id().unwrap(), head);
    assert_eq!(journal.artifact_set_root().unwrap(), root);
    assert_eq!(journal.len().unwrap(), 0);
    assert!(journal.is_empty().unwrap());
    for (artifact_id, witness) in artifact_ids.iter().copied().zip(witnesses) {
        assert!(journal.artifact(artifact_id).unwrap().is_none());
        assert_eq!(
            journal
                .artifact_set_proof(artifact_id)
                .unwrap()
                .to_canonical_bytes(),
            *witness
        );
    }
}

#[test]
fn validated_direct_child_payloads_archive_idempotently_without_selection() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payloads = vec![axiom_bytes(ZfcAxiom::Pairing), relation_definition_bytes()];
    let artifact_ids = artifact_ids(&payloads);
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let blocks = artifact_ids
        .iter()
        .copied()
        .map(|artifact_id| journal.prepare_block(artifact_id).unwrap())
        .collect::<Vec<_>>();
    let mut payload_store = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(
            payloads.len(),
            payloads.iter().map(Vec::len).sum::<usize>() as u64,
        ),
    )
    .unwrap();
    let journal_image = fs::read(directory.journal_path()).unwrap();
    let head = journal.head_block_id().unwrap();
    let root = journal.artifact_set_root().unwrap();

    for ((block, payload), artifact_id) in blocks
        .iter()
        .zip(&payloads)
        .zip(artifact_ids.iter().copied())
    {
        assert_eq!(
            payload_store
                .validate_and_insert_candidate_payload(&journal, block, payload.clone())
                .unwrap(),
            ArtifactPayloadInsertOutcome::Inserted
        );
        let archived = payload_store.get(artifact_id).unwrap().unwrap();
        assert_eq!(archived.artifact_id(), artifact_id);
        assert_eq!(archived.canonical_artifact_bytes(), payload);
    }

    assert_eq!(journal.head_block_id().unwrap(), head);
    assert_eq!(journal.artifact_set_root().unwrap(), root);
    assert!(journal.is_empty().unwrap());
    assert_eq!(fs::read(directory.journal_path()).unwrap(), journal_image);

    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    assert_eq!(
        payload_store
            .validate_and_insert_candidate_payload(&journal, &blocks[0], payloads[0].clone())
            .unwrap(),
        ArtifactPayloadInsertOutcome::AlreadyPresent
    );
    assert_eq!(payload_store.len().unwrap(), payloads.len());
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
    assert_eq!(fs::read(directory.journal_path()).unwrap(), journal_image);
}

#[test]
fn rejected_candidate_payload_archives_nothing_and_remains_retryable() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_ids(std::slice::from_ref(&payload))[0];
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_id).unwrap();
    let mut payload_store = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(1, payload.len() as u64),
    )
    .unwrap();
    let journal_image = fs::read(directory.journal_path()).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let wrong_payload = relation_definition_bytes();

    assert!(matches!(
        payload_store.validate_and_insert_candidate_payload(&journal, &block, wrong_payload),
        Err(CandidatePayloadArchiveError::Validation { source })
            if matches!(
                source.as_ref(),
                ArtifactChainJournalError::BlockAdmission {
                    source: ArtifactBlockApplyError::Admission {
                        source: LedgerError::ArtifactIdMismatch {
                            expected,
                            actual: _,
                        },
                    },
                } if *expected == artifact_id
            )
    ));
    assert!(payload_store.is_empty().unwrap());
    assert_eq!(fs::read(directory.journal_path()).unwrap(), journal_image);
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );

    assert_eq!(
        payload_store
            .validate_and_insert_candidate_payload(&journal, &block, payload)
            .unwrap(),
        ArtifactPayloadInsertOutcome::Inserted
    );
    assert!(journal.is_empty().unwrap());
    assert_eq!(fs::read(directory.journal_path()).unwrap(), journal_image);
}

#[test]
fn oversized_candidate_payload_returns_exact_validation_error_without_mutation() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_ids(std::slice::from_ref(&payload))[0];
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_id).unwrap();
    let mut payload_store = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(1, payload.len() as u64),
    )
    .unwrap();
    let journal_image = fs::read(directory.journal_path()).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let oversized_len = ARTIFACT_PAYLOAD_MAX_BYTES + 1;

    assert!(matches!(
        payload_store.validate_and_insert_candidate_payload(
            &journal,
            &block,
            vec![0; oversized_len],
        ),
        Err(CandidatePayloadArchiveError::Validation { source })
            if matches!(
                source.as_ref(),
                ArtifactChainJournalError::BlockAdmission {
                    source: ArtifactBlockApplyError::Admission {
                        source: LedgerError::Decode {
                            source: ArtifactPayloadError::InputTooLong { actual, maximum },
                        },
                    },
                } if *actual == oversized_len && *maximum == ARTIFACT_PAYLOAD_MAX_BYTES
            )
    ));
    assert!(journal.is_empty().unwrap());
    assert!(payload_store.is_empty().unwrap());
    assert_eq!(fs::read(directory.journal_path()).unwrap(), journal_image);
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
}

#[test]
fn archive_policy_failure_follows_validation_and_does_not_select() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_ids(std::slice::from_ref(&payload))[0];
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_id).unwrap();
    let mut payload_store = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(1, u64::try_from(payload.len() - 1).unwrap()),
    )
    .unwrap();
    let journal_image = fs::read(directory.journal_path()).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();

    assert!(matches!(
        payload_store.validate_and_insert_candidate_payload(&journal, &block, payload),
        Err(CandidatePayloadArchiveError::Archive { source })
            if matches!(
                source.as_ref(),
                CanonicalArtifactPayloadStoreError::PayloadByteLimitExceeded {
                    actual,
                    maximum,
                } if *actual == *maximum + 1
            )
    ));
    assert!(journal.is_empty().unwrap());
    assert!(payload_store.is_empty().unwrap());
    assert_eq!(fs::read(directory.journal_path()).unwrap(), journal_image);
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
}

#[test]
fn poisoned_archive_precedes_invalid_candidate_validation() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_ids(std::slice::from_ref(&payload))[0];
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_id).unwrap();
    let mut payload_store = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(1, payload.len() as u64),
    )
    .unwrap();
    archive_payloads(
        &mut payload_store,
        std::slice::from_ref(&payload),
        std::slice::from_ref(&artifact_id),
    );

    let payload_path = directory.path.join(PAYLOAD_STORE_FILE_NAME);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&payload_path)
        .unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut changed = [0_u8; 1];
    file.read_exact(&mut changed).unwrap();
    changed[0] ^= 0xff;
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&changed).unwrap();
    file.sync_all().unwrap();
    assert!(matches!(
        payload_store.get(artifact_id),
        Err(CanonicalArtifactPayloadStoreError::StoredEntryChanged {
            artifact_id: actual,
        }) if actual == artifact_id
    ));

    assert!(matches!(
        payload_store.validate_and_insert_candidate_payload(&journal, &block, vec![0]),
        Err(CandidatePayloadArchiveError::Archive { source })
            if matches!(
                source.as_ref(),
                CanonicalArtifactPayloadStoreError::Poisoned
            )
    ));
    assert!(journal.is_empty().unwrap());
}

#[test]
fn stale_direct_child_is_rejected_without_archive_mutation() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let candidate_payload = axiom_bytes(ZfcAxiom::Pairing);
    let selected_payload = axiom_bytes(ZfcAxiom::Union);
    let artifact_ids = artifact_ids(&[candidate_payload.clone(), selected_payload.clone()]);
    let candidate_id = artifact_ids[0];
    let selected_id = artifact_ids[1];
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let candidate = journal.prepare_block(candidate_id).unwrap();
    let selected = journal.prepare_block(selected_id).unwrap();
    journal.apply_block(&selected, selected_payload).unwrap();
    let mut payload_store = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(1, candidate_payload.len() as u64),
    )
    .unwrap();
    let journal_image = fs::read(directory.journal_path()).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();

    assert!(matches!(
        payload_store.validate_and_insert_candidate_payload(
            &journal,
            &candidate,
            candidate_payload,
        ),
        Err(CandidatePayloadArchiveError::Validation { source })
            if matches!(
                source.as_ref(),
                ArtifactChainJournalError::BlockAdmission {
                    source: ArtifactBlockApplyError::ParentBlockIdMismatch {
                        expected,
                        actual,
                    },
                } if *expected == selected.id() && *actual == candidate.parent_block_id()
            )
    ));
    assert_eq!(journal.head_block_id().unwrap(), selected.id());
    assert!(payload_store.is_empty().unwrap());
    assert_eq!(fs::read(directory.journal_path()).unwrap(), journal_image);
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
}

#[test]
fn stored_single_artifact_candidate_validation_is_repeatable_and_changes_no_store() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (payloads, artifact_ids) = dependency_chain_with_len(1);
    let total_payload_bytes = payloads.iter().map(Vec::len).sum::<usize>() as u64;
    let journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_ids[0]).unwrap();
    assert_eq!(block.to_canonical_bytes().len(), ARTIFACT_BLOCK_BYTES);

    let mut candidate_store =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(1))
            .unwrap();
    assert_eq!(
        candidate_store.insert(&block).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    let mut payload_store = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(1, total_payload_bytes),
    )
    .unwrap();
    archive_payloads(&mut payload_store, &payloads, &artifact_ids);

    let journal_image = fs::read(directory.journal_path()).unwrap();
    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let head = journal.head_block_id().unwrap();
    let root = journal.artifact_set_root().unwrap();
    let witnesses = artifact_ids
        .iter()
        .map(|artifact_id| {
            journal
                .artifact_set_proof(*artifact_id)
                .unwrap()
                .to_canonical_bytes()
        })
        .collect::<Vec<_>>();

    for _ in 0..2 {
        let loaded_block = load_block(&mut candidate_store, block.id());
        journal
            .validate_block(
                &loaded_block,
                load_payload(&mut payload_store, artifact_ids[0]),
            )
            .unwrap();
        assert_empty_journal_unchanged(
            &journal,
            &directory,
            &journal_image,
            head,
            root,
            &artifact_ids,
            &witnesses,
        );
    }

    assert_eq!(candidate_store.len().unwrap(), 1);
    assert_eq!(payload_store.len().unwrap(), 1);
    assert_eq!(
        payload_store.total_payload_bytes().unwrap(),
        total_payload_bytes
    );
    assert_eq!(
        fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
}

#[test]
fn stored_siblings_validate_independently_then_fail_as_stale_direct_children() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payloads = vec![
        axiom_bytes(ZfcAxiom::Pairing),
        axiom_bytes(ZfcAxiom::Union),
        axiom_bytes(ZfcAxiom::PowerSet),
    ];
    let artifact_ids = artifact_ids(&payloads);
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let sibling_a = journal.prepare_block(artifact_ids[0]).unwrap();
    let sibling_b = journal.prepare_block(artifact_ids[1]).unwrap();

    let mut branch_b = ArtifactChainState::new(definition);
    branch_b
        .apply_block(&sibling_b, payloads[1].clone())
        .unwrap();
    let child_of_b = branch_b.prepare_block(artifact_ids[2]).unwrap();

    let blocks = [&sibling_a, &sibling_b, &child_of_b];
    let mut candidate_store = ArtifactBlockCandidateStore::create(
        &directory.path,
        definition,
        candidate_limits(blocks.len()),
    )
    .unwrap();
    for block in blocks {
        assert_eq!(
            candidate_store.insert(block).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
    }
    let mut payload_store = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(
            payloads.len(),
            payloads.iter().map(Vec::len).sum::<usize>() as u64,
        ),
    )
    .unwrap();
    archive_payloads(&mut payload_store, &payloads, &artifact_ids);

    let initial_journal_image = fs::read(directory.journal_path()).unwrap();
    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let genesis = journal.head_block_id().unwrap();
    let empty_root = journal.artifact_set_root().unwrap();

    for (block, artifact_id) in [(&sibling_a, artifact_ids[0]), (&sibling_b, artifact_ids[1])] {
        journal
            .validate_block(
                &load_block(&mut candidate_store, block.id()),
                load_payload(&mut payload_store, artifact_id),
            )
            .unwrap();
        assert_eq!(journal.head_block_id().unwrap(), genesis);
        assert_eq!(journal.artifact_set_root().unwrap(), empty_root);
        assert_eq!(
            fs::read(directory.journal_path()).unwrap(),
            initial_journal_image
        );
    }

    assert!(matches!(
        journal.validate_block(
            &load_block(&mut candidate_store, child_of_b.id()),
            load_payload(&mut payload_store, artifact_ids[2]),
        ),
        Err(ArtifactChainJournalError::BlockAdmission {
            source: ArtifactBlockApplyError::ParentBlockIdMismatch {
                expected,
                actual,
            },
        }) if expected == genesis && actual == sibling_b.id()
    ));
    assert_eq!(
        fs::read(directory.journal_path()).unwrap(),
        initial_journal_image
    );

    journal
        .apply_block(
            &sibling_a,
            load_payload(&mut payload_store, artifact_ids[0]),
        )
        .unwrap();
    let selected_image = fs::read(directory.journal_path()).unwrap();
    let selected_root = journal.artifact_set_root().unwrap();

    for stale in [&sibling_a, &sibling_b, &child_of_b] {
        assert!(matches!(
            journal.validate_block(&load_block(&mut candidate_store, stale.id()), vec![0]),
            Err(ArtifactChainJournalError::BlockAdmission {
                source: ArtifactBlockApplyError::ParentBlockIdMismatch {
                    expected,
                    actual,
                },
            }) if expected == sibling_a.id() && actual == stale.parent_block_id()
        ));
        assert_eq!(journal.head_block_id().unwrap(), sibling_a.id());
        assert_eq!(journal.artifact_set_root().unwrap(), selected_root);
        assert_eq!(fs::read(directory.journal_path()).unwrap(), selected_image);
    }
    assert_eq!(journal.block(sibling_a.id()).unwrap(), Some(&sibling_a));
    assert_eq!(journal.block(sibling_b.id()).unwrap(), None);
    assert_eq!(journal.block(child_of_b.id()).unwrap(), None);
    assert_eq!(
        fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap(),
        candidate_image
    );
    assert_eq!(
        fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap(),
        payload_image
    );
}

#[test]
fn archived_payload_is_revalidated_against_the_selected_proof_context() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (payloads, artifact_ids) = dependency_chain_with_len(2);
    let dependency_id = artifact_ids[0];
    let child_id = artifact_ids[1];
    let dependency_proof_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payloads[0].clone())
        .unwrap()
        .as_proof()
        .unwrap()
        .proof_id();
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let child_only = journal.prepare_block(child_id).unwrap();
    let mut candidate_store =
        ArtifactBlockCandidateStore::create(&directory.path, definition, candidate_limits(2))
            .unwrap();
    assert_eq!(
        candidate_store.insert(&child_only).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    let mut payload_store = CanonicalArtifactPayloadStore::create(
        &directory.path,
        payload_limits(
            payloads.len(),
            payloads.iter().map(Vec::len).sum::<usize>() as u64,
        ),
    )
    .unwrap();
    archive_payloads(&mut payload_store, &payloads, &artifact_ids);

    let initial_image = fs::read(directory.journal_path()).unwrap();
    assert!(matches!(
        journal.validate_block(
            &load_block(&mut candidate_store, child_only.id()),
            load_payload(&mut payload_store, child_id),
        ),
        Err(ArtifactChainJournalError::BlockAdmission {
            source: ArtifactBlockApplyError::Admission {
                source: LedgerError::ProofCheck {
                    source: CheckError::UnknownProofReference {
                        step: 0,
                        proof_id: actual_dependency,
                    },
                },
            },
        }) if actual_dependency == dependency_proof_id
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), initial_image);
    assert!(journal.is_empty().unwrap());

    let dependency_block = journal.prepare_block(dependency_id).unwrap();
    journal
        .apply_block(
            &dependency_block,
            load_payload(&mut payload_store, dependency_id),
        )
        .unwrap();
    let child_after_dependency = journal.prepare_block(child_id).unwrap();
    assert_eq!(
        candidate_store.insert(&child_after_dependency).unwrap(),
        ArtifactBlockCandidateInsertOutcome::Inserted
    );
    let selected_image = fs::read(directory.journal_path()).unwrap();
    let selected_root = journal.artifact_set_root().unwrap();

    journal
        .validate_block(
            &load_block(&mut candidate_store, child_after_dependency.id()),
            load_payload(&mut payload_store, child_id),
        )
        .unwrap();
    assert_eq!(journal.head_block_id().unwrap(), dependency_block.id());
    assert_eq!(journal.artifact_set_root().unwrap(), selected_root);
    assert_eq!(journal.len().unwrap(), 1);
    assert!(journal.artifact(child_id).unwrap().is_none());
    assert_eq!(fs::read(directory.journal_path()).unwrap(), selected_image);

    assert!(matches!(
        journal.validate_block(
            &load_block(&mut candidate_store, child_only.id()),
            load_payload(&mut payload_store, child_id),
        ),
        Err(ArtifactChainJournalError::BlockAdmission {
            source: ArtifactBlockApplyError::ParentBlockIdMismatch { .. },
        })
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), selected_image);
}

#[test]
fn journal_validation_matches_apply_errors_and_remains_retryable() {
    let validation_directory = TestDirectory::new();
    let application_directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_ids(std::slice::from_ref(&payload))[0];
    let validation_journal =
        ArtifactChainJournal::create(&validation_directory.path, definition).unwrap();
    let mut application_journal =
        ArtifactChainJournal::create(&application_directory.path, definition).unwrap();
    let block = validation_journal.prepare_block(artifact_id).unwrap();
    let validation_image = fs::read(validation_directory.journal_path()).unwrap();
    let application_image = fs::read(application_directory.journal_path()).unwrap();

    let validation_error = validation_journal
        .validate_block(&block, vec![0])
        .unwrap_err();
    let application_error = application_journal
        .apply_block(&block, vec![0])
        .unwrap_err();
    let unwrap_admission = |error| match error {
        ArtifactChainJournalError::BlockAdmission { source } => source,
        other => panic!("expected block-admission error, got {other}"),
    };
    assert_eq!(
        unwrap_admission(validation_error),
        unwrap_admission(application_error)
    );
    assert_eq!(
        fs::read(validation_directory.journal_path()).unwrap(),
        validation_image
    );
    assert_eq!(
        fs::read(application_directory.journal_path()).unwrap(),
        application_image
    );

    validation_journal
        .validate_block(&block, payload.clone())
        .unwrap();
    assert!(validation_journal.is_empty().unwrap());
    assert_eq!(
        fs::read(validation_directory.journal_path()).unwrap(),
        validation_image
    );
    application_journal.apply_block(&block, payload).unwrap();
    assert_eq!(application_journal.head_block_id().unwrap(), block.id());
}

#[test]
fn poisoned_journal_rejects_validation_before_candidate_work() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let payload = axiom_bytes(ZfcAxiom::Pairing);
    let artifact_id = artifact_ids(std::slice::from_ref(&payload))[0];
    let mut journal = ArtifactChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(artifact_id).unwrap();
    let image = fs::read(directory.journal_path()).unwrap();
    journal.core.poisoned = true;

    assert!(matches!(
        journal.validate_block(&block, vec![0]),
        Err(ArtifactChainJournalError::Poisoned)
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
    assert!(matches!(
        ArtifactChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ArtifactChainJournalError::Locked)
    ));
}
