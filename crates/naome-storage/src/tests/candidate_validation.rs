use naome_chain::PROOF_BLOCK_BYTES;
use naome_checker::CheckError;

use super::*;
use crate::{
    CanonicalProofPayloadStore, ProofBlockCandidateInsertOutcome, ProofBlockCandidateStore,
    ProofBlockCandidateStoreLimits, ProofPayloadInsertOutcome, ProofPayloadStoreLimits,
};

const CANDIDATE_STORE_FILE_NAME: &str = "proof-block-candidate-store.log";
const PAYLOAD_STORE_FILE_NAME: &str = "proof-payload-store.log";

fn candidate_limits(entries: usize) -> ProofBlockCandidateStoreLimits {
    ProofBlockCandidateStoreLimits::new(entries).unwrap()
}

fn payload_limits(entries: usize, payload_bytes: u64) -> ProofPayloadStoreLimits {
    ProofPayloadStoreLimits::new(entries, payload_bytes).unwrap()
}

fn archive_payloads(
    store: &mut CanonicalProofPayloadStore,
    payloads: &[Vec<u8>],
    expected_ids: &[ProofId],
) {
    assert_eq!(payloads.len(), expected_ids.len());
    let mut source = ProofDag::new();
    for (payload, expected_id) in payloads.iter().zip(expected_ids.iter().copied()) {
        let record = source
            .apply_canonical_proof_bytes_with_expected_id(payload.clone(), expected_id)
            .unwrap();
        assert_eq!(
            store.insert(record).unwrap(),
            ProofPayloadInsertOutcome::Inserted
        );
    }
}

fn proof_ids(payloads: &[Vec<u8>]) -> Vec<ProofId> {
    let mut dag = ProofDag::new();
    payloads
        .iter()
        .map(|payload| {
            dag.apply_canonical_proof_bytes(payload.clone())
                .unwrap()
                .proof_id()
        })
        .collect()
}

fn load_payload(store: &mut CanonicalProofPayloadStore, proof_id: ProofId) -> Vec<u8> {
    let payload = store.get(proof_id).unwrap().unwrap();
    assert_eq!(payload.proof_id(), proof_id);
    payload.into_canonical_proof_bytes().into_vec()
}

fn load_block(store: &mut ProofBlockCandidateStore, block_id: ProofBlockId) -> ProofBlock {
    let block = store.get(block_id).unwrap().unwrap();
    assert_eq!(block.id(), block_id);
    block
}

fn assert_empty_journal_unchanged(
    journal: &ProofChainJournal,
    directory: &TestDirectory,
    image: &[u8],
    head: ProofBlockId,
    root: ProofSetRoot,
    proof_ids: &[ProofId],
    witnesses: &[Vec<u8>],
) {
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
    assert_eq!(journal.head_block_id().unwrap(), head);
    assert_eq!(journal.proof_set_root().unwrap(), root);
    assert_eq!(journal.len().unwrap(), 0);
    assert!(journal.is_empty().unwrap());
    for (proof_id, witness) in proof_ids.iter().copied().zip(witnesses) {
        assert!(journal.proof(proof_id).unwrap().is_none());
        assert_eq!(
            journal
                .proof_set_proof(proof_id)
                .unwrap()
                .to_canonical_bytes(),
            *witness
        );
    }
}

#[test]
fn stored_single_proof_candidate_validation_is_repeatable_and_changes_no_store() {
    let directory = TestDirectory::new();
    let definition = chain_definition(CHAIN_BYTE);
    let (payloads, proof_ids) = dependency_chain_with_len(1);
    let total_payload_bytes = payloads.iter().map(Vec::len).sum::<usize>() as u64;
    let journal = ProofChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(proof_ids[0]).unwrap();
    assert_eq!(block.to_canonical_bytes().len(), PROOF_BLOCK_BYTES);

    let mut candidate_store =
        ProofBlockCandidateStore::create(&directory.path, definition, candidate_limits(1)).unwrap();
    assert_eq!(
        candidate_store.insert(&block).unwrap(),
        ProofBlockCandidateInsertOutcome::Inserted
    );
    let mut payload_store =
        CanonicalProofPayloadStore::create(&directory.path, payload_limits(1, total_payload_bytes))
            .unwrap();
    archive_payloads(&mut payload_store, &payloads, &proof_ids);

    let journal_image = fs::read(directory.journal_path()).unwrap();
    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let head = journal.head_block_id().unwrap();
    let root = journal.proof_set_root().unwrap();
    let witnesses = proof_ids
        .iter()
        .map(|proof_id| {
            journal
                .proof_set_proof(*proof_id)
                .unwrap()
                .to_canonical_bytes()
        })
        .collect::<Vec<_>>();

    for _ in 0..2 {
        let loaded_block = load_block(&mut candidate_store, block.id());
        journal
            .validate_block(
                &loaded_block,
                load_payload(&mut payload_store, proof_ids[0]),
            )
            .unwrap();
        assert_empty_journal_unchanged(
            &journal,
            &directory,
            &journal_image,
            head,
            root,
            &proof_ids,
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
    let proof_ids = proof_ids(&payloads);
    let mut journal = ProofChainJournal::create(&directory.path, definition).unwrap();
    let sibling_a = journal.prepare_block(proof_ids[0]).unwrap();
    let sibling_b = journal.prepare_block(proof_ids[1]).unwrap();

    let mut branch_b = ProofChainState::new(definition);
    branch_b
        .apply_block(&sibling_b, payloads[1].clone())
        .unwrap();
    let child_of_b = branch_b.prepare_block(proof_ids[2]).unwrap();

    let blocks = [&sibling_a, &sibling_b, &child_of_b];
    let mut candidate_store = ProofBlockCandidateStore::create(
        &directory.path,
        definition,
        candidate_limits(blocks.len()),
    )
    .unwrap();
    for block in blocks {
        assert_eq!(
            candidate_store.insert(block).unwrap(),
            ProofBlockCandidateInsertOutcome::Inserted
        );
    }
    let mut payload_store = CanonicalProofPayloadStore::create(
        &directory.path,
        payload_limits(
            payloads.len(),
            payloads.iter().map(Vec::len).sum::<usize>() as u64,
        ),
    )
    .unwrap();
    archive_payloads(&mut payload_store, &payloads, &proof_ids);

    let initial_journal_image = fs::read(directory.journal_path()).unwrap();
    let candidate_image = fs::read(directory.path.join(CANDIDATE_STORE_FILE_NAME)).unwrap();
    let payload_image = fs::read(directory.path.join(PAYLOAD_STORE_FILE_NAME)).unwrap();
    let genesis = journal.head_block_id().unwrap();
    let empty_root = journal.proof_set_root().unwrap();

    for (block, proof_id) in [(&sibling_a, proof_ids[0]), (&sibling_b, proof_ids[1])] {
        journal
            .validate_block(
                &load_block(&mut candidate_store, block.id()),
                load_payload(&mut payload_store, proof_id),
            )
            .unwrap();
        assert_eq!(journal.head_block_id().unwrap(), genesis);
        assert_eq!(journal.proof_set_root().unwrap(), empty_root);
        assert_eq!(
            fs::read(directory.journal_path()).unwrap(),
            initial_journal_image
        );
    }

    assert!(matches!(
        journal.validate_block(
            &load_block(&mut candidate_store, child_of_b.id()),
            load_payload(&mut payload_store, proof_ids[2]),
        ),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::ParentBlockIdMismatch {
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
        .apply_block(&sibling_a, load_payload(&mut payload_store, proof_ids[0]))
        .unwrap();
    let selected_image = fs::read(directory.journal_path()).unwrap();
    let selected_root = journal.proof_set_root().unwrap();

    for stale in [&sibling_a, &sibling_b, &child_of_b] {
        assert!(matches!(
            journal.validate_block(&load_block(&mut candidate_store, stale.id()), vec![0]),
            Err(ProofChainJournalError::BlockAdmission {
                source: ProofBlockApplyError::ParentBlockIdMismatch {
                    expected,
                    actual,
                },
            }) if expected == sibling_a.id() && actual == stale.parent_block_id()
        ));
        assert_eq!(journal.head_block_id().unwrap(), sibling_a.id());
        assert_eq!(journal.proof_set_root().unwrap(), selected_root);
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
    let (payloads, proof_ids) = dependency_chain_with_len(2);
    let dependency_id = proof_ids[0];
    let child_id = proof_ids[1];
    let mut journal = ProofChainJournal::create(&directory.path, definition).unwrap();
    let child_only = journal.prepare_block(child_id).unwrap();
    let mut candidate_store =
        ProofBlockCandidateStore::create(&directory.path, definition, candidate_limits(2)).unwrap();
    assert_eq!(
        candidate_store.insert(&child_only).unwrap(),
        ProofBlockCandidateInsertOutcome::Inserted
    );
    let mut payload_store = CanonicalProofPayloadStore::create(
        &directory.path,
        payload_limits(
            payloads.len(),
            payloads.iter().map(Vec::len).sum::<usize>() as u64,
        ),
    )
    .unwrap();
    archive_payloads(&mut payload_store, &payloads, &proof_ids);

    let initial_image = fs::read(directory.journal_path()).unwrap();
    assert!(matches!(
        journal.validate_block(
            &load_block(&mut candidate_store, child_only.id()),
            load_payload(&mut payload_store, child_id),
        ),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::Admission {
                source: LedgerError::Check {
                    source: CheckError::UnknownProofReference {
                        step: 0,
                        proof_id: actual_dependency,
                    },
                },
            },
        }) if actual_dependency == dependency_id
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
        ProofBlockCandidateInsertOutcome::Inserted
    );
    let selected_image = fs::read(directory.journal_path()).unwrap();
    let selected_root = journal.proof_set_root().unwrap();

    journal
        .validate_block(
            &load_block(&mut candidate_store, child_after_dependency.id()),
            load_payload(&mut payload_store, child_id),
        )
        .unwrap();
    assert_eq!(journal.head_block_id().unwrap(), dependency_block.id());
    assert_eq!(journal.proof_set_root().unwrap(), selected_root);
    assert_eq!(journal.len().unwrap(), 1);
    assert!(journal.proof(child_id).unwrap().is_none());
    assert_eq!(fs::read(directory.journal_path()).unwrap(), selected_image);

    assert!(matches!(
        journal.validate_block(
            &load_block(&mut candidate_store, child_only.id()),
            load_payload(&mut payload_store, child_id),
        ),
        Err(ProofChainJournalError::BlockAdmission {
            source: ProofBlockApplyError::ParentBlockIdMismatch { .. },
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
    let proof_id = proof_ids(std::slice::from_ref(&payload))[0];
    let validation_journal =
        ProofChainJournal::create(&validation_directory.path, definition).unwrap();
    let mut application_journal =
        ProofChainJournal::create(&application_directory.path, definition).unwrap();
    let block = validation_journal.prepare_block(proof_id).unwrap();
    let validation_image = fs::read(validation_directory.journal_path()).unwrap();
    let application_image = fs::read(application_directory.journal_path()).unwrap();

    let validation_error = validation_journal
        .validate_block(&block, vec![0])
        .unwrap_err();
    let application_error = application_journal
        .apply_block(&block, vec![0])
        .unwrap_err();
    let unwrap_admission = |error| match error {
        ProofChainJournalError::BlockAdmission { source } => source,
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
    let proof_id = proof_ids(std::slice::from_ref(&payload))[0];
    let mut journal = ProofChainJournal::create(&directory.path, definition).unwrap();
    let block = journal.prepare_block(proof_id).unwrap();
    let image = fs::read(directory.journal_path()).unwrap();
    journal.core.poisoned = true;

    assert!(matches!(
        journal.validate_block(&block, vec![0]),
        Err(ProofChainJournalError::Poisoned)
    ));
    assert_eq!(fs::read(directory.journal_path()).unwrap(), image);
    assert!(matches!(
        ProofChainJournal::open_recovering_unverified(&directory.path, definition),
        Err(ProofChainJournalError::Locked)
    ));
}
