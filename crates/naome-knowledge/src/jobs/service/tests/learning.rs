//! Real checker admission and native journal boundaries, without process timing.
use super::*;
fn native() -> (Directory, Owner) {
    let directory = Directory::new();
    let settings = Settings {
        native_proof_learning: true,
        ..Settings::default()
    };
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    (
        directory,
        Owner::new(disk, journal, settings, Arc::default()),
    )
}
fn checked_solution() -> crate::learning::Solution {
    crate::learning::tests::own_solution()
}
fn submit_native(owner: &mut Owner, input: Input) -> (u64, oneshot::Receiver<Completion>) {
    let (reply, receive) = oneshot::channel();
    owner
        .submit(input, Binding::new([0; 32], [0; 32]), reply)
        .unwrap();
    (owner.journal.next_id - 1, receive)
}
fn finish(owner: &mut Owner, id: u64, solution: crate::learning::Solution) {
    let solution = if let Input::Peer {
        question,
        artifact,
        certificate,
        ..
    } = &owner.journal.records.get(&id).unwrap().input
    {
        crate::learning::peer::extract(question, artifact, certificate).unwrap()
    } else {
        solution
    };
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    let record = owner.journal.records.get_mut(&id).unwrap();
    record.checkpoint = 1;
    crate::learning::tests::completed(record.native.as_mut().unwrap(), solution.clone());
    owner
        .complete(
            id,
            process::Outcome {
                state: State::Complete,
                result: Ok(Output::Native {
                    terminal: crate::learning::experience::TerminalEvidence::certified(&solution)
                        .into(),
                    solution: Some(solution),
                    diagnostic: "certified_candidate".into(),
                    frontier: None,
                }),
            },
        )
        .unwrap();
}
fn learning(owner: &Owner) -> serde_json::Value {
    serde_json::to_value(owner.journal.learning.as_ref().unwrap()).unwrap()
}

#[test]
fn native_completion_binds_its_actual_model_terminal_trace_and_work() {
    use crate::learning::experience::{ExperienceSummary, TerminalEvidence};
    let (_directory, mut owner) = native();
    let question = crate::learning::tests::own_question();
    let (id, mut receiver) = submit_native(
        &mut owner,
        Input::Solve {
            question: question.clone(),
        },
    );
    finish(&mut owner, id, checked_solution());
    let completed = receiver.try_recv().unwrap();
    let summary = completed.experience.unwrap();
    summary.validate().unwrap();
    assert_eq!(summary.job, id);
    assert_eq!(summary.checkpoint, completed.model_checkpoint.unwrap());
    assert_eq!(
        summary.request_binding,
        crate::learning::digest(&completed.binding)
    );
    let native = owner.journal.records[&id].native.as_ref().unwrap();
    assert_eq!(
        summary.native_context,
        crate::learning::digest(&(&native.base_hash, &native.required, &native.prerequisites))
    );
    assert_eq!(
        summary.question,
        crate::hex(
            naome_authoring::CompiledQuestion::compile(&question)
                .unwrap()
                .resolution_id()
        )
    );
    assert!(matches!(
        summary.terminal,
        TerminalEvidence::CertifiedCandidate { .. }
    ));
    assert!(summary.trace.checked_trajectory.is_some());
    assert!(summary.trace.observed_branches.is_none());
    assert_eq!(summary.reserved_units, completed.reserved_units);
    assert_eq!(summary.spent_ms, completed.spent_ms);
    for field in [
        "job",
        "question",
        "checkpoint",
        "policy",
        "spent_ms",
        "reserved_units",
        "search_limit",
        "request_binding",
        "native_context",
    ] {
        let mut value = serde_json::to_value(&summary).unwrap();
        value[field] = if value[field].is_number() {
            serde_json::json!(value[field].as_u64().unwrap() + 1)
        } else {
            serde_json::json!("11".repeat(32))
        };
        let changed: ExperienceSummary = serde_json::from_value(value).unwrap();
        assert!(changed.validate().is_err(), "{field}");
    }
    let mut record = owner.journal.records[&id].clone();
    if let Some(Output::Native { terminal, .. }) = &mut record.result {
        **terminal = TerminalEvidence::Unknown;
    }
    assert!(ExperienceSummary::from_record(&record).is_err());
    record = owner.journal.records[&id].clone();
    record
        .native
        .as_mut()
        .unwrap()
        .progress
        .as_mut()
        .unwrap()
        .cost
        .as_mut()
        .unwrap()
        .search_expansions += 1;
    assert!(ExperienceSummary::from_record(&record).is_err());
}

#[test]
fn technical_and_interrupted_records_preserve_uncertainty_without_fake_proofs() {
    use crate::learning::experience::{ExperienceSummary, TerminalEvidence};
    let (_directory, mut owner) = native();
    let (id, _receiver) = submit_native(
        &mut owner,
        Input::Solve {
            question: crate::learning::tests::own_question(),
        },
    );
    for (state, terminal) in [
        (State::Failed, TerminalEvidence::TechnicalFailure),
        (State::Expired, TerminalEvidence::Interrupted),
        (State::Cancelled, TerminalEvidence::Interrupted),
        (State::InDoubt, TerminalEvidence::Interrupted),
    ] {
        let mut record = owner.journal.records[&id].clone();
        record.state = state;
        record.failure = Some("worker ended without a retained search unit".into());
        let summary = ExperienceSummary::from_record(&record).unwrap().unwrap();
        summary.validate().unwrap();
        assert_eq!(summary.terminal, terminal);
        assert!(summary.cost.is_none());
        assert!(summary.trace.checked_trajectory.is_none());
        assert!(summary.trace.observed_branches.is_none());
        assert!(!summary.terminal.observed_search_failure(0));
    }
}

#[test]
fn failed_native_experience_reloads_from_the_existing_job_journal() {
    let (directory, mut owner) = native();
    let settings = owner.settings;
    let input = Input::Solve {
        question: crate::learning::tests::own_question(),
    };
    let (id, mut receiver) = submit_native(&mut owner, input.clone());
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    owner
        .complete(
            id,
            process::Outcome {
                state: State::Failed,
                result: Err("worker could not finish its reserved unit".into()),
            },
        )
        .unwrap();
    let summary = receiver.try_recv().unwrap().experience.unwrap();
    let binding = owner.journal.records[&id].binding.clone();
    let role_settings = owner.journal.records[&id].settings;
    drop(owner);
    let (disk, _journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let record = disk
        .request(&input, &binding, role_settings)
        .unwrap()
        .unwrap();
    assert_eq!(record.id, id);
    assert!(record.result.is_none());
    let restored = crate::learning::experience::ExperienceSummary::from_record(&record)
        .unwrap()
        .unwrap();
    assert_eq!(summary.receipt, restored.receipt);
    assert!(restored.cost.is_none());
    assert!(restored.trace.checked_trajectory.is_none());
}
#[test]
fn native_mode_finalizes_structural_finding_without_a_solver_snapshot() {
    let (directory, mut owner) = native();
    let source = crate::learning::tests::own_question();
    let (id, _receive) = submit_native(
        &mut owner,
        Input::Find {
            cursor: 0,
            question: source.clone(),
        },
    );
    let record = owner.journal.records.get(&id).unwrap();
    assert_eq!(record.provider, crate::frontier::PROVIDER);
    assert!(record.native.is_none());
    let contract = crate::jobs::provider::contract(record).unwrap();
    assert_eq!(contract.units, 1);
    assert!(contract.resumable);
    assert_eq!(
        record.input,
        Input::Find {
            cursor: 0,
            question: source
        }
    );
    assert!(crate::jobs::provider::valid_checkpoint(record));
    let settings = owner.settings;
    drop(owner);
    let (_disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let restored = journal.records.get(&id).unwrap();
    assert!(restored.native.is_none());
    assert_eq!(restored.provider, crate::frontier::PROVIDER);
}
fn accepted(owner: &mut Owner) -> u64 {
    let solution = checked_solution();
    let source = crate::learning::tests::own_question();
    let (id, _receive) = submit_native(
        owner,
        Input::Solve {
            question: source.clone(),
        },
    );
    finish(owner, id, solution.clone());
    assert_eq!(
        learning(owner)["accepted"],
        0,
        "a provider result is not accepted training data"
    );
    assert!(
        owner
            .disk
            .accept_learning(&mut owner.journal, id, &"ff".repeat(32))
            .is_err()
    );
    let q = naome_authoring::CompiledQuestion::compile(&source).unwrap();
    let mut graph = crate::Graph::default();
    let (root, batch) = graph.prepare_generated(&solution.source, &[], &q).unwrap();
    graph
        .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert!(graph.contains(root).unwrap());
    assert_eq!(
        learning(owner)["accepted"],
        0,
        "the parent must acknowledge this exact checked root"
    );
    owner
        .disk
        .accept_learning(&mut owner.journal, id, &crate::hex(root.as_bytes()))
        .unwrap();
    assert_eq!(learning(owner)["local_examples"], 1);
    owner
        .journal
        .learning
        .as_ref()
        .unwrap()
        .require_theorems(std::slice::from_ref(&solution.proof_id))
        .unwrap();
    id
}
#[test]
fn only_the_exact_admitted_own_solution_enters_local_replay_once() {
    let (directory, mut owner) = native();
    let id = accepted(&mut owner);
    let before = learning(&owner);
    let root = crate::hex(
        crate::object::proof_address(&checked_solution().proof_id)
            .unwrap()
            .as_bytes(),
    );
    owner
        .disk
        .accept_learning(&mut owner.journal, id, &root)
        .unwrap();
    assert_eq!(learning(&owner), before);
    let settings = owner.settings;
    drop(owner);
    let (_disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    assert_eq!(
        serde_json::to_value(journal.learning.unwrap()).unwrap(),
        before
    );
}

#[test]
fn growing_learning_metadata_keeps_the_disk_working_set_bounded_and_its_source_owned() {
    let (directory, mut owner) = native();
    let id = accepted(&mut owner);
    let mut snapshot = learning(&owner);
    let anchors = snapshot["anchors"].clone();
    let model = snapshot["model"].clone();
    let capacity = crate::resources::limits().closure_bytes.min(128 * 1024) / 4;
    // The current bounded numeric diagnostics cannot contain arbitrarily long
    // map keys. Fill every allowed capability/budget cell instead; the source
    // proof and immutable originating job remain unchanged.
    let cells = snapshot["feedback"]["attempts"]["cells"]
        .as_object_mut()
        .unwrap();
    for budget in [32, 128, 256] {
        for skill in 0..6 {
            for level in 0..4 {
                cells.insert(
                    (budget * 24 + skill * 4 + level).to_string(),
                    serde_json::json!([12, 5, 1000000, 2, 7]),
                );
            }
        }
    }
    owner.journal.learning = Some(serde_json::from_value(snapshot).unwrap());
    owner.journal.learning.as_ref().unwrap().validate().unwrap();
    owner.save().unwrap();
    let mut snapshot = learning(&owner);
    snapshot["draws"] = serde_json::json!(4000);
    owner.journal.learning = Some(serde_json::from_value(snapshot).unwrap());
    owner.save().unwrap();
    let current = learning(&owner);
    assert!(crate::checkpoint::encode(&current).unwrap().len() <= capacity);
    assert_eq!(current["anchors"], anchors);
    assert_eq!(current["accepted"], 1);
    assert_eq!(current["model"], model);
    let settings = owner.settings;
    drop(owner);
    let (_disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let restored = journal.learning.as_ref().unwrap();
    restored.validate().unwrap();
    let restored = serde_json::to_value(restored).unwrap();
    assert_eq!(restored["accepted"], 1);
    assert_eq!(restored["anchors"], anchors);
    assert!(journal.records.get(&id).unwrap().result.is_some());
}
#[test]
fn peer_reconstruction_keeps_peer_origin_and_does_not_claim_local_discovery() {
    let (directory, mut owner) = native();
    let solution = checked_solution();
    let peer = libp2p::PeerId::random().to_string();
    let admission = PeerAdmission {
        certificate: Some(
            crate::learning::peer::pack(
                naome_authoring::compile(&checked_solution().source)
                    .unwrap()
                    .canonical_proof_bytes(),
                &[],
            )
            .unwrap(),
        ),
        ordinal: 1,
        artifact: crate::hex(
            crate::object::proof_address(&solution.proof_id)
                .unwrap()
                .as_bytes(),
        ),
        peer: peer.clone(),
        question: Some(crate::learning::tests::own_question()),
        binding: Binding::new([1; 32], [2; 32]),
    };
    owner
        .disk
        .enqueue_peer(&mut owner.journal, admission.clone())
        .unwrap();
    owner.fill_internal().unwrap();
    let id = owner
        .journal
        .records
        .values()
        .find(|r| matches!(r.input, Input::Peer { .. }))
        .unwrap()
        .id;
    finish(&mut owner, id, solution.clone());
    let state = learning(&owner);
    assert_eq!(state["peer_examples"], 1);
    assert_eq!(state["local_examples"], 0);
    assert_eq!(state["replay"][0]["origin"]["Peer"]["peer"], peer);
    assert_eq!(
        state["replay"][0]["origin"]["Peer"]["artifact"],
        crate::hex(
            crate::object::proof_address(&solution.proof_id)
                .unwrap()
                .as_bytes()
        )
    );
    assert_eq!(
        state["feedback"]["attempts"]["cells"],
        serde_json::json!({}),
        "received mathematics is not a local search success"
    );
    owner
        .disk
        .enqueue_peer(&mut owner.journal, admission)
        .unwrap();
    assert!(owner.disk.pending_peer().unwrap().is_none());
    assert_eq!(learning(&owner), state);
    assert!(
        state["replay"][0]["tree"]["Stored"]["steps"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        serde_json::to_vec(&state["replay"][0]).unwrap().len() < 2048,
        "stored replay bytes={}, coverage bytes={}",
        serde_json::to_vec(&state["replay"][0]).unwrap().len(),
        serde_json::to_vec(&state["replay"][0]["tree"]["Stored"]["coverage"])
            .unwrap()
            .len()
    );
    let epoch = owner.journal.learning.as_ref().unwrap().learning_epoch();
    let (training, _) = submit_native(&mut owner, Input::Train { epoch });
    let native = owner
        .journal
        .records
        .get(&training)
        .unwrap()
        .native
        .as_ref()
        .unwrap();
    assert_eq!(native.evidence.len(), 1);
    native.validate().unwrap();
    let mut forged = native.clone();
    forged.evidence[0].proof_id = "ff".repeat(32);
    assert!(forged.validate().is_err());
    let settings = owner.settings;
    drop(owner);
    let (_disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    assert_eq!(
        serde_json::to_value(journal.learning.unwrap()).unwrap(),
        state
    );
}
#[test]
fn reserved_or_unclassified_peer_admissions_have_one_durable_unsupported_disposition() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../learning/curriculum.json")).unwrap();
    let reserved = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|q| q["development"] == true)
        .unwrap()["source"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!crate::learning::State::eligible(&reserved));
    for question in [None, Some(reserved)] {
        let (directory, mut owner) = native();
        let admission = PeerAdmission {
            certificate: Some(
                crate::learning::peer::pack(
                    naome_authoring::compile(&checked_solution().source)
                        .unwrap()
                        .canonical_proof_bytes(),
                    &[],
                )
                .unwrap(),
            ),
            ordinal: 1,
            artifact: "a1".repeat(32),
            peer: libp2p::PeerId::random().to_string(),
            question,
            binding: Binding::new([1; 32], [2; 32]),
        };
        owner
            .disk
            .enqueue_peer(&mut owner.journal, admission.clone())
            .unwrap();
        owner.fill_internal().unwrap();
        assert!(owner.disk.pending_peer().unwrap().is_none());
        assert!(
            !owner
                .journal
                .records
                .values()
                .any(|r| matches!(r.input, Input::Peer { .. }))
        );
        assert_eq!(learning(&owner)["accepted"], 0);
        let settings = owner.settings;
        drop(owner);
        let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
        let mut owner = Owner::new(disk, journal, settings, Arc::default());
        owner
            .disk
            .enqueue_peer(&mut owner.journal, admission)
            .unwrap();
        assert!(owner.disk.pending_peer().unwrap().is_none());
        assert_eq!(learning(&owner)["accepted"], 0);
    }
}
#[test]
fn canonical_question_is_sampled_once_across_local_and_peer_history() {
    let (_directory, mut owner) = native();
    accepted(&mut owner);
    let before = learning(&owner);
    let solution = checked_solution();
    let admission = PeerAdmission {
        certificate: Some(
            crate::learning::peer::pack(
                naome_authoring::compile(&checked_solution().source)
                    .unwrap()
                    .canonical_proof_bytes(),
                &[],
            )
            .unwrap(),
        ),
        ordinal: 1,
        artifact: crate::hex(
            crate::object::proof_address(&solution.proof_id)
                .unwrap()
                .as_bytes(),
        ),
        peer: libp2p::PeerId::random().to_string(),
        question: Some(crate::learning::tests::own_question()),
        binding: Binding::new([1; 32], [2; 32]),
    };
    owner
        .disk
        .enqueue_peer(&mut owner.journal, admission)
        .unwrap();
    owner.fill_internal().unwrap();
    let id = owner
        .journal
        .records
        .values()
        .find(|r| matches!(r.input, Input::Peer { .. }))
        .unwrap()
        .id;
    finish(&mut owner, id, solution);
    assert_eq!(learning(&owner)["accepted"], before["accepted"]);
    assert_eq!(learning(&owner)["peer_examples"], 0);
}
#[test]
fn native_model_chunks_require_original_training_reservations_and_immutable_read_custody() {
    let (_directory, mut owner) = native();
    accepted(&mut owner);
    let (id, _receive) = submit_native(&mut owner, Input::Train { epoch: 1 });
    let blob = crate::learning::Blob::of(b"bounded-model");
    assert!(
        owner
            .disk
            .model_io(
                &mut owner.journal,
                id,
                1,
                &blob,
                0..1,
                Some(b"bounded-model".to_vec())
            )
            .is_err()
    );
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    crate::checkpoint::fail_next_commit();
    assert!(
        owner
            .disk
            .model_io(
                &mut owner.journal,
                id,
                1,
                &blob,
                0..1,
                Some(b"bounded-model".to_vec())
            )
            .unwrap_err()
            .retryable()
    );
    assert_eq!(
        owner.journal.records[&id]
            .native
            .as_ref()
            .unwrap()
            .io_operations,
        0
    );
    assert!(
        owner.journal.records[&id]
            .native
            .as_ref()
            .unwrap()
            .written
            .is_empty()
    );
    assert!(
        owner
            .disk
            .model_io(
                &mut owner.journal,
                id,
                2,
                &blob,
                0..1,
                Some(b"bounded-model".to_vec())
            )
            .is_err()
    );
    owner
        .disk
        .model_io(
            &mut owner.journal,
            id,
            1,
            &blob,
            0..1,
            Some(b"bounded-model".to_vec()),
        )
        .unwrap();
    assert!(
        owner
            .disk
            .model_io(&mut owner.journal, id, 1, &blob, 0..1, None)
            .is_err(),
        "staged bytes do not grant snapshot read authority"
    );
    assert!(
        owner
            .disk
            .model_io(
                &mut owner.journal,
                id,
                1,
                &blob,
                0..1,
                Some(b"altered-model".to_vec())
            )
            .is_err()
    );
    let optimizer = crate::learning::Blob::of(b"bounded-adam");
    owner
        .disk
        .model_io(
            &mut owner.journal,
            id,
            1,
            &optimizer,
            0..1,
            Some(b"bounded-adam".to_vec()),
        )
        .unwrap();
    crate::learning::tests::candidate_refs(
        owner
            .journal
            .records
            .get_mut(&id)
            .unwrap()
            .native
            .as_mut()
            .unwrap(),
        blob.clone(),
        optimizer,
    );
    owner
        .disk
        .verify_models(owner.journal.records[&id].native.as_ref().unwrap())
        .unwrap();
    owner.save().unwrap();
    assert_eq!(
        owner
            .disk
            .model_io(&mut owner.journal, id, 1, &blob, 0..1, None)
            .unwrap(),
        b"bounded-model"
    );
    let reserved = owner.journal.records[&id].reserved_units;
    owner
        .journal
        .records
        .get_mut(&id)
        .unwrap()
        .native
        .as_mut()
        .unwrap()
        .io_bytes = crate::resources::limits().native_model_io_bytes;
    assert!(
        owner
            .disk
            .model_io(&mut owner.journal, id, 1, &blob, 0..1, None)
            .is_err()
    );
    assert_eq!(owner.journal.records[&id].reserved_units, reserved);
}
#[test]
fn model_chunk_pairs_commit_atomically_and_charge_every_original_chunk_after_restart() {
    let (directory, mut owner) = native();
    accepted(&mut owner);
    let (id, _receive) = submit_native(&mut owner, Input::Train { epoch: 1 });
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    let bytes = vec![37; crate::resources::limits().native_model_chunk_bytes + 17];
    let blob = crate::learning::Blob::of(&bytes);
    let original = serde_json::to_value(owner.journal.records[&id].native.as_ref()).unwrap();
    crate::checkpoint::fail_next_commit();
    assert!(
        owner
            .disk
            .model_io(&mut owner.journal, id, 1, &blob, 0..2, Some(bytes.clone()))
            .unwrap_err()
            .retryable()
    );
    assert_eq!(
        serde_json::to_value(owner.journal.records[&id].native.as_ref()).unwrap(),
        original
    );
    assert!(
        owner
            .disk
            .model_io(&mut owner.journal, id, 1, &blob, 0..3, Some(bytes.clone()))
            .is_err()
    );
    owner
        .disk
        .model_io(&mut owner.journal, id, 1, &blob, 0..2, Some(bytes.clone()))
        .unwrap();
    let saved = owner.journal.records[&id].native.as_ref().unwrap();
    assert_eq!(saved.io_bytes, bytes.len());
    assert_eq!(saved.io_operations, 2);
    assert_eq!(saved.written.len(), 1);
    let settings = owner.settings;
    drop(owner);
    let (_disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let saved = journal.records[&id].native.as_ref().unwrap();
    assert_eq!(saved.io_bytes, bytes.len());
    assert_eq!(saved.io_operations, 2);
    let connection = rusqlite::Connection::open(directory.0.join("research/jobs.sqlite3")).unwrap();
    let parts = connection
        .prepare("SELECT payload FROM entries WHERE kind='model' ORDER BY key")
        .unwrap()
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts.concat(), bytes);
}

#[test]
fn model_chunk_disk_pressure_defers_the_same_original_unit_without_a_fresh_allowance() {
    let (_directory, mut owner) = native();
    accepted(&mut owner);
    let (id, _receive) = submit_native(&mut owner, Input::Train { epoch: 1 });
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    let before = owner.journal.records[&id].clone();
    let (reply, mut receipt) = oneshot::channel();
    owner.model_io.insert(
        id,
        PendingModel {
            unit: 1,
            blob: crate::learning::Blob::of(b"state"),
            range: 0..1,
            bytes: Some(b"state".to_vec()),
            reply,
        },
    );
    crate::resources::with_disk_available(0, || owner.persist_learning().unwrap());
    assert!(matches!(
        receipt.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(owner.model_io.contains_key(&id));
    assert_eq!(
        owner.journal.records[&id].reserved_units,
        before.reserved_units
    );
    assert_eq!(owner.journal.records[&id].checkpoint, 0);
    owner.persist_learning().unwrap();
    assert!(receipt.try_recv().unwrap().is_ok());
    let after = &owner.journal.records[&id];
    assert_eq!(after.reserved_units, before.reserved_units);
    assert_eq!(after.expires_ms, before.expires_ms);
    assert_eq!(after.native.as_ref().unwrap().io_bytes, 5);
}

#[test]
fn a_projected_program_retains_its_peer_receipt_and_distinct_native_identity_on_reopen() {
    let (directory, mut owner) = native();
    let original = checked_solution();
    let question = crate::learning::tests::own_question();
    let q = naome_authoring::CompiledQuestion::compile(&question).unwrap();
    let known = crate::learning::proof::verify(
        &crate::learning::evidence::compile(
            q.proved_target(),
            &crate::learning::peer::pack(
                naome_authoring::compile(&original.source)
                    .unwrap()
                    .canonical_proof_bytes(),
                &[],
            )
            .unwrap(),
        )
        .unwrap(),
        q.proved_target(),
    )
    .unwrap();
    let mut context = naome_checker::ArtifactState::new();
    context
        .register_proof(original.checked().unwrap().into_checked_proof())
        .unwrap();
    let commands = vec![
        naome_proof::program::Command::ProofReference {
            proof_id: *known.native_id.as_bytes(),
        },
        naome_proof::program::Command::Seal { proof: 0 },
    ];
    let mut work =
        crate::proof_work::Work::open(&directory.0.join("peer-program.sqlite3")).unwrap();
    work.append_group(&commands).unwrap();
    let budget = crate::resources::adaptive::Budget {
        memory_bytes: 256 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: 32768,
        batch_steps: 128,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };
    while work.advance(&budget, &context).unwrap() {}
    while !work.prepare_export(&budget).unwrap() {}
    let checked = work.into_checked().unwrap();
    let manifest = checked.proof().unwrap().manifest().clone();
    let projected = crate::learning::program::project(
        manifest.clone(),
        |i| {
            commands
                .get(i as usize)
                .cloned()
                .ok_or_else(|| "command missing".into())
        },
        |id| {
            assert_eq!(id, known.native_id);
            crate::learning::proof::verify(
                &crate::learning::proof::Term::Native {
                    certificate: known.certificate.clone(),
                    lemmas: known.lemmas.clone(),
                    definitions: known.definitions.clone(),
                    target: known.target.clone(),
                },
                &known.target,
            )
        },
        vec![],
    )
    .unwrap();
    let verified = crate::learning::proof::verify(
        &crate::learning::proof::Term::Native {
            certificate: projected.certificate,
            lemmas: projected.lemmas,
            definitions: projected.definitions,
            target: q.proved_target().clone(),
        },
        q.proved_target(),
    )
    .unwrap();
    let packet =
        crate::learning::evidence::pack_with_program(&verified, Some(projected.origin)).unwrap();
    let source_artifact = crate::hex(manifest.artifact_id().as_bytes());
    let translated = crate::hex(verified.native_id.as_bytes());
    assert_ne!(translated, crate::hex(manifest.proof_id().as_bytes()));
    let admission = PeerAdmission {
        certificate: Some(packet),
        ordinal: 1,
        artifact: source_artifact.clone(),
        peer: libp2p::PeerId::random().to_string(),
        question: Some(question),
        binding: Binding::new([1; 32], [2; 32]),
    };
    owner
        .disk
        .enqueue_peer(&mut owner.journal, admission)
        .unwrap();
    owner.fill_internal().unwrap();
    let id = owner
        .journal
        .records
        .values()
        .find(|r| matches!(r.input, Input::Peer { .. }))
        .unwrap()
        .id;
    finish(&mut owner, id, original);
    let state = learning(&owner);
    assert_eq!(state["peer_examples"], 1);
    assert_eq!(state["local_examples"], 0);
    assert_eq!(state["replay"][0]["proof_id"], translated);
    assert_eq!(
        state["replay"][0]["origin"]["Peer"]["artifact"],
        source_artifact
    );
    let settings = owner.settings;
    drop(owner);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    assert_eq!(
        serde_json::to_value(journal.learning.as_ref().unwrap()).unwrap(),
        state
    );
    let evidence = disk
        .replay_evidence(journal.learning.as_ref().unwrap())
        .unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].proof_id, translated);
}

#[test]
fn prerequisite_submission_checks_the_snapshot_without_replacing_the_goal_account() {
    let (_directory, mut owner) = native();
    let solution = checked_solution();
    let mut graph = crate::Graph::default();
    let root = graph.produce(&solution.source).unwrap().1.id;
    let entry = crate::learning::knowledge::Entry {
        packet: graph.learning_certificate(root).unwrap().unwrap(),
    };
    let input = Input::Solve {
        question: crate::learning::tests::own_question(),
    };
    let required = vec![solution.proof_id.clone()];
    let binding = Binding::new([0; 32], [0; 32]);
    let (reply, mut receive) = oneshot::channel();
    let next = owner.journal.next_id;
    owner
        .submit_after(
            input.clone(),
            binding.clone(),
            required.clone(),
            Default::default(),
            reply,
        )
        .unwrap();
    assert!(
        receive
            .try_recv()
            .unwrap()
            .result
            .unwrap_err()
            .contains("prerequisites")
    );
    assert_eq!(owner.journal.next_id, next);
    assert!(!owner.journal.accounts.contains_key(&input.account_key()));
    owner
        .journal
        .learning
        .as_mut()
        .unwrap()
        .remember_theorem(entry)
        .unwrap();
    let (reply, _receive) = oneshot::channel();
    owner
        .submit_after(
            input.clone(),
            binding,
            required.clone(),
            Default::default(),
            reply,
        )
        .unwrap();
    let record = owner.journal.records.get(&next).unwrap();
    let native = record.native.as_ref().unwrap();
    assert_eq!(native.required, required);
    native.base.require_theorems(&required).unwrap();
    native.validate().unwrap();
    assert_eq!(record.input.account_key(), input.account_key());
}

#[test]
fn temporary_canonical_inputs_retry_with_the_original_spent_time_and_reservations() {
    let (_directory, mut owner) = native();
    let input = Input::Solve {
        question: crate::learning::tests::own_question(),
    };
    let (id, _receive) = submit_native(&mut owner, input.clone());
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    let record = owner.journal.records.get_mut(&id).unwrap();
    record.checkpoint = 1;
    record.state = State::Failed;
    record.acknowledged = true;
    record.spent_ms = 25;
    owner
        .journal
        .accounts
        .get_mut(&input.account_key())
        .unwrap()
        .spent_ms = 25;
    owner.journal.total_spent_ms = 25;
    owner.save().unwrap();
    let original = owner.journal.records[&id].clone();
    let solution = checked_solution();
    let mut graph = crate::Graph::default();
    graph.produce(&solution.source).unwrap();
    let required = vec![solution.proof_id];
    let full = graph.prerequisites(&required).unwrap().unwrap();
    let (reply, _receive) = oneshot::channel();
    owner
        .submit_after(
            input.clone(),
            Binding::new([1; 32], [0; 32]),
            required.clone(),
            full,
            reply,
        )
        .unwrap();
    let retry = &owner.journal.records[&(id + 1)];
    assert_eq!(retry.created_ms, original.created_ms);
    assert_eq!(retry.expires_ms, original.expires_ms);
    assert_eq!(retry.spent_ms, original.spent_ms);
    assert_eq!(retry.reserved_units, original.reserved_units);
    assert_eq!(retry.input.account_key(), input.account_key());
    let native = retry.native.as_ref().unwrap();
    assert!(native.base.require_theorems(&required).is_err());
    native
        .prerequisites
        .require(&native.base, &required)
        .unwrap();
    native.validate().unwrap();
    assert_eq!(owner.journal.total_reserved_units, 1);
}

#[test]
fn a_required_lemma_cannot_join_a_running_snapshot_that_does_not_offer_it() {
    let (_directory, mut owner) = native();
    let input = Input::Solve {
        question: crate::learning::tests::own_question(),
    };
    let (id, _receive) = submit_native(&mut owner, input.clone());
    let record_before = serde_json::to_vec(owner.journal.records.get(&id).unwrap()).unwrap();
    let accounts_before = serde_json::to_vec(&owner.journal.accounts).unwrap();
    let solution = checked_solution();
    let mut graph = crate::Graph::default();
    let root = graph.produce(&solution.source).unwrap().1.id;
    owner
        .journal
        .learning
        .as_mut()
        .unwrap()
        .remember_theorem(crate::learning::knowledge::Entry {
            packet: graph.learning_certificate(root).unwrap().unwrap(),
        })
        .unwrap();
    let next = owner.journal.next_id;
    let (reply, mut receive) = oneshot::channel();
    owner
        .submit_after(
            input,
            Binding::new([0; 32], [0; 32]),
            vec![solution.proof_id],
            Default::default(),
            reply,
        )
        .unwrap();
    assert!(
        receive
            .try_recv()
            .unwrap()
            .result
            .unwrap_err()
            .contains("snapshot predates")
    );
    assert_eq!(owner.journal.next_id, next);
    assert_eq!(
        serde_json::to_vec(owner.journal.records.get(&id).unwrap()).unwrap(),
        record_before
    );
    assert_eq!(
        serde_json::to_vec(&owner.journal.accounts).unwrap(),
        accounts_before
    );
}

#[test]
fn evicted_own_history_is_reserved_once_and_reloads_identically_after_reopening() {
    let (directory, mut owner) = native();
    let source = accepted(&mut owner);
    let mut state = learning(&owner);
    state["replay"] = serde_json::json!([]);
    state["anchors"] = serde_json::json!([]);
    owner.journal.learning = Some(serde_json::from_value(state.clone()).unwrap());
    owner.save().unwrap();
    let (id, _receive) = submit_native(&mut owner, Input::Train { epoch: 1 });
    let request = owner.journal.records[&id]
        .native
        .as_ref()
        .unwrap()
        .history_request
        .clone()
        .unwrap();
    assert!(
        owner
            .disk
            .history_page(&mut owner.journal, id, 1, &request)
            .is_err()
    );
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    crate::checkpoint::fail_next_commit();
    assert!(
        owner
            .disk
            .history_page(&mut owner.journal, id, 1, &request)
            .unwrap_err()
            .retryable()
    );
    assert!(
        owner.journal.records[&id]
            .native
            .as_ref()
            .unwrap()
            .history
            .is_none()
    );
    let receipt = owner
        .disk
        .history_page(&mut owner.journal, id, 1, &request)
        .unwrap();
    let charged = owner.journal.records[&id].native.as_ref().unwrap().io_bytes;
    assert!(charged >= receipt.read_bytes + receipt.blob.bytes);
    let repeated = owner
        .disk
        .history_page(&mut owner.journal, id, 1, &request)
        .unwrap();
    assert_eq!(receipt, repeated);
    assert_eq!(
        owner.journal.records[&id].native.as_ref().unwrap().io_bytes,
        charged
    );
    assert_eq!(
        learning(&owner),
        state,
        "history preparation does not mutate the global working state"
    );
    let bytes = owner
        .disk
        .model_io(
            &mut owner.journal,
            id,
            1,
            &receipt.blob,
            0..receipt.blob.chunks(),
            None,
        )
        .unwrap();
    let job = owner.journal.records[&id].native.as_ref().unwrap();
    let prepared = crate::learning::history::inspect_reload(job, &receipt, &bytes).unwrap();
    assert!(prepared.examples().any(|example| example.job == source));
    assert_eq!(prepared.sample_counts(), job.base.sample_counts());
    assert_eq!(prepared.learning_epoch(), job.base.learning_epoch());
    let settings = owner.settings;
    let reserved = owner.journal.records[&id].reserved_units;
    drop(owner);
    let (mut disk, mut journal) = Disk::open(&directory.0, settings, 0).unwrap();
    assert_eq!(journal.records[&id].reserved_units, reserved);
    journal.records.get_mut(&id).unwrap().state = State::Running;
    let restored = disk.history_page(&mut journal, id, 1, &request).unwrap();
    assert_eq!(restored, receipt);
    let restored_bytes = disk
        .model_io(
            &mut journal,
            id,
            1,
            &restored.blob,
            0..restored.blob.chunks(),
            None,
        )
        .unwrap();
    assert_eq!(restored_bytes, bytes);
    let restored_state = crate::learning::history::inspect_reload(
        journal.records[&id].native.as_ref().unwrap(),
        &restored,
        &restored_bytes,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(prepared).unwrap(),
        serde_json::to_value(restored_state).unwrap()
    );
}

#[test]
fn an_unselected_checked_peer_source_is_rechecked_without_claiming_new_samples() {
    let (directory, mut owner) = native();
    let question = crate::learning::tests::own_question();
    let solution = checked_solution();
    let artifact = crate::hex(
        crate::object::proof_address(&solution.proof_id)
            .unwrap()
            .as_bytes(),
    );
    let admission = PeerAdmission {
        certificate: Some(
            crate::learning::peer::pack(
                naome_authoring::compile(&solution.source)
                    .unwrap()
                    .canonical_proof_bytes(),
                &[],
            )
            .unwrap(),
        ),
        ordinal: 1,
        artifact: artifact.clone(),
        peer: libp2p::PeerId::random().to_string(),
        question: Some(question),
        binding: Binding::new([1; 32], [2; 32]),
    };
    owner
        .disk
        .enqueue_peer(&mut owner.journal, admission.clone())
        .unwrap();
    owner.fill_internal().unwrap();
    let source = owner
        .journal
        .records
        .values()
        .find(|record| matches!(record.input, Input::Peer { .. }))
        .unwrap()
        .id;
    finish(&mut owner, source, solution);
    // The history index records complete checked conversions even when the
    // bounded working selector declines them. Exercise that terminal receipt
    // independently of a particular coverage filter or buffer population.
    owner
        .disk
        .peer_status(
            &mut owner.journal,
            &admission,
            PeerStatus::Unsupported {
                reason: "duplicate or no supported ambiguous decisions".into(),
            },
        )
        .unwrap();
    let mut state = learning(&owner);
    state["replay"] = serde_json::json!([]);
    state["anchors"] = serde_json::json!([]);
    owner.journal.learning = Some(serde_json::from_value(state).unwrap());
    owner.save().unwrap();
    let connection = rusqlite::Connection::open(directory.0.join("research/jobs.sqlite3")).unwrap();
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM entries WHERE kind='peer_receipt' AND key=?1",
            [artifact],
            |row| row.get(0),
        )
        .unwrap();
    let receipt: PeerReceipt = crate::checkpoint::decode(&payload).unwrap();
    assert!(matches!(receipt.status, PeerStatus::Unsupported { .. }));
    let before = learning(&owner);
    let (id, _receive) = submit_native(&mut owner, Input::Train { epoch: 1 });
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    let request = owner.journal.records[&id]
        .native
        .as_ref()
        .unwrap()
        .history_request
        .clone()
        .unwrap();
    owner
        .disk
        .peer_status(&mut owner.journal, &admission, PeerStatus::Queued)
        .unwrap();
    assert!(
        owner
            .disk
            .history_page(&mut owner.journal, id, 1, &request)
            .is_err(),
        "a nonterminal receipt cannot authorize historical replay"
    );
    owner
        .disk
        .peer_status(
            &mut owner.journal,
            &admission,
            PeerStatus::Unsupported {
                reason: "duplicate or no supported ambiguous decisions".into(),
            },
        )
        .unwrap();
    let receipt = owner
        .disk
        .history_page(&mut owner.journal, id, 1, &request)
        .unwrap();
    let bytes = owner
        .disk
        .model_io(
            &mut owner.journal,
            id,
            1,
            &receipt.blob,
            0..receipt.blob.chunks(),
            None,
        )
        .unwrap();
    let job = owner.journal.records[&id].native.as_ref().unwrap();
    let prepared = crate::learning::history::inspect_reload(job, &receipt, &bytes).unwrap();
    assert!(prepared.examples().any(|example| example.job == source));
    assert_eq!(prepared.sample_counts(), job.base.sample_counts());
    assert_eq!(learning(&owner), before);
}

#[test]
fn historical_admission_must_still_exist_and_match_the_original_source_record() {
    for swapped in [false, true] {
        let (_directory, mut owner) = native();
        let source = accepted(&mut owner);
        let (id, _receive) = submit_native(&mut owner, Input::Train { epoch: 1 });
        owner.journal.records.get_mut(&id).unwrap().state = State::Running;
        owner.reserve(id, 1).unwrap();
        let request = owner.journal.records[&id]
            .native
            .as_ref()
            .unwrap()
            .history_request
            .clone()
            .unwrap();
        let update = if swapped {
            crate::checkpoint::Update::put("learned", source, &"f1".repeat(32)).unwrap()
        } else {
            crate::checkpoint::Update::Remove {
                kind: "learned",
                key: source.to_string(),
            }
        };
        owner
            .disk
            .save_with(&mut owner.journal, vec![update])
            .unwrap();
        let error = owner
            .disk
            .history_page(&mut owner.journal, id, 1, &request)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(if swapped {
                "identity differs"
            } else {
                "receipt missing"
            }),
            "{error}"
        );
        assert!(
            owner.journal.records[&id]
                .native
                .as_ref()
                .unwrap()
                .history
                .is_none()
        );
        assert_eq!(owner.journal.records[&id].reserved_units, 1);
    }
}
