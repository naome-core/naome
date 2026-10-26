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
                    solution: Some(solution),
                    diagnostic: "certified_candidate".into(),
                }),
            },
        )
        .unwrap();
}
fn learning(owner: &Owner) -> serde_json::Value {
    serde_json::to_value(owner.journal.learning.as_ref().unwrap()).unwrap()
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
        state["statistics"],
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
        state["replay"][0]["tree"]["Peer"]["steps"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(serde_json::to_vec(&state["replay"][0]).unwrap().len() < 2048);
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
        question: Some("goal=all(x,mem(x,x))".into()),
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
                0,
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
                0,
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
                0,
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
            0,
            Some(b"bounded-model".to_vec()),
        )
        .unwrap();
    assert!(
        owner
            .disk
            .model_io(&mut owner.journal, id, 1, &blob, 0, None)
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
                0,
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
            0,
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
            .model_io(&mut owner.journal, id, 1, &blob, 0, None)
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
            .model_io(&mut owner.journal, id, 1, &blob, 0, None)
            .is_err()
    );
    assert_eq!(owner.journal.records[&id].reserved_units, reserved);
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
            index: 0,
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
