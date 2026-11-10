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
        evidence,
        ..
    } = &owner.journal.records.get(&id).unwrap().input
    {
        crate::learning::peer::extract_source(question, artifact, evidence).unwrap()
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
            naome_checker::question::ResearchQuestion::from_hex(&question)
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
        record.failure = Some(WorkerFailure::Execution.into());
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
    let cause = crate::Error::Research(crate::ResearchFailure::WorkBudgetExhausted);
    let failure = crate::outcome::JobFailureCode::from_owner(&cause);
    owner
        .complete(
            id,
            process::Outcome {
                state: State::Failed,
                result: Err(failure),
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
    assert_eq!(record.failure, Some(failure));
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
    let error = owner
        .disk
        .accept_learning(&mut owner.journal, id, &"ff".repeat(32))
        .unwrap_err();
    assert_eq!(
        error,
        crate::Error::from(crate::ResearchFailure::LearningProgramIdentity)
    );
    assert_eq!(learning(owner)["accepted"], 0);
    let q = naome_checker::question::ResearchQuestion::from_hex(&source).unwrap();
    let mut graph = crate::Graph::default();
    let program = crate::learning::program::Candidate::from_solution(&solution, &q).unwrap();
    let mut work = crate::proof_work::Work::open(
        &graph
            .ownership()
            .directory()
            .join("own-native-program.sqlite3"),
    )
    .unwrap();
    for group in program.commands.chunks(naome_proof::program::CHUNK_RECORDS) {
        work.append_group(group).unwrap();
    }
    let budget = crate::resources::adaptive::Budget {
        memory_bytes: 8 * 1024 * 1024,
        cache_bytes: 32768,
        concurrency: 1,
        batch_steps: 128,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    };
    while work.advance(&budget, graph.checked_context()).unwrap() {}
    while !work.prepare_export(&budget).unwrap() {}
    let checked = work.into_checked().unwrap();
    let proof = checked.proof().unwrap();
    assert_eq!(proof.manifest(), &program.manifest);
    q.classify_checked_program(proof).unwrap();
    let root = proof.manifest().artifact_id();
    let store = graph.ownership();
    let mut progress = store.start_program(proof.manifest()).unwrap();
    while progress.commands < proof.manifest().commands {
        let chunk = proof
            .input_chunk(progress.commands, 128, naome_proof::program::CHUNK_BYTES)
            .unwrap();
        store.append_program(proof.manifest(), &chunk).unwrap();
        progress = store.program_progress(proof.manifest()).unwrap();
    }
    let mut preparation = graph.begin_program_admission(&checked).unwrap();
    while !preparation.advance(&graph, &checked, 128).unwrap() {}
    let batch = preparation.finish(&graph, &checked).unwrap();
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
    let question = naome_checker::question::ResearchQuestion::from_hex(
        &crate::learning::tests::own_question(),
    )
    .unwrap();
    let program =
        crate::learning::program::Candidate::from_solution(&checked_solution(), &question).unwrap();
    let root = crate::hex(program.manifest.artifact_id().as_bytes());
    owner
        .disk
        .accept_learning(&mut owner.journal, id, &root)
        .unwrap();
    assert_eq!(learning(&owner), before);
    let error = owner
        .disk
        .accept_learning(&mut owner.journal, id, &"ff".repeat(32))
        .unwrap_err();
    assert_eq!(
        error,
        crate::Error::from(crate::ResearchFailure::LearningReceiptMismatch)
    );
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
fn bounded_journal_history_includes_terminal_failures_without_invented_training_labels() {
    use crate::learning::experience::TerminalEvidence;
    let (directory, mut owner) = native();
    let (reply, mut receiver) = oneshot::channel();
    owner
        .submit(
            Input::Solve {
                question: crate::learning::tests::own_question(),
            },
            Binding::new([1; 32], [2; 32]),
            reply,
        )
        .unwrap();
    let failed = owner.journal.next_id - 1;
    owner.journal.records.get_mut(&failed).unwrap().state = State::Running;
    owner.reserve(failed, 1).unwrap();
    owner
        .complete(
            failed,
            process::Outcome {
                state: State::Failed,
                result: Err(WorkerFailure::Execution.into()),
            },
        )
        .unwrap();
    let original = receiver.try_recv().unwrap().experience.unwrap();
    let accepted = accepted(&mut owner);
    let mut state = learning(&owner);
    state["history_cursor"]["lane"] = serde_json::json!("Records");
    owner.journal.learning = Some(serde_json::from_value(state.clone()).unwrap());
    owner.save().unwrap();
    let (id, _receiver) = submit_native(&mut owner, Input::Train { epoch: 1 });
    let request = owner.journal.records[&id]
        .native
        .as_ref()
        .unwrap()
        .history_request
        .clone()
        .unwrap();
    assert_eq!(request.lane, crate::learning::history::Lane::Records);
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    let receipt = owner
        .disk
        .history_page(&mut owner.journal, id, 1, &request)
        .unwrap();
    assert!(receipt.read_operations <= crate::learning::history::SOURCES);
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
    let page: crate::learning::history::Page = crate::checkpoint::decode(&bytes).unwrap();
    assert!(page.sources.is_empty());
    assert!(page.records.len() <= crate::learning::history::SOURCES);
    let observed = page
        .records
        .iter()
        .find(|r| r.job == failed)
        .unwrap()
        .observation
        .as_ref()
        .unwrap();
    assert_eq!(observed.summary.receipt, original.receipt);
    assert_eq!(
        observed.summary.terminal,
        TerminalEvidence::TechnicalFailure
    );
    assert!(observed.summary.cost.is_none());
    assert!(observed.frontier.is_none());
    let checked = page
        .records
        .iter()
        .find(|r| r.job == accepted)
        .unwrap()
        .observation
        .as_ref()
        .unwrap();
    assert!(matches!(
        checked.summary.terminal,
        TerminalEvidence::CertifiedCandidate { .. }
    ));
    let native = owner.journal.records[&id].native.as_ref().unwrap();
    let restored = crate::learning::history::inspect_reload(native, &receipt, &bytes).unwrap();
    assert_eq!(
        serde_json::to_value(restored).unwrap(),
        state,
        "operational observations alone add no proof labels, samples or model updates"
    );
    let mut omitted = page.clone();
    omitted.records.retain(|r| r.job != failed);
    assert!(
        crate::learning::history::inspect_reload(
            native,
            &receipt,
            &crate::checkpoint::encode(&omitted).unwrap()
        )
        .is_err()
    );
    let settings = owner.settings;
    let io = native.io_bytes;
    let reserved = owner.journal.records[&id].reserved_units;
    drop(owner);
    let (mut disk, mut journal) = Disk::open(&directory.0, settings, 0).unwrap();
    journal.records.get_mut(&id).unwrap().state = State::Running;
    assert_eq!(
        disk.history_page(&mut journal, id, 1, &request).unwrap(),
        receipt
    );
    assert_eq!(journal.records[&id].native.as_ref().unwrap().io_bytes, io);
    assert_eq!(journal.records[&id].reserved_units, reserved);
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
        evidence: Some(crate::learning::peer::Source::Certificate(
            crate::learning::peer::pack(
                crate::learning::proof::check_artifact(
                    &checked_solution().source,
                    &naome_checker::ArtifactState::new(),
                )
                .unwrap()
                .normal_form()
                .canonical_bytes(),
                &[],
            )
            .unwrap(),
        )),
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
            evidence: Some(crate::learning::peer::Source::Certificate(
                crate::learning::peer::pack(
                    crate::learning::proof::check_artifact(
                        &checked_solution().source,
                        &naome_checker::ArtifactState::new(),
                    )
                    .unwrap()
                    .normal_form()
                    .canonical_bytes(),
                    &[],
                )
                .unwrap(),
            )),
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
        evidence: Some(crate::learning::peer::Source::Certificate(
            crate::learning::peer::pack(
                crate::learning::proof::check_artifact(
                    &checked_solution().source,
                    &naome_checker::ArtifactState::new(),
                )
                .unwrap()
                .normal_form()
                .canonical_bytes(),
                &[],
            )
            .unwrap(),
        )),
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
    assert_eq!(
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
            .unwrap_err(),
        crate::Error::Research(crate::ResearchFailure::NativeModelIoLacksOriginalReservation),
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
    let forged_length = crate::learning::Blob {
        sha256: blob.sha256.clone(),
        bytes: blob.bytes + 1,
    };
    assert_eq!(
        owner.disk.verify_blob(&forged_length).unwrap_err(),
        crate::Error::ResearchMismatch {
            code: crate::ResearchFailure::ModelChunkLength,
            expected: forged_length.bytes as u64,
            actual: blob.bytes as u64,
        }
    );
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

fn binary_peer_admission(
    ordinal: u64,
    prefix: &[naome_proof::program::Command],
    secondary: naome_foundation::ZfcAxiom,
) -> (PeerAdmission, String) {
    let (question, packet) = crate::learning::tests::binary_program(prefix, secondary);
    let artifact = crate::hex(packet.manifest.artifact_id().as_bytes());
    let proof = crate::hex(packet.manifest.proof_id().as_bytes());
    let admission = PeerAdmission {
        evidence: Some(crate::learning::peer::Source::Program(Box::new(packet))),
        ordinal,
        artifact: artifact.clone(),
        peer: libp2p::PeerId::random().to_string(),
        question: Some(question),
        binding: Binding::new([1; 32], [2; 32]),
    };
    (admission, proof)
}

#[test]
fn a_native_program_retains_its_peer_receipt_and_training_input_on_reopen() {
    let (directory, mut owner) = native();
    let original = checked_solution();
    let (admission, proof) = binary_peer_admission(1, &[], naome_foundation::ZfcAxiom::Pairing);
    let artifact = admission.artifact.clone();
    owner
        .disk
        .enqueue_peer(&mut owner.journal, admission)
        .unwrap();
    owner.fill_internal().unwrap();
    let id = owner
        .journal
        .records
        .values()
        .find(|record| matches!(record.input, Input::Peer { .. }))
        .unwrap()
        .id;
    finish(&mut owner, id, original);
    let state = learning(&owner);
    assert_eq!(state["peer_examples"], 1);
    assert_eq!(state["local_examples"], 0);
    assert_eq!(state["replay"][0]["proof_id"], proof);
    assert_eq!(state["replay"][0]["origin"]["Peer"]["artifact"], artifact);
    let settings = owner.settings;
    drop(owner);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let restored = journal.learning.as_ref().unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), state);
    let evidence = disk.replay_evidence(restored).unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].proof_id, proof);
    assert!(restored.has_training_graphs(&evidence).unwrap());
}

#[test]
fn peer_program_padding_does_not_advance_learning_after_reopen() {
    use naome_foundation::ZfcAxiom::{self, Pairing, PowerSet, Union};
    use naome_proof::program::Command;

    // Several independent programs need the real checker lease in sequence.
    // Give the journal scenario its own process-wide admission budget.
    const TEST: &str = "jobs::service::tests::learning::peer_program_padding_does_not_advance_learning_after_reopen";
    if std::env::var_os("NAOME_NATIVE_REPLAY_EQUIVALENCE_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_NATIVE_REPLAY_EQUIVALENCE_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }

    fn learn(owner: &mut Owner, ordinal: u64, prefix: &[Command], secondary: ZfcAxiom) -> String {
        let (admission, proof) = binary_peer_admission(ordinal, prefix, secondary);
        owner
            .disk
            .enqueue_peer(&mut owner.journal, admission)
            .unwrap();
        owner.fill_internal().unwrap();
        let id = owner.journal.next_id - 1;
        finish(owner, id, checked_solution());
        proof
    }

    let padding = Command::Equal { left: 0, right: 1 };
    let (directory, mut owner) = native();
    let first = learn(&mut owner, 1, &[padding.clone(), padding.clone()], Pairing);
    let before = learning(&owner);
    assert_eq!(before["epoch"], 1);
    assert_eq!(before["replay"][0]["proof_id"], first);

    let settings = owner.settings;
    drop(owner);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let mut owner = Owner::new(disk, journal, settings, Arc::default());

    let duplicate = learn(
        &mut owner,
        2,
        &[padding.clone(), padding.clone(), padding.clone()],
        Pairing,
    );
    assert_ne!(first, duplicate);
    assert_eq!(learning(&owner)["epoch"], before["epoch"]);
    assert_eq!(learning(&owner)["replay"], before["replay"]);

    let shorter = learn(&mut owner, 3, &[padding], Pairing);
    assert_ne!(shorter, first);
    let after = learning(&owner);
    assert_eq!(after["epoch"], 2);
    assert_eq!(after["peer_examples"], 1);
    assert_eq!(after["replay"].as_array().unwrap().len(), 1);
    assert_eq!(after["replay"][0]["proof_id"], shorter);
    assert_eq!(after["anchors"][0]["proof_id"], shorter);

    let alternative = learn(&mut owner, 4, &[], Union);
    let other = learn(&mut owner, 5, &[], PowerSet);
    let with_distinct_replays = learning(&owner);
    assert_eq!(with_distinct_replays["epoch"], 4);
    assert_eq!(with_distinct_replays["replay"].as_array().unwrap().len(), 2);
    assert_eq!(with_distinct_replays["replay"][0]["proof_id"], alternative);
    assert_eq!(with_distinct_replays["replay"][1]["proof_id"], other);

    let same_cost = [Command::Member { element: 0, set: 1 }];
    let duplicate = learn(&mut owner, 6, &same_cost, Pairing);
    assert_ne!(shorter, duplicate);
    assert_eq!(learning(&owner)["epoch"], 4);

    let best = learn(&mut owner, 7, &[], Pairing);
    let after = learning(&owner);
    assert_eq!(after["epoch"], 5);
    assert_eq!(after["peer_examples"], 1);
    assert_eq!(after["model"], before["model"]);
    assert_eq!(after["replay"], with_distinct_replays["replay"]);
    assert_eq!(after["anchors"][0]["proof_id"], best);
    drop(owner);

    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let restored = journal.learning.as_ref().unwrap();
    let evidence = disk.replay_evidence(restored).unwrap();
    assert_eq!(evidence.len(), 3);
    assert_eq!(evidence[0].proof_id, alternative);
    assert_eq!(evidence[1].proof_id, other);
    assert_eq!(evidence[2].proof_id, best);
    assert!(restored.has_training_graphs(&evidence).unwrap());
}

use crate::jobs::provider::{self, Probe, Supervisor};
use crate::resources::feedback::{Phase, Sample};

#[derive(Default)]
struct WorkerCheckpoint(Option<crate::learning::Progress>);
impl Supervisor for WorkerCheckpoint {
    fn reserve(&mut self, unit: u32) -> Result<(), crate::outcome::WorkerFailure> {
        assert_eq!(unit, 1);
        Ok(())
    }
    fn checkpoint(&mut self, unit: u32) -> Result<(), crate::outcome::WorkerFailure> {
        assert_eq!(self.0.as_ref().unwrap().unit, unit);
        Ok(())
    }
    fn learning(
        &mut self,
        unit: u32,
        progress: crate::learning::Progress,
    ) -> Result<(), crate::outcome::WorkerFailure> {
        assert_eq!(unit, 1);
        assert!(self.0.replace(progress).is_none());
        Ok(())
    }
    fn probe(&mut self, _: Probe) -> Result<(), crate::outcome::WorkerFailure> {
        Ok(())
    }
    fn blocked_nanos(&self) -> u64 {
        0
    }
    fn observe(&mut self, _: Phase, _: Sample) -> Result<(), crate::outcome::WorkerFailure> {
        Ok(())
    }
}

fn run_native_job(owner: &mut Owner, id: u64) -> Completion {
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    let (progress, output) = drive_native(owner.journal.records[&id].clone());
    let record = owner.journal.records.get_mut(&id).unwrap();
    record
        .native
        .as_mut()
        .unwrap()
        .retain_progress(id, progress)
        .unwrap();
    record.checkpoint = 1;
    owner
        .complete(
            id,
            process::Outcome {
                state: State::Complete,
                result: Ok(output),
            },
        )
        .unwrap();
    completion(&owner.journal.records[&id]).unwrap()
}

fn drive_native(record: Record) -> (crate::learning::Progress, Output) {
    std::thread::spawn(move || {
        let mut provider = provider::select(&record).unwrap();
        let mut checkpoint = WorkerCheckpoint::default();
        let output =
            provider::drive(provider.as_mut(), &mut checkpoint, record.checkpoint).unwrap();
        (checkpoint.0.unwrap(), output)
    })
    .join()
    .unwrap()
}

#[test]
fn peer_program_completion_retries_memory_pressure_after_worker_success() {
    let (directory, mut owner) = native();
    // Fixture construction also rechecks its program. Keep its cache off
    // the journal owner, as with a real separate worker.
    let (admission, proof) =
        std::thread::spawn(|| binary_peer_admission(1, &[], naome_foundation::ZfcAxiom::Pairing))
            .join()
            .unwrap();
    owner
        .disk
        .enqueue_peer(&mut owner.journal, admission)
        .unwrap();
    owner.fill_internal().unwrap();
    let id = owner.journal.next_id - 1;
    owner.journal.records.get_mut(&id).unwrap().state = State::Running;
    owner.reserve(id, 1).unwrap();
    let record = owner.journal.records[&id].clone();
    let (progress, output) = drive_native(record);
    let Output::Native {
        solution: Some(solution),
        ..
    } = &output
    else {
        panic!("worker must return an independently checked program");
    };
    assert_eq!(solution.proof_id, proof);

    let record = owner.journal.records.get_mut(&id).unwrap();
    record
        .native
        .as_mut()
        .unwrap()
        .retain_progress(id, progress)
        .unwrap();
    record.checkpoint = 1;
    let deadline = record.expires_ms;
    owner.save().unwrap();
    owner.running.insert(
        id,
        Running {
            cancel: None,
            clock: Instant::now(),
        },
    );

    let mut invalid = output.clone();
    if let Output::Native {
        solution: Some(solution),
        ..
    } = &mut invalid
    {
        solution.proof_id = "00".repeat(32);
    }
    assert!(
        owner
            .complete(
                id,
                process::Outcome {
                    state: State::Complete,
                    result: Ok(invalid),
                }
            )
            .is_err()
    );

    crate::resources::fail_next_memory_allocation();
    owner
        .complete(
            id,
            process::Outcome {
                state: State::Complete,
                result: Ok(output),
            },
        )
        .unwrap();
    assert!(!owner.running.contains_key(&id));
    assert_eq!(owner.journal.records[&id].state, State::Complete);
    assert!(!owner.journal.records[&id].acknowledged);
    assert_eq!(learning(&owner)["peer_examples"], 0);

    // Restart before retrying. The retained completion keeps its original
    // job, deadline, and work unit without recreating the worker.
    let settings = owner.settings;
    drop(owner);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let mut owner = Owner::new(disk, journal, settings, Arc::default());
    owner.recover_internal().unwrap();
    owner.recover_internal().unwrap();
    assert!(owner.journal.records[&id].acknowledged);
    assert_eq!(owner.journal.records[&id].expires_ms, deadline);
    assert_eq!(owner.journal.total_reserved_units, 1);
    assert_eq!(owner.journal.next_id, id + 1);
    assert_eq!(learning(&owner)["peer_examples"], 1);
    let settings = owner.settings;
    drop(owner);
    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let state = journal.learning.as_ref().unwrap();
    let replay = disk.replay_evidence(state).unwrap();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].proof_id, proof);
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
    assert!(matches!(
        receive.try_recv().unwrap().result,
        Err(CompletionFailure::Admission(
            AdmissionFailure::PrerequisitesNotRetained
        ))
    ));
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
fn optional_checked_lemma_reaches_the_native_job_without_becoming_required() {
    let (_directory, mut owner) = native();
    let solution = checked_solution();
    let mut graph = crate::Graph::default();
    let root = graph.produce(&solution.source).unwrap().1.id;
    let proof = graph
        .checked_context()
        .artifact_proof_id(root)
        .unwrap()
        .unwrap();
    let prerequisites = graph.offered_solving_inputs(proof, &[]).unwrap().unwrap();
    let (sender, mut queue) = mpsc::channel(1);
    let client = Client {
        sender,
        feedback: Arc::default(),
        research: Default::default(),
    };
    let _ticket = client
        .submit_after(
            Input::Solve {
                question: crate::learning::tests::own_question(),
            },
            Binding::new([0; 32], [0; 32]),
            Vec::new(),
            prerequisites.clone(),
        )
        .unwrap();
    let Command::Submit(input, binding, required, inputs, reply) = queue.try_recv().unwrap() else {
        panic!("expected a solve request");
    };
    let id = owner.journal.next_id;
    owner
        .submit_after(input, binding, required, inputs, reply)
        .unwrap();
    let native = owner.journal.records[&id].native.as_ref().unwrap();
    assert!(native.required.is_empty());
    assert!(native.prerequisites.contains_inputs(&prerequisites));
    native.validate().unwrap();
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
    let question = naome_checker::question::ResearchQuestion::from_hex(
        &crate::learning::tests::own_question(),
    )
    .unwrap();
    let theorem = solution.theorem(&question).unwrap().unwrap();
    assert!(
        owner
            .journal
            .learning
            .as_mut()
            .unwrap()
            .remember_theorem(theorem)
            .unwrap()
    );
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
    assert!(matches!(
        receive.try_recv().unwrap().result,
        Err(CompletionFailure::Admission(
            AdmissionFailure::InFlightPrerequisites
        ))
    ));
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
    assert_eq!(
        owner
            .disk
            .history_page(&mut owner.journal, id, 1, &request)
            .unwrap_err(),
        crate::Error::Research(
            crate::ResearchFailure::HistoryReadLacksItsOriginalTrainingReservation
        ),
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
        evidence: Some(crate::learning::peer::Source::Certificate(
            crate::learning::peer::pack(
                crate::learning::proof::check_artifact(
                    &solution.source,
                    &naome_checker::ArtifactState::new(),
                )
                .unwrap()
                .normal_form()
                .canonical_bytes(),
                &[],
            )
            .unwrap(),
        )),
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
                reason: WorkerFailure::ReplayNotSelected.into(),
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
                reason: WorkerFailure::ReplayNotSelected.into(),
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

#[test]
fn solve_handoff_rechecks_a_certificate_that_cites_a_checked_program() {
    use naome_checker::question::ResearchQuestion;
    use naome_foundation::{Formula, FreeVariable};
    use naome_proof::program::{CHUNK_BYTES, Command};

    let (_directory, mut owner) = native();
    let mut graph = crate::Graph::default();
    let mut work = crate::proof_work::Work::open(
        &graph
            .ownership()
            .directory()
            .join("mixed-prerequisite.sqlite3"),
    )
    .unwrap();
    work.append_group(&[
        Command::Reflexivity { variable: 0 },
        Command::Generalization {
            premise: 0,
            variable: 0,
        },
        Command::Seal { proof: 1 },
    ])
    .unwrap();
    let budget = crate::resources::tests::snapshot(false).budget;
    while work.advance(&budget, graph.checked_context()).unwrap() {}
    while !work.prepare_export(&budget).unwrap() {}
    let checked = work.into_checked().unwrap();
    let proof = checked.proof().unwrap();
    let manifest = proof.manifest().clone();
    let program_id = manifest.proof_id();
    let store = graph.ownership();
    store.start_program(&manifest).unwrap();
    store
        .append_program(&manifest, &proof.input_chunk(0, 3, CHUNK_BYTES).unwrap())
        .unwrap();
    let mut prepared = crate::graph::program::PreparedProgram::new(checked);
    while !prepared.advance(&graph, 64).unwrap() {}
    graph
        .commit_batch(
            manifest.artifact_id(),
            prepared.take_batch().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    let x = FreeVariable::new(0);
    let reflexivity = Formula::for_all(x, Formula::equal(x, x));
    let other = naome_foundation::ZfcAxiom::Pairing.formula();
    let mixed_source =
        crate::test_inputs::weaken_citation(program_id, reflexivity.clone(), other.clone());
    let (mixed, accepted) = graph.produce(&mixed_source).unwrap();
    assert_eq!(
        graph.direct_dependencies(accepted.id).unwrap().as_ref(),
        &[naome_proof::ArtifactId::from(program_id)]
    );
    let (pairing, _) = graph
        .produce(&crate::test_inputs::proof(vec![
            naome_proof::ProofStep::ZfcAxiom(naome_foundation::ZfcAxiom::Pairing),
        ]))
        .unwrap();
    let mixed_id = mixed.proof_id().unwrap().unwrap();
    let pairing_id = pairing.proof_id().unwrap().unwrap();
    let required = [mixed_id, pairing_id]
        .map(|id| crate::hex(id.as_bytes()))
        .to_vec();
    let goal = ResearchQuestion::from_formula(Formula::conjunction(
        Formula::implies(other.clone(), reflexivity),
        other,
    ))
    .unwrap();
    let source = goal.to_hex();
    let input = Input::Solve {
        question: source.clone(),
    };
    let prerequisites = graph.prerequisites(&required).unwrap().unwrap();
    let (reply, _receive) = oneshot::channel();
    let id = owner.journal.next_id;
    owner
        .submit_after(
            input,
            Binding::new([0; 32], [0; 32]),
            required.clone(),
            prerequisites,
            reply,
        )
        .unwrap();
    let snapshot = owner.journal.records[&id].native.as_ref().unwrap();
    assert!(snapshot.base.require_theorems(&required).is_err());
    assert_eq!(snapshot.required, required);
    let mut worker: crate::learning::Job =
        crate::checkpoint::decode(&crate::checkpoint::encode(snapshot).unwrap()).unwrap();
    worker.validate().unwrap();
    worker
        .execute(
            1,
            Some(&source),
            id,
            &mut crate::learning::Engine::default(),
            &mut crate::learning::tests::MemoryStore::default(),
        )
        .unwrap();
    let candidate = worker.progress.unwrap().result.unwrap();
    assert!(
        candidate.source.is_empty(),
        "mixed checked operands must remain native"
    );
    let program = crate::learning::program::Candidate::from_solution(&candidate, &goal).unwrap();
    assert_eq!(
        crate::hex(program.manifest.proof_id().as_bytes()),
        candidate.proof_id
    );
    let cited: std::collections::BTreeSet<_> = program
        .commands
        .into_iter()
        .filter_map(|command| match command {
            Command::ProofReference { proof_id } => Some(proof_id),
            _ => None,
        })
        .collect();
    assert_eq!(cited, [*mixed_id.as_bytes(), *pairing_id.as_bytes()].into());
}

#[test]
fn model_verification_reports_missing_and_corrupted_chunk_without_caching() {
    let (_directory, mut owner) = native();
    let blob = crate::learning::Blob::of(b"good");
    assert_eq!(
        owner.disk.verify_blob(&blob).unwrap_err(),
        crate::Error::ResearchIndex {
            code: crate::ResearchFailure::ModelChunkMissing,
            index: 0,
        }
    );
    owner
        .disk
        .save_with(
            &mut owner.journal,
            vec![crate::checkpoint::Update::Put {
                kind: "model",
                key: blob.key(0),
                payload: b"evil".to_vec(),
            }],
        )
        .unwrap();
    let error = owner.disk.verify_blob(&blob).unwrap_err();
    let actual = crate::learning::Blob::of(b"evil");
    assert_eq!(
        error,
        crate::Error::ModelDigestMismatch(Box::new(crate::ModelDigestMismatch {
            expected: crate::object::id_bytes(&blob.sha256).unwrap(),
            actual: crate::object::id_bytes(&actual.sha256).unwrap(),
        }))
    );
    let value = serde_json::to_value(error).unwrap();
    assert_eq!(
        value["code"],
        u32::from(crate::ResearchFailure::ModelDigestMismatch)
    );
    assert_eq!(
        value["expected_digest"],
        serde_json::json!(crate::object::id_bytes(&blob.sha256).unwrap())
    );
    assert_eq!(
        value["actual_digest"],
        serde_json::json!(crate::object::id_bytes(&actual.sha256).unwrap())
    );
    assert!(
        owner.disk.verify_blob(&blob).is_err(),
        "corrupted data must not enter the verification cache"
    );
}

#[test]
fn peer_queue_reports_invalid_ordinal_without_consuming_the_row() {
    let (_directory, mut owner) = native();
    let mut admission = PeerAdmission {
        evidence: None,
        ordinal: 0,
        artifact: crate::hex(&[7; 32]),
        peer: libp2p::PeerId::random().to_string(),
        question: None,
        binding: Binding::new([1; 32], [2; 32]),
    };
    assert_eq!(
        owner
            .disk
            .enqueue_peer(&mut owner.journal, admission.clone())
            .unwrap_err(),
        crate::Error::from(crate::ResearchFailure::PeerOrdinalZero),
    );
    admission.ordinal = 2;
    let valid_question = admission.question.replace("invalid".into());
    let expected = naome_checker::question::ResearchQuestion::from_hex("invalid").unwrap_err();
    assert_eq!(
        owner
            .disk
            .enqueue_peer(&mut owner.journal, admission.clone())
            .unwrap_err(),
        crate::Error::from(expected),
    );
    admission.question = valid_question;
    owner
        .disk
        .save_with(
            &mut owner.journal,
            vec![
                crate::checkpoint::Update::put("peer_pending", format!("{:020}", 1), &admission)
                    .unwrap(),
            ],
        )
        .unwrap();
    for _ in 0..2 {
        let error = owner.disk.pending_peer().unwrap_err();
        assert_eq!(
            error,
            crate::Error::from(crate::ResearchFailure::PeerQueueOrdinalMismatch)
        );
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            u32::from(crate::ResearchFailure::PeerQueueOrdinalMismatch),
        );
    }
}

#[test]
fn catalog_retry_uses_the_real_failed_receipt_and_survives_job_reopen() {
    // The fixture installs a process-wide resource snapshot.
    const TEST: &str = "jobs::service::tests::learning::catalog_retry_uses_the_real_failed_receipt_and_survives_job_reopen";
    if std::env::var_os("NAOME_CATALOG_RETRY_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_CATALOG_RETRY_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }

    use crate::frontier::{Frontier, evidence::Outcome};
    use crate::learning::Origin;

    crate::resources::tests::budget(false);
    let graph_dir = Directory::new();
    let frontier_dir = Directory::new();
    let mut graph = crate::Graph::open(&graph_dir.0).unwrap();
    let (question, donor) = crate::learning::tests::catalog_case(&mut graph);
    drop(graph);
    let mut graph = crate::Graph::open(&graph_dir.0).unwrap();
    let mut gate = crate::question::LocalQuestions::new(Some(|_| std::future::ready(Ok(true))));
    assert!(gate.generation_decision(&graph, &question).passed());

    let (directory, mut owner) = native();
    let settings = owner.settings;
    let model = learning(&owner)["model"].clone();
    let binding = gate.formal_context(&graph).binding();
    let input = Input::Solve {
        question: question.to_hex(),
    };
    let mut frontier = Frontier::open(&frontier_dir.0, &graph, 937, settings).unwrap();
    assert!(frontier.catalog_retry(&graph, &question).unwrap().is_none());
    let (reply, _receiver) = oneshot::channel();
    owner.submit(input.clone(), binding.clone(), reply).unwrap();
    let first = owner.journal.next_id - 1;
    let miss = run_native_job(&mut owner, first);
    assert!(matches!(
        miss.result,
        Ok(Output::Native { solution: None, .. })
    ));
    assert_eq!(
        miss.experience
            .as_ref()
            .unwrap()
            .cost
            .as_ref()
            .unwrap()
            .search_expansions,
        128
    );
    frontier
        .attempted(&question, &graph, &miss, Outcome::NoCandidate)
        .unwrap();
    owner.journal.records.get_mut(&first).unwrap().acknowledged = true;
    owner.save().unwrap();
    drop(frontier);

    let frontier = Frontier::open(&frontier_dir.0, &graph, 937, settings).unwrap();
    let (required, prerequisites) = frontier.solving_inputs(&graph, &question, &[]).unwrap();
    assert!(required.is_empty() && prerequisites.is_empty());
    let source = frontier.catalog_retry(&graph, &question).unwrap().unwrap();
    assert_eq!(source.proof_id(), donor);
    let mut retry_binding = binding;
    retry_binding.catalog = Some(source);
    let (reply, _receiver) = oneshot::channel();
    owner.submit(input, retry_binding.clone(), reply).unwrap();
    let retry = owner.journal.next_id - 1;
    assert!(retry > first);
    assert_eq!(owner.journal.records[&retry].binding, retry_binding);
    drop(owner);

    let (disk, journal) = Disk::open(&directory.0, settings, 0).unwrap();
    let mut owner = Owner::new(disk, journal, settings, Arc::default());
    assert_eq!(owner.journal.records[&retry].binding, retry_binding);
    let complete = run_native_job(&mut owner, retry);
    let solved = complete.experience.unwrap();
    assert!(matches!(solved.origin, Origin::Local));
    assert_eq!(solved.checkpoint, miss.experience.unwrap().checkpoint);
    assert_eq!(solved.cost.as_ref().unwrap().search_expansions, 5);
    let Output::Native {
        solution: Some(solution),
        ..
    } = complete.result.unwrap()
    else {
        panic!("retry must produce a checked native proof");
    };
    assert!(
        retry_binding
            .catalog
            .as_ref()
            .unwrap()
            .supports(&solution)
            .unwrap()
    );
    solution.check_target(&question).unwrap();
    let root = crate::learning::tests::publish_catalog_solution(&mut graph, &solution);
    assert!(graph.contains(root).unwrap());
    assert_eq!(learning(&owner)["accepted"], 0);
    owner
        .disk
        .accept_learning(&mut owner.journal, retry, &crate::hex(root.as_bytes()))
        .unwrap();
    let after = learning(&owner);
    assert_eq!(after["model"], model);
    eprintln!(
        "catalog-retry published={} source={} search_expansions={} replay_samples={} model_policy={}",
        solution.proof_id,
        crate::hex(donor.as_bytes()),
        128 + solution.cost.search_expansions,
        after["accepted"],
        solved.policy,
    );
}

#[test]
fn compact_planned_catalog_cut_is_verified_and_credits_the_finder() {
    const TEST: &str = "jobs::service::tests::learning::compact_planned_catalog_cut_is_verified_and_credits_the_finder";
    if std::env::var_os("NAOME_COMPACT_CATALOG_CUT_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_COMPACT_CATALOG_CUT_TEST", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }

    use crate::frontier::{Frontier, evidence::Outcome};
    use crate::learning::experience::{Capacity, TerminalEvidence};
    use naome_checker::question::ResearchQuestion;
    use naome_foundation::{Formula, FreeVariable};

    fn submit(owner: &mut Owner, question: &ResearchQuestion, binding: Binding) -> Completion {
        let (reply, _receiver) = oneshot::channel();
        owner
            .submit(
                Input::Solve {
                    question: question.to_hex(),
                },
                binding,
                reply,
            )
            .unwrap();
        let id = owner.journal.next_id - 1;
        let result = run_native_job(owner, id);
        owner.journal.records.get_mut(&id).unwrap().acknowledged = true;
        owner.compact();
        owner.save().unwrap();
        result
    }

    fn publish(
        frontier: &mut Frontier,
        graph: &mut crate::Graph,
        question: &ResearchQuestion,
        completion: &Completion,
    ) -> (naome_proof::ArtifactId, String) {
        let Ok(Output::Native {
            solution: Some(solution),
            ..
        }) = &completion.result
        else {
            panic!("native job must produce a proof");
        };
        assert!(!solution.refuted);
        solution.check_target(question).unwrap();
        let root = crate::learning::tests::publish_catalog_solution(graph, solution);
        frontier
            .attempted(question, graph, completion, Outcome::Candidate)
            .unwrap();
        frontier.prepared(question, completion.id, root).unwrap();
        frontier
            .verified(question, graph, completion.id, root)
            .unwrap();
        (root, solution.proof_id.clone())
    }

    fn research_binding(
        frontier: &mut Frontier,
        graph: &crate::Graph,
        question: &ResearchQuestion,
        mut binding: Binding,
        limits: Limits,
    ) -> Binding {
        let decision = frontier
            .research_decision(question, graph, limits, binding.catalog.is_some())
            .unwrap();
        assert!(decision.forecast.is_some());
        binding.research = Some(Box::new(decision));
        binding
    }

    crate::resources::tests::budget(false);
    let graph_dir = Directory::new();
    let frontier_dir = Directory::new();
    let mut graph = crate::Graph::open(&graph_dir.0).unwrap();
    let (_jobs_dir, mut owner) = native();
    let settings = owner.settings;
    let mut frontier = Frontier::open(&frontier_dir.0, &graph, 937, settings).unwrap();
    frontier.feedback(
        owner
            .journal
            .learning
            .as_ref()
            .map(crate::learning::State::feedback),
    );
    frontier.refresh(&graph, |_| true).unwrap();
    let mut gate = crate::question::LocalQuestions::new(Some(|_| std::future::ready(Ok(true))));
    let [a, b, c, witness] = [0, 1, 2, 3].map(FreeVariable::new);
    let atoms = [
        Formula::member(a, b),
        Formula::member(b, c),
        Formula::member(c, a),
        Formula::member(b, a),
        Formula::member(c, b),
        Formula::member(a, c),
        Formula::member(a, a),
        Formula::member(b, b),
        Formula::member(c, c),
        Formula::equal(a, b),
        Formula::equal(a, c),
        Formula::equal(b, c),
    ];
    let guard = |step: usize| {
        let premise = atoms[(6 + (step + 3) * 5) % 12].clone();
        let result = atoms[(6 + (step + 4) * 5) % 12].clone();
        Formula::implies(Formula::negate(premise), result)
    };
    let body = [Formula::equal(a, b), Formula::member(a, c)]
        .into_iter()
        .chain((0..4).map(guard))
        .fold(Formula::member(b, c), |body, premise| {
            Formula::implies(premise, body)
        });
    let close = |body| {
        [a, b, c]
            .into_iter()
            .rev()
            .fold(body, |body, var| Formula::for_all(var, body))
    };
    let helper = ResearchQuestion::from_formula(close(body.clone())).unwrap();
    let goal = ResearchQuestion::from_formula(close(Formula::implies(
        Formula::for_all(witness, Formula::implies(body, Formula::member(witness, a))),
        Formula::member(c, a),
    )))
    .unwrap();
    assert!(gate.generation_decision(&graph, &goal).passed());
    let miss = submit(&mut owner, &goal, gate.formal_context(&graph).binding());
    let first = miss.experience.as_ref().unwrap();
    assert_eq!(
        first.terminal,
        TerminalEvidence::Unsupported(Capacity::Facts)
    );
    assert_eq!(first.cost.as_ref().unwrap().search_expansions, 128);
    frontier
        .attempted(&goal, &graph, &miss, Outcome::NoCandidate)
        .unwrap();
    let plan = frontier
        .loop_work(&goal, &graph, |q| {
            gate.generation_decision(&graph, q).passed()
        })
        .unwrap();
    assert_eq!(plan.pending.as_slice(), std::slice::from_ref(&helper));
    assert!(
        helper.to_hex().len() + 64 <= crate::resources::active_limits().question_cache_bytes / 2
    );
    drop(plan);
    let binding = research_binding(
        &mut frontier,
        &graph,
        &helper,
        gate.formal_context(&graph).binding(),
        settings.solving.limits,
    );
    let result = submit(&mut owner, &helper, binding);
    let (helper_id, proof) = publish(&mut frontier, &mut graph, &helper, &result);
    assert_eq!(frontier.support_updates(), 0);

    let planned = frontier.loop_work(&goal, &graph, |_| true).unwrap();
    assert_eq!(planned.required, [proof]);
    assert!(planned.pending.is_empty());
    assert!(gate.generation_decision(&graph, &goal).passed());
    let catalog = frontier
        .planned_catalog_retry(&graph, &goal, &planned.required)
        .unwrap()
        .unwrap();
    assert_eq!(naome_proof::ArtifactId::from(catalog.proof_id()), helper_id);
    drop(planned);
    let mut binding = gate.formal_context(&graph).binding();
    binding.catalog = Some(catalog);
    let binding = research_binding(
        &mut frontier,
        &graph,
        &goal,
        binding,
        settings.solving.limits,
    );
    let retry = submit(&mut owner, &goal, binding);
    assert_eq!(
        retry.experience.as_ref().unwrap().checkpoint,
        first.checkpoint
    );
    assert_eq!(
        retry
            .experience
            .as_ref()
            .unwrap()
            .cost
            .as_ref()
            .unwrap()
            .search_expansions,
        5
    );
    let (root, _) = publish(&mut frontier, &mut graph, &goal, &retry);
    assert_eq!(
        graph.learning_proof_dependencies(root).unwrap().as_ref(),
        &[helper_id]
    );
    assert_eq!(frontier.support_updates(), 1);
    assert_eq!(
        frontier.learning_snapshot()["research_effects"]["reused"],
        1
    );
    drop(frontier);
    drop(graph);

    let graph = crate::Graph::open(&graph_dir.0).unwrap();
    let mut frontier = Frontier::open(&frontier_dir.0, &graph, 937, settings).unwrap();
    let checkpoint = frontier.learning_snapshot();
    frontier.verified(&goal, &graph, retry.id, root).unwrap();
    assert_eq!(frontier.learning_snapshot(), checkpoint);
    assert_eq!(frontier.support_updates(), 1);
}
