use super::*;
#[test]
fn disk_pressure_at_work_creation_and_append_retains_the_completed_provider_candidate() {
    const CASE: &str = "autonomous::program::tests::disk_pressure_at_work_creation_and_append_retains_the_completed_provider_candidate";
    if std::env::var_os("NAOME_PROGRAM_CREATION_CASE").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env("NAOME_PROGRAM_CREATION_CASE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    // This case tests disk deferral, not the host's current pressure state.
    crate::resources::tests::budget(false);
    let graph = Graph::default();
    let owner = jobs::tests::Manual::new();
    let question = ResearchQuestion::from_hex(&crate::mocks::create_question(0)).unwrap();
    let mut generated = Generated::new(17, 1);
    let path = graph
        .ownership()
        .directory()
        .join(".program-work/candidate-17.sqlite3");
    crate::resources::with_disk_available(0, || {
        let error = generated
            .prepare(&graph, &owner.client, &question)
            .err()
            .expect("work creation must defer");
        assert!(error.retryable());
        assert!(!path.exists());
    });
    assert_eq!((generated.job, generated.unit), (17, 1));
    assert!(
        generated
            .prepare(&graph, &owner.client, &question)
            .unwrap()
            .is_none()
    );
    assert!(path.exists() && generated.pending.is_some());
    assert_eq!((generated.job, generated.unit), (17, 1));

    let records = vec![Command::Equal { left: 0, right: 0 }];
    let respond = || {
        let (send, receive) = oneshot::channel();
        send.send(Ok(records.clone())).unwrap();
        receive
    };
    generated.pending = Some(respond());
    crate::resources::with_disk_available(0, || {
        let error = generated
            .prepare(&graph, &owner.client, &question)
            .err()
            .expect("import must defer before advancing its in-memory cursor");
        assert!(error.retryable());
    });
    assert_eq!(
        (
            generated.unit,
            generated.prefix.commands,
            generated.prefix.hash
        ),
        (1, 0, [0; 32])
    );
    assert_eq!(
        generated.work.as_ref().unwrap().status().unwrap().commands,
        0
    );
    generated.pending = Some(respond());
    assert!(
        generated
            .prepare(&graph, &owner.client, &question)
            .unwrap()
            .is_none()
    );
    assert_eq!((generated.unit, generated.prefix.commands), (2, 1));
    assert_eq!(
        generated.work.as_ref().unwrap().status().unwrap().commands,
        1
    );
}

#[test]
fn native_scoped_solver_result_publishes_and_reopens_with_its_exact_program_trace() {
    crate::resources::tests::budget(false);
    let directory = crate::checkpoint::tests::Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let (question, solution) = crate::learning::tests::typed_scope_candidate(true);
    let candidate =
        crate::learning::program::Candidate::from_solution(&solution, &question).unwrap();
    assert!(
        candidate
            .commands
            .iter()
            .any(|command| matches!(command, Command::Deduce { .. }))
    );
    let certificate = solution.checked().unwrap();
    let unfolded = naome_proof::program::Projection::from_normal_form(certificate.normal_form());
    let input_bytes = |records: &[Command]| {
        records
            .iter()
            .map(|command| naome_proof::program::encode_command(command).unwrap().len())
            .sum::<usize>()
    };
    let baseline_bytes = input_bytes(unfolded.commands());
    let mut comparison = Work::open(&directory.0.join("unfolded-measurement.sqlite3")).unwrap();
    for group in unfolded.commands().chunks(CHUNK_RECORDS) {
        comparison.append_group(group).unwrap();
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
    let baseline_inputs = graph.prepare_generated_helpers(&solution.helpers).unwrap();
    let compare_started = Instant::now();
    let mut baseline_work = 0;
    while comparison
        .advance(&budget, baseline_inputs.context())
        .unwrap()
    {
        baseline_work += comparison.last_quantum_steps();
    }
    baseline_work += comparison.last_quantum_steps();
    let baseline_checker_micros = compare_started.elapsed().as_micros();
    while !comparison.prepare_export(&budget).unwrap() {}
    let baseline = comparison.into_checked().unwrap();
    question
        .classify_checked_program(baseline.proof().unwrap())
        .unwrap();
    drop(baseline_inputs);

    let owner = jobs::tests::Manual::new();
    let started = Instant::now();
    let search = solution.cost.search_expansions;
    let mut generated = Generated::native(29, solution, &question).unwrap();
    let batch = (0..4096)
        .find_map(|_| generated.prepare(&graph, &owner.client, &question).unwrap())
        .expect("bounded typed scope should reach independently checked admission");
    let elapsed = started.elapsed().as_micros();
    let root = batch.0;
    assert_eq!(root, candidate.manifest.artifact_id());
    assert!(!graph.contains(root).unwrap());
    graph
        .commit_batch(root, batch.1, Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert_eq!(
        graph.program_manifest(root).unwrap(),
        Some(candidate.manifest.clone())
    );
    let packet = graph
        .learning_certificate(root)
        .unwrap()
        .expect("typed scope replay packet");
    assert_eq!(
        crate::learning::evidence::decode(&packet)
            .unwrap()
            .program
            .unwrap()
            .manifest,
        candidate.manifest
    );
    let scope = generated.native.as_ref().unwrap();
    assert!(scope.checker_work > 0 && candidate.manifest.input_bytes < baseline_bytes as u64);
    eprintln!(
        "typed_scope matched_successes=1/1 scope_bytes={} unfolded_bytes={baseline_bytes} search_expansions={search} scope_checker_work={} unfolded_checker_work={baseline_work} scope_checker_micros={} unfolded_checker_micros={baseline_checker_micros} scope_publication_micros={elapsed}",
        candidate.manifest.input_bytes,
        scope.checker_work,
        scope.checker_time.as_micros()
    );
    drop(generated);
    drop(graph);
    let graph = Graph::open(&directory.0).unwrap();
    assert!(graph.contains(root).unwrap());
    assert_eq!(
        graph.program_manifest(root).unwrap(),
        Some(candidate.manifest)
    );
}

#[test]
fn finder_and_solver_bind_a_checked_program_and_definition_through_publication() {
    crate::resources::tests::budget(false);
    let mut graph = Graph::default();
    let owner = jobs::tests::Manual::new();
    let (first, seed) = crate::learning::tests::typed_scope_candidate(false);
    let mut generated = Generated::native(71, seed, &first).unwrap();
    let (first_id, batch) = (0..4096)
        .find_map(|_| generated.prepare(&graph, &owner.client, &first).unwrap())
        .expect("checked source program");
    graph
        .commit_batch(first_id, batch, Instant::now() + Duration::from_secs(5))
        .unwrap();
    let first_proof = graph
        .program_manifest(first_id)
        .unwrap()
        .unwrap()
        .proof_id();

    let second = ResearchQuestion::from_hex(&crate::learning::tests::own_question()).unwrap();
    let seed = crate::learning::tests::own_solution();
    for helper in &seed.helpers {
        graph.produce(helper).unwrap();
    }
    let (second_proof, second_ingest) = graph.produce(&seed.source).unwrap();
    let second_proof = second_proof.proof_id().unwrap().unwrap();
    let definition = naome_proof::DefinitionCertificate::relation(
        2,
        naome_proof::DefinedFormula::member(
            crate::test_inputs::variable(0),
            crate::test_inputs::variable(1),
        ),
    )
    .unwrap();
    let (_, definition_ingest) = graph
        .produce(&crate::test_inputs::definition(&definition))
        .unwrap();

    let (question, solution, required, definition_id) =
        crate::learning::tests::typed_definition_consumer(&graph, &first, &second);
    assert_eq!(definition_id, definition.definition_id());
    assert!(required.contains(&crate::hex(first_proof.as_bytes())));
    assert!(required.contains(&crate::hex(second_proof.as_bytes())));
    let planned = crate::learning::program::Candidate::from_solution(&solution, &question).unwrap();
    assert!(planned.commands.iter().any(|command| matches!(command,
        Command::ProofReference { proof_id } if proof_id == first_proof.as_bytes()
    )));
    assert!(planned.commands.iter().any(|command| matches!(command,
        Command::DefinedRelation { definition_id: offered, .. } if offered == definition_id.as_bytes()
    )));
    let mut generated = Generated::native(72, solution, &question).unwrap();
    let (root, batch) = (0..4096)
        .find_map(|_| generated.prepare(&graph, &owner.client, &question).unwrap())
        .expect("independent program acceptance with the exact checked inputs");
    assert_eq!(root, planned.manifest.artifact_id());
    graph
        .commit_batch_granted(
            root,
            batch,
            Instant::now() + Duration::from_secs(5),
            None,
            Some(&question),
        )
        .unwrap();
    let mut persisted = Vec::new();
    for position in 0..planned.manifest.commands {
        persisted.extend(
            graph
                .program_chunk(root, position, 1, naome_proof::program::RECORD_BYTES)
                .unwrap()
                .unwrap()
                .records,
        );
    }
    assert_eq!(persisted, planned.commands);
    assert!(persisted.iter().any(|command| matches!(command,
        Command::ProofReference { proof_id } if proof_id == second_proof.as_bytes()
    )));
    assert!(graph.contains(first_id).unwrap());
    assert!(graph.contains(second_ingest.id).unwrap());
    assert!(graph.contains(definition_ingest.id).unwrap());
    assert_eq!(
        graph.program_manifest(root).unwrap(),
        Some(planned.manifest)
    );
}
