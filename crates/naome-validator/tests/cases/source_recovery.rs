use super::*;
use continuous::{continuous, publish};

fn recovery(open: &str, directory: &str) -> String {
    open.replace(
        "[sources]\n",
        &format!("[sources]\nrecovery_directory = {directory:?}\n"),
    )
}

fn corrupt_sources(layout: &Layout) -> Images {
    layout.write(
        "candidates/artifact-block-candidate-store.log",
        b"corrupt candidate generation",
    );
    layout.write(
        "payloads/artifact-payload-store.log",
        b"corrupt payload generation",
    );
    layout.images_in(&["candidates", "payloads"])
}

fn stopped_choice() -> (Corpus, Layout, String) {
    let corpus = Corpus::new([1; 4]);
    let layout = Layout::new();
    let gates = std::array::from_fn(|_| Gate::bind());
    let actor = (corpus.proposers[0] + 1) % 4;
    let config = continuous(configured(&corpus, &layout, actor, &gates))
        .replace("base_millis = \"1000\"", "base_millis = \"120000\"");
    publish(&layout, &[corpus.blocks[0].id()]);
    let mut node = Process::start(&layout, &config);
    drop(node.child.stdin.take());
    node.ready();
    node.event("supervisor_candidate_selected");
    node.signal(rustix::process::Signal::TERM);
    node.event("stopped");
    assert!(node.exit().success());
    let open = config.replace("mode = \"create\"", "mode = \"open\"");
    (corpus, layout, open)
}

fn refused(layout: &Layout, config: &str, code: &str) {
    let before = layout.images();
    let mut node = Process::start(layout, config);
    assert_eq!(node.event("error")["code"], code);
    assert!(!node.exit().success());
    assert!(!node.observed.iter().any(|e| e["event"] == "ready"));
    assert_eq!(layout.images(), before);
}

#[test]
fn explicit_source_recovery_preserves_choice_and_authority_and_reuses_generation() {
    let _fixture = process_fixture_guard();
    let (_, layout, open) = stopped_choice();
    let authority = layout.images();
    let old_sources = corrupt_sources(&layout);
    refused(&layout, &open, "source_candidates_open");
    fs::create_dir(layout.root.join("recovery")).unwrap();
    let config = recovery(&open, "recovery");
    let mut previous = None;
    for _ in 0..2 {
        let mut node = Process::start(&layout, &config);
        drop(node.child.stdin.take());
        assert_eq!(node.ready()["driver"]["height"], "1");
        refused(&layout, &config, "source_recovery_locked");
        node.signal(rustix::process::Signal::TERM);
        node.event("stopped");
        assert!(node.exit().success());
        assert_eq!(layout.images(), authority);
        assert_eq!(layout.images_in(&["candidates", "payloads"]), old_sources);
        let image = layout.images_in(&["recovery/candidates", "recovery/payloads"]);
        if let Some(previous) = &previous {
            assert_eq!(&image, previous);
        }
        previous = Some(image);
    }
    let seal = layout.root.join("recovery/source-generation-v0.json");
    assert!(seal.is_file());
    let original = fs::read(&seal).unwrap();
    fs::write(&seal, b"partial seal").unwrap();
    refused(&layout, &config, "source_recovery_binding");
    fs::write(&seal, original).unwrap();
    layout.write(
        "recovery/payloads/artifact-payload-store.log",
        b"new corruption",
    );
    let damaged = layout.images_in(&["recovery/candidates", "recovery/payloads"]);
    refused(&layout, &config, "source_payloads_open");
    assert_eq!(
        layout.images_in(&["recovery/candidates", "recovery/payloads"]),
        damaged
    );
    fs::remove_file(&seal).unwrap();
    refused(&layout, &config, "source_recovery_incomplete_generation");
    assert_eq!(layout.images_in(&["candidates", "payloads"]), old_sources);
}

#[test]
fn explicit_source_recovery_rejects_overlap_partial_initialization_and_changed_binding() {
    let _fixture = process_fixture_guard();
    let (_, layout, open) = stopped_choice();
    let old_sources = corrupt_sources(&layout);
    for path in [
        "candidates",
        "payloads",
        "vote-journal",
        "finality-anchor",
        "evidence",
        ".",
    ] {
        refused(
            &layout,
            &recovery(&open, path),
            "source_recovery_directory_overlap",
        );
    }
    std::os::unix::fs::symlink(layout.root.join("vote-journal"), layout.root.join("alias"))
        .unwrap();
    refused(
        &layout,
        &recovery(&open, "alias"),
        "source_recovery_directory",
    );
    fs::create_dir(layout.root.join("partial")).unwrap();
    fs::create_dir(layout.root.join("partial/candidates")).unwrap();
    refused(
        &layout,
        &recovery(&open, "partial"),
        "source_recovery_incomplete_generation",
    );
    fs::create_dir(layout.root.join("recovery")).unwrap();
    let config = recovery(&open, "recovery");
    let mut node = Process::start(&layout, &config);
    drop(node.child.stdin.take());
    node.ready();
    node.signal(rustix::process::Signal::TERM);
    node.event("stopped");
    assert!(node.exit().success());
    fs::create_dir(layout.root.join("other-candidates")).unwrap();
    refused(
        &layout,
        &config.replace(
            "candidate_directory = \"candidates\"",
            "candidate_directory = \"other-candidates\"",
        ),
        "source_recovery_binding",
    );
    refused(
        &layout,
        &config.replacen("mode = \"open\"", "mode = \"create\"", 1),
        "source_recovery_requires_supervised_restart",
    );
    assert_eq!(layout.images_in(&["candidates", "payloads"]), old_sources);
}

#[test]
fn explicit_source_recovery_does_not_resume_an_incomplete_signing_preparation() {
    let _fixture = process_fixture_guard();
    let (corpus, layout, open) = stopped_choice();
    let actor = (corpus.proposers[0] + 1) % 4;
    {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
            corpus.context,
            &corpus.entries,
            ArtifactChainState::new(corpus.definition).branch_snapshot(),
        )
        .unwrap();
        let round = branch.begin_round_zero().unwrap();
        let mut journal = naome_storage::FixedValidatorAnchoredVoteSafetyJournalV0::open(
            layout.root.join("vote-journal"),
            layout.root.join("vote-anchor"),
            corpus.context,
            branch.fixed_agreement_set_id(),
            corpus.keys[actor].clone(),
            naome_storage::FixedValidatorVoteSafetyReplayLimitV0::new(256).unwrap(),
        )
        .unwrap();
        let mut session = journal.issue_signing_session(&round).unwrap();
        let effect = session.decide_prevote_without_proposal().unwrap();
        assert!(matches!(
            session.prepare_vote(&round, effect).unwrap(),
            naome_storage::FixedValidatorVotePrepareOutcomeV0::Prepared(_)
        ));
    }
    let old_sources = corrupt_sources(&layout);
    fs::create_dir(layout.root.join("recovery")).unwrap();
    let config = recovery(&open, "recovery");
    for _ in 0..2 {
        refused(&layout, &config, "startup_pending_vote");
        assert_eq!(layout.images_in(&["candidates", "payloads"]), old_sources);
    }
}

#[test]
fn explicit_source_recovery_rejects_invalid_replacement_and_reacquires_after_sigkill() {
    let _fixture = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    for gate in &gates {
        gate.allow_backend_restart();
    }
    let actor = corpus.proposers[0];
    let configs = std::array::from_fn(|i| {
        continuous(configured(&corpus, &layouts[i], i, &gates))
            .replace("base_millis = \"1000\"", "base_millis = \"120000\"")
    });
    let mut invalid_bytes = corpus.blocks[0].to_canonical_bytes();
    invalid_bytes[64] ^= 1;
    let invalid = ArtifactBlock::from_canonical_bytes(&invalid_bytes).unwrap();
    for layout in &layouts {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let inserted = ArtifactBlockCandidateStore::open(
            &layout.root.join("candidates"),
            corpus.definition,
            ArtifactBlockCandidateStoreLimits::new(128).unwrap(),
        )
        .unwrap()
        .insert(&invalid)
        .unwrap();
        assert_eq!(
            inserted,
            naome_storage::ArtifactBlockCandidateInsertOutcome::Inserted
        );
    }
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    pump_until(&mut nodes, "source recovery initial sessions", |nodes| {
        nodes.iter().all(|node| {
            node.observed
                .iter()
                .any(|e| e["event"] == "peer_session" && e["state"] == "established")
        })
    });
    let listening = nodes[actor]
        .observed
        .iter()
        .find(|e| e["event"] == "listening")
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_owned();
    nodes[actor].signal(rustix::process::Signal::TERM);
    nodes[actor].event("stopped");
    assert!(nodes[actor].exit().success());
    let authority = layouts[actor].images();
    let old_sources = corrupt_sources(&layouts[actor]);
    fs::create_dir(layouts[actor].root.join("recovery")).unwrap();
    let config = recovery(
        &configs[actor]
            .replace("mode = \"create\"", "mode = \"open\"")
            .replace(
                "listen = \"/ip4/127.0.0.1/tcp/0\"",
                &format!("listen = {listening:?}"),
            ),
        "recovery",
    );
    nodes[actor] = Process::start(&layouts[actor], &config);
    drop(nodes[actor].child.stdin.take());
    assert_eq!(nodes[actor].ready()["driver"]["height"], "1");
    nodes[actor].until(|e| e["event"] == "peer_session" && e["state"] == "established");
    for (i, node) in nodes.iter().enumerate() {
        if i != actor {
            node.signal(rustix::process::Signal::STOP);
        }
    }
    publish(&layouts[actor], &[corpus.blocks[0].id()]);
    nodes[actor].until(|e| {
        e["event"] == "command_result" && e["outcome"]["event"] == "acquisition_started"
    });
    nodes[actor].child.kill().unwrap();
    assert!(!nodes[actor].exit().success());
    assert_eq!(layouts[actor].images(), authority);
    let seal = fs::read(
        layouts[actor]
            .root
            .join("recovery/source-generation-v0.json"),
    )
    .unwrap();
    let generation = layouts[actor].images_in(&["recovery/candidates", "recovery/payloads"]);
    // A structurally addressed block with a false resulting root may be
    // retained as raw input, but its otherwise canonical payload must never
    // become admitted source data or a signing choice.
    publish(&layouts[actor], &[invalid.id()]);
    nodes[actor] = Process::start(&layouts[actor], &config);
    drop(nodes[actor].child.stdin.take());
    assert_eq!(nodes[actor].ready()["driver"]["height"], "1");
    assert_eq!(
        layouts[actor].images_in(&["recovery/candidates", "recovery/payloads"]),
        generation
    );
    assert_eq!(
        fs::read(
            layouts[actor]
                .root
                .join("recovery/source-generation-v0.json")
        )
        .unwrap(),
        seal
    );
    for (i, node) in nodes.iter().enumerate() {
        if i != actor {
            node.signal(rustix::process::Signal::CONT);
        }
    }
    pump_until_with_bound(
        &mut nodes,
        "source recovery invalid replacement",
        Duration::from_secs(90),
        |nodes| {
            nodes[actor].observed.iter().any(|e| {
                e["event"] == "acquisition_failed" && e["code"] == "source_payload_failure"
            })
        },
    );
    assert_eq!(layouts[actor].images(), authority);
    assert!(!nodes[actor].observed.iter().any(|e| {
        e["event"] == "supervisor_candidate_selected" || e["event"] == "publication_prepared"
    }));
    assert_eq!(
        layouts[actor].images_in(&["recovery/payloads"]),
        generation
            .into_iter()
            .filter(|(path, _)| path.starts_with("recovery/payloads"))
            .collect::<Images>(),
    );
    for index in 0..3 {
        for layout in &layouts {
            publish(layout, &[corpus.blocks[index].id()]);
        }
        pump_recovery_until(&mut nodes, "source recovery finality", |nodes| {
            nodes.iter().all(|node| reached(node, &corpus, index))
        });
    }
    assert!(
        nodes[actor]
            .observed
            .iter()
            .any(|e| e["event"] == "acquisition_complete")
    );
    stop(&mut nodes);
    let completed_generation =
        layouts[actor].images_in(&["recovery/candidates", "recovery/payloads"]);
    let final_authority = layouts[actor].images();
    let mut reopened = Process::start(&layouts[actor], &config);
    drop(reopened.child.stdin.take());
    assert_eq!(reopened.ready()["driver"]["height"], "4");
    reopened.signal(rustix::process::Signal::TERM);
    reopened.event("stopped");
    assert!(reopened.exit().success());
    assert_eq!(layouts[actor].images(), final_authority);
    assert_eq!(
        layouts[actor].images_in(&["recovery/candidates", "recovery/payloads"]),
        completed_generation
    );
    refused(
        &layouts[actor],
        &config.replace("candidate_entries = \"128\"", "candidate_entries = \"1\""),
        "source_candidates_open",
    );
    assert_eq!(
        layouts[actor].images_in(&["candidates", "payloads"]),
        old_sources
    );
    verify(&corpus, &layouts);
}
