use super::*;

#[test]
fn candidate_historical_sibling_uses_retained_parent_after_two_selections_and_reopens_terminal() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 3, Role::Precommit);
    let sibling = Proof::after_prefix(&fixture, &[], 2, 2, Role::Precommit);
    let layout = Layout::new();
    write_proof(&sibling, &layout, "input");
    let plan = Plan::new(fixture.peers[1]);
    let peer = plan.peer;
    let config = source_config(
        &layout,
        plan.configure(fixture.config(&layout, 1, "create", None, false)),
    );
    let mut node = Process::start(&layout, &config);
    node.ready();
    let address = address(&mut node);
    initial_arm(&mut node);
    let provider_guard = PARENT_JOURNALS.read().unwrap();
    let sdk = plan.start(
        &provider_guard,
        fixture.definition,
        &address,
        vec![sibling.value.artifact_block()],
        vec![sibling.payload.clone()],
        None,
    );
    connected(&mut node, peer);
    let authority = layout.images();
    load(&mut node, &sdk, peer, &sibling);
    assert_eq!(layout.images(), authority);
    let sources = source_images(&layout);
    select(&mut node, &layout, &[&first, &second]);
    let initial = result(&mut node, json!({"command":"status", "id":1}));
    assert_eq!(initial["driver"]["height"], "3");
    assert_eq!(initial["driver"]["round"], "0");
    let before = layout.images();
    halt(
        &result(&mut node, command(&sibling, "input", true)),
        &first,
        &sibling,
    );
    assert!(stopped(&mut node)["discarded"]["driver"].is_null());
    assert_ne!(layout.images(), before);
    assert_eq!(source_images(&layout), sources);
    sdk.stop();
    drop(provider_guard);
    let durable = layout.images();
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    assert_eq!(reopened.event("error")["code"], "startup_finality_stopped");
    assert!(!reopened.exit().success());
    assert_eq!(layout.images(), durable);
    assert_eq!(source_images(&layout), sources);
}

#[test]
fn candidate_historical_delegated_rejections_consume_without_writes_and_strictly_reopen_healthy() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let sibling = Proof::new(&fixture, false, 2, Role::Precommit);
    for mode in [
        "missing-candidate",
        "missing-payload",
        "selected",
        "control",
        "duplicate",
        "signature",
        "round",
        "target",
    ] {
        let layout = Layout::new();
        let proof = if mode == "selected" { &first } else { &sibling };
        write_proof(proof, &layout, "input");
        let plan = Plan::new(fixture.peers[1]);
        let peer = plan.peer;
        let config = source_config(
            &layout,
            plan.configure(fixture.config(&layout, 1, "create", None, false)),
        );
        let mut node = Process::start(&layout, &config);
        node.ready();
        let address = address(&mut node);
        initial_arm(&mut node);
        let provider_guard = PARENT_JOURNALS.read().unwrap();
        let sdk = plan.start(
            &provider_guard,
            fixture.definition,
            &address,
            vec![proof.value.artifact_block()],
            vec![proof.payload.clone()],
            None,
        );
        connected(&mut node, peer);
        if mode == "missing-payload" {
            let target = hex(proof.value.artifact_block().id().as_bytes());
            acquire(
                &mut node,
                json!({"command":"acquire_ancestry", "id":1, "target":target, "peer_id":peer.to_string()}),
            );
            sdk.request("block", &target);
        } else if mode != "missing-candidate" {
            load(&mut node, &sdk, peer, proof);
        }
        select(&mut node, &layout, &[&first]);
        let initial = result(&mut node, json!({"command":"status", "id":2}));
        let before = layout.images();
        let sources = source_images(&layout);
        let mut input = command(proof, "input", true);
        match mode {
            "control" => {
                layout.write("input.control", [0]);
            }
            "duplicate" => input["vote_files"] = json!(["input.vote", "input.vote"]),
            "signature" => {
                let mut vote = proof.vote.clone();
                *vote.last_mut().unwrap() ^= 1;
                layout.write("input.vote", vote);
            }
            "round" => input["evidence_round"] = json!(u64::MAX),
            "target" => input["target"] = json!(hex(first.value.artifact_block().id().as_bytes())),
            _ => {}
        }
        failed(&result(&mut node, input), true);
        stopped(&mut node);
        assert_eq!(layout.images(), before, "{mode}");
        assert_eq!(source_images(&layout), sources);
        sdk.stop();
        drop(provider_guard);
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        let ready = reopened.ready();
        for field in ["height", "round", "phase", "head"] {
            assert_eq!(
                ready["driver"][field], initial["driver"][field],
                "{mode}: {field}"
            );
        }
        reopened.shutdown();
        assert_eq!(layout.images(), before);
        assert_eq!(source_images(&layout), sources);
    }
}

#[test]
fn candidate_proof_anchor_failures_consume_both_operations_and_refuse_partial_pair_restart() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let sibling = Proof::new(&fixture, false, 2, Role::Precommit);
    for conflict in [false, true] {
        for (directory, offset) in [("finality-anchor", 149), ("vote-anchor", 184)] {
            let layout = Layout::new();
            write_proof(&sibling, &layout, "input");
            let plan = Plan::new(fixture.peers[1]);
            let peer = plan.peer;
            let config = source_config(
                &layout,
                plan.configure(fixture.config(&layout, 1, "create", None, false)),
            );
            let mut node = Process::start(&layout, &config);
            node.ready();
            let address = address(&mut node);
            initial_arm(&mut node);
            let provider_guard = PARENT_JOURNALS.read().unwrap();
            let sdk = plan.start(
                &provider_guard,
                fixture.definition,
                &address,
                vec![sibling.value.artifact_block()],
                vec![sibling.payload.clone()],
                None,
            );
            connected(&mut node, peer);
            load(&mut node, &sdk, peer, &sibling);
            if conflict {
                select(&mut node, &layout, &[&first]);
            }
            let before = layout.images();
            let sources = source_images(&layout);
            let anchor = before
                .iter()
                .find(|(path, _)| {
                    path.starts_with(directory)
                        && path.extension().is_some_and(|ext| ext == "anchor")
                })
                .unwrap();
            let next = u64::from_be_bytes(anchor.1[offset..offset + 8].try_into().unwrap()) + 1;
            let collision = layout
                .root
                .join(format!("{}.tmp-{next:016x}", anchor.0.display()));
            fs::write(&collision, b"candidate proof anchor collision").unwrap();
            failed(
                &result(&mut node, command(&sibling, "input", conflict)),
                conflict,
            );
            stopped(&mut node);
            fs::remove_file(collision).unwrap();
            let after = layout.images();
            assert_eq!(before.len(), after.len());
            for ((path, old), (actual_path, new)) in before.iter().zip(&after) {
                assert_eq!(path, actual_path);
                let changes = path
                    == std::path::Path::new("finality-journal/artifact-chain.journal")
                    || (directory == "vote-anchor"
                        && ((path.starts_with("finality-anchor")
                            && path.extension().is_some_and(|ext| ext == "anchor"))
                            || (path.starts_with("vote-journal")
                                && path.extension().is_some_and(|ext| ext == "journal"))));
                if changes {
                    assert_ne!(old, new, "{conflict}: {path:?}");
                } else {
                    assert_eq!(old, new, "{conflict}: {path:?}");
                }
            }
            assert_eq!(source_images(&layout), sources);
            sdk.stop();
            drop(provider_guard);
            let mut reopened = Process::start(&layout, &config.replace("create", "open"));
            assert_eq!(reopened.event("error")["code"], "startup_open");
            assert!(!reopened.exit().success());
            assert_eq!(layout.images(), after);
            assert_eq!(source_images(&layout), sources);
        }
    }
}
