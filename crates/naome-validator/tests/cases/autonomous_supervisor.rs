//! Actual processes receive no command input: gates and signals are external faults.
use super::*;
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreLimits, ArtifactPayloadStoreLimits,
    CanonicalArtifactPayloadStore,
};

// Each fixture drives four durable signers with short protocol deadlines.
// Bound their aggregate process and fsync load without reducing any oracle.
pub(super) fn process_fixture_guard() -> std::sync::MutexGuard<'static, ()> {
    static ACTIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) fn configured(
    corpus: &Corpus,
    layout: &Layout,
    actor: usize,
    gates: &[Gate; 6],
) -> String {
    configured_with_sources(corpus, layout, actor, gates, true)
}

fn configured_with_sources(
    corpus: &Corpus,
    layout: &Layout,
    actor: usize,
    gates: &[Gate; 6],
    seed: bool,
) -> String {
    let _guard = PARENT_JOURNALS.read().unwrap();
    for name in ["candidates", "payloads", "evidence"] {
        fs::create_dir(layout.root.join(name)).unwrap();
    }
    let mut candidates = ArtifactBlockCandidateStore::create(
        layout.root.join("candidates"),
        corpus.definition,
        ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(
        layout.root.join("payloads"),
        ArtifactPayloadStoreLimits::new(16, 1_048_576).unwrap(),
    )
    .unwrap();
    let mut dag = ArtifactDag::new();
    for (block, bytes) in corpus.blocks.iter().zip(&corpus.payloads) {
        if !seed {
            break;
        }
        let _ = candidates.insert(block).unwrap();
        let _ = payloads
            .insert(dag.apply_canonical_artifact_bytes(bytes.clone()).unwrap())
            .unwrap();
    }
    drop((candidates, payloads));
    let targets = corpus
        .blocks
        .iter()
        .map(|b| format!("{:?}", hex(b.id().as_bytes())))
        .collect::<Vec<_>>()
        .join(",");
    let peers = (0..4)
        .filter(|&i| i != actor)
        .map(|i| format!("{:?}", corpus.peers[i].to_string()))
        .collect::<Vec<_>>()
        .join(",");
    let base = corpus.config(layout, actor, gates, 1000)
        .replace("[network]\n", "[network]\npublication_retry_millis = \"100\"\nserve_finality_proofs = true\nserve_artifact_sources = true\n")
        .replace("catch_up_heights = \"0\"", "catch_up_heights = \"16\"")
        .replace("proposal_preparations = \"8\"", "proposal_preparations = \"128\"")
        .replace("vote_preparations = \"64\"", "vote_preparations = \"256\"")
        .replace("max_round = \"4\"", "max_round = \"32\"")
        .replace("max_round = \"8\"", "max_round = \"32\"");
    // Leave headroom below the shared responder budget's one-request/second
    // refill; proof polling and multi-request source fills share that budget.
    format!(
        "{base}\n[sources]\nmode = \"open\"\ncandidate_directory = \"candidates\"\npayload_directory = \"payloads\"\ncandidate_entries = \"16\"\npayload_entries = \"16\"\npayload_bytes = \"1048576\"\n[evidence]\nmode = \"create\"\ndirectory = \"evidence\"\n[supervisor]\ntargets = [{targets}]\npeers = [{peers}]\ninterval_millis = \"1500\"\nacquisition_blocks = \"16\"\n"
    )
}

fn spawn(layouts: &[Layout; 4], configs: &[String; 4], gates: &mut [Gate; 6]) -> [Process; 4] {
    let mut nodes = std::array::from_fn(|i| {
        let mut node = Process::start(&layouts[i], &configs[i]);
        drop(node.child.stdin.take());
        node
    });
    let addresses = nodes.each_mut().map(|node| {
        node.ready();
        let event = node.event("listening");
        let port = event["address"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .parse::<u16>()
            .unwrap();
        ([127, 0, 0, 1], port).into()
    });
    for (gate, &(_, higher)) in gates.iter_mut().zip(&PAIRS) {
        gate.start(addresses[higher]);
    }
    nodes
}

fn reached(node: &Process, corpus: &Corpus, index: usize) -> bool {
    let expected_height = (index + 2).to_string();
    node.observed.iter().any(|e| {
        e["event"] == "finality"
            && e["state"]["driver"]["head"] == hex(corpus.blocks[index].id().as_bytes())
            && e["state"]["driver"]["height"] == expected_height
    })
}

fn stop(nodes: &mut [Process; 4]) {
    for node in nodes.iter() {
        node.signal(rustix::process::Signal::TERM);
    }
    for node in nodes.iter_mut() {
        assert_eq!(node.event("stopped")["reason"], "sigterm");
        assert!(node.exit().success());
        assert!(!node.observed.iter().any(|e| e["event"] == "command_result"));
    }
}

fn verify(corpus: &Corpus, layouts: &[Layout; 4]) {
    let ancestry = layouts
        .each_ref()
        .map(|layout| corpus.verify_with_limit(layout, 3, 32, false));
    assert!(ancestry.iter().all(|prefix| prefix == &ancestry[0]));
}

#[test]
fn autonomous_supervisor_finalizes_three_heights_with_closed_stdin_and_strictly_reopens() {
    let _fixture_guard = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    let configs = std::array::from_fn(|i| configured(&corpus, &layouts[i], i, &gates));
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    pump_until(&mut nodes, "autonomous three heights", |nodes| {
        nodes.iter().all(|n| reached(n, &corpus, 2))
    });
    stop(&mut nodes);
    verify(&corpus, &layouts);
    drop(gates);
    // No command reconstitutes the plan. The same persisted policy opens with
    // the finality journal already beyond the finite target list.
    for i in 0..4 {
        let mut node = Process::start(
            &layouts[i],
            &configs[i].replace("mode = \"create\"", "mode = \"open\""),
        );
        drop(node.child.stdin.take());
        assert_eq!(node.ready()["driver"]["height"], "4");
        node.signal(rustix::process::Signal::TERM);
        node.event("stopped");
        assert!(node.exit().success());
    }
}

#[test]
fn autonomous_supervisor_equal_partition_stalls_then_heals_without_commands() {
    let _fixture_guard = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    for (gate, &(a, b)) in gates.iter().zip(&PAIRS) {
        if (a < 2) != (b < 2) {
            gate.cut();
        }
    }
    let configs = std::array::from_fn(|i| configured(&corpus, &layouts[i], i, &gates));
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    pump_until(&mut nodes, "partitioned round progress", |nodes| {
        nodes
            .iter()
            .all(|n| n.observed.iter().any(|e| e["event"] == "timer_due"))
    });
    for node in &nodes {
        assert!(!node.observed.iter().any(|e| e["event"] == "finality"));
    }
    for gate in &gates {
        gate.heal();
    }
    pump_until(&mut nodes, "autonomous healing", |nodes| {
        nodes.iter().all(|n| reached(n, &corpus, 2))
    });
    stop(&mut nodes);
    verify(&corpus, &layouts);
}

#[test]
fn autonomous_supervisor_acquires_missing_sources_from_configured_peers() {
    let _fixture_guard = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    let proposer = corpus.proposers[0];
    let empty_first_peer = (0..4).find(|&i| i != proposer).unwrap();
    let configs = std::array::from_fn(|i| {
        configured_with_sources(
            &corpus,
            &layouts[i],
            i,
            &gates,
            i != proposer && i != empty_first_peer,
        )
        .replace("base_millis = \"1000\"", "base_millis = \"120000\"")
    });
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    // Three heights include ordered fallback and multiple bounded source
    // requests at the sustainable polling cadence configured above.
    pump_until_with_bound(
        &mut nodes,
        "autonomous source acquisition",
        Duration::from_secs(90),
        |nodes| nodes.iter().all(|n| reached(n, &corpus, 2)),
    );
    assert!(
        nodes[proposer]
            .observed
            .iter()
            .any(|e| e["event"] == "acquisition_complete")
    );
    let selected: Vec<_> = nodes[proposer]
        .observed
        .iter()
        .filter(|e| e["event"] == "supervisor_acquisition_selected" && e["kind"] == "ancestry")
        .collect();
    assert_eq!(
        selected.first().unwrap()["peer_id"],
        corpus.peers[empty_first_peer].to_string()
    );
    assert!(
        selected
            .iter()
            .any(|e| e["peer_id"] != corpus.peers[empty_first_peer].to_string())
    );
    for node in &nodes {
        node.signal(rustix::process::Signal::TERM);
    }
    for node in &mut nodes {
        node.event("stopped");
        assert!(node.exit().success());
    }
    for (i, layout) in layouts.iter().enumerate() {
        assert!(
            !publication_restart::signed_with_limits(&corpus, layout, i, 3, (32, 256, 32))
                .is_empty()
        );
    }
    verify(&corpus, &layouts);
}

#[test]
fn autonomous_supervisor_rejects_changed_missing_and_corrupt_restart_policy() {
    let _fixture_guard = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let layout = Layout::new();
    let gates = std::array::from_fn(|_| Gate::bind());
    let actor = (corpus.proposers[0] + 1) % 4;
    let config = configured(&corpus, &layout, actor, &gates)
        .replace("base_millis = \"1000\"", "base_millis = \"120000\"");
    let mut node = Process::start(&layout, &config);
    drop(node.child.stdin.take());
    node.ready();
    node.signal(rustix::process::Signal::TERM);
    node.event("stopped");
    assert!(node.exit().success());
    let open = config.replace("mode = \"create\"", "mode = \"open\"");
    let before = layout.images();
    for changed in [
        open.replace("interval_millis = \"1500\"", "interval_millis = \"101\""),
        open.split("[supervisor]").next().unwrap().to_owned(),
    ] {
        let mut node = Process::start(&layout, &changed);
        let error = node.event("error");
        assert!(matches!(
            error["code"].as_str(),
            Some("supervisor_policy_mismatch" | "supervisor_policy_missing")
        ));
        assert!(!node.exit().success());
        assert_eq!(layout.images(), before);
    }
    let path = layout.root.join("vote-journal/supervisor-policy-v0.json");
    fs::write(&path, b"corrupt").unwrap();
    let corrupted = layout.images();
    let mut node = Process::start(&layout, &open);
    assert_eq!(node.event("error")["code"], "supervisor_policy_mismatch");
    assert!(!node.exit().success());
    assert_eq!(layout.images(), corrupted);
    fs::remove_file(&path).unwrap();
    let missing = layout.images();
    let mut node = Process::start(&layout, &open);
    assert_eq!(node.event("error")["code"], "file_open");
    assert!(!node.exit().success());
    assert_eq!(layout.images(), missing);
}

#[test]
fn autonomous_supervisor_sigkill_replays_completed_publications_without_new_commands() {
    let _fixture_guard = process_fixture_guard();
    use std::os::unix::process::ExitStatusExt;
    let corpus = Corpus::new([1; 4]);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    for gate in &gates {
        gate.cut();
        gate.allow_backend_restart();
    }
    let configs = std::array::from_fn(|i| {
        configured(&corpus, &layouts[i], i, &gates)
            .replace("base_millis = \"1000\"", "base_millis = \"120000\"")
    });
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    let actor = corpus.proposers[0];
    // With every path cut, the proposer durably completes its proposal and
    // prevote and then waits without a quorum. No fault lands in preparation.
    pump_until(&mut nodes, "isolated completed publications", |nodes| {
        nodes[actor]
            .observed
            .iter()
            .filter(|e| e["event"] == "publication_complete")
            .count()
            >= 2
    });
    let listening = nodes[actor]
        .observed
        .iter()
        .find(|e| e["event"] == "listening")
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_owned();
    nodes[actor].child.kill().unwrap();
    assert_eq!(
        nodes[actor].exit().signal(),
        Some(rustix::process::Signal::KILL.as_raw())
    );
    let before =
        publication_restart::signed_with_limits(&corpus, &layouts[actor], actor, 1, (32, 256, 32));
    assert!(before.contains_key(&(1, 0, 0)));
    assert!(before.contains_key(&(1, 0, 1)));
    let open = configs[actor]
        .replace("mode = \"create\"", "mode = \"open\"")
        .replace(
            "listen = \"/ip4/127.0.0.1/tcp/0\"",
            &format!("listen = {listening:?}"),
        );
    nodes[actor] = Process::start(&layouts[actor], &open);
    drop(nodes[actor].child.stdin.take());
    let ready = nodes[actor].ready();
    assert_eq!(ready["driver"]["height"], "1");
    assert!(ready["publication_recovery_remaining"].as_u64().unwrap() >= 1);
    for gate in &gates {
        gate.heal();
    }
    pump_until(&mut nodes, "autonomous publication recovery", |nodes| {
        nodes.iter().all(|n| reached(n, &corpus, 2))
    });
    stop(&mut nodes);
    let after =
        publication_restart::signed_with_limits(&corpus, &layouts[actor], actor, 3, (32, 256, 32));
    for (identity, signed) in before {
        assert_eq!(after.get(&identity), Some(&signed));
    }
    verify(&corpus, &layouts);
}

#[test]
fn autonomous_supervisor_live_source_corruption_stops_before_authoring() {
    let _fixture_guard = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    for candidate in [true, false] {
        let layout = Layout::new();
        let gates = std::array::from_fn(|_| Gate::bind());
        let actor = (corpus.proposers[0] + 1) % 4;
        let config = configured(&corpus, &layout, actor, &gates)
            .replace("base_millis = \"1000\"", "base_millis = \"200\"");
        let mut node = Process::start(&layout, &config);
        drop(node.child.stdin.take());
        node.ready();
        node.until(|e| {
            e["event"] == "proposal_job_waiting" && e["job"]["state"] == "not_scheduled"
        });
        let path = layout.root.join(if candidate {
            "candidates/artifact-block-candidate-store.log"
        } else {
            "payloads/artifact-payload-store.log"
        });
        let mut damaged = fs::read(&path).unwrap();
        damaged.fill(0);
        fs::write(&path, &damaged).unwrap();
        assert_eq!(node.event("stopped")["reason"], "proposal_job_fatal");
        assert!(!node.exit().success());
        assert_eq!(fs::read(&path).unwrap(), damaged);
        assert!(
            !node
                .observed
                .iter()
                .any(|e| e["event"] == "proposal_job_attempt"
                    && e["outcome"]["event"] == "proposal_authored")
        );
        let before = layout.images();
        let mut reopened = Process::start(
            &layout,
            &config.replace("mode = \"create\"", "mode = \"open\""),
        );
        reopened.event("error");
        assert!(!reopened.exit().success());
        assert_eq!(layout.images(), before);
    }
}

#[test]
fn autonomous_supervisor_six_heights_interleave_retry_debt_and_isolated_peer_catches_up() {
    let _fixture_guard = process_fixture_guard();
    let corpus = Corpus::with_heights([1; 4], 6);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    let isolated = 3;
    for (gate, &(a, b)) in gates.iter().zip(&PAIRS) {
        if a == isolated || b == isolated {
            gate.cut();
        }
    }
    // Keep an offline recipient throughout six heights. Retry debt must give
    // ordinary work opportunities while the finite queue is still nonempty.
    let configs = std::array::from_fn(|i| {
        configured(&corpus, &layouts[i], i, &gates)
            .replace("base_millis = \"1000\"", "base_millis = \"3000\"")
    });
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    pump_until(&mut nodes, "autonomous strict-majority prefix", |nodes| {
        nodes[..isolated].iter().all(|n| reached(n, &corpus, 5))
    });
    assert!(
        !nodes[isolated]
            .observed
            .iter()
            .any(|e| e["event"] == "finality")
    );
    for gate in &gates {
        gate.heal();
    }
    pump_until(&mut nodes, "autonomous isolated peer catch-up", |nodes| {
        reached(&nodes[isolated], &corpus, 5)
    });
    assert!(
        nodes[isolated]
            .observed
            .iter()
            .any(|e| e["event"] == "sync_progress" || e["event"] == "sync_proposal_input")
    );
    stop(&mut nodes);
    assert!(nodes.iter().all(|node| {
        node.observed
            .iter()
            .filter(|e| e["event"] == "proposal_job_attempt")
            .all(|e| e["job"]["height"].as_str().unwrap().parse::<u64>().unwrap() <= 6)
    }));
    let mut interleaved = false;
    for node in &nodes[..isolated] {
        let mut originals = std::collections::BTreeMap::new();
        let mut gap = false;
        for event in &node.observed {
            match event["event"].as_str().unwrap() {
                "publication_prepared" => {
                    if gap {
                        interleaved = true;
                    }
                    gap = false;
                }
                "publication_recovered" => gap = false,
                "publication_complete" => {
                    let publication = &event["disposed"];
                    let id = publication["signer_state"].as_str().unwrap();
                    if publication["recovered"] == true {
                        assert_eq!(
                            originals.get(id),
                            Some(&publication["message_sha256"]),
                            "live retries must retain the original signed message"
                        );
                    } else {
                        assert!(
                            originals
                                .insert(id.to_owned(), publication["message_sha256"].clone())
                                .is_none()
                        );
                    }
                    gap = publication["local_admission_skipped"] == true
                        && event["publication_recovery_remaining"].as_u64().unwrap() > 0;
                }
                "timer_due" | "transitioned" | "admission" | "finality" if gap => {
                    interleaved = true
                }
                _ => {}
            }
        }
    }
    assert!(
        interleaved,
        "ordinary work must run between historical messages before the retry queue empties"
    );
    let ancestry = layouts
        .each_ref()
        .map(|layout| corpus.verify_with_limit(layout, 6, 32, false));
    assert!(ancestry.iter().all(|prefix| prefix == &ancestry[0]));
    drop(gates);
    for i in 0..4 {
        let before =
            publication_restart::signed_with_limits(&corpus, &layouts[i], i, 6, (32, 256, 32));
        let mut node = Process::start(
            &layouts[i],
            &configs[i].replace("mode = \"create\"", "mode = \"open\""),
        );
        drop(node.child.stdin.take());
        assert_eq!(node.ready()["driver"]["height"], "7");
        node.signal(rustix::process::Signal::TERM);
        node.event("stopped");
        assert!(node.exit().success());
        assert_eq!(
            publication_restart::signed_with_limits(&corpus, &layouts[i], i, 6, (32, 256, 32)),
            before
        );
    }
}
