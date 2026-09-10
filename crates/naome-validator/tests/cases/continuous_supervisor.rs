use super::*;

pub(super) fn continuous(config: String) -> String {
    config
        .lines()
        .map(|line| {
            if line.starts_with("targets = [") {
                "candidate_inbox = \"candidate-inbox.json\""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn publish(layout: &Layout, ids: &[ArtifactBlockId]) {
    let bytes = serde_json::to_vec(
        &json!({"candidates": ids.iter().map(|id| hex(id.as_bytes())).collect::<Vec<_>>()}),
    )
    .unwrap();
    let temporary = layout.root.join("candidate-inbox.next");
    fs::write(&temporary, bytes).unwrap();
    fs::rename(temporary, layout.root.join("candidate-inbox.json")).unwrap();
}

use naome_chain::ArtifactBlockId;

#[test]
fn continuous_supervisor_waits_on_invalid_inbox_without_changing_durable_choice() {
    let _fixture = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let layout = Layout::new();
    let gates = std::array::from_fn(|_| Gate::bind());
    let actor = (corpus.proposers[0] + 1) % 4;
    let config = continuous(configured(&corpus, &layout, actor, &gates))
        .replace("base_millis = \"1000\"", "base_millis = \"120000\"");
    let mut node = Process::start(&layout, &config);
    drop(node.child.stdin.take());
    node.ready();
    let path = layout.root.join("candidate-inbox.json");
    let choice = layout.root.join("vote-journal/supervisor-choice-v0.json");
    let before = fs::read(&choice).unwrap();
    assert_eq!(node.event("supervisor_inbox_waiting")["code"], "file_open");
    for (bytes, code) in [
        (b"{".to_vec(), "supervisor_inbox_schema"),
        (vec![b' '; 20_001], "file_too_large"),
        (
            serde_json::to_vec(
                &json!({"candidates": vec![hex(corpus.blocks[0].id().as_bytes()); 257]}),
            )
            .unwrap(),
            "supervisor_inbox_limit",
        ),
        (
            serde_json::to_vec(&json!({"candidates": ["not-an-id"]})).unwrap(),
            "source_block_id",
        ),
    ] {
        fs::write(&path, bytes).unwrap();
        node.until(|e| e["event"] == "supervisor_inbox_waiting" && e["code"] == code);
        assert_eq!(fs::read(&choice).unwrap(), before);
    }
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&choice, &path).unwrap();
    node.until(|e| e["event"] == "supervisor_inbox_waiting" && e["code"] == "file_open");
    assert_eq!(fs::read(&choice).unwrap(), before);
    fs::remove_file(&path).unwrap();
    publish(&layout, &[corpus.blocks[0].id()]);
    assert_eq!(
        node.event("supervisor_candidate_selected")["target"],
        hex(corpus.blocks[0].id().as_bytes())
    );
    node.signal(rustix::process::Signal::TERM);
    node.event("stopped");
    assert!(node.exit().success());
    assert!(!node.observed.iter().any(|e| e["event"] == "command_result"));
}

#[test]
fn continuous_supervisor_validates_and_persists_lowest_eligible_choice_across_sigkill() {
    let _fixture = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let layout = Layout::new();
    let gates = std::array::from_fn(|_| Gate::bind());
    let actor = (corpus.proposers[0] + 1) % 4;
    let config = continuous(configured(&corpus, &layout, actor, &gates))
        .replace("base_millis = \"1000\"", "base_millis = \"120000\"");
    let genesis = ArtifactChainState::new(corpus.definition);
    let mut valid = corpus
        .blocks
        .iter()
        .map(|block| genesis.prepare_block(block.artifact_id()).unwrap())
        .collect::<Vec<_>>();
    valid.sort_by_key(|block| *block.id().as_bytes());
    let expected = valid[0].id();
    let parent = genesis.head_block_id();
    let artifact = corpus.blocks[0].artifact_id();
    let invalid = (0u32..10_000)
        .map(|nonce| {
            let mut root = [0; 32];
            root[..4].copy_from_slice(&nonce.to_be_bytes());
            ArtifactBlock::new(
                parent,
                naome_chain::ArtifactSetRoot::from_bytes(root),
                valid[0].resulting_artifact_set_root(),
                artifact,
            )
        })
        .find(|block| block.id().as_bytes() < expected.as_bytes())
        .expect("invalid smaller candidate fixture");
    {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let mut candidates = ArtifactBlockCandidateStore::open(
            layout.root.join("candidates"),
            corpus.definition,
            ArtifactBlockCandidateStoreLimits::new(128).unwrap(),
        )
        .unwrap();
        for block in valid.iter().chain(std::iter::once(&invalid)) {
            let _ = candidates.insert(block).unwrap();
        }
    }
    let mut node = Process::start(&layout, &config);
    drop(node.child.stdin.take());
    node.ready();
    let mut hints = valid
        .iter()
        .rev()
        .map(ArtifactBlock::id)
        .collect::<Vec<_>>();
    hints.extend([invalid.id(), ArtifactBlockId::from_bytes([0; 32]), expected]);
    publish(&layout, &hints);
    assert_eq!(
        node.event("supervisor_candidate_selected")["target"],
        hex(expected.as_bytes())
    );
    assert_eq!(
        node.event("proposal_job_waiting")["job"]["target"],
        hex(expected.as_bytes())
    );
    node.child.kill().unwrap();
    assert!(!node.exit().success());
    let choice_path = layout.root.join("vote-journal/supervisor-choice-v0.json");
    let before = fs::read(&choice_path).unwrap();
    publish(&layout, &[valid[1].id()]);
    let open = config.replace("mode = \"create\"", "mode = \"open\"");
    let mut node = Process::start(&layout, &open);
    drop(node.child.stdin.take());
    node.ready();
    assert_eq!(
        node.event("proposal_job_waiting")["job"]["target"],
        hex(expected.as_bytes())
    );
    node.signal(rustix::process::Signal::TERM);
    node.event("stopped");
    assert!(node.exit().success());
    assert_eq!(fs::read(&choice_path).unwrap(), before);
    assert!(
        !node
            .observed
            .iter()
            .any(|e| e["event"] == "supervisor_candidate_selected")
    );
    // A damaged preference cannot be treated as an empty inbox or a new choice.
    let mut damaged = before.clone();
    let last = damaged.len() - 1;
    damaged[last] = if damaged[last] == b'0' { b'1' } else { b'0' };
    fs::write(&choice_path, damaged).unwrap();
    let images = layout.images();
    let mut node = Process::start(&layout, &open);
    assert_eq!(node.event("error")["code"], "supervisor_choice_integrity");
    assert!(!node.exit().success());
    assert_eq!(layout.images(), images);
    for (field, value) in [("height", "2".to_owned()), ("parent", "ff".repeat(32))] {
        use sha2::{Digest, Sha256};
        let mut record: Value = serde_json::from_slice(&before[..before.len() - 65]).unwrap();
        record[field] = json!(value);
        let mut bytes = serde_json::to_vec(&record).unwrap();
        let checksum = hex(&Sha256::digest(&bytes));
        bytes.push(b'\n');
        bytes.extend_from_slice(checksum.as_bytes());
        fs::write(&choice_path, bytes).unwrap();
        let images = layout.images();
        let mut node = Process::start(&layout, &open);
        assert_eq!(node.event("error")["code"], "supervisor_choice_position");
        assert!(!node.exit().success());
        assert_eq!(layout.images(), images);
    }
    fs::remove_file(&choice_path).unwrap();
    let images = layout.images();
    let mut node = Process::start(&layout, &open);
    assert_eq!(node.event("error")["code"], "file_open");
    assert!(!node.exit().success());
    assert_eq!(layout.images(), images);
}

#[test]
fn continuous_supervisor_accepts_post_startup_batches_for_36_heights_and_heals_an_offline_peer() {
    let _fixture = process_fixture_guard();
    let corpus = Corpus::with_heights([1; 4], 36);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    for (gate, &(a, b)) in gates.iter().zip(&PAIRS) {
        if a == 3 || b == 3 {
            gate.cut();
        }
    }
    let configs = std::array::from_fn(|i| {
        continuous(configured(&corpus, &layouts[i], i, &gates))
            .replace("base_millis = \"1000\"", "base_millis = \"3000\"")
            .replace("catch_up_heights = \"16\"", "catch_up_heights = \"64\"")
            .replace(
                "vote_preparations = \"256\"",
                "vote_preparations = \"1024\"",
            )
            // Evidence inboxes retain prior-height inputs. The short fixture's
            // 128-entry cap saturates at H28; provision this longer bounded run.
            .replace("\nentries = \"128\"", "\nentries = \"1024\"")
    });
    assert!(
        configs
            .iter()
            .all(|c| !c.contains(&hex(corpus.blocks[0].id().as_bytes())))
    );
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    for node in &mut nodes {
        node.transcript_limit = 32_768;
    }
    for index in 0..36 {
        // Every next-height hint is published after the preceding height was
        // established. There is no startup plan or stdin command stream.
        for layout in &layouts {
            publish(layout, &[corpus.blocks[index].id()]);
        }
        pump_until(
            &mut nodes,
            &format!("continuous online majority height {}", index + 1),
            |nodes| nodes[..3].iter().all(|n| reached(n, &corpus, index)),
        );
        if index == 11 {
            assert!(!nodes[3].observed.iter().any(|e| e["event"] == "finality"));
            for gate in &gates {
                gate.heal();
            }
        }
    }
    pump_until_with_bound(
        &mut nodes,
        "continuous healed peer",
        Duration::from_secs(90),
        |nodes| nodes.iter().all(|n| reached(n, &corpus, 35)),
    );
    stop(&mut nodes);
    let ancestry = layouts
        .each_ref()
        .map(|layout| corpus.verify_with_limit(layout, 36, 32, false));
    assert!(ancestry.iter().all(|prefix| prefix == &ancestry[0]));
    assert!(
        nodes[3]
            .observed
            .iter()
            .any(|e| e["event"] == "sync_progress" || e["event"] == "sync_proposal_input")
    );
}

#[test]
fn continuous_supervisor_acquires_untrusted_hints_with_ordered_peer_fallback() {
    let _fixture = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    let proposer = corpus.proposers[0];
    let empty = (0..4).find(|&i| i != proposer).unwrap();
    let configs = std::array::from_fn(|i| {
        continuous(configured_with_sources(
            &corpus,
            &layouts[i],
            i,
            &gates,
            i != proposer && i != empty,
        ))
        .replace("base_millis = \"1000\"", "base_millis = \"120000\"")
    });
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    // Equal hint/peer counts expose coupled-cursor starvation: the lowest
    // available candidate must eventually reach a peer beyond the empty first.
    for index in 0..3 {
        let hints = [
            corpus.blocks[index].id(),
            ArtifactBlockId::from_bytes([0xfe; 32]),
            ArtifactBlockId::from_bytes([0xff; 32]),
        ];
        assert!(hints[0].as_bytes() < hints[1].as_bytes());
        for layout in &layouts {
            publish(layout, &hints);
        }
        pump_until_with_bound(
            &mut nodes,
            "continuous source fallback",
            Duration::from_secs(90),
            |nodes| nodes.iter().all(|n| reached(n, &corpus, index)),
        );
    }
    assert!(
        nodes[proposer]
            .observed
            .iter()
            .any(|e| e["event"] == "acquisition_complete")
    );
    let peers = nodes[proposer]
        .observed
        .iter()
        .filter(|e| e["event"] == "supervisor_acquisition_selected")
        .map(|e| e["peer_id"].clone())
        .collect::<Vec<_>>();
    assert!(peers.contains(&json!(corpus.peers[empty].to_string())));
    assert!(
        peers
            .iter()
            .any(|peer| *peer != json!(corpus.peers[empty].to_string()))
    );
    stop(&mut nodes);
    verify(&corpus, &layouts);
}

#[test]
fn continuous_supervisor_sigkill_with_outstanding_acquisition_retries_after_restart() {
    let _fixture = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    for gate in &gates {
        gate.allow_backend_restart();
    }
    let actor = corpus.proposers[0];
    let configs = std::array::from_fn(|i| {
        continuous(configured_with_sources(
            &corpus,
            &layouts[i],
            i,
            &gates,
            i != actor,
        ))
        .replace("base_millis = \"1000\"", "base_millis = \"120000\"")
    });
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    pump_until(&mut nodes, "continuous acquisition sessions", |nodes| {
        nodes.iter().all(|n| {
            n.observed
                .iter()
                .any(|e| e["event"] == "peer_session" && e["state"] == "established")
        })
    });
    // Pause every potential responder after the transport sessions exist.
    // This fixes the crash boundary after request start and before a response;
    // it makes no claim about an interrupted source-store append or signature.
    for (i, node) in nodes.iter().enumerate() {
        if i != actor {
            node.signal(rustix::process::Signal::STOP);
        }
    }
    publish(&layouts[actor], &[corpus.blocks[0].id()]);
    nodes[actor].until(|e| {
        e["event"] == "command_result"
            && e["id"] == 0
            && e["outcome"]["event"] == "acquisition_started"
    });
    let listening = nodes[actor]
        .observed
        .iter()
        .find(|e| e["event"] == "listening")
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        !nodes[actor]
            .observed
            .iter()
            .any(|e| e["event"] == "supervisor_candidate_selected"
                || e["event"] == "publication_prepared")
    );
    nodes[actor].child.kill().unwrap();
    assert!(!nodes[actor].exit().success());
    let open = configs[actor]
        .replace("mode = \"create\"", "mode = \"open\"")
        .replace(
            "listen = \"/ip4/127.0.0.1/tcp/0\"",
            &format!("listen = {listening:?}"),
        );
    nodes[actor] = Process::start(&layouts[actor], &open);
    drop(nodes[actor].child.stdin.take());
    assert_eq!(nodes[actor].ready()["driver"]["height"], "1");
    for (i, node) in nodes.iter().enumerate() {
        if i != actor {
            node.signal(rustix::process::Signal::CONT);
        }
    }
    let hints = corpus
        .blocks
        .iter()
        .map(ArtifactBlock::id)
        .collect::<Vec<_>>();
    for layout in &layouts {
        publish(layout, &hints);
    }
    pump_until_with_bound(
        &mut nodes,
        "continuous acquisition restart",
        Duration::from_secs(90),
        |nodes| nodes.iter().all(|n| reached(n, &corpus, 2)),
    );
    assert!(
        nodes[actor]
            .observed
            .iter()
            .any(|e| e["event"] == "acquisition_complete")
    );
    stop(&mut nodes);
    verify(&corpus, &layouts);
}
