//! Real direct publisher processes; validator directories receive no offer files.
//! One read-only FIFO status probe establishes the acquisition crash boundary.
use super::*;
use naome_chain::ArtifactBlockId;
use naome_network::{CandidateOffer, Keypair};
use naome_storage::{ArtifactChainJournal, CandidateBranchRecoveryBundleLimits};
use sha2::{Digest, Sha256};

struct Publisher {
    layout: Layout,
    peer: naome_network::PeerId,
    seed: [u8; 32],
    port: u16,
}
impl Publisher {
    fn new(corpus: &Corpus, skip: usize) -> Self {
        // All validator peers dial the publisher, whose fixed listener is known
        // before the validator processes expose their ephemeral listeners.
        let (seed, peer) = (0u16..256)
            .filter_map(|i| {
                let seed = [i as u8; 32];
                let mut identity_seed = seed;
                let peer = Keypair::ed25519_from_bytes(&mut identity_seed)
                    .unwrap()
                    .public()
                    .to_peer_id();
                corpus
                    .peers
                    .iter()
                    .all(|p| p.to_bytes() < peer.to_bytes())
                    .then_some((seed, peer))
            })
            .nth(skip)
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let layout = Layout::new();
        for name in ["candidates", "payloads", "journal"] {
            fs::create_dir(layout.root.join(name)).unwrap();
        }
        Self {
            layout,
            peer,
            seed,
            port,
        }
    }
    fn start(&self, corpus: &Corpus, nodes: &[Process; 4]) -> Process {
        use std::os::unix::fs::PermissionsExt;
        let path = self.layout.root.join("publisher.seed");
        fs::write(&path, self.seed).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut config = format!(
            "version = 0\nmode = \"create\"\ndeployment_discriminator = {:?}\nidentity_seed_file = \"publisher.seed\"\nlisten = \"/ip4/127.0.0.1/tcp/{}\"\njournal_directory = \"journal\"\noffer_file = \"offer.json\"\n",
            hex(&[0x91; 32]),
            self.port
        );
        for (i, node) in nodes.iter().enumerate() {
            let address = node
                .observed
                .iter()
                .find(|e| e["event"] == "listening")
                .unwrap()["address"]
                .as_str()
                .unwrap();
            config.push_str(&format!(
                "[[peers]]\npeer_id = {:?}\naddress = {:?}\n",
                corpus.peers[i].to_string(),
                address
            ));
        }
        config.push_str("[sources]\nmode = \"create\"\ncandidate_directory = \"candidates\"\npayload_directory = \"payloads\"\ncandidate_entries = \"128\"\npayload_entries = \"128\"\npayload_bytes = \"1048576\"\n");
        let mut process = Process::start_publisher(&self.layout, &config);
        drop(process.child.stdin.take());
        process.event("publisher_ready");
        process.event("listening");
        process.transcript_limit = 65_536;
        process
    }
    fn publish(&self, ids: &[ArtifactBlockId], bundle: Option<&[u8]>) -> String {
        let mut ids = ids.to_vec();
        ids.sort_unstable_by_key(|id| *id.as_bytes());
        ids.dedup();
        if let Some(bytes) = bundle {
            fs::write(self.layout.root.join("source.bundle"), bytes).unwrap();
        }
        let bytes=serde_json::to_vec(&json!({"candidates":ids.iter().map(|id|hex(id.as_bytes())).collect::<Vec<_>>(),"bundle_file":bundle.map(|_|"source.bundle")})).unwrap();
        fs::write(self.layout.root.join("offer.pending"), bytes).unwrap();
        fs::rename(
            self.layout.root.join("offer.pending"),
            self.layout.root.join("offer.json"),
        )
        .unwrap();
        let offer =
            CandidateOffer::new(ArtifactChainDefinition::new([0x91; 32]).id(), ids).unwrap();
        hex(&Sha256::digest(offer.to_wire_bytes()))
    }
}
fn configured_network(
    corpus: &Corpus,
    layout: &Layout,
    actor: usize,
    gates: &[Gate; 6],
    publishers: &[&Publisher],
    seed: bool,
) -> String {
    let base = configured_with_sources(corpus, layout, actor, gates, seed);
    let (network, supervisor) = base.split_once("[supervisor]").unwrap();
    let extra = publishers
        .iter()
        .map(|p| {
            format!(
                "{{ peer_id = {:?}, address = \"/ip4/127.0.0.1/tcp/{}\" }}",
                p.peer.to_string(),
                p.port
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let mut config = network
        .lines()
        .map(|line| {
            if line.starts_with("peers = [") {
                format!("{},{}]", line.strip_suffix(']').unwrap(), extra)
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    config.push_str("\n[supervisor]\n");
    config.push_str(
        &supervisor
            .lines()
            .filter(|line| !line.starts_with("targets = ") && !line.starts_with("peers = "))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let publishers_text = publishers
        .iter()
        .map(|p| format!("{:?}", p.peer.to_string()))
        .collect::<Vec<_>>()
        .join(",");
    let validators = (0..4)
        .filter(|i| *i != actor)
        .map(|i| format!("{:?}", corpus.peers[i].to_string()))
        .collect::<Vec<_>>()
        .join(",");
    config.push_str(&format!(
        "\npeers = [{publishers_text},{validators}]\ncandidate_publishers = [{publishers_text}]\n"
    ));
    config
}
fn pump(
    nodes: &mut [Process; 4],
    publishers: &mut [Process],
    label: &str,
    bound: Duration,
    predicate: impl Fn(&[Process; 4], &[Process]) -> bool,
) {
    let deadline = Instant::now() + bound;
    loop {
        let mut process_failure = None;
        for (index, node) in nodes.iter_mut().chain(publishers.iter_mut()).enumerate() {
            let mut output_closed = false;
            let mut error = None;
            if node.child.try_wait().unwrap().is_none() {
                for _ in 0..16 {
                    match node.observe_or_closed(Duration::from_millis(1)) {
                        Ok(Some(event)) if event["event"] == "error" => {
                            error = Some(event);
                            break;
                        }
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(_) => {
                            output_closed = true;
                            break;
                        }
                    }
                }
            }
            let exit = node.child.try_wait().unwrap();
            let drain = exit.as_ref().map(|_| node.drain_after_exit());
            if exit.is_some() || output_closed || error.is_some() {
                use std::os::unix::process::ExitStatusExt;
                process_failure = Some(json!({
                    "process_type":if index < 4 { "validator" } else { "publisher" },
                    "process_index":if index < 4 { index } else { index - 4 },
                    "pid":node.child.id(),
                    "exit_status":exit.as_ref().map(ToString::to_string),
                    "exit_code":exit.as_ref().and_then(|status| status.code()),
                    "exit_signal":exit.as_ref().and_then(|status| status.signal()),
                    "output_closed":output_closed,
                    "observed_error":error,
                    "post_exit_drain":drain,
                }));
                break;
            }
        }
        assert!(
            process_failure.is_none(),
            "{label}: process failure: {}; diagnostics: {}",
            process_failure.unwrap_or(serde_json::Value::Null),
            timeout_diagnostics(nodes, publishers)
        );
        if predicate(nodes, publishers) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{label}: {}",
            timeout_diagnostics(nodes, publishers)
        );
    }
}

// Read only the already observed transcript; diagnostics must not issue new
// commands, change delivery, or hide which half of the pump predicate stalled.
fn timeout_diagnostics(nodes: &[Process; 4], publishers: &[Process]) -> serde_json::Value {
    fn outcome(event: &serde_json::Value) -> &serde_json::Value {
        if event["event"] == "command_result" {
            &event["outcome"]
        } else {
            event
        }
    }
    fn latest(process: &Process, prefix: &str) -> Option<serde_json::Value> {
        process
            .observed
            .iter()
            .rev()
            .find(|event| {
                outcome(event)["event"]
                    .as_str()
                    .is_some_and(|name| name.starts_with(prefix))
            })
            .cloned()
    }
    fn sync_counts(process: &Process) -> std::collections::BTreeMap<String, usize> {
        let mut counts = std::collections::BTreeMap::new();
        for event in &process.observed {
            let event = outcome(event);
            if let Some(name) = event["event"].as_str()
                && (name.starts_with("sync_")
                    || name.starts_with("follow_")
                    || name == "supervisor_sync_waiting")
            {
                let reason = event["reason"].as_str().or_else(|| event["code"].as_str());
                let key = match reason {
                    Some(reason) => format!("{name}:{reason}"),
                    None => name.to_owned(),
                };
                let peer = event["peer_id"]
                    .as_str()
                    .or_else(|| event["job"]["peer_id"].as_str());
                let key = peer.map_or_else(|| key.clone(), |peer| format!("{key}:{peer}"));
                *counts.entry(key).or_insert(0) += 1;
            }
        }
        counts
    }
    fn recent(process: &Process) -> Vec<&serde_json::Value> {
        process
            .observed
            .iter()
            .rev()
            .filter(|event| outcome(event)["event"] != "publication_retry_scheduled")
            .take(12)
            .collect()
    }
    let nodes = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let driver = node.observed.iter().rev().find_map(|event| {
                let event = outcome(event);
                event["state"].get("driver").or_else(|| event.get("driver"))
            });
            json!({
                "node":index,
                "latest_finality":node.observed.iter().rev().find(|event| event["event"] == "finality"),
                "latest_observed_driver":driver,
                "latest_height":latest(node, "supervisor_height"),
                "latest_choice":latest(node, "supervisor_candidate_selected"),
                "latest_proposal":latest(node, "proposal_job_"),
                "latest_acquisition":latest(node, "acquisition_"),
                "latest_acquisition_selection":latest(node, "supervisor_acquisition_"),
                "latest_sync_stopped":latest(node, "sync_stopped"),
                "latest_sync_deferred":latest(node, "sync_deferred"),
                "latest_sync_progress":latest(node, "sync_progress"),
                "latest_sync_response":latest(node, "sync_response_"),
                "sync_event_reason_counts":sync_counts(node),
                "latest_error":latest(node, "error"),
                "latest_stopped":latest(node, "stopped"),
                "latest_fatal":node.observed.iter().rev().find(|event| {
                    matches!(outcome(event)["event"].as_str(), Some(
                        "listener_failed" | "allocation_failed" | "timing_failed" |
                        "finality_stopped" | "proof_failed" | "driver_unavailable" |
                        "unsupported_runtime_event"
                    ))
                }),

                "recent_non_retry_newest_first":recent(node),
            })
        })
        .collect::<Vec<_>>();
    let publishers = publishers
        .iter()
        .enumerate()
        .map(|(index, publisher)| {
            let mut digests = Vec::new();
            for event in publisher.observed.iter().rev() {
                if event["event"] == "publisher_offer_receipted"
                    && let Some(digest) = event["offer_sha256"].as_str()
                    && !digests.contains(&digest)
                {
                    digests.push(digest);
                    if digests.len() == 4 {
                        break;
                    }
                }
            }
            let receipts = digests
                .into_iter()
                .map(|digest| {
                    let matching = publisher.observed.iter().filter(|event| {
                        event["event"] == "publisher_offer_receipted"
                            && event["offer_sha256"] == digest
                    });
                    let count = matching.clone().count();
                    let peers = matching
                        .filter_map(|event| event["peer_id"].as_str())
                        .collect::<std::collections::BTreeSet<_>>();
                    json!({"offer_sha256":digest, "event_count":count, "distinct_peers":peers})
                })
                .collect::<Vec<_>>();
            json!({
                "publisher":index,
                "latest_loaded":latest(publisher, "publisher_offer_loaded"),
                "latest_error":latest(publisher, "error"),
                "latest_stopped":latest(publisher, "publisher_stopped"),

                "latest_four_receipted_digests":receipts,
                "recent_non_retry_newest_first":recent(publisher),
            })
        })
        .collect::<Vec<_>>();
    json!({"nodes":nodes, "publishers":publishers})
}
fn stop_publishers(publishers: &mut [Process]) {
    for p in publishers {
        p.signal(rustix::process::Signal::TERM);
        p.event("publisher_stopped");
        assert!(p.exit().success());
    }
}
fn source_bundle(corpus: &Corpus) -> Vec<u8> {
    let _guard = PARENT_JOURNALS.read().unwrap();
    let layout = Layout::new();
    let journal = ArtifactChainJournal::create(&layout.root, corpus.definition).unwrap();
    let mut candidates = ArtifactBlockCandidateStore::create(
        &layout.root,
        corpus.definition,
        ArtifactBlockCandidateStoreLimits::new(128).unwrap(),
    )
    .unwrap();
    let mut payloads = CanonicalArtifactPayloadStore::create(
        &layout.root,
        ArtifactPayloadStoreLimits::new(128, 1_048_576).unwrap(),
    )
    .unwrap();
    let mut dag = ArtifactDag::new();
    for (block, bytes) in corpus.blocks.iter().zip(&corpus.payloads) {
        let _ = candidates.insert(block).unwrap();
        let _ = payloads
            .insert(dag.apply_canonical_artifact_bytes(bytes.clone()).unwrap())
            .unwrap();
    }
    journal
        .export_candidate_branch_recovery_bundle_v0(
            corpus.blocks.last().unwrap().id(),
            &mut candidates,
            &mut payloads,
            CandidateBranchRecoveryBundleLimits::new(128, 1_048_576, 1_048_576).unwrap(),
        )
        .unwrap()
        .into_canonical_bytes()
}

#[test]
fn network_intake_acquires_post_startup_sources_and_survives_acquisition_sigkill() {
    let _fixture = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let publisher = Publisher::new(&corpus, 0);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    for gate in &gates {
        gate.allow_backend_restart();
    }
    let configs = std::array::from_fn(|i| {
        configured_network(&corpus, &layouts[i], i, &gates, &[&publisher], false)
            .replace("base_millis = \"1000\"", "base_millis = \"120000\"")
            .replace("interval_millis = \"1500\"", "interval_millis = \"5000\"")
    });
    let actor = (corpus.proposers[0] + 1) % 4;
    let mut nodes = spawn_with_probe(&layouts, &configs, &mut gates, Some(actor));
    for n in &mut nodes {
        n.transcript_limit = 65_536;
    }
    let mut publishers = [publisher.start(&corpus, &nodes)];
    let digest = publisher.publish(
        &corpus
            .blocks
            .iter()
            .map(ArtifactBlock::id)
            .collect::<Vec<_>>(),
        Some(&source_bundle(&corpus)),
    );
    pump(
        &mut nodes,
        &mut publishers,
        "durable offers before acquisition",
        Duration::from_secs(20),
        |_, p| {
            p[0].observed
                .iter()
                .filter(|e| {
                    e["event"] == "publisher_offer_receipted" && e["offer_sha256"] == digest
                })
                .count()
                == 4
        },
    );
    publishers[0].signal(rustix::process::Signal::STOP);
    for (i, node) in nodes.iter().enumerate() {
        if i != actor {
            node.signal(rustix::process::Signal::STOP);
        }
    }
    // This FIFO application reply must be generated after every responder is
    // frozen. Earlier reports in any stdout/reader queue cannot cross it.
    nodes[actor].send(json!({"command":"sources_status", "id":700}));
    pump(
        &mut nodes,
        &mut publishers,
        "read-only crash probe barrier",
        Duration::from_secs(10),
        |nodes, _| {
            nodes[actor]
                .observed
                .iter()
                .any(|e| e["event"] == "command_result" && e["id"] == 700)
        },
    );
    let after_pause = nodes[actor]
        .observed
        .iter()
        .position(|e| e["event"] == "command_result" && e["id"] == 700)
        .unwrap()
        + 1;
    drop(nodes[actor].child.stdin.take());
    pump(
        &mut nodes,
        &mut publishers,
        "post-startup source acquisition",
        Duration::from_secs(90),
        |nodes, _| {
            nodes[actor].observed[after_pause..].iter().any(|e| {
                e["event"] == "command_result" && e["outcome"]["event"] == "acquisition_started"
            })
        },
    );
    let started = nodes[actor].observed[after_pause..]
        .iter()
        .position(|e| {
            e["event"] == "command_result" && e["outcome"]["event"] == "acquisition_started"
        })
        .unwrap()
        + after_pause;
    assert!(!nodes[actor].observed[started..].iter().any(|e| matches!(
        e["event"].as_str(),
        Some("acquisition_complete" | "acquisition_failed" | "acquisition_cancelled")
    )));
    let address = nodes[actor]
        .observed
        .iter()
        .find(|e| e["event"] == "listening")
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_owned();
    nodes[actor].child.kill().unwrap();
    assert!(!nodes[actor].exit().success());
    let offers = fs::read(
        layouts[actor]
            .root
            .join("vote-journal/candidate-offers-v0.json"),
    )
    .unwrap();
    nodes[actor] = Process::start(
        &layouts[actor],
        &configs[actor]
            .replace("mode = \"create\"", "mode = \"open\"")
            .replace(
                "listen = \"/ip4/127.0.0.1/tcp/0\"",
                &format!("listen = {address:?}"),
            ),
    );
    drop(nodes[actor].child.stdin.take());
    nodes[actor].ready();
    nodes[actor].transcript_limit = 65_536;
    publishers[0].signal(rustix::process::Signal::CONT);
    for (i, node) in nodes.iter().enumerate() {
        if i != actor {
            node.signal(rustix::process::Signal::CONT);
        }
    }
    assert_eq!(
        offers,
        fs::read(
            layouts[actor]
                .root
                .join("vote-journal/candidate-offers-v0.json")
        )
        .unwrap()
    );
    pump(
        &mut nodes,
        &mut publishers,
        "network source acquisition after restart",
        Duration::from_secs(420),
        |nodes, p| {
            nodes.iter().all(|n| reached(n, &corpus, 2))
                && p[0].observed.iter().any(|e| {
                    e["event"] == "publisher_offer_receipted" && e["offer_sha256"] == digest
                })
        },
    );
    stop(&mut nodes);
    stop_publishers(&mut publishers);
    verify(&corpus, &layouts);
    for layout in &layouts {
        assert!(!layout.root.join("offer.json").exists());
    }
}

#[test]
fn network_intake_100_heights_with_competing_full_offers_and_partition_healing() {
    let _fixture = process_fixture_guard();
    let corpus = Corpus::with_heights([1; 4], 100);
    let honest = Publisher::new(&corpus, 0);
    let noisy = Publisher::new(&corpus, 1);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    for (gate, &(a, b)) in gates.iter().zip(&PAIRS) {
        if a == 3 || b == 3 {
            gate.cut();
        }
    }
    let configs = std::array::from_fn(|i| {
        configured_network(&corpus, &layouts[i], i, &gates, &[&honest, &noisy], true)
            .replace("base_millis = \"1000\"", "base_millis = \"3000\"")
            .replace("catch_up_heights = \"16\"", "catch_up_heights = \"128\"")
            .replace(
                "vote_preparations = \"256\"",
                "vote_preparations = \"4096\"",
            )
            .replace(
                "proposal_preparations = \"128\"",
                "proposal_preparations = \"512\"",
            )
            .replace("\nentries = \"128\"", "\nentries = \"4096\"")
    });
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    for n in &mut nodes {
        n.transcript_limit = 131_072;
    }
    let mut publishers = [honest.start(&corpus, &nodes), noisy.start(&corpus, &nodes)];
    for index in 0..100 {
        let noise = (0..32)
            .map(|i| {
                let mut id = [0; 32];
                id[30] = index as u8;
                id[31] = i;
                ArtifactBlockId::from_bytes(id)
            })
            .collect::<Vec<_>>();
        let noise_digest = noisy.publish(&noise, None);
        honest.publish(&[corpus.blocks[index].id()], None);
        pump(
            &mut nodes,
            &mut publishers,
            &format!("network offer height {}", index + 1),
            Duration::from_secs(if index == 12 { 180 } else { 90 }),
            |nodes, publishers| {
                nodes[..if index < 12 { 3 } else { 4 }]
                    .iter()
                    .all(|n| reached(n, &corpus, index))
                    && publishers[1]
                        .observed
                        .iter()
                        .filter(|e| {
                            e["event"] == "publisher_offer_receipted"
                                && e["offer_sha256"] == noise_digest
                        })
                        .count()
                        == 4
            },
        );
        if index == 11 {
            assert!(!nodes[3].observed.iter().any(|e| e["event"] == "finality"));
            for gate in &gates {
                gate.heal();
            }
        }
    }
    pump(
        &mut nodes,
        &mut publishers,
        "network healed observer",
        Duration::from_secs(120),
        |nodes, _| nodes.iter().all(|n| reached(n, &corpus, 99)),
    );
    stop(&mut nodes);
    stop_publishers(&mut publishers);
    let ancestry = layouts
        .each_ref()
        .map(|layout| corpus.verify_with_limit(layout, 100, 32, false));
    assert!(ancestry.iter().all(|prefix| prefix == &ancestry[0]));
    for layout in &layouts {
        let bytes = fs::read(layout.root.join("vote-journal/candidate-offers-v0.json")).unwrap();
        assert!(bytes.len() <= 20_000);
        assert!(!layout.root.join("offer.json").exists());
    }
}

#[test]
fn network_intake_receipts_survive_sigkill_and_strict_reopen_rejects_missing_corrupt_or_changed_policy()
 {
    let _fixture = process_fixture_guard();
    let corpus = Corpus::new([1; 4]);
    let publisher = Publisher::new(&corpus, 0);
    let layouts = std::array::from_fn(|_| Layout::new());
    let mut gates = std::array::from_fn(|_| Gate::bind());
    let configs = std::array::from_fn(|i| {
        configured_network(&corpus, &layouts[i], i, &gates, &[&publisher], false)
            .replace("base_millis = \"1000\"", "base_millis = \"120000\"")
            .replace("interval_millis = \"1500\"", "interval_millis = \"120000\"")
    });
    let mut nodes = spawn(&layouts, &configs, &mut gates);
    let mut publishers = [publisher.start(&corpus, &nodes)];
    let id = corpus.blocks[0].id();
    let digest = publisher.publish(&[id], None);
    pump(
        &mut nodes,
        &mut publishers,
        "receipt only after durable intake",
        Duration::from_secs(30),
        |_, p| {
            p[0].observed
                .iter()
                .filter(|e| {
                    e["event"] == "publisher_offer_receipted" && e["offer_sha256"] == digest
                })
                .count()
                == 4
        },
    );
    let actor = (corpus.proposers[0] + 1) % 4;
    let path = layouts[actor]
        .root
        .join("vote-journal/candidate-offers-v0.json");
    let saved = fs::read(&path).unwrap();
    assert!(
        String::from_utf8(saved.clone())
            .unwrap()
            .contains(&hex(id.as_bytes()))
    );
    nodes[actor].child.kill().unwrap();
    assert!(!nodes[actor].exit().success());
    for (i, node) in nodes.iter_mut().enumerate() {
        if i != actor {
            node.signal(rustix::process::Signal::TERM);
            node.event("stopped");
            assert!(node.exit().success());
        }
    }
    stop_publishers(&mut publishers);
    drop(gates);
    let open = configs[actor].replace("mode = \"create\"", "mode = \"open\"");
    let mut reopened = Process::start(&layouts[actor], &open);
    drop(reopened.child.stdin.take());
    assert_eq!(reopened.ready()["driver"]["height"], "1");
    assert_eq!(saved, fs::read(&path).unwrap());
    reopened.signal(rustix::process::Signal::TERM);
    reopened.event("stopped");
    assert!(reopened.exit().success());
    for altered in [
        open.replace("interval_millis = \"120000\"", "interval_millis = \"1500\""),
        open.replace(
            &format!("candidate_publishers = [{:?}]", publisher.peer.to_string()),
            "candidate_inbox = \"offer.json\"",
        ),
    ] {
        let before = layouts[actor].images();
        let mut bad = Process::start(&layouts[actor], &altered);
        assert_eq!(bad.event("error")["code"], "supervisor_policy_mismatch");
        assert!(!bad.exit().success());
        assert_eq!(before, layouts[actor].images());
    }
    fs::write(&path, b"corrupt").unwrap();
    let before = layouts[actor].images();
    let mut bad = Process::start(&layouts[actor], &open);
    assert_eq!(bad.event("error")["code"], "offer_encoding");
    assert!(!bad.exit().success());
    assert_eq!(before, layouts[actor].images());
    fs::remove_file(&path).unwrap();
    let before = layouts[actor].images();
    let mut bad = Process::start(&layouts[actor], &open);
    assert_eq!(bad.event("error")["code"], "file_open");
    assert!(!bad.exit().success());
    assert_eq!(before, layouts[actor].images());
}
