//! Actual validator binaries produce finality; archives receive only whole proofs.

use std::{fs, os::unix::fs::PermissionsExt, path::Path, path::PathBuf};

use naome_chain::{ArtifactChainState, ArtifactDag};
use naome_consensus::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, AgreementWeight, ConsensusHeight,
    ConsensusValueV0, PreselectedProposerStateV0,
};
use naome_network::{Keypair, PeerId};
use naome_proof::{ArtifactPayload, ProofCertificate};
use serde_json::{Value, json};

use super::archive;
use crate::support::*;

const PLACEHOLDER: &str = "/ip4/127.0.0.1/tcp/9";
type Image = Vec<(PathBuf, Vec<u8>)>;
type ProofBytes = (ConsensusValueV0, Vec<u8>, Vec<u8>);

fn validator_binary() -> PathBuf {
    // Validation must select/build both packages with the same profile and
    // target. Never run nested Cargo or skip a missing producer executable.
    let path = Path::new(env!("CARGO_BIN_EXE_naome-verifier")).with_file_name("naome-validator");
    assert!(
        path.is_file(),
        "build both CLI binaries first: cargo build -p naome-validator -p naome-verifier --bins --locked (add --release for release tests)"
    );
    path
}

fn start_validator(layout: &Layout, config: &str) -> Process {
    Process::start_executable(&validator_binary(), &layout.write("validator.toml", config))
}

fn seed(layout: &Layout, name: &str, bytes: &[u8]) {
    let path = layout.write(name, bytes);
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn validator_config(
    fixture: &Fixture,
    layout: &Layout,
    actor: usize,
    noise: [u8; 32],
    peers: &[(PeerId, String)],
    targets: &[PeerId],
    serving: Option<bool>,
) -> String {
    for name in ["vote-journal", "vote-anchor"] {
        fs::create_dir_all(layout.root.join(name)).unwrap();
    }
    seed(layout, "signing.seed", &fixture.keys[actor].to_bytes());
    seed(layout, "noise.seed", &noise);
    let validators = fixture
        .entries
        .iter()
        .map(|entry| {
            format!(
                "[[validators]]\nconsensus_key = {:?}\nweight = {:?}\n",
                hex(entry.consensus_key().as_bytes()),
                entry.agreement_weight().units().to_string(),
            )
        })
        .collect::<String>();
    let peers = peers
        .iter()
        .map(|(id, address)| format!("{{peer_id = {:?}, address = {address:?}}}", id.to_string(),))
        .collect::<Vec<_>>()
        .join(", ");
    let targets = targets
        .iter()
        .map(|id| format!("{:?}", id.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let serving = serving
        .map(|enabled| format!("serve_finality_proofs = {enabled}\n"))
        .unwrap_or_default();
    format!(
        r#"version = 0
mode = "create"
deployment_discriminator = "{deployment}"
genesis_id = "{genesis}"
protocol_version = 7
signing_seed_file = "signing.seed"
{validators}
[directories]
finality_journal = "finality-journal"
finality_anchor = "finality-anchor"
vote_journal = "vote-journal"
vote_anchor = "vote-anchor"
[network]
identity_seed_file = "noise.seed"
listen = "/ip4/127.0.0.1/tcp/0"
peers = [{peers}]
publication_targets = [{targets}]
{serving}
[limits]
finality_max_round = "8"
vote_preparations = "32"
proposal_preparations = "32"
recovery_max_round = "8"
catch_up_heights = "8"
driver_max_round = "8"
[limits.higher]
entries = "16"
bytes = "1048576"
[limits.current]
entries = "16"
bytes = "1048576"
[limits.finality]
entries = "16"
bytes = "1048576"
[limits.nil_precommit]
entries = "16"
bytes = "1048576"
[timeouts.proposal]
base_millis = "120000"
round_increment_millis = "1"
[timeouts.prevote]
base_millis = "120000"
round_increment_millis = "1"
[timeouts.precommit]
base_millis = "120000"
round_increment_millis = "1"
"#,
        deployment = hex(fixture.definition.deployment_discriminator()),
        genesis = hex(fixture.context.genesis_id().as_bytes())
    )
}

fn network_id(seed: [u8; 32]) -> PeerId {
    Keypair::ed25519_from_bytes(seed)
        .unwrap()
        .public()
        .to_peer_id()
}

fn connected(process: &mut Process, peer: PeerId, validator: bool) {
    let predicate = |event: &Value| {
        event["event"] == "peer_session"
            && if validator {
                event["state"] == "established" && event["peer"] == peer.to_string()
            } else {
                event["kind"] == "established" && event["peer_id"] == peer.to_string()
            }
    };
    if !process.observed.iter().any(predicate) {
        process.until(predicate);
    }
}

fn sync(process: &mut Process, id: u64, peer: PeerId, count: u64) -> Value {
    let started = process
        .request(json!({"command":"sync", "id":id, "peer_id":peer.to_string(), "count":count}));
    assert_eq!(started["outcome"]["kind"], "sync_started", "{started}");
    process.until(|event| {
        event["id"] == id
            && matches!(
                event["event"].as_str(),
                Some("sync_completed" | "sync_stopped" | "command_failed")
            )
    })
}

fn validator_status(process: &mut Process, id: u64) -> Value {
    let response = process.request(json!({"command":"status", "id":id}));
    assert_eq!(response["event"], "command_result");
    response["outcome"].clone()
}

fn received_publications(process: &mut Process, id: u64, height: usize, targets: &[PeerId]) {
    // At most one proposal, prevote and precommit are released locally per
    // height. Drain their actual receipts before proving serving is read-only.
    for _ in 0..=3 {
        let state = validator_status(process, id);
        assert_eq!(state["driver"]["height"], height.to_string());
        assert_eq!(state["driver"]["phase"], "Proposal");
        assert_eq!(state["publication_recovery_remaining"], 0);
        if state["publication"].is_null() {
            let prepared = process
                .observed
                .iter()
                .filter(|event| event["event"] == "publication_prepared")
                .count();
            let completed: Vec<_> = process
                .observed
                .iter()
                .filter(|event| event["event"] == "publication_complete")
                .collect();
            assert_eq!(prepared, completed.len());
            for event in completed {
                let deliveries = event["disposed"]["deliveries"].as_array().unwrap();
                assert_eq!(deliveries.len(), targets.len());
                for (delivery, target) in deliveries.iter().zip(targets) {
                    assert_eq!(delivery["peer"], target.to_string());
                    assert_eq!(delivery["state"], "received");
                }
            }
            return;
        }
        process.event("publication_complete");
    }
    panic!("publication receipts did not settle within the local height bound");
}

fn authority_images(layout: &Layout) -> Image {
    let mut result = layout.images();
    for directory in ["vote-journal", "vote-anchor"] {
        for entry in fs::read_dir(layout.root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            result.push((
                path.strip_prefix(&layout.root).unwrap().to_path_buf(),
                fs::read(&path).unwrap(),
            ));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

fn retained(fixture: &Fixture, layout: &Layout) -> Vec<ProofBytes> {
    let before = layout.images();
    let records = fixture.inspect(layout, |journal| {
        (1..=journal.finalized_len().unwrap() as u64)
            .map(|height| {
                let record = journal
                    .finality_record(ConsensusHeight::new(height))
                    .unwrap()
                    .unwrap();
                (
                    record.value(),
                    record.canonical_envelope_bytes().to_vec(),
                    record.canonical_artifact_bytes().to_vec(),
                )
            })
            .collect()
    });
    assert_eq!(before, layout.images());
    records
}

#[test]
fn validator_provider_four_actual_signers_feed_archive_then_both_strictly_reopen_and_relay() {
    live_archive(false);
}

#[test]
fn archive_following_four_actual_signers_feed_successive_proofs_and_strict_reopen_relay() {
    live_archive(true);
}

fn live_archive(following: bool) {
    let mut fixture = Fixture::new();
    fixture.entries = fixture
        .keys
        .iter()
        .map(|key| ActiveAgreementEntry::new(consensus_key(key), AgreementWeight::new(1)))
        .collect();
    let genesis = fixture.genesis();
    let round = genesis.begin_round_zero().unwrap();
    let snapshot =
        ActiveAgreementSnapshot::try_from_preselected(round.position(), &fixture.entries).unwrap();
    let mut schedule = PreselectedProposerStateV0::from_zeroed_preselected_snapshot(&snapshot);
    let proposers: [usize; 2] = std::array::from_fn(|_| {
        let (key, next) = schedule.select_next().unwrap();
        schedule = next;
        fixture
            .entries
            .iter()
            .position(|entry| entry.consensus_key() == key)
            .unwrap()
    });
    let mut seeds: [[u8; 32]; 6] = std::array::from_fn(|index| [0x30 + index as u8; 32]);
    seeds.sort_by_key(|seed| network_id(*seed).to_bytes());
    let ids = seeds.map(network_id);
    let (sink_id, archive_id) = (ids[0], ids[1]);
    let validator_ids: [PeerId; 4] = std::array::from_fn(|actor| ids[actor + 2]);
    let layouts: [Layout; 4] = std::array::from_fn(|_| Layout::new());
    let archive_layout = Layout::new();
    let sink_layout = Layout::new();
    let mut addresses: [String; 4] = std::array::from_fn(|_| PLACEHOLDER.into());
    let mut configs: [String; 4] = std::array::from_fn(|_| String::new());
    let mut owners: [Option<Process>; 4] = std::array::from_fn(|_| None);
    // Higher Noise identities listen before their lower-identity dialers start.
    for actor in (0..4).rev() {
        let mut peers: Vec<_> = (0..4)
            .filter(|other| *other != actor)
            .map(|other| (validator_ids[other], addresses[other].clone()))
            .collect();
        peers.extend([
            (archive_id, PLACEHOLDER.into()),
            (sink_id, PLACEHOLDER.into()),
        ]);
        let targets: Vec<_> = (0..4)
            .filter(|other| *other != actor)
            .map(|other| validator_ids[other])
            .collect();
        assert!(!targets.contains(&archive_id) && !targets.contains(&sink_id));
        configs[actor] = validator_config(
            &fixture,
            &layouts[actor],
            actor,
            seeds[actor + 2],
            &peers,
            &targets,
            Some(actor == 0),
        );
        let mut owner = start_validator(&layouts[actor], &configs[actor]);
        assert_eq!(owner.ready()["driver"]["height"], "1");
        addresses[actor] = archive::listening(&mut owner);
        owners[actor] = Some(owner);
    }
    let mut validators: [Process; 4] = std::array::from_fn(|actor| owners[actor].take().unwrap());
    for (actor, validator) in validators.iter_mut().enumerate() {
        for (other, id) in validator_ids.iter().enumerate() {
            if other != actor {
                connected(validator, *id, true);
            }
        }
    }
    let archive_config = archive::config(
        &fixture,
        &archive_layout,
        "create",
        seeds[1],
        &[
            (validator_ids[0], addresses[0].clone()),
            (sink_id, PLACEHOLDER.into()),
        ],
    );
    let mut consumer = Process::start(&archive_layout, &archive_config);
    assert_eq!(consumer.ready()["head"]["height"], "0");
    archive::listening(&mut consumer);
    connected(&mut consumer, validator_ids[0], false);
    connected(&mut validators[0], archive_id, true);
    if following {
        let started = consumer.request(json!({"command":"follow_finality", "id":190, "peer_id":validator_ids[0].to_string(), "count":1, "interval_millis":"50"}));
        assert_eq!(started["outcome"]["kind"], "follow_started");
        consumer
            .until(|event| event["event"] == "follow_waiting" && event["reason"] == "unavailable");
    }
    let mut selected = ArtifactChainState::new(fixture.definition);
    let mut expected_blocks = Vec::new();
    let mut expected_payloads = Vec::new();
    for (index, actor) in proposers.into_iter().enumerate() {
        let payload = ArtifactPayload::Proof(
            ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, (index + 1) as u8]).unwrap(),
        )
        .to_canonical_bytes();
        let artifact = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = selected.prepare_block(artifact).unwrap();
        selected.apply_block(&block, payload.clone()).unwrap();
        layouts[actor].write("block.bin", block.to_canonical_bytes());
        layouts[actor].write("payload.bin", &payload);
        let authored = validators[actor].request(json!({"command":"author_fresh", "id":100+index, "block_file":"block.bin", "payload_file":"payload.bin"}));
        assert_eq!(
            authored["outcome"]["event"], "proposal_authored",
            "{authored}"
        );
        for owner in &mut validators {
            let finalized = owner.event("finality");
            assert_eq!(
                finalized["state"]["driver"]["height"],
                (index + 2).to_string()
            );
            assert_eq!(
                finalized["state"]["driver"]["head"],
                hex(block.id().as_bytes())
            );
        }
        for (actor, owner) in validators.iter_mut().enumerate() {
            let targets: Vec<_> = validator_ids
                .iter()
                .enumerate()
                .filter_map(|(other, id)| (other != actor).then_some(*id))
                .collect();
            received_publications(owner, 230 + index as u64, index + 2, &targets);
        }
        // The fixture supplies no consensus signatures or complete envelopes.
        // Remove the author's source files after production; strict provider
        // reopen and archive relay must use only the retained history.
        fs::remove_file(layouts[actor].root.join("block.bin")).unwrap();
        fs::remove_file(layouts[actor].root.join("payload.bin")).unwrap();
        if !following {
            assert_eq!(consumer.status()["head"]["height"], index.to_string());
        }
        let before = authority_images(&layouts[0]);
        let last_height = (index + 1).to_string();
        let synchronized = if following {
            consumer.until(|event| {
                event["event"] == "sync_completed"
                    && event["id"] == 190
                    && event["last_height"] == last_height
            })
        } else {
            sync(&mut consumer, 200 + index as u64, validator_ids[0], 1)
        };
        assert_eq!(synchronized["event"], "sync_completed", "{synchronized}");
        assert_eq!(synchronized["completed"], "1");
        assert_eq!(consumer.status()["head"]["height"], (index + 1).to_string());
        assert_eq!(
            authority_images(&layouts[0]),
            before,
            "proof serving writes no signer/finality bytes"
        );
        expected_blocks.push(block);
        expected_payloads.push(payload);
    }
    if following {
        consumer
            .until(|event| event["event"] == "follow_waiting" && event["reason"] == "unavailable");
        assert_eq!(
            consumer.request(json!({"command":"cancel_sync", "id":209}))["outcome"]["sync_id"],
            190
        );
    } else {
        assert_eq!(
            sync(&mut consumer, 210, validator_ids[0], 1)["reason"],
            "unavailable"
        );
    }
    for owner in &mut validators {
        assert_eq!(validator_status(owner, 220)["driver"]["height"], "3");
        owner.shutdown();
    }
    consumer.shutdown();
    let proofs = retained(&fixture, &layouts[0]);
    assert_eq!(proofs.len(), 2);
    for (index, (value, _, payload)) in proofs.iter().enumerate() {
        assert_eq!(value.artifact_block(), expected_blocks[index]);
        assert_eq!(*payload, expected_payloads[index]);
    }
    assert_eq!(retained(&fixture, &archive_layout), proofs);
    let ancestry = fixture.inspect(&archive_layout, |journal| {
        journal.head().unwrap().ancestry_id()
    });
    assert_eq!(ancestry, proofs.last().unwrap().0.ancestry_id());
    for layout in &layouts {
        let values: Vec<_> = retained(&fixture, layout)
            .into_iter()
            .map(|record| record.0)
            .collect();
        assert_eq!(
            values,
            proofs.iter().map(|record| record.0).collect::<Vec<_>>()
        );
    }
    let source_before = authority_images(&layouts[0]);
    let changed_targets = validator_config(
        &fixture,
        &layouts[0],
        0,
        seeds[2],
        &[
            (archive_id, PLACEHOLDER.into()),
            (sink_id, PLACEHOLDER.into()),
        ],
        &[],
        Some(true),
    )
    .replace("mode = \"create\"", "mode = \"open\"");
    let mut refused = start_validator(&layouts[0], &changed_targets);
    assert_eq!(refused.event("error")["code"], "publication_journal");
    assert!(!refused.exit().success());
    assert!(!refused.observed.iter().any(|event| matches!(
        event["event"].as_str(),
        Some("ready" | "listening" | "proof_response_queued")
    )));
    assert_eq!(authority_images(&layouts[0]), source_before);
    // Delivery debt remains bound to the original ordered recipients even
    // when this restarted process is currently serving only archive readers.
    let reopened_config = configs[0].replace("mode = \"create\"", "mode = \"open\"");
    let mut provider = start_validator(&layouts[0], &reopened_config);
    assert_eq!(provider.ready()["driver"]["height"], "3");
    let provider_address = archive::listening(&mut provider);
    let archive_before = archive_layout.images();
    let mut relay = Process::start(
        &archive_layout,
        &archive::config(
            &fixture,
            &archive_layout,
            "open",
            seeds[1],
            &[
                (validator_ids[0], provider_address.clone()),
                (sink_id, PLACEHOLDER.into()),
            ],
        ),
    );
    assert_eq!(relay.ready()["head"]["height"], "2");
    let relay_address = archive::listening(&mut relay);
    assert!(relay.request(json!({"command":"status", "id":299}))["outcome"]["sync"].is_null());
    let mut sink = Process::start(
        &sink_layout,
        &archive::config(
            &fixture,
            &sink_layout,
            "create",
            seeds[0],
            &[
                (validator_ids[0], provider_address),
                (archive_id, relay_address),
            ],
        ),
    );
    sink.ready();
    archive::listening(&mut sink);
    connected(&mut sink, validator_ids[0], false);
    connected(&mut sink, archive_id, false);
    assert_eq!(
        sync(&mut sink, 300, validator_ids[0], 1)["event"],
        "sync_completed"
    );
    assert_eq!(
        sync(&mut sink, 301, archive_id, 1)["event"],
        "sync_completed"
    );
    assert_eq!(sink.status(), relay.status());
    sink.shutdown();
    relay.shutdown();
    provider.shutdown();
    assert_eq!(authority_images(&layouts[0]), source_before);
    assert_eq!(archive_layout.images(), archive_before);
    assert_eq!(retained(&fixture, &sink_layout), proofs);
    assert!(!archive_layout.root.join("vote-journal").exists());
    assert!(!sink_layout.root.join("vote-journal").exists());
}

#[test]
fn validator_provider_opt_in_foreign_missing_and_terminal_history_boundaries() {
    for enabled in [None, Some(false), Some(true)] {
        let mut fixture = Fixture::new();
        fixture.entries = vec![ActiveAgreementEntry::new(
            consensus_key(&fixture.keys[0]),
            AgreementWeight::new(1),
        )];
        let [
            (foreign_key, foreign_seed),
            (archive_key, archive_seed),
            (provider_key, provider_seed),
        ] = archive::identities();
        let (foreign_id, archive_id, provider_id) = (
            foreign_key.public().to_peer_id(),
            archive_key.public().to_peer_id(),
            provider_key.public().to_peer_id(),
        );
        let source = Layout::new();
        let target = Layout::new();
        let foreign_layout = Layout::new();
        let config = validator_config(
            &fixture,
            &source,
            0,
            provider_seed,
            &[
                (archive_id, PLACEHOLDER.into()),
                (foreign_id, PLACEHOLDER.into()),
            ],
            &[],
            enabled,
        );
        let mut provider = start_validator(&source, &config);
        provider.ready();
        let address = archive::listening(&mut provider);
        let payload = ArtifactPayload::Proof(
            ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, 1]).unwrap(),
        )
        .to_canonical_bytes();
        let artifact = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let selected = ArtifactChainState::new(fixture.definition);
        let block = selected.prepare_block(artifact).unwrap();
        source.write("block.bin", block.to_canonical_bytes());
        source.write("payload.bin", &payload);
        assert_eq!(provider.request(json!({"command":"author_fresh", "id":1, "block_file":"block.bin", "payload_file":"payload.bin"}))["outcome"]["event"], "proposal_authored");
        assert_eq!(provider.event("finality")["state"]["driver"]["height"], "2");
        fs::remove_file(source.root.join("block.bin")).unwrap();
        fs::remove_file(source.root.join("payload.bin")).unwrap();
        let mut consumer = Process::start(
            &target,
            &archive::config(
                &fixture,
                &target,
                "create",
                archive_seed,
                &[(provider_id, address.clone())],
            ),
        );
        consumer.ready();
        archive::listening(&mut consumer);
        connected(&mut consumer, provider_id, false);
        connected(&mut provider, archive_id, true);
        let source_before = authority_images(&source);
        let target_before = target.images();
        let result = sync(&mut consumer, 10, provider_id, 1);
        if enabled != Some(true) {
            assert_eq!(result["reason"], "transport_failure", "{result}");
            assert_eq!(result["completed"], "0");
            assert_eq!(target.images(), target_before);
            consumer.shutdown();
            provider.shutdown();
            assert!(
                !provider
                    .observed
                    .iter()
                    .any(|event| event["event"] == "proof_response_queued")
            );
            assert_eq!(authority_images(&source), source_before);
            continue;
        }
        assert_eq!(result["event"], "sync_completed");
        assert_eq!(
            sync(&mut consumer, 11, provider_id, 1)["reason"],
            "unavailable"
        );
        let mut foreign = Fixture::new();
        foreign.entries = fixture.entries.clone();
        foreign.context = naome_consensus::ConsensusContextV0::new(
            fixture.context.chain_id(),
            naome_consensus::ConsensusGenesisId::from_bytes([0xfe; 32]),
            fixture.context.protocol_version(),
        );
        let mut foreign_archive = Process::start(
            &foreign_layout,
            &archive::config(
                &foreign,
                &foreign_layout,
                "create",
                foreign_seed,
                &[(provider_id, address)],
            ),
        );
        foreign_archive.ready();
        archive::listening(&mut foreign_archive);
        connected(&mut foreign_archive, provider_id, false);
        let foreign_before = foreign_layout.images();
        assert_eq!(
            sync(&mut foreign_archive, 12, provider_id, 1)["reason"],
            "unavailable"
        );
        assert_eq!(foreign_layout.images(), foreign_before);
        assert_eq!(authority_images(&source), source_before);

        // Adversarial sibling bytes are independently signed by the test key;
        // they are never attributed to the honest producer process.
        let conflicting_payload = ArtifactPayload::Proof(
            ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, 2]).unwrap(),
        )
        .to_canonical_bytes();
        let conflicting_id = ArtifactDag::new()
            .apply_canonical_artifact_bytes(conflicting_payload.clone())
            .unwrap()
            .artifact_id();
        let genesis = fixture.genesis();
        let round = genesis.begin_round_zero().unwrap();
        let mut sibling = Proof {
            value: round.value_for_artifact_block(selected.prepare_block(conflicting_id).unwrap()),
            position: round.position(),
            proposer: 0,
            payload: conflicting_payload,
            envelope: Vec::new(),
        };
        sibling.envelope = envelope(&sibling, &fixture.keys[0], &[&fixture.keys[0]], 2);
        sibling.write(&source, "sibling");
        assert_eq!(provider.request(json!({"command":"halt_historical_envelope", "id":20, "envelope_file":"sibling.envelope", "payload_file":"sibling.payload"}))["outcome"]["event"], "finality_stopped");
        let stopped = provider.event("stopped");
        assert_eq!(stopped["reason"], "command_fatal");
        assert_eq!(stopped["locks_released"], true);
        assert!(!provider.exit().success());
        connected_disappearance(&mut consumer, provider_id);
        let target_after = target.images();
        let request = consumer.request(
            json!({"command":"sync", "id":21, "peer_id":provider_id.to_string(), "count":1}),
        );
        assert!(
            matches!(request["outcome"]["kind"].as_str(), Some("sync_stopped"))
                || request["event"] == "command_rejected",
            "{request}"
        );
        assert_eq!(target.images(), target_after);
        consumer.shutdown();
        foreign_archive.shutdown();
        let halted = authority_images(&source);
        let mut reopened = start_validator(
            &source,
            &config.replace("mode = \"create\"", "mode = \"open\""),
        );
        assert_eq!(reopened.event("error")["code"], "startup_finality_stopped");
        assert!(!reopened.exit().success());
        assert!(!reopened.observed.iter().any(|event| matches!(
            event["event"].as_str(),
            Some("ready" | "listening" | "proof_response_queued")
        )));
        assert_eq!(authority_images(&source), halted);
    }
}

fn connected_disappearance(process: &mut Process, peer: PeerId) {
    let predicate = |event: &Value| {
        event["event"] == "peer_session"
            && event["kind"] == "disconnected"
            && event["peer_id"] == peer.to_string()
    };
    if !process.observed.iter().any(predicate) {
        process.until(predicate);
    }
}

#[test]
fn validator_provider_rejects_non_boolean_and_duplicate_options_before_authority_creation() {
    let fixture = Fixture::new();
    for option in [
        "serve_finality_proofs = \"true\"",
        "serve_finality_proofs = 1",
        "serve_finality_proofs = []",
        "serve_finality_proofs = true\nserve_finality_proofs = false",
    ] {
        let layout = Layout::new();
        let config = validator_config(&fixture, &layout, 0, [0x40; 32], &[], &[], Some(true))
            .replace("serve_finality_proofs = true", option);
        let before = authority_images(&layout);
        assert!(before.is_empty());
        let mut process = start_validator(&layout, &config);
        assert_eq!(process.event("error")["code"], "config_schema");
        assert!(!process.exit().success());
        assert_eq!(authority_images(&layout), before);
        assert!(
            !process
                .observed
                .iter()
                .any(|event| event["event"] == "ready")
        );
    }
}
