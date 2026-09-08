use std::fs;

use naome_network::{Keypair, PeerId};
use serde_json::{Value, json};

use crate::support::*;

pub(super) fn identities() -> [(Keypair, [u8; 32]); 3] {
    let mut identities = std::array::from_fn(|index| {
        let seed = [0x40 + index as u8; 32];
        (Keypair::ed25519_from_bytes(seed).unwrap(), seed)
    });
    identities.sort_by_key(|(key, _)| key.public().to_peer_id().to_bytes());
    identities
}

pub(super) fn config(
    fixture: &Fixture,
    layout: &Layout,
    mode: &str,
    seed: [u8; 32],
    peers: &[(PeerId, String)],
) -> String {
    let path = layout.write("noise.seed", seed);
    seed_permissions(&path, true);
    let peers = if peers.is_empty() {
        "peers = []\n".to_string()
    } else {
        peers
            .iter()
            .map(|(id, address)| {
                format!(
                    "[[network.peers]]\npeer_id = {:?}\naddress = {address:?}\n",
                    id.to_string()
                )
            })
            .collect::<String>()
    };
    format!(
        "{}\n[network]\nidentity_seed_file = \"noise.seed\"\nlisten = \"/ip4/127.0.0.1/tcp/0\"\n{peers}",
        fixture.config(mode)
    )
}

pub(super) fn listening(process: &mut Process) -> String {
    process.event("listening")["address"]
        .as_str()
        .unwrap()
        .to_string()
}

fn connected(process: &mut Process, peer: PeerId) {
    if process.observed.iter().any(|event| {
        event["event"] == "peer_session"
            && event["kind"] == "established"
            && event["peer_id"] == peer.to_string()
    }) {
        return;
    }
    process.until(|event| {
        event["event"] == "peer_session"
            && event["kind"] == "established"
            && event["peer_id"] == peer.to_string()
    });
}

fn sync(process: &mut Process, id: u64, peer: PeerId, count: u64) -> Value {
    let started = process
        .request(json!({"command": "sync", "id": id, "peer_id": peer.to_string(), "count": count}));
    assert_eq!(started["outcome"]["kind"], "sync_started", "{started}");
    process.until(|event| {
        event["id"] == id
            && matches!(
                event["event"].as_str(),
                Some("sync_completed" | "sync_stopped" | "command_failed")
            )
    })
}

pub(super) fn check_history(fixture: &Fixture, layout: &Layout, proofs: &[&Proof]) {
    let images = layout.images();
    fixture.inspect(layout, |journal| {
        assert_eq!(journal.finalized_len().unwrap(), proofs.len());
        for proof in proofs {
            let record = journal
                .finality_record(proof.position.height())
                .unwrap()
                .unwrap();
            assert_eq!(record.value(), proof.value);
            assert_eq!(record.canonical_envelope_bytes(), proof.envelope);
            assert_eq!(record.canonical_artifact_bytes(), proof.payload);
        }
        assert_eq!(
            journal.head().unwrap().ancestry_id(),
            proofs.last().unwrap().value.ancestry_id()
        );
    });
    assert_eq!(
        images,
        layout.images(),
        "strict diagnostic reopen changes no authority bytes"
    );
}

#[test]
fn archive_sync_strict_restart_and_three_process_relay_keep_exact_first_proofs() {
    let fixture = Fixture::new();
    let first = fixture.proof(&[], 0, 1);
    let variant = fixture.proof(&[], 1, 1);
    assert_eq!(variant.value, first.value);
    let second = fixture.proof(&[&first], 1, 2);
    let source = Layout::new();
    let middle = Layout::new();
    let sink = Layout::new();
    first.write(&source, "first");
    variant.write(&source, "variant");
    second.write(&source, "second");
    let [
        (sink_key, sink_seed),
        (middle_key, middle_seed),
        (source_key, source_seed),
    ] = identities();
    let (sink_id, middle_id, source_id) = (
        sink_key.public().to_peer_id(),
        middle_key.public().to_peer_id(),
        source_key.public().to_peer_id(),
    );
    let placeholder = "/ip4/127.0.0.1/tcp/9".to_string();
    let mut serving = Process::start(
        &source,
        &config(
            &fixture,
            &source,
            "create",
            source_seed,
            &[(middle_id, placeholder.clone())],
        ),
    );
    serving.ready();
    let source_address = listening(&mut serving);
    assert_eq!(
        serving.request(Proof::command(1, "first"))["outcome"]["kind"],
        "finalized"
    );
    assert_eq!(
        serving.request(Proof::command(2, "variant"))["outcome"]["kind"],
        "already_finalized"
    );
    assert_eq!(
        serving.request(Proof::command(3, "second"))["outcome"]["kind"],
        "finalized"
    );
    for name in ["first", "variant", "second"] {
        for suffix in ["envelope", "payload"] {
            fs::remove_file(source.root.join(format!("{name}.{suffix}"))).unwrap();
        }
    }
    let source_images = source.images();
    let mut copying = Process::start(
        &middle,
        &config(
            &fixture,
            &middle,
            "create",
            middle_seed,
            &[(source_id, source_address), (sink_id, placeholder.clone())],
        ),
    );
    copying.ready();
    listening(&mut copying);
    connected(&mut copying, source_id);
    connected(&mut serving, middle_id);
    let result = sync(&mut copying, 10, source_id, 2);
    assert_eq!(result["event"], "sync_completed");
    assert_eq!(result["completed"], "2");
    assert_eq!(copying.status(), serving.status());
    assert_eq!(source.images(), source_images, "serving is read-only");
    // The third height is unavailable; only the acknowledged H1/H2 prefix remains.
    let middle_images = middle.images();
    let unavailable = sync(&mut copying, 11, source_id, 1);
    assert_eq!(unavailable["event"], "sync_stopped");
    assert_eq!(unavailable["reason"], "unavailable");
    assert_eq!(unavailable["completed"], "0");
    assert_eq!(middle.images(), middle_images);
    copying.shutdown();
    serving.shutdown();
    check_history(&fixture, &source, &[&first, &second]);
    check_history(&fixture, &middle, &[&first, &second]);
    // Middle never had local proof source files. Reopen the same authority pair,
    // then serve the strictly reconstructed history to a fresh third process.
    let mut relay = Process::start(
        &middle,
        &config(
            &fixture,
            &middle,
            "open",
            middle_seed,
            &[(sink_id, placeholder)],
        ),
    );
    let reopened = relay.ready();
    assert_eq!(reopened["head"]["height"], "2");
    let relay_address = listening(&mut relay);
    assert_eq!(middle.images(), middle_images);
    let mut receiving = Process::start(
        &sink,
        &config(
            &fixture,
            &sink,
            "create",
            sink_seed,
            &[(middle_id, relay_address)],
        ),
    );
    receiving.ready();
    listening(&mut receiving);
    connected(&mut receiving, middle_id);
    connected(&mut relay, sink_id);
    assert_eq!(
        sync(&mut receiving, 12, middle_id, 2)["event"],
        "sync_completed"
    );
    assert_eq!(receiving.status(), reopened);
    receiving.shutdown();
    relay.shutdown();
    assert_eq!(middle.images(), middle_images);
    check_history(&fixture, &sink, &[&first, &second]);
    for layout in [&source, &middle, &sink] {
        assert!(!layout.root.join("vote-journal").exists());
        assert!(!layout.root.join("vote-anchor").exists());
    }
}

#[test]
fn archive_configuration_rejects_key_reuse_and_invalid_network_before_authority_creation() {
    let fixture = Fixture::new();
    let [(local, seed), _, (remote, _)] = identities();
    let peer = (
        remote.public().to_peer_id(),
        "/ip4/127.0.0.1/tcp/9".to_string(),
    );
    for (bytes, mode, reason) in [
        (
            fixture.keys[0].to_bytes().to_vec(),
            0o600,
            "consensus_identity_reuse",
        ),
        (seed.to_vec(), 0o644, "seed_permissions"),
        (vec![1; 31], 0o600, "seed_length"),
        (vec![1; 33], 0o600, "seed_length"),
    ] {
        let layout = Layout::new();
        let configuration = config(
            &fixture,
            &layout,
            "create",
            seed,
            std::slice::from_ref(&peer),
        );
        let path = layout.write("noise.seed", &bytes);
        seed_permissions(&path, mode == 0o600);
        let mut rejected = Process::start(&layout, &configuration);
        assert_eq!(rejected.event("error")["code"], reason);
        assert!(!rejected.exit().success());
        assert!(!layout.journal().exists());
        assert!(!layout.anchor().exists());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    let layout = Layout::new();
    let valid = config(
        &fixture,
        &layout,
        "create",
        seed,
        std::slice::from_ref(&peer),
    );
    for (configuration, reason) in [
        (
            valid.replace("/ip4/127.0.0.1/tcp/9", "/dns4/localhost/tcp/9"),
            "tcp_address",
        ),
        (
            valid.replace("/ip4/127.0.0.1/tcp/9", "/ip4/127.0.0.1/tcp/0"),
            "tcp_peer_port_zero",
        ),
        (
            valid.replace(&peer.0.to_string(), "invalid-peer"),
            "peer_id",
        ),
        (
            valid.replace(
                &peer.0.to_string(),
                &local.public().to_peer_id().to_string(),
            ),
            "network_config",
        ),
        (
            config(
                &fixture,
                &layout,
                "create",
                seed,
                &[peer.clone(), peer.clone()],
            ),
            "network_config",
        ),
        (
            config(&fixture, &layout, "create", seed, &vec![peer; 9]),
            "peers_limit",
        ),
    ] {
        let mut rejected = Process::start(&layout, &configuration);
        assert_eq!(rejected.event("error")["code"], reason);
        assert!(!rejected.exit().success());
        assert!(!layout.journal().exists());
        assert!(!layout.anchor().exists());
    }
    // A serving-only archive is valid. It never chooses an unknown peer itself.
    let mut isolated = Process::start(&layout, &config(&fixture, &layout, "create", seed, &[]));
    isolated.ready();
    listening(&mut isolated);
    assert_eq!(isolated.request(json!({"command":"sync","id":501,"peer_id":remote.public().to_peer_id().to_string(),"count":1}))["code"], "sync_request_start");
    assert_eq!(
        isolated.request(json!({"command":"cancel_sync","id":502}))["code"],
        "sync_inactive"
    );
    isolated.shutdown();
}
