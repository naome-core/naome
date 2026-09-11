use super::support::*;
use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_consensus::verified_membership::*;
use naome_network::Keypair;
use naome_proof::{ArtifactPayload, ProofCertificate};
use serde_json::{Value, json};
use std::{
    fs,
    net::TcpListener,
    time::{Duration, Instant},
};

fn seed(id: u8, role: u8) -> [u8; 32] {
    let mut seed = [id; 32];
    seed[0] = role;
    seed
}
fn keys(id: u8) -> [SigningKey; 3] {
    std::array::from_fn(|role| SigningKey::from_bytes(&seed(id, role as u8)))
}
fn member(id: u8) -> Member {
    let keys = keys(id);
    Member {
        organization: [id; 32],
        consensus_key: keys[0].verifying_key().to_bytes(),
        approval_key: keys[1].verifying_key().to_bytes(),
        network_key: keys[2].verifying_key().to_bytes(),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn config(layout: &Layout, id: u8, addresses: &[String], mode: &str) -> String {
    for name in ["journal", "anchor", "inbox"] {
        fs::create_dir_all(layout.root.join(name)).unwrap();
    }
    for (role, name) in ["consensus.seed", "approval.seed", "network.seed"]
        .into_iter()
        .enumerate()
    {
        layout.seed(name, &seed(id, role as u8));
    }
    let mut text = format!(
        r#"profile = "verified_membership"
mode = "{mode}"
deployment_discriminator = "{}"
organization = "{}"
consensus_seed_file = "consensus.seed"
approval_seed_file = "approval.seed"
network_seed_file = "network.seed"
journal_directory = "journal"
anchor_directory = "anchor"
inbox_directory = "inbox"
listen = "{}"
"#,
        hex(&[74; 32]),
        hex(&[id; 32]),
        addresses[id as usize - 1]
    );
    for peer in 1..=4 {
        if peer == id {
            continue;
        }
        let identity = Keypair::ed25519_from_bytes(seed(peer, 2))
            .unwrap()
            .public()
            .to_peer_id();
        text.push_str(&format!(
            "\n[[bootstraps]]\npeer_id = \"{identity}\"\naddress = \"{}\"\n",
            addresses[peer as usize - 1]
        ));
    }
    for id in 1..=4 {
        let member = member(id);
        text.push_str(&format!("\n[[genesis_members]]\norganization = \"{}\"\nconsensus_key = \"{}\"\napproval_key = \"{}\"\nnetwork_key = \"{}\"\n", hex(&member.organization), hex(&member.consensus_key), hex(&member.approval_key), hex(&member.network_key)));
    }
    text.push_str("\n[limits]\nmaximum_round = 128\nmaximum_records = 10000\nmaximum_bytes = 100000000\n[timing]\nphase_base_millis = 2000\nround_increment_millis = 100\ntick_millis = 10\n");
    text
}
fn addresses() -> Vec<String> {
    let reserved: Vec<_> = (0..5)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    reserved
        .iter()
        .map(|listener| {
            format!(
                "/ip4/127.0.0.1/tcp/{}",
                listener.local_addr().unwrap().port()
            )
        })
        .collect()
}
fn command(process: &mut Process, value: Value) -> Value {
    let id = value["id"].clone();
    process.send(value);
    process.until(|value| value["id"] == id)
}
fn status(process: &mut Process) -> Value {
    command(process, json!({"command":"status","id":999}))["state"].clone()
}
fn stop(process: &mut Process) {
    command(process, json!({"command":"shutdown","id":998}));
    process.event("membership_stopped");
    assert!(process.exit().success());
}

#[test]
fn membership_initializer_creates_private_distinct_keys_and_refuses_overwrite() {
    use std::os::unix::fs::PermissionsExt;
    let layout = Layout::new();
    let directory = layout.root.join("identity");
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_naome-validator"))
            .arg("--membership-init")
            .arg(&directory)
            .output()
            .unwrap()
    };
    let output = run();
    assert!(output.status.success(), "{:?}", output);
    let manifest: Value =
        serde_json::from_slice(&fs::read(directory.join("identity.json")).unwrap()).unwrap();
    let mut seeds = Vec::new();
    for role in ["consensus", "approval", "network"] {
        let path = directory.join(format!("{role}.seed"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let seed: [u8; 32] = fs::read(&path).unwrap().try_into().unwrap();
        assert_eq!(
            manifest[format!("{role}_key")],
            hex(&SigningKey::from_bytes(&seed).verifying_key().to_bytes())
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(&hex(&seed)));
        seeds.push(seed);
    }
    assert_ne!(seeds[0], seeds[1]);
    assert_ne!(seeds[0], seeds[2]);
    assert_ne!(seeds[1], seeds[2]);
    for name in ["", "journal", "anchor", "inbox"] {
        assert_eq!(
            fs::metadata(directory.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    assert!(!run().status.success());
    assert_eq!(
        fs::read(directory.join("consensus.seed")).unwrap(),
        seeds[0]
    );
}

#[test]
fn five_membership_processes_apply_approve_finalize_export_and_restart_observer() {
    let addresses = addresses();
    let layouts: Vec<_> = (0..5).map(|_| Layout::new()).collect();
    let configs: Vec<_> = (1..=5)
        .map(|id| config(&layouts[id - 1], id as u8, &addresses, "create"))
        .collect();
    let mut processes: Vec<_> = (0..5)
        .map(|i| Process::start_membership(&layouts[i], &configs[i]))
        .collect();
    for (index, process) in processes.iter_mut().enumerate() {
        assert_eq!(
            process.event("membership_ready")["state"]["active"],
            index != 4
        );
    }
    let application = command(&mut processes[4], json!({"command":"apply","id":1}));
    let request_id = application["request_id"].as_str().unwrap().to_owned();
    let deadline = Instant::now() + Duration::from_secs(60);
    for process in processes.iter_mut().take(3) {
        loop {
            assert!(Instant::now() < deadline, "membership application gossip");
            let state = status(process);
            if state["requests"]
                .as_array()
                .unwrap()
                .iter()
                .any(|request| request["id"] == request_id)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            command(
                process,
                json!({"command":"approve","id":2,"request_id":request_id})
            )["event"],
            "membership_approved"
        );
    }
    assert_eq!(
        command(
            &mut processes[0],
            json!({"command":"export_approval","id":20,"request_id":request_id,"file":"approval.bin"})
        )["event"],
        "membership_approval_exported"
    );
    let exported =
        MembershipApproval::from_bytes(&fs::read(layouts[0].root.join("approval.bin")).unwrap())
            .unwrap();
    assert_eq!(exported.organization, member(1).organization);
    assert_eq!(hex(&exported.request), request_id);
    loop {
        assert!(Instant::now() < deadline, "membership approval gossip");
        let state = status(&mut processes[0]);
        if state["requests"][0]["approvals"] == 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut artifacts = ArtifactChainState::new(ArtifactChainDefinition::new([74; 32]));
    for (offset, bytes) in [&[0, 0, 0, 1, 0x10, 1][..], &[0, 0, 0, 1, 0x10, 2][..]]
        .into_iter()
        .enumerate()
    {
        let proof = ProofCertificate::from_canonical_bytes(bytes)
            .unwrap()
            .into_unchecked_normal_form()
            .certificate()
            .clone();
        let payload = ArtifactPayload::Proof(proof).to_canonical_bytes();
        let id = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())
            .unwrap()
            .artifact_id();
        let block = artifacts.prepare_block(id).unwrap();
        layouts[0].write("candidate.block", block.to_canonical_bytes());
        layouts[0].write("candidate.payload", &payload);
        assert_eq!(
            command(
                &mut processes[0],
                json!({"command":"candidate","id":3,"block_file":"candidate.block","payload_file":"candidate.payload"})
            )["event"],
            "membership_candidate_received"
        );
        for process in &mut processes {
            loop {
                assert!(Instant::now() < deadline, "membership process finality");
                if status(process)["height"] == offset + 1 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        artifacts.apply_block(&block, payload).unwrap();
    }
    let selected = status(&mut processes[4]);
    assert_eq!(selected["height"], 2);
    assert_eq!(selected["active"], false);
    assert_eq!(selected["pending_activation"], 16385);
    for process in &mut processes {
        assert_eq!(status(process)["ancestry"], selected["ancestry"]);
    }
    assert_eq!(
        command(
            &mut processes[4],
            json!({"command":"export_proof","id":4,"height":2,"file":"height2.proof"})
        )["event"],
        "membership_proof_exported"
    );
    let exported = MembershipFinalityProof::from_bytes(
        &fs::read(layouts[4].root.join("height2.proof")).unwrap(),
    )
    .unwrap();
    assert_eq!(exported.proposal.value.height(), 2);
    for process in &mut processes {
        stop(process);
    }
    let mut observer = Process::start_membership(
        &layouts[4],
        &configs[4].replace("mode = \"create\"", "mode = \"open\""),
    );
    let reopened = observer.event("membership_ready")["state"].clone();
    assert_eq!(reopened["ancestry"], selected["ancestry"]);
    assert_eq!(reopened["active"], false);
    stop(&mut observer);
}

#[test]
fn membership_rejects_active_identity_mismatch_and_stops_on_inbox_save_failure() {
    let layout = Layout::new();
    let addresses = addresses();
    let config = config(&layout, 1, &addresses, "create");
    let bad = config.replace(
        &format!("organization = \"{}\"", hex(&[1; 32])),
        &format!("organization = \"{}\"", hex(&[9; 32])),
    );
    // Only the local setting is replaced, keeping trusted genesis unchanged.
    let bad = bad.replacen(
        &format!("[[genesis_members]]\norganization = \"{}\"", hex(&[9; 32])),
        &format!("[[genesis_members]]\norganization = \"{}\"", hex(&[1; 32])),
        1,
    );
    let mut process = Process::start_membership(&layout, &bad);
    assert_eq!(
        process.event("error")["code"],
        "membership_identity_binding"
    );
    assert!(!process.exit().success());
    assert!(
        !layout
            .root
            .join("journal/verified-membership.journal")
            .exists()
    );
    let mut process = Process::start_membership(&layout, &config);
    process.event("membership_ready");
    fs::rename(layout.root.join("inbox"), layout.root.join("inbox-saved")).unwrap();
    layout.write("inbox", b"unusable directory");
    process.send(json!({"command":"reject","id":8,"request_id":hex(&[8;32])}));
    assert_eq!(
        process.event("error")["code"],
        "membership_inbox_persistence_failed"
    );
    assert!(!process.exit().success());
}
