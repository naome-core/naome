mod boundaries;
mod custody;
mod integrity;

use super::*;
use naome_consensus::ConsensusVoteRole as Role;
use naome_storage::{
    ArtifactBlockCandidateInsertOutcome, ArtifactBlockCandidateStore,
    ArtifactBlockCandidateStoreLimits, ArtifactChainJournal, ArtifactPayloadInsertOutcome,
    ArtifactPayloadStoreLimits, CandidateBranchRecoveryBundleLimits as Limits,
    CandidateBranchRecoveryBundleV0 as Bundle, CanonicalArtifactPayloadStore,
};

pub(super) struct Transfer {
    pub(super) bytes: Vec<u8>,
    pub(super) blocks: Vec<ArtifactBlock>,
    payloads: Vec<Vec<u8>>,
}

impl Transfer {
    pub(super) fn new(fixture: &Fixture, count: u8, selected: usize) -> Self {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let layout = Layout::new();
        let (blocks, payloads) = branch(fixture, count);
        let mut journal = ArtifactChainJournal::create(&layout.root, fixture.definition).unwrap();
        for (block, bytes) in blocks.iter().zip(&payloads).take(selected) {
            journal.apply_block(block, bytes.clone()).unwrap();
        }
        let mut candidates = ArtifactBlockCandidateStore::create(
            &layout.root,
            fixture.definition,
            ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
        )
        .unwrap();
        let mut store = CanonicalArtifactPayloadStore::create(
            &layout.root,
            ArtifactPayloadStoreLimits::new(16, 1_048_576).unwrap(),
        )
        .unwrap();
        let mut dag = ArtifactDag::new();
        for (block, bytes) in blocks.iter().zip(&payloads) {
            assert_eq!(
                candidates.insert(block).unwrap(),
                ArtifactBlockCandidateInsertOutcome::Inserted
            );
            assert_eq!(
                store
                    .insert(dag.apply_canonical_artifact_bytes(bytes.clone()).unwrap())
                    .unwrap(),
                ArtifactPayloadInsertOutcome::Inserted
            );
        }
        let bytes = journal
            .export_candidate_branch_recovery_bundle_v0(
                blocks.last().unwrap().id(),
                &mut candidates,
                &mut store,
                Limits::new(16, u64::MAX, u64::MAX).unwrap(),
            )
            .unwrap()
            .into_canonical_bytes();
        Self {
            bytes,
            blocks,
            payloads,
        }
    }

    pub(super) fn command(&self, stage: bool) -> Value {
        let bundle =
            Bundle::from_canonical_bytes(&self.bytes, Limits::new(16, u64::MAX, u64::MAX).unwrap())
                .unwrap();
        let mut command = json!({"command": if stage { "stage_candidate_bundle" } else { "export_candidate_bundle" },
            "id":u64::MAX, "target": hex(bundle.target_block_id().as_bytes()), "bundle_file":"branch.bundle",
            "max_blocks":bundle.block_count(), "max_payload_bytes":bundle.total_payload_bytes(), "max_bundle_bytes":bundle.encoded_bytes()});
        if stage {
            command["anchor"] = json!(hex(bundle.anchor_block_id().as_bytes()));
        }
        command
    }
}

fn initial_arm(node: &mut Process) {
    if !node.observed.iter().any(|v| v["event"] == "timer_armed") {
        node.event("timer_armed");
    }
}

fn select(node: &mut Process, layout: &Layout, proofs: &[&Proof]) {
    for (index, proof) in proofs.iter().enumerate() {
        let name = format!("selected-{index}");
        proof.write(layout, &name);
        if proof.round > 0 {
            assert_eq!(
                result(node, proof.higher_command(20, &name, true))["event"],
                "transitioned"
            );
            node.event("timer_armed");
        }
        let selected = result(node, proof.current_command(21, &name, true));
        assert_eq!(selected["event"], "finality");
        assert_eq!(
            selected["state"]["driver"]["head"],
            hex(proof.value.artifact_block().id().as_bytes())
        );
        node.event("timer_armed");
    }
}

fn reject(node: &mut Process, input: Value, code: &str) {
    node.send(input);
    assert_eq!(node.event("command_rejected")["code"], code);
}

fn no_staging_writes(outcome: &Value, code: &str) {
    assert_eq!(outcome["event"], "bundle_stage_failed", "{outcome}");
    assert_eq!(outcome["code"], code, "{outcome}");
    for field in [
        "candidate_acknowledged_count",
        "candidate_inserted_count",
        "payload_acknowledged_count",
        "payload_inserted_count",
    ] {
        assert_eq!(outcome[field], 0, "{field}: {outcome}");
    }
    assert_eq!(outcome["bundle_bytes_discarded"], true);
}

#[test]
fn offline_bundle_export_stages_only_unselected_suffix_then_separate_proof_finalizes_and_reopens() {
    let fixture = Fixture::new();
    let first = Proof::new(&fixture, false, 1, Role::Precommit);
    let second = Proof::after_prefix(&fixture, &[&first], 0, 2, Role::Precommit);
    let third = Proof::after_prefix(&fixture, &[&first, &second], 0, 3, Role::Precommit);
    let transfer = Transfer::new(&fixture, 3, 1);
    assert_eq!(transfer.blocks[2], third.value.artifact_block());
    let source = Layout::new();
    let plan = Plan::new(fixture.peers[1]);
    let peer = plan.peer;
    let config = source_config(
        &source,
        plan.configure(fixture.config(&source, 1, "create", None, false)),
    );
    let mut node = Process::start(&source, &config);
    node.ready();
    let address = address(&mut node);
    initial_arm(&mut node);
    select(&mut node, &source, &[&first]);
    let provider_guard = PARENT_JOURNALS.read().unwrap();
    let sdk = plan.start(
        &provider_guard,
        fixture.definition,
        &address,
        transfer.blocks.clone(),
        transfer.payloads.clone(),
        None,
    );
    connected(&mut node, peer);
    let target = transfer.command(false)["target"].clone();
    acquire(
        &mut node,
        json!({"command":"acquire_ancestry", "id":1,"target":target,"peer_id":peer.to_string()}),
    );
    for block in transfer.blocks[1..].iter().rev() {
        sdk.request("block", &hex(block.id().as_bytes()));
    }
    assert_eq!(
        acquire(
            &mut node,
            json!({"command":"acquire_payloads", "id":2,"target":target,"peer_id":peer.to_string(),"max_blocks":2})
        )["validated_blocks"],
        2
    );
    for block in &transfer.blocks[1..] {
        sdk.request("payload", &hex(block.artifact_id().as_bytes()));
    }
    let authority = source.images();
    let sources = source_images(&source);
    let state = result(&mut node, json!({"command":"status","id":3}));
    for (field, code) in [
        ("max_blocks", "block_limit"),
        ("max_payload_bytes", "payload_limit"),
        ("max_bundle_bytes", "bundle_limit"),
    ] {
        let mut command = transfer.command(false);
        command[field] = json!(command[field].as_u64().unwrap() - 1);
        let refused = result(&mut node, command);
        assert_eq!(refused["event"], "bundle_export_failed");
        assert_eq!(refused["code"], code);
        assert_eq!(refused["output_created"], false);
        assert!(!source.root.join("branch.bundle").exists());
        assert_eq!(refused["state"], state);
    }
    let exported = result(&mut node, transfer.command(false));
    assert_eq!(exported["event"], "bundle_exported");
    assert_eq!(exported["block_count"], 2);
    assert_eq!(
        exported["anchor"],
        hex(first.value.artifact_block().id().as_bytes())
    );
    assert_eq!(exported["target"], target);
    assert_eq!(exported["encoded_bytes"], transfer.bytes.len().to_string());
    assert_eq!(exported["state"], state);
    assert_eq!(
        fs::read(source.root.join("branch.bundle")).unwrap(),
        transfer.bytes
    );
    assert_eq!(source.images(), authority);
    assert_eq!(source_images(&source), sources);
    node.shutdown();
    sdk.stop();
    drop(provider_guard);
    let mut reopened = Process::start(&source, &config.replace("create", "open"));
    reopened.ready();
    initial_arm(&mut reopened);
    let mut command = transfer.command(false);
    command["bundle_file"] = json!("reopened.bundle");
    assert_eq!(result(&mut reopened, command)["event"], "bundle_exported");
    assert_eq!(
        fs::read(source.root.join("reopened.bundle")).unwrap(),
        transfer.bytes
    );
    reopened.shutdown();
    assert_eq!(source.images(), authority);
    assert_eq!(source_images(&source), sources);

    let destination = Layout::new();
    let config = source_config(
        &destination,
        fixture.config(&destination, 1, "create", None, false),
    );
    let mut node = Process::start(&destination, &config);
    node.ready();
    initial_arm(&mut node);
    select(&mut node, &destination, &[&first, &second]);
    fs::copy(
        source.root.join("branch.bundle"),
        destination.root.join("branch.bundle"),
    )
    .unwrap();
    let authority = destination.images();
    let state = result(&mut node, json!({"command":"status","id":4}));
    let sources = source_images(&destination);
    for field in ["max_blocks", "max_payload_bytes"] {
        let mut input = transfer.command(true);
        input[field] = json!(input[field].as_u64().unwrap() - 1);
        no_staging_writes(&result(&mut node, input), "bundle_decode");
        assert_eq!(source_images(&destination), sources);
    }
    let mut input = transfer.command(true);
    input["max_bundle_bytes"] = json!(transfer.bytes.len() - 1);
    reject(&mut node, input, "file_too_large");
    let staged = result(&mut node, transfer.command(true));
    assert_eq!(staged["event"], "bundle_staged");
    assert_eq!(staged["selected_prefix_count"], 1);
    assert_eq!(staged["candidate_block_count"], 1);
    assert_eq!(staged["candidate_inserted_count"], 1);
    assert_eq!(staged["payload_inserted_count"], 1);
    assert_eq!(staged["sources"]["candidate_entries"], 1);
    assert_eq!(staged["sources"]["payload_entries"], 1);
    assert_eq!(staged["state"], state);
    assert_eq!(destination.images(), authority);
    let sources = source_images(&destination);
    let repeated = result(&mut node, transfer.command(true));
    assert_eq!(repeated["event"], "bundle_staged");
    assert_eq!(repeated["candidate_inserted_count"], 0);
    assert_eq!(repeated["payload_inserted_count"], 0);
    assert_eq!(repeated["state"], state);
    assert_eq!(source_images(&destination), sources);
    assert_eq!(destination.images(), authority);
    destination.write("third.control", &third.control);
    destination.write("third.vote", &third.vote);
    assert!(!destination.root.join("third.payload").exists());
    let finalized = result(
        &mut node,
        json!({"command":"finalize_candidate_votes", "id":5,"target":target,"evidence_round":third.round,"control_file":"third.control","vote_files":["third.vote"]}),
    );
    assert_eq!(finalized["event"], "finality");
    assert_eq!(finalized["state"]["driver"]["height"], "4");
    assert_eq!(finalized["state"]["driver"]["round"], "0");
    assert_eq!(finalized["state"]["driver"]["head"], target);
    assert_eq!(node.event("timer_armed")["phase"], "Proposal");
    no_staging_writes(
        &result(&mut node, transfer.command(true)),
        "target_selected",
    );
    let mut export = transfer.command(false);
    export["bundle_file"] = json!("selected.bundle");
    assert_eq!(result(&mut node, export)["code"], "target_selected");
    assert!(!destination.root.join("selected.bundle").exists());
    assert_eq!(
        fs::read(destination.root.join("branch.bundle")).unwrap(),
        transfer.bytes
    );
    assert_eq!(source_images(&destination), sources);
    node.shutdown();
    let authority = destination.images();
    let mut reopened = Process::start(&destination, &config.replace("create", "open"));
    let ready = reopened.ready();
    assert_eq!(ready["driver"], finalized["state"]["driver"]);
    let status = result(&mut reopened, json!({"command":"sources_status","id":6}));
    assert_eq!(status["candidate_entries"], 1);
    assert_eq!(status["payload_entries"], 1);
    reopened.shutdown();
    assert_eq!(source_images(&destination), sources);
    assert_eq!(destination.images(), authority);
}
