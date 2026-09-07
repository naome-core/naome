mod boundaries;
mod busy;

use super::source_bundles::Transfer;
use super::*;

fn serving(config: String) -> String {
    config.replace("[network]", "[network]\nserve_artifact_sources = true")
}

fn stage(node: &mut Process, layout: &Layout, transfer: &Transfer) {
    layout.write("branch.bundle", &transfer.bytes);
    assert_eq!(
        result(node, transfer.command(true))["event"],
        "bundle_staged"
    );
}

fn ancestry(id: u64, peer: naome_network::PeerId, block: &ArtifactBlock) -> Value {
    json!({"command":"acquire_ancestry", "id":id, "peer_id":peer.to_string(), "target":hex(block.id().as_bytes())})
}

fn fill(id: u64, peer: naome_network::PeerId, block: &ArtifactBlock, count: u64) -> Value {
    json!({"command":"acquire_payloads", "id":id, "peer_id":peer.to_string(), "target":hex(block.id().as_bytes()), "max_blocks":count})
}

fn failed(node: &mut Process, command: Value) -> Value {
    let id = command["id"].clone();
    assert_eq!(result(node, command)["event"], "acquisition_started");
    node.until(|v| v["id"] == id && v["event"] == "acquisition_failed")
}

fn response(node: &mut Process, kind: &str, busy: bool) -> Value {
    let event = node.until(|v| v["event"] == "source_response_queued" && v["kind"] == kind);
    assert_eq!(event["sources_busy"], busy);
    event
}

#[test]
fn explicitly_staged_unselected_branch_is_served_acquired_then_separately_authored_and_reopened() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 3, 0);
    let source = Layout::new();
    let destination = Layout::new();
    let config = serving(source_config(
        &source,
        fixture.config(&source, 1, "create", Some("/ip4/127.0.0.1/tcp/1"), false),
    ));
    let mut server = Process::start(&source, &config);
    server.ready();
    let listen = address(&mut server);
    if !server.observed.iter().any(|v| v["event"] == "timer_armed") {
        server.event("timer_armed");
    }
    let initial = result(&mut server, json!({"command":"status", "id":0}));
    stage(&mut server, &source, &transfer);
    let source_bytes = source_images(&source);
    let source_authority = source.images();
    let client_config = source_config(
        &destination,
        fixture.config(&destination, 0, "create", Some(&listen), true),
    );
    let mut client = Process::start(&destination, &client_config);
    client.ready();
    connected(&mut client, fixture.peers[1]);
    let client_authority = destination.images();
    acquire(
        &mut client,
        ancestry(1, fixture.peers[1], &transfer.blocks[2]),
    );
    assert_eq!(
        acquire(
            &mut client,
            fill(2, fixture.peers[1], &transfer.blocks[2], 3)
        )["validated_blocks"],
        3
    );
    for kind in ["block", "block", "block", "payload", "payload", "payload"] {
        assert_eq!(
            response(&mut server, kind, false)["peer"],
            fixture.peers[0].to_string()
        );
    }
    assert_eq!(source.images(), source_authority);
    assert_eq!(destination.images(), client_authority);
    assert_eq!(
        result(&mut server, json!({"command":"status", "id":3}))["driver"],
        initial["driver"]
    );
    assert_eq!(
        result(&mut client, transfer.command(false))["event"],
        "bundle_exported"
    );
    assert_eq!(
        fs::read(destination.root.join("branch.bundle")).unwrap(),
        transfer.bytes
    );
    assert_eq!(source_images(&source), source_bytes);
    assert!(!destination.root.join("payload.bin").exists());
    let target = hex(transfer.blocks[0].id().as_bytes());
    assert_eq!(
        result(
            &mut client,
            json!({"command":"author_candidate", "id":4, "target":target})
        )["event"],
        "proposal_authored"
    );
    for node in [&mut client, &mut server] {
        assert_eq!(node.event("finality")["state"]["driver"]["head"], target);
        node.shutdown();
    }
    assert_eq!(source_images(&source), source_bytes);
    let authority = source.images();
    let mut server = Process::start(
        &source,
        &config.replace("mode = \"create\"", "mode = \"open\""),
    );
    assert_eq!(server.ready()["driver"]["head"], target);
    let listen = address(&mut server);
    // A new, empty receiver must fetch even the still-unselected suffix after
    // strict reopen; no completed local acquisition can mask a missing reply.
    let fresh = Layout::new();
    let config = source_config(
        &fresh,
        fixture.config(&fresh, 0, "create", Some(&listen), false),
    );
    let mut client = Process::start(&fresh, &config);
    client.ready();
    connected(&mut client, fixture.peers[1]);
    acquire(
        &mut client,
        ancestry(5, fixture.peers[1], &transfer.blocks[2]),
    );
    assert_eq!(
        acquire(
            &mut client,
            fill(6, fixture.peers[1], &transfer.blocks[2], 3)
        )["validated_blocks"],
        3
    );
    assert_eq!(
        result(&mut client, transfer.command(false))["event"],
        "bundle_exported"
    );
    assert_eq!(
        fs::read(fresh.root.join("branch.bundle")).unwrap(),
        transfer.bytes
    );
    client.shutdown();
    server.shutdown();
    assert_eq!(source.images(), authority);
    assert_eq!(source_images(&source), source_bytes);
    let before = destination.images();
    let mut reopened = Process::start(
        &destination,
        &client_config.replace("mode = \"create\"", "mode = \"open\""),
    );
    assert_eq!(reopened.ready()["driver"]["head"], target);
    reopened.shutdown();
    assert_eq!(destination.images(), before);
}
