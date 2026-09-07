use crate::support::*;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs};

fn configured(text: &str, value: &str) -> String {
    text.replace(
        "[network]",
        &format!("[network]\npublication_retry_millis = {value}"),
    )
}

fn completed(node: &Process, recovered: bool) -> BTreeMap<String, Value> {
    node.observed
        .iter()
        .filter(|event| {
            event["event"] == "publication_complete" && event["disposed"]["recovered"] == recovered
        })
        .map(|event| {
            let publication = &event["disposed"];
            assert_eq!(publication["deliveries"][0]["state"], "refused");
            (
                publication["signer_state"].as_str().unwrap().to_owned(),
                publication["message_sha256"].clone(),
            )
        })
        .collect()
}

#[test]
fn periodic_publication_process_retries_unavailable_peer_and_strictly_reopens_original_debt() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = configured(
        &fixture.config(&layout, 0, "create", Some("/ip4/127.0.0.1/tcp/1"), true),
        "\"100\"",
    );
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let block = fixture.proposal(&layout);
    node.send(json!({"command": "author_fresh", "id": 1, "block_file": "block.bin", "payload_file": "payload.bin"}));
    assert_eq!(
        node.event("command_result")["outcome"]["event"],
        "proposal_authored"
    );
    let finality = node.event("finality");
    assert_eq!(
        finality["state"]["driver"]["head"],
        hex(block.id().as_bytes())
    );
    while completed(&node, true).len() != 3 {
        node.event("publication_complete");
    }
    node.shutdown();
    let originals = completed(&node, false);
    assert_eq!(originals.len(), 3);
    assert_eq!(completed(&node, true), originals);
    assert!(
        node.observed
            .iter()
            .any(|event| event["event"] == "publication_retry_scheduled" && event["queued"] == "3")
    );
    assert!(
        !node
            .observed
            .iter()
            .any(|event| event["event"] == "peer_completed" && event["received"] == true)
    );
    let before = layout.images();
    fs::remove_file(layout.root.join("block.bin")).unwrap();
    fs::remove_file(layout.root.join("payload.bin")).unwrap();
    let mut reopened = Process::start(
        &layout,
        &config.replace("mode = \"create\"", "mode = \"open\""),
    );
    assert_eq!(reopened.ready()["driver"]["height"], "2");
    // Drain strict-startup debt, then demand a distinct timer-triggered pass.
    while completed(&reopened, true).len() != 3 {
        reopened.event("publication_complete");
    }
    assert_eq!(reopened.event("publication_retry_scheduled")["queued"], "3");
    for _ in 0..3 {
        reopened.event("publication_complete");
    }
    reopened.shutdown();
    assert_eq!(completed(&reopened, true), originals);
    assert_eq!(
        without_delivery_progress(&layout.images()),
        without_delivery_progress(&before),
        "retry and strict reopen must not rewrite signer or finality authority"
    );
    assert!(
        reopened
            .observed
            .iter()
            .all(|event| event["event"] != "publication_prepared" && event["event"] != "finality")
    );
}

#[test]
fn periodic_publication_configuration_is_explicit_and_invalid_values_preserve_authority() {
    let fixture = Fixture::new();
    for mode in ["create", "open"] {
        let layout = Layout::new();
        let mut config = fixture.config(&layout, 0, "create", None, false);
        if mode == "open" {
            let mut node = Process::start(&layout, &config);
            node.ready();
            node.shutdown();
            config = config.replace("mode = \"create\"", "mode = \"open\"");
        }
        let before = layout.images();
        for value in [
            "\"0\"",
            "\"01\"",
            "\"-1\"",
            "\"+1\"",
            "\"1.0\"",
            "\" 1\"",
            "\"18446744073709551616\"",
            "1",
            "true",
        ] {
            let mut node = Process::start(&layout, &configured(&config, value));
            node.event("error");
            assert!(!node.exit().success());
            assert!(!node.observed.iter().any(|event| event["event"] == "ready"));
            assert_eq!(layout.images(), before);
        }
        // A value above u32 milliseconds remains accepted at its exact width.
        let mut node = Process::start(&layout, &configured(&config, "\"4294967296\""));
        node.ready();
        node.shutdown();
        assert!(
            !node
                .observed
                .iter()
                .any(|event| event["event"] == "publication_retry_scheduled")
        );
    }
}
