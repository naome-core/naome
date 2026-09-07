use super::*;

#[test]
fn closed_stdout_with_idle_stdin_releases_active_acquisition_and_all_stores() {
    use std::{
        io::{BufRead, BufReader},
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::{Command, Stdio},
    };
    let fixture = Fixture::new();
    let layout = Layout::new();
    let provider = Plan::new(fixture.peers[0]);
    let peer = provider.peer;
    let config = source_config(
        &layout,
        provider.configure(fixture.config(&layout, 0, "create", None, false)),
    );
    let path = layout.write("validator.toml", &config);
    let (output, reader) = UnixStream::pair().unwrap();
    reader.set_read_timeout(Some(BOUND)).unwrap();
    let child = spawn(
        Command::new(env!("CARGO_BIN_EXE_naome-validator"))
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(OwnedFd::from(output)))
            .stderr(Stdio::inherit()),
    );
    let mut node = Process::unobserved(child);
    let mut reader = BufReader::new(reader);
    let read = |reader: &mut BufReader<UnixStream>| {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        serde_json::from_str::<Value>(&line).unwrap()
    };
    let mut listening = None;
    let mut ready = false;
    let mut armed = false;
    while listening.is_none() || !ready || !armed {
        let event = read(&mut reader);
        match event["event"].as_str().unwrap() {
            "ready" => ready = true,
            "timer_armed" => armed = true,
            "listening" => listening = Some(event["address"].as_str().unwrap().to_owned()),
            _ => panic!("unexpected startup report {event}"),
        }
    }
    let (blocks, payloads) = branch(&fixture, 1);
    let target = hex(blocks[0].id().as_bytes());
    let provider_guard = PARENT_JOURNALS.read().unwrap();
    let sdk = provider.start(
        &provider_guard,
        fixture.definition,
        &listening.unwrap(),
        blocks,
        payloads,
        Some(target.clone()),
    );
    loop {
        let event = read(&mut reader);
        if event["event"] == "peer_session" && event["state"] == "established" {
            break;
        }
    }
    node.send(
        json!({"command":"acquire_ancestry", "id":1, "target":target, "peer_id":peer.to_string()}),
    );
    let started = read(&mut reader);
    assert_eq!(started["outcome"]["event"], "acquisition_started");
    sdk.request("block", &target);
    let authority = layout.images();
    let sources = source_images(&layout);
    drop(reader);
    // One failed report, then idle open stdin and a held network response:
    // only writer-failure notification can promptly wake this owner.
    node.send(json!({"command":"sources_status", "id":2}));
    assert!(!node.exit().success());
    sdk.stop();
    drop(provider_guard);
    assert_eq!(layout.images(), authority);
    assert_eq!(source_images(&layout), sources);
    let mut reopened = Process::start(
        &layout,
        &config.replace("mode = \"create\"", "mode = \"open\""),
    );
    reopened.ready();
    assert!(
        result(&mut reopened, json!({"command":"sources_status", "id":3}))["acquisition"].is_null()
    );
    reopened.shutdown();
    assert_eq!(layout.images(), authority);
    assert_eq!(source_images(&layout), sources);
}

#[test]
fn durable_prefixes_survive_cancel_late_response_shutdown_signals_and_eof_without_resume() {
    for payload_phase in [false, true] {
        for stop in ["cancel", "shutdown", "sigterm", "eof"] {
            let fixture = Fixture::new();
            let layout = Layout::new();
            let provider = Plan::new(fixture.peers[0]);
            let peer = provider.peer;
            let config = source_config(
                &layout,
                provider.configure(fixture.config(&layout, 0, "create", None, false)),
            );
            let mut node = Process::start(&layout, &config);
            let initial = node.ready();
            let node_address = address(&mut node);
            let (blocks, payloads) = branch(&fixture, 2);
            let target = hex(blocks[1].id().as_bytes());
            let missing = if payload_phase {
                hex(blocks[1].artifact_id().as_bytes())
            } else {
                hex(blocks[0].id().as_bytes())
            };
            let provider_guard = PARENT_JOURNALS.read().unwrap();
            let sdk = provider.start(
                &provider_guard,
                fixture.definition,
                &node_address,
                blocks.clone(),
                payloads,
                Some(missing.clone()),
            );
            connected(&mut node, peer);
            let authority = layout.images();
            let ancestry = json!({"command":"acquire_ancestry", "id":1, "target":target, "peer_id":peer.to_string()});
            if payload_phase {
                acquire(&mut node, ancestry.clone());
                sdk.request("block", &target);
                sdk.request("block", &hex(blocks[0].id().as_bytes()));
            }
            let mut command = if payload_phase {
                json!({"command":"acquire_payloads", "id":10, "target":target, "peer_id":peer.to_string(), "max_blocks":2})
            } else {
                ancestry
            };
            command["id"] = json!(10);
            assert_eq!(
                result(&mut node, command.clone())["event"],
                "acquisition_started"
            );
            if payload_phase {
                sdk.request("payload", &hex(blocks[0].artifact_id().as_bytes()));
                sdk.request("payload", &missing);
            } else {
                sdk.request("block", &target);
                sdk.request("block", &missing);
            }
            let progress = node.event("acquisition_progress");
            assert_eq!(progress["id"], 10);
            let active = result(&mut node, json!({"command":"sources_status", "id":11}));
            assert_eq!(active["acquisition"]["id"], 10);
            assert!(
                active.get("candidate_entries").is_none(),
                "active cursor owns the source borrow"
            );
            for command in [
                json!({"command":"author_candidate", "id":12, "target":target}),
                json!({"command":"author_stored_retained", "id":12}),
                json!({"command":"acquire_ancestry", "id":12, "target":"invalid", "peer_id":peer.to_string()}),
            ] {
                node.send(command);
                assert_eq!(node.event("command_rejected")["code"], "sources_busy");
            }
            node.send(json!({"command":"sync_finality", "id":12, "peer_id":"invalid", "count":0}));
            assert_eq!(node.event("command_rejected")["code"], "sync_busy");
            node.write(b"{\"command\":\"sources_status\",\"id\":12,\"extra\":true}\n");
            assert_eq!(node.event("command_rejected")["code"], "command_schema");
            let status = result(&mut node, json!({"command":"status", "id":13}));
            assert_eq!(status["driver"]["head"], initial["driver"]["head"]);
            assert_eq!(layout.images(), authority);
            let prefix = source_images(&layout);
            if stop == "cancel" {
                let cancelled = result(&mut node, json!({"command":"cancel_acquisition", "id":14}));
                assert_eq!(cancelled["active"], true);
                assert_eq!(cancelled["acquisition_id"], 10);
                assert_eq!(node.event("acquisition_cancelled")["id"], 10);
                assert_eq!(
                    result(&mut node, json!({"command":"cancel_acquisition", "id":15}))["active"],
                    false
                );
                command["id"] = json!(16);
                node.send(command.clone());
                assert_eq!(
                    node.event("command_rejected")["code"],
                    if payload_phase {
                        "source_payload_failure"
                    } else {
                        "source_request_start"
                    }
                );
                assert_eq!(source_images(&layout), prefix);
                sdk.release();
                node.event("network_event_discarded");
                assert_eq!(
                    source_images(&layout),
                    prefix,
                    "late response must not retain bytes"
                );
                command["id"] = json!(17);
                acquire(&mut node, command);
                sdk.request(if payload_phase { "payload" } else { "block" }, &missing);
                assert_eq!(layout.images(), authority);
                node.shutdown();
            } else {
                match stop {
                    "shutdown" => node.send(json!({"command":"shutdown", "id":18})),
                    "sigterm" => node.signal(rustix::process::Signal::TERM),
                    "eof" => drop(node.child.stdin.take()),
                    _ => unreachable!(),
                }
                let stopped = node.event("stopped");
                assert_eq!(stopped["reason"], stop);
                assert_eq!(stopped["locks_released"], true);
                assert!(node.exit().success());
                assert!(
                    node.observed
                        .iter()
                        .any(|v| v["event"] == "acquisition_cancelled"
                            && v["id"] == 10
                            && v["reason"] == stop)
                );
                assert_eq!(source_images(&layout), prefix);
            }
            sdk.stop();
            drop(provider_guard);
            let before = source_images(&layout);
            let mut reopened = Process::start(
                &layout,
                &config.replace("mode = \"create\"", "mode = \"open\""),
            );
            assert_eq!(
                reopened.ready()["driver"]["head"],
                initial["driver"]["head"]
            );
            let status = result(&mut reopened, json!({"command":"sources_status", "id":19}));
            assert!(status["acquisition"].is_null());
            assert_eq!(
                status["candidate_entries"],
                if payload_phase || stop == "cancel" {
                    2
                } else {
                    1
                }
            );
            assert_eq!(
                status["payload_entries"],
                if payload_phase {
                    if stop == "cancel" { 2 } else { 1 }
                } else {
                    0
                }
            );
            reopened.shutdown();
            assert_eq!(source_images(&layout), before);
            assert_eq!(layout.images(), authority);
        }
    }
}
