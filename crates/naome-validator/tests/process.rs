#![cfg(unix)]

#[path = "cases/current_finality.rs"]
mod current_finality;
#[path = "cases/current_pair.rs"]
mod current_pair;
#[path = "cases/explicit_proofs.rs"]
mod explicit_proofs;
#[path = "cases/historical_conflict.rs"]
mod historical_conflict;
#[path = "cases/inbox_disposal.rs"]
mod inbox_disposal;
mod support;

use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    process::{Command, Stdio},
    time::Instant,
};
use support::*;

#[test]
fn two_actual_processes_exchange_noise_receipts_finalize_and_strictly_restart() {
    let fixture = Fixture::new();
    let source_layout = Layout::new();
    let receiver_layout = Layout::new();
    let receiver_config = fixture.config(
        &receiver_layout,
        1,
        "create",
        Some("/ip4/127.0.0.1/tcp/1"),
        false,
    );
    let mut receiver = Process::start(&receiver_layout, &receiver_config);
    let initial = receiver.ready();
    assert_eq!(initial["driver"]["height"], "1");
    let address = receiver.event("listening")["address"]
        .as_str()
        .unwrap()
        .to_owned();
    let source_config = fixture.config(&source_layout, 0, "create", Some(&address), true);
    let mut source = Process::start(&source_layout, &source_config);
    source.ready();
    source.until(|value| value["event"] == "peer_session" && value["state"] == "established");
    receiver.until(|value| value["event"] == "peer_session" && value["state"] == "established");
    assert!(
        !receiver
            .observed
            .iter()
            .any(|value| value["event"] == "finality")
    );
    let block = fixture.proposal(&source_layout);
    source.send(json!({"command": "author_fresh", "id": 1, "block_file": "block.bin", "payload_file": "payload.bin"}));
    let authored = source.event("command_result");
    assert_eq!(authored["outcome"]["event"], "proposal_authored");
    let source_finality = source.event("finality");
    let receiver_finality = receiver.event("finality");
    let expected = hex(block.id().as_bytes());
    for event in [source_finality, receiver_finality] {
        assert_eq!(event["state"]["driver"]["head"], expected);
        assert_eq!(event["state"]["driver"]["height"], "2");
    }
    assert_eq!(
        source
            .observed
            .iter()
            .filter(|v| v["event"] == "peer_completed"
                && v["received"] == true
                && v["peer"] == fixture.peers[1].to_string())
            .count(),
        3
    );
    assert_eq!(
        source
            .observed
            .iter()
            .filter(|v| v["event"] == "publication_complete"
                && v["disposed"]["deliveries"][0]["state"] == "received")
            .count(),
        3
    );
    assert_eq!(
        receiver
            .observed
            .iter()
            .filter(|v| v["event"] == "admission"
                && v["source"]["kind"] == "peer"
                && v["source"]["peer"] == fixture.peers[0].to_string()
                && v["all_admitted"] == true
                && v["receipt_queued"] == true)
            .count(),
        3
    );
    // Receiver remains running through all three source-correlated receipts.
    source.shutdown();
    receiver.shutdown();
    for (layout, config) in [
        (&source_layout, source_config),
        (&receiver_layout, receiver_config),
    ] {
        let durable = layout.images();
        let mut reopened = Process::start(
            layout,
            &config.replace("mode = \"create\"", "mode = \"open\""),
        );
        let state = reopened.ready();
        assert_eq!(state["driver"]["head"], expected);
        assert_eq!(state["driver"]["height"], "2");
        assert_eq!(state["driver"]["round"], "0");
        assert_eq!(state["driver"]["phase"], "Proposal");
        reopened.shutdown();
        assert_eq!(layout.images(), durable);
    }
}

#[test]
fn explicit_shutdown_sigint_and_eof_release_locks_with_open_stdin() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture.config(&layout, 0, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let summary = node.shutdown();
    assert_eq!(summary["locks_released"], true);
    assert_eq!(summary["discarded"]["timer"], true);
    let durable = layout.images();
    for reason in ["sigint", "eof"] {
        let mut node = Process::start(&layout, &config.replace("create", "open"));
        node.ready();
        if reason == "sigint" {
            node.write(b"{\"command\":\"status\",\"id\":");
            node.signal(rustix::process::Signal::INT);
        } else {
            drop(node.child.stdin.take());
        }
        let stopped = node.event("stopped");
        assert_eq!(stopped["reason"], reason);
        assert!(node.exit().success());
        assert_eq!(layout.images(), durable);
    }
}

#[test]
fn split_command_survives_runtime_timeout_and_preserves_full_u64_request_id() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture
        .config(&layout, 0, "create", None, false)
        .replace("60000", "200");
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.write(b"{\"command\":\"status\",\"id\":1844674407");
    node.event("timer_due");
    node.write(b"3709551615}\n");
    let response = node.event("command_result");
    assert_eq!(response["id"].as_u64(), Some(u64::MAX));
    node.shutdown();
    assert_eq!(
        node.observed
            .iter()
            .filter(|v| v["id"].as_u64() == Some(u64::MAX))
            .count(),
        1
    );
}

#[test]
fn malformed_input_and_oversized_or_truncated_frames_never_reparse_a_suffix() {
    let fixture = Fixture::new();
    for failure in ["input_too_large", "input_truncated"] {
        let layout = Layout::new();
        let config = fixture.config(&layout, 0, "create", None, false);
        let mut node = Process::start(&layout, &config);
        node.ready();
        node.write(b"not json\n\xff\n{\"command\":\"status\",\"id\":1,\"extra\":true}\n");
        for _ in 0..3 {
            assert_eq!(node.event("command_rejected")["code"], "command_schema");
        }
        let durable = layout.images();
        if failure == "input_too_large" {
            let mut bytes = vec![b' '; 65_537];
            bytes.extend_from_slice(b"{\"command\":\"shutdown\",\"id\":2}\n");
            let _ = node.child.stdin.as_mut().unwrap().write_all(&bytes);
        } else {
            node.write(b"{\"command\":\"shutdown\",\"id\":2}");
            drop(node.child.stdin.take());
        }
        assert_eq!(node.event("stopped")["reason"], failure);
        assert!(!node.exit().success());
        assert!(!node.observed.iter().any(|value| value["id"] == 2));
        assert_eq!(layout.images(), durable);
    }
}

#[test]
fn queued_raw_input_is_not_admission_and_source_refusals_do_not_retry() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.event("timer_armed");
    let durable = layout.images();
    layout.write(
        "vote.bin",
        vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES],
    );
    node.send(json!({"command": "submit_vote", "id": 1, "vote_file": "vote.bin"}));
    assert_eq!(
        node.event("command_result")["outcome"]["event"],
        "input_queued"
    );
    let admission = node.event("admission");
    assert_eq!(admission["source"]["kind"], "caller");
    assert_eq!(admission["all_admitted"], false);
    let _ = fixture.proposal(&layout);
    node.send(json!({"command": "author_fresh", "id": 2, "block_file": "block.bin", "payload_file": "payload.bin"}));
    assert_eq!(
        node.event("command_result")["outcome"]["event"],
        "proposal_rejected"
    );
    layout.write(
        "vote.bin",
        vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES + 1],
    );
    node.send(json!({"command": "submit_vote", "id": 3, "vote_file": "vote.bin"}));
    assert_eq!(node.event("command_rejected")["code"], "file_too_large");
    assert!(
        spawn(Command::new("mkfifo").arg(layout.root.join("fifo")))
            .wait()
            .unwrap()
            .success()
    );
    node.send(json!({"command": "submit_vote", "id": 4, "vote_file": "fifo"}));
    assert_eq!(node.event("command_rejected")["code"], "file_not_regular");
    node.send(json!({"command": "author_retained", "id": 5, "payload_file": "payload.bin"}));
    assert_eq!(
        node.event("command_result")["outcome"]["event"],
        "proposal_rejected"
    );
    layout.write(
        "control.bin",
        vec![0; naome_network::CONSENSUS_PUSH_MIN_PROPOSAL_BYTES],
    );
    node.send(json!({"command": "submit_proposal", "id": 6, "control_file": "control.bin", "payload_file": "payload.bin"}));
    assert_eq!(
        node.event("command_result")["outcome"]["event"],
        "input_queued"
    );
    assert_eq!(node.event("admission")["all_admitted"], false);
    node.shutdown();
    assert!(
        !node
            .observed
            .iter()
            .any(|v| v["event"] == "publication_prepared")
    );
    assert_eq!(layout.images(), durable);
}

#[test]
fn invalid_config_and_seed_files_refuse_before_create_and_healthy_open_writes() {
    let fixture = Fixture::new();
    for mode in ["create", "open"] {
        let layout = Layout::new();
        let original = fixture.config(&layout, 0, "create", None, false);
        if mode == "open" {
            let mut node = Process::start(&layout, &original);
            node.ready();
            node.shutdown();
        }
        let original = original.replace("mode = \"create\"", &format!("mode = \"{mode}\""));
        let durable = layout.images();
        let invalid = [
            original.replacen("version = 0", "version = 1", 1),
            format!("{original}\n[remote_signer]\nurl = 'http://invalid'\n"),
            original.replace(&format!("mode = \"{mode}\""), "mode = \"repair\""),
            original.replace("finality_max_round = \"8\"", "finality_max_round = \"0\""),
            original.replace("vote_preparations = \"32\"", "vote_preparations = \"0\""),
            original.replace(
                "proposal_preparations = \"8\"",
                "proposal_preparations = \"0\"",
            ),
            original.replace("entries = \"8\"", "entries = \"0\""),
            original.replace("bytes = \"1048576\"", "bytes = \"0\""),
            original.replace(
                "driver_max_round = \"4\"",
                "driver_max_round = \"18446744073709551616\"",
            ),
            original
                .replace(
                    "driver_max_round = \"4\"",
                    "driver_max_round = \"18446744073709551615\"",
                )
                .replace(
                    "round_increment_millis = \"1\"",
                    "round_increment_millis = \"18446744073709551615\"",
                ),
            original.replace("base_millis = \"60000\"", "base_millis = \"0\""),
            original.replace("weight = \"3\"", "weight = \"0\""),
            original.replace(
                "weight = \"3\"",
                "weight = \"340282366920938463463374607431768211456\"",
            ),
            original.replace("/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/udp/1234"),
            original.replace(
                &hex(fixture.entries[1].consensus_key().as_bytes()),
                &hex(fixture.entries[0].consensus_key().as_bytes()),
            ),
            original.replace(
                "weight = \"3\"",
                "weight = \"340282366920938463463374607431768211455\"",
            ),
            original.replace(
                "publication_targets = []",
                &format!("publication_targets = [{:?}]", fixture.peers[1].to_string()),
            ),
            original.replace(
                "peers = []",
                &format!(
                    "peers = [{{ peer_id = {:?}, address = '/ip4/127.0.0.1/tcp/1' }}]",
                    fixture.peers[0].to_string()
                ),
            ),
            original.replace(
                "peers = []",
                &format!(
                    "peers = [{{ peer_id = {:?}, address = '/ip4/127.0.0.1/tcp/0' }}]",
                    fixture.peers[1].to_string()
                ),
            ),
        ];
        for config in invalid {
            let mut node = Process::start(&layout, &config);
            node.event("error");
            assert!(!node.exit().success());
            assert!(!node.observed.iter().any(|value| value["event"] == "ready"));
            assert_eq!(layout.images(), durable);
        }
        for (name, bytes) in [
            ("short", vec![1; 31]),
            ("long", vec![1; 33]),
            ("wrong", vec![1; 32]),
            ("same", fixture.noise[0].to_vec()),
        ] {
            layout.seed(name, &bytes);
            let mut node = Process::start(&layout, &original.replace("signing.seed", name));
            node.event("error");
            assert!(!node.exit().success());
            assert_eq!(layout.images(), durable);
        }
        for mode in [0o640, 0o604] {
            layout.seed("bad-permissions", &[1; 32]);
            fs::set_permissions(
                layout.root.join("bad-permissions"),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();
            let mut node = Process::start(
                &layout,
                &original.replace("signing.seed", "bad-permissions"),
            );
            assert_eq!(node.event("error")["code"], "seed_permissions");
            assert!(!node.exit().success());
            assert_eq!(layout.images(), durable);
        }
        symlink("signing.seed", layout.root.join("link")).unwrap();
        symlink("missing", layout.root.join("dangling")).unwrap();
        assert!(
            spawn(Command::new("mkfifo").arg(layout.root.join("fifo")))
                .wait()
                .unwrap()
                .success()
        );
        for name in ["link", "dangling", "fifo", "finality-journal"] {
            let mut node = Process::start(&layout, &original.replace("signing.seed", name));
            node.event("error");
            assert!(!node.exit().success());
            assert_eq!(layout.images(), durable);
        }
    }
}

#[test]
fn explicit_modes_never_fall_back_between_create_and_open() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture.config(&layout, 0, "create", None, false);
    let empty = layout.images();
    let mut missing = Process::start(&layout, &config.replace("create", "open"));
    assert_eq!(missing.event("error")["code"], "startup_open");
    assert!(!missing.exit().success());
    assert!(empty.is_empty());
    assert!(layout.images().iter().all(|(path, bytes)| {
        path.extension()
            .is_some_and(|extension| extension == "lock")
            && bytes.is_empty()
    }));
    let mut node = Process::start(&layout, &config);
    node.ready();
    node.shutdown();
    let durable = layout.images();
    let mut duplicate = Process::start(&layout, &config);
    assert_eq!(duplicate.event("error")["code"], "startup_create");
    assert!(!duplicate.exit().success());
    assert_eq!(layout.images(), durable);
}

#[test]
fn stalled_stdout_cannot_retain_journal_locks_or_hang_process_exit() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture.config(&layout, 0, "create", None, false);
    let path = layout.write("validator.toml", &config);
    let mut child = spawn(
        Command::new(env!("CARGO_BIN_EXE_naome-validator"))
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    );
    // Hold stdout open without reading. Enough bounded status requests fill
    // both the pipe and the process's report queue; failure must drop owners.
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        for id in 0..10_000 {
            if writeln!(stdin, "{{\"command\":\"status\",\"id\":{id}}}").is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + BOUND;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("stalled stdout held the process");
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    assert!(!status.success());
    writer.join().unwrap();
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    reopened.ready();
    reopened.shutdown();
}

#[test]
fn final_report_timeout_is_not_repeated_as_a_second_error_flush() {
    use std::{
        io::ErrorKind,
        os::{fd::OwnedFd, unix::net::UnixStream},
        time::Duration,
    };
    let fixture = Fixture::new();
    let layout = Layout::new();
    let config = fixture.config(&layout, 0, "create", None, false);
    let path = layout.write("validator.toml", &config);
    let (mut output, _unread_receiver) = UnixStream::pair().unwrap();
    output.set_nonblocking(true).unwrap();
    let mut filled = 0;
    loop {
        match output.write(&[0; 8192]) {
            Ok(count) => {
                filled += count;
                assert!(filled < 16 * 1024 * 1024);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill test stdout: {error}"),
        }
    }
    output.set_nonblocking(false).unwrap();
    // The first output write blocks, but the report queue has ample space for
    // ready, shutdown and stopped. This reaches the flush timeout, not a full
    // queue refusal, and used to perform two consecutive two-second waits.
    let child = spawn(
        Command::new(env!("CARGO_BIN_EXE_naome-validator"))
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(OwnedFd::from(output))),
    );
    let mut node = Process::unobserved(child);
    let started = Instant::now();
    node.send(json!({"command": "shutdown", "id": 1}));
    assert!(!node.exit().success());
    assert!(
        started.elapsed() < Duration::from_millis(3500),
        "final report timeout was repeated"
    );
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    reopened.ready();
    reopened.shutdown();
}

#[test]
fn shutdown_reports_in_flight_publication_and_discards_inboxes_before_strict_reopen() {
    let fixture = Fixture::new();
    let source_layout = Layout::new();
    let receiver_layout = Layout::new();
    let receiver_config = fixture.config(
        &receiver_layout,
        1,
        "create",
        Some("/ip4/127.0.0.1/tcp/1"),
        false,
    );
    let mut receiver = Process::start(&receiver_layout, &receiver_config);
    receiver.ready();
    let address = receiver.event("listening")["address"]
        .as_str()
        .unwrap()
        .to_owned();
    let config = fixture.config(&source_layout, 0, "create", Some(&address), true);
    let mut source = Process::start(&source_layout, &config);
    source.ready();
    source.until(|v| v["event"] == "peer_session" && v["state"] == "established");
    receiver.until(|v| v["event"] == "peer_session" && v["state"] == "established");
    receiver.signal(rustix::process::Signal::STOP);
    // A stopped child is still killed/reaped by Process::drop on any failure.
    let _ = fixture.proposal(&source_layout);
    source.send(json!({"command": "author_fresh", "id": 1, "block_file": "block.bin", "payload_file": "payload.bin"}));
    assert_eq!(
        source.event("command_result")["outcome"]["event"],
        "proposal_authored"
    );
    assert_eq!(source.event("peer_attempted")["started"], true);
    let before = source_layout.images();
    let stopped = source.shutdown();
    assert_eq!(
        stopped["discarded"]["publication"]["deliveries"][0]["state"],
        "in_flight"
    );
    assert_eq!(stopped["discarded"]["driver"]["current_inbox"], 1);
    assert_eq!(stopped["discarded"]["driver"]["finality_inbox"], 1);
    assert_eq!(stopped["discarded"]["driver"]["height"], "1");
    assert_eq!(stopped["discarded"]["timer"], true);
    assert_eq!(source_layout.images(), before);
    receiver.signal(rustix::process::Signal::CONT);
    receiver.shutdown();
    let mut reopened = Process::start(&source_layout, &config.replace("create", "open"));
    let state = reopened.ready();
    assert_eq!(state["driver"]["height"], "1");
    assert_eq!(state["driver"]["phase"], "Proposal");
    assert_eq!(state["driver"]["current_inbox"], 0);
    assert_eq!(state["driver"]["finality_inbox"], 0);
    assert!(state["publication"].is_null());
    reopened.shutdown();
    assert_eq!(source_layout.images(), before);
}

#[test]
fn pending_vote_proposal_and_anchored_terminal_state_refuse_without_ready_or_repair() {
    use naome_consensus::FixedValidatorProposalSourceV0 as Source;
    use naome_storage::{
        FixedValidatorProposalPrepareOutcomeV0 as Proposal,
        FixedValidatorVotePrepareOutcomeV0 as Vote,
    };
    let fixture = Fixture::new();
    for state in ["pending_vote", "pending_proposal", "signer_stopped"] {
        let layout = Layout::new();
        let config = fixture.config(&layout, 0, "open", None, false);
        let block = fixture.proposal(&layout);
        (|| {
            let _guard = PARENT_JOURNALS.read().unwrap();
            drop(fixture.create_node(&layout));
            let branch = naome_consensus::FixedConsensusBranchV0::try_from_virtual_genesis(
                fixture.context,
                &fixture.entries,
                naome_chain::ArtifactChainState::new(fixture.definition).branch_snapshot(),
            )
            .unwrap();
            let round = branch.begin_round_zero().unwrap();
            let mut journal = naome_storage::FixedValidatorAnchoredVoteSafetyJournalV0::open(
                layout.root.join("vote-journal"),
                layout.root.join("vote-anchor"),
                fixture.context,
                branch.fixed_agreement_set_id(),
                fixture.keys[0].clone(),
                naome_storage::FixedValidatorVoteSafetyReplayLimitV0::new(32).unwrap(),
            )
            .unwrap();
            let mut session = journal.issue_signing_session(&round).unwrap();
            if state == "pending_vote" {
                let effect = session.decide_prevote_without_proposal().unwrap();
                assert!(matches!(
                    session.prepare_vote(&round, effect).unwrap(),
                    Vote::Prepared(_)
                ));
                return;
            }
            let Proposal::Prepared(prepared) = session
                .prepare_proposal(
                    &round,
                    Source::Fresh {
                        artifact_block: block,
                        canonical_artifact_bytes: fs::read(layout.root.join("payload.bin"))
                            .unwrap(),
                    },
                )
                .unwrap()
            else {
                panic!("durable preparation");
            };
            if state == "pending_proposal" {
                return;
            }
            let acknowledgement = session.acknowledge_prepared_proposal(prepared).unwrap();
            let _ = session.sign_prepared_proposal(acknowledgement).unwrap();
            let payload = naome_proof::ArtifactPayload::Proof(
                naome_proof::ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, 2])
                    .unwrap(),
            )
            .to_canonical_bytes();
            let artifact = naome_chain::ArtifactDag::new()
                .apply_canonical_artifact_bytes(payload.clone())
                .unwrap()
                .artifact_id();
            let other = naome_chain::ArtifactChainState::new(fixture.definition)
                .prepare_block(artifact)
                .unwrap();
            assert_ne!(block.id(), other.id());
            assert!(matches!(
                session
                    .prepare_proposal(
                        &round,
                        Source::Fresh {
                            artifact_block: other,
                            canonical_artifact_bytes: payload
                        }
                    )
                    .unwrap(),
                Proposal::Halted(_)
            ));
        })();
        let durable = layout.images();
        for _ in 0..2 {
            let mut node = Process::start(&layout, &config);
            assert_eq!(node.event("error")["code"], format!("startup_{state}"));
            assert!(!node.exit().success());
            assert!(
                !node
                    .observed
                    .iter()
                    .any(|v| matches!(v["event"].as_str(), Some("ready" | "listening")))
            );
            assert_eq!(layout.images(), durable);
        }
    }
}
