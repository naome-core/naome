use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

use serde_json::json;

use crate::support::*;

#[test]
fn acknowledged_import_survives_actual_process_kill_and_reopens_without_source_files() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let proof = fixture.proof(&[], 1, 1);
    proof.write(&layout, "proof");
    let mut process = Process::start(&layout, &fixture.config("create"));
    process.ready();
    assert_eq!(
        process.request(Proof::command(1, "proof"))["outcome"]["kind"],
        "finalized"
    );
    let state = process.status();
    let images = layout.images();
    process.child.kill().unwrap();
    assert!(!process.exit().success());
    fs::remove_file(layout.root.join("proof.envelope")).unwrap();
    fs::remove_file(layout.root.join("proof.payload")).unwrap();
    let mut reopened = Process::start(&layout, &fixture.config("open"));
    assert_eq!(reopened.ready(), state);
    reopened.shutdown();
    assert_eq!(layout.images(), images);
    fixture.inspect(&layout, |journal| {
        let record = journal
            .finality_record(proof.value.height())
            .unwrap()
            .unwrap();
        assert_eq!(record.canonical_envelope_bytes(), proof.envelope);
        assert_eq!(record.canonical_artifact_bytes(), proof.payload);
    });
}

#[test]
fn explicit_create_and_open_never_replace_existing_history_or_fall_back_to_creation() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let mut missing = Process::start(&layout, &fixture.config("open"));
    assert_eq!(missing.event("error")["code"], "startup_open");
    assert!(!missing.exit().success());
    assert!(!layout.journal().exists());
    assert!(!layout.anchor().exists());
    let proof = fixture.proof(&[], 0, 1);
    proof.write(&layout, "proof");
    let mut owner = Process::start(&layout, &fixture.config("create"));
    owner.ready();
    assert_eq!(
        owner.request(Proof::command(1, "proof"))["outcome"]["kind"],
        "finalized"
    );
    let images = layout.images();
    let mut competing = Process::start(&layout, &fixture.config("open"));
    assert_eq!(competing.event("error")["code"], "startup_open");
    assert!(!competing.exit().success());
    assert_eq!(layout.images(), images);
    owner.shutdown();
    let mut recreate = Process::start(&layout, &fixture.config("create"));
    assert_eq!(recreate.event("error")["code"], "startup_create");
    assert!(!recreate.exit().success());
    assert_eq!(layout.images(), images);
    let mut reopened = Process::start(&layout, &fixture.config("open"));
    assert_eq!(reopened.ready()["head"]["height"], "1");
    reopened.shutdown();
}

#[test]
fn complete_journal_anchor_mismatches_and_foreign_configuration_fail_closed_without_repair() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 0, 2);
    first.write(&layout, "first");
    second.write(&layout, "second");
    let mut process = Process::start(&layout, &fixture.config("create"));
    process.ready();
    assert_eq!(
        process.request(Proof::command(1, "first"))["outcome"]["kind"],
        "finalized"
    );
    let first_journal = fs::read(layout.journal()).unwrap();
    let first_anchor = fs::read(layout.anchor()).unwrap();
    assert_eq!(
        process.request(Proof::command(2, "second"))["outcome"]["kind"],
        "finalized"
    );
    process.shutdown();
    let second_journal = fs::read(layout.journal()).unwrap();
    let second_anchor = fs::read(layout.anchor()).unwrap();

    let fork_layout = Layout::new();
    let sibling = fixture.proof(&[], 0, 3);
    sibling.write(&fork_layout, "sibling");
    let mut fork = Process::start(&fork_layout, &fixture.config("create"));
    fork.ready();
    assert_eq!(
        fork.request(Proof::command(1, "sibling"))["outcome"]["kind"],
        "finalized"
    );
    fork.shutdown();
    let fork_anchor = fs::read(fork_layout.anchor()).unwrap();
    assert_ne!(fork_anchor, first_anchor);
    for (journal, anchor) in [
        (&second_journal, &first_anchor),
        (&first_journal, &second_anchor),
        (&first_journal, &fork_anchor),
    ] {
        fs::write(layout.journal(), journal).unwrap();
        fs::write(layout.anchor(), anchor).unwrap();
        let images = layout.images();
        for _ in 0..2 {
            let mut rejected = Process::start(&layout, &fixture.config("open"));
            assert_eq!(rejected.event("error")["code"], "startup_open");
            assert!(!rejected.exit().success());
            assert_eq!(layout.images(), images);
        }
    }
    fs::write(layout.journal(), &second_journal).unwrap();
    fs::write(layout.anchor(), &second_anchor).unwrap();
    let images = layout.images();
    let config = fixture.config("open");
    for foreign in [
        config.replace("protocol_version = 7", "protocol_version = 8"),
        config.replace(
            &hex(fixture.context.genesis_id().as_bytes()),
            &hex(&[0x93; 32]),
        ),
        config.replace("weight = \"3\"", "weight = \"4\""),
        config.replace("finality_max_round = \"8\"", "finality_max_round = \"9\""),
    ] {
        let mut rejected = Process::start(&layout, &foreign);
        assert_eq!(rejected.event("error")["code"], "startup_open");
        assert!(!rejected.exit().success());
        assert_eq!(layout.images(), images);
    }
    let mut reopened = Process::start(&layout, &config);
    assert_eq!(reopened.ready()["head"]["height"], "2");
    reopened.shutdown();
    assert_eq!(layout.images(), images);
}

#[test]
fn real_anchor_install_failure_stops_without_a_success_report_or_implicit_gap_repair() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let proof = fixture.proof(&[], 0, 1);
    proof.write(&layout, "proof");
    let mut process = Process::start(&layout, &fixture.config("create"));
    process.ready();
    let before_journal = fs::read(layout.journal()).unwrap();
    let before_anchor = fs::read(layout.anchor()).unwrap();
    let collision = layout.write(
        "finality-anchor/fixed-validator-finality.anchor.tmp-0000000000000001",
        b"caller-owned collision",
    );
    process.write(
        format!(
            "{}\n{}\n",
            Proof::command(1, "proof"),
            json!({"command": "status", "id": 2})
        )
        .as_bytes(),
    );
    let failed = process.event("command_failed");
    assert_eq!(failed["id"], 1);
    assert_eq!(failed["code"], "finality_commit");
    assert_eq!(failed["strict_restart_required"], true);
    let stopped = process.event("stopped");
    assert_eq!(stopped["reason"], "finality_commit");
    assert_eq!(stopped["locks_released"], true);
    assert!(!process.exit().success());
    assert!(
        process
            .observed
            .iter()
            .all(|event| event["event"] != "command_result" && event["id"] != 2)
    );
    assert_eq!(fs::read(layout.anchor()).unwrap(), before_anchor);
    assert_eq!(fs::read(collision).unwrap(), b"caller-owned collision");
    let after = fs::read(layout.journal()).unwrap();
    assert!(after.len() > before_journal.len());
    assert!(after.starts_with(&before_journal));
    let images = layout.images();
    for _ in 0..2 {
        let mut reopened = Process::start(&layout, &fixture.config("open"));
        assert_eq!(reopened.event("error")["code"], "startup_open");
        assert!(!reopened.exit().success());
        assert_eq!(layout.images(), images);
    }
}

#[test]
fn partial_stdin_signal_termination_preserves_history_and_releases_owners() {
    partial_stdin_signal(StopSignal::Interrupt);
}

#[test]
fn partial_stdin_terminate_signal_preserves_history_and_releases_owners() {
    partial_stdin_signal(StopSignal::Terminate);
}

fn partial_stdin_signal(signal: StopSignal) {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 0, 2);
    first.write(&layout, "first");
    second.write(&layout, "second");
    let mut process = Process::start(&layout, &fixture.config("create"));
    process.ready();
    assert_eq!(
        process.request(Proof::command(1, "first"))["outcome"]["kind"],
        "finalized"
    );
    let state = process.status();
    let images = layout.images();
    process.write(Proof::command(2, "second").to_string().as_bytes());
    process.signal(signal);
    let stopped = process.event("stopped");
    assert_eq!(stopped["reason"], signal.reason());
    assert_eq!(stopped["locks_released"], true);
    assert!(process.exit().success());
    assert!(process.observed.iter().all(|event| event["id"] != 2));
    let mut reopened = Process::start(&layout, &fixture.config("open"));
    assert_eq!(reopened.ready(), state);
    reopened.shutdown();
    assert_eq!(layout.images(), images);
}

#[test]
fn truncated_and_oversized_input_never_execute_an_incomplete_command() {
    for oversized in [false, true] {
        let fixture = Fixture::new();
        let layout = Layout::new();
        let proof = fixture.proof(&[], 0, 1);
        proof.write(&layout, "proof");
        let mut process = Process::start(&layout, &fixture.config("create"));
        process.ready();
        let images = layout.images();
        if oversized {
            process.write(&vec![b' '; 65_537]);
        } else {
            process.write(Proof::command(1, "proof").to_string().as_bytes());
            drop(process.child.stdin.take());
        }
        let stopped = process.event("stopped");
        assert_eq!(
            stopped["reason"],
            if oversized {
                "input_too_large"
            } else {
                "input_truncated"
            }
        );
        assert!(!process.exit().success());
        assert!(
            process
                .observed
                .iter()
                .all(|event| event["event"] != "command_result")
        );
        assert_eq!(layout.images(), images);
        let mut reopened = Process::start(&layout, &fixture.config("open"));
        assert_eq!(reopened.ready()["head"]["height"], "0");
        reopened.shutdown();
    }
}

#[test]
fn closed_stdout_with_idle_open_stdin_releases_finality_ownership() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let proof = fixture.proof(&[], 0, 1);
    proof.write(&layout, "proof");
    let mut initial = Process::start(&layout, &fixture.config("create"));
    initial.ready();
    assert_eq!(
        initial.request(Proof::command(1, "proof"))["outcome"]["kind"],
        "finalized"
    );
    let state = initial.status();
    initial.shutdown();
    let images = layout.images();
    let path = layout.write("verifier.toml", fixture.config("open"));
    let (peer, stdout) = std::io::pipe().unwrap();
    // Close the peer before spawn: even if the child runs first, its initial
    // ready write must fail rather than succeeding before a parent-side close.
    drop(peer);
    let child = spawn(
        Command::new(env!("CARGO_BIN_EXE_naome-verifier"))
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::inherit()),
    );
    // Keep stdin open without sending any command: only the writer's failed
    // ready frame can wake the journal owner, not a later emit or stdin EOF.
    let mut process = Process::unobserved(child);
    assert!(!process.exit().success());
    let mut reopened = Process::start(&layout, &fixture.config("open"));
    assert_eq!(reopened.ready(), state);
    reopened.shutdown();
    assert_eq!(layout.images(), images);
}

#[test]
fn stalled_or_closed_stdout_cannot_retain_finality_ownership() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let proof = fixture.proof(&[], 0, 1);
    proof.write(&layout, "proof");
    let mut initial = Process::start(&layout, &fixture.config("create"));
    initial.ready();
    assert_eq!(
        initial.request(Proof::command(1, "proof"))["outcome"]["kind"],
        "finalized"
    );
    let state = initial.status();
    initial.shutdown();
    let images = layout.images();
    for closed in [false, true] {
        let path = layout.write("verifier.toml", fixture.config("open"));
        let mut child = spawn(
            Command::new(env!("CARGO_BIN_EXE_naome-verifier"))
                .arg(path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit()),
        );
        if closed {
            drop(child.stdout.take());
        }
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || {
            for id in 0..4096 {
                if writeln!(stdin, "{}", json!({"command": "status", "id": id})).is_err() {
                    break;
                }
            }
        });
        let mut process = Process::unobserved(child);
        assert!(!process.exit().success());
        writer.join().unwrap();
        let mut reopened = Process::start(&layout, &fixture.config("open"));
        assert_eq!(reopened.ready(), state);
        reopened.shutdown();
        assert_eq!(layout.images(), images);
    }
}
