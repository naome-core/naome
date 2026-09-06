use std::fs;

use naome_chain::ArtifactDag;
use naome_consensus::ConsensusHeight;
use naome_foundation::FreeVariable;
use naome_ledger::LedgerError;
use naome_proof::{ArtifactPayload, ProofCertificate, ProofStep};
use serde_json::json;

use crate::support::*;

#[test]
fn reopened_history_supplies_the_exact_selected_dependency_for_a_later_artifact() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let first = fixture.proof(&[], 0, 1);
    let first_id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(first.payload.clone())
        .unwrap()
        .as_proof()
        .unwrap()
        .proof_id();
    let certificate = ProofCertificate::new(vec![
        ProofStep::ProofReference { proof_id: first_id },
        ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(7),
        },
    ])
    .unwrap()
    .into_unchecked_normal_form();
    let payload = ArtifactPayload::Proof(certificate.certificate().clone()).to_canonical_bytes();
    assert!(matches!(
        ArtifactDag::new().apply_canonical_artifact_bytes(payload.clone()),
        Err(LedgerError::ProofCheck { .. })
    ));
    let second = fixture.proof_with_payload(&[&first], 1, payload);
    assert_ne!(
        second.value.artifact_block().artifact_id(),
        first.value.artifact_block().artifact_id()
    );
    first.write(&layout, "first");
    second.write(&layout, "second");
    let mut process = Process::start(&layout, &fixture.config("create"));
    process.ready();
    assert_eq!(
        process.request(Proof::command(1, "first"))["outcome"]["kind"],
        "finalized"
    );
    process.shutdown();
    fs::remove_file(layout.root.join("first.envelope")).unwrap();
    fs::remove_file(layout.root.join("first.payload")).unwrap();
    let mut reopened = Process::start(&layout, &fixture.config("open"));
    assert_eq!(reopened.ready()["head"]["height"], "1");
    assert_eq!(
        reopened.request(Proof::command(2, "second"))["outcome"]["kind"],
        "finalized"
    );
    reopened.shutdown();
    fixture.inspect(&layout, |journal| {
        assert_eq!(journal.finalized_len().unwrap(), 2);
        assert_eq!(
            journal
                .finality_record(ConsensusHeight::new(2))
                .unwrap()
                .unwrap()
                .canonical_artifact_bytes(),
            second.payload
        );
    });
}

#[test]
fn keyless_process_retains_two_heights_and_first_evidence_across_strict_restart() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 2, 2);
    let later_round = fixture.proof(&[], 3, 1);
    assert_eq!(later_round.value, first.value);
    first.write(&layout, "first");
    second.write(&layout, "second");
    later_round.write(&layout, "later");
    let variant = envelope(
        &first,
        &fixture.keys[first.proposer],
        &[&fixture.keys[0], &fixture.keys[1], &fixture.keys[3]],
        2,
    );
    assert_ne!(variant, first.envelope);
    layout.write("variant.envelope", variant);
    layout.write("variant.payload", &first.payload);

    let mut process = Process::start(&layout, &fixture.config("create"));
    let genesis = process.ready();
    assert_eq!(genesis["head"]["height"], "0");
    assert!(genesis["halt"].is_null());
    for (id, name, height) in [(1, "first", "1"), (2, "second", "2")] {
        let result = process.request(Proof::command(id, name));
        assert_eq!(result["event"], "command_result");
        assert_eq!(result["outcome"]["kind"], "finalized");
        assert_eq!(result["outcome"]["height"], height);
    }
    let selected = process.status();
    assert_eq!(selected["head"]["height"], "2");
    assert_eq!(
        selected["head"]["ancestry_id"],
        hex(second.value.ancestry_id().as_bytes())
    );
    assert_eq!(
        selected["head"]["artifact_block_id"],
        hex(second.value.artifact_block().id().as_bytes())
    );
    assert_ne!(selected["state_id"], genesis["state_id"]);
    let images = layout.images();
    let record =
        process.request(json!({"command": "record", "id": 3, "height": 1}))["outcome"]["record"]
            .clone();
    assert_eq!(record["height"], "1");
    assert_eq!(record["round"], "0");
    assert_eq!(record["envelope_bytes"], first.envelope.len());
    assert_eq!(record["payload_bytes"], first.payload.len());
    for name in ["first", "variant", "later"] {
        // IDs are correlation labels and do not suppress a later command.
        let result = process.request(Proof::command(1, name));
        assert_eq!(result["outcome"]["kind"], "already_finalized");
        assert_eq!(
            result["outcome"]["retained_envelope_id"],
            record["envelope_id"]
        );
        assert_eq!(result["outcome"]["state_id"], selected["state_id"]);
        assert_eq!(layout.images(), images);
    }
    process.shutdown();
    fixture.inspect(&layout, |journal| {
        assert_eq!(journal.finalized_len().unwrap(), 2);
        for (height, proof) in [(1, &first), (2, &second)] {
            let retained = journal
                .finality_record(ConsensusHeight::new(height))
                .unwrap()
                .unwrap();
            assert_eq!(retained.canonical_envelope_bytes(), proof.envelope);
            assert_eq!(retained.canonical_artifact_bytes(), proof.payload);
            assert_eq!(retained.value(), proof.value);
        }
    });
    assert_eq!(layout.images(), images);
    let mut reopened = Process::start(&layout, &fixture.config("open"));
    assert_eq!(reopened.ready(), selected);
    assert_eq!(
        reopened.request(Proof::command(1, "second"))["outcome"]["kind"],
        "already_finalized"
    );
    reopened.shutdown();
    assert_eq!(layout.images(), images);

    let mut names = fs::read_dir(&layout.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        [
            "finality-anchor",
            "finality-journal",
            "first.envelope",
            "first.payload",
            "later.envelope",
            "later.payload",
            "second.envelope",
            "second.payload",
            "variant.envelope",
            "variant.payload",
            "verifier.toml"
        ]
    );
}

#[test]
fn historical_sibling_after_two_heights_anchors_terminal_halt_and_reopens_without_a_head() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 0, 2);
    let sibling = fixture.proof(&[], 1, 3);
    for (name, proof) in [
        ("first", &first),
        ("second", &second),
        ("sibling", &sibling),
    ] {
        proof.write(&layout, name);
    }
    let mut process = Process::start(&layout, &fixture.config("create"));
    process.ready();
    for (id, name) in [(1, "first"), (2, "second")] {
        assert_eq!(
            process.request(Proof::command(id, name))["outcome"]["kind"],
            "finalized"
        );
    }
    let before = fs::read(layout.journal()).unwrap();
    process.write(
        format!(
            "{}\n{}\n",
            Proof::command(3, "sibling"),
            json!({"command": "status", "id": 4})
        )
        .as_bytes(),
    );
    let result = process.until(|value| value["id"] == 3);
    assert_eq!(result["outcome"]["kind"], "halted");
    let halt = result["outcome"]["halt"].clone();
    assert_eq!(halt["kind"], "SelectedSibling");
    assert_eq!(halt["height"], "1");
    assert_eq!(
        halt["first_ancestry"],
        hex(first.value.ancestry_id().as_bytes())
    );
    assert_eq!(
        halt["second_ancestry"],
        hex(sibling.value.ancestry_id().as_bytes())
    );
    let stopped = process.event("stopped");
    assert_eq!(stopped["reason"], "finality_halted");
    assert_eq!(stopped["locks_released"], true);
    assert!(!process.exit().success());
    assert!(process.observed.iter().all(|value| value["id"] != 4));
    let after = fs::read(layout.journal()).unwrap();
    assert!(after.len() > before.len());
    assert!(after.starts_with(&before));
    let images = layout.images();
    fixture.inspect(&layout, |journal| {
        assert!(journal.head().is_err());
        assert!(journal.finalized_len().is_err());
        assert!(journal.finality_record(ConsensusHeight::new(1)).is_err());
        assert_eq!(
            hex(journal.halt().unwrap().unwrap().state_id().as_bytes()),
            halt["state_id"]
        );
    });
    let mut reopened = Process::start(&layout, &fixture.config("open"));
    let state = reopened.event("halted")["state"].clone();
    assert!(state["head"].is_null());
    assert_eq!(state["halt"], halt);
    assert_eq!(reopened.event("stopped")["reason"], "finality_halted");
    assert!(!reopened.exit().success());
    assert!(
        reopened
            .observed
            .iter()
            .all(|value| value["event"] != "ready")
    );
    assert_eq!(layout.images(), images);
}
