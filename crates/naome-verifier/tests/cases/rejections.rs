#[cfg(unix)]
use std::{fs, fs::File, os::unix::fs::symlink, process::Command};

use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactBlockApplyError, ArtifactChainState, ArtifactDag};
#[cfg(unix)]
use naome_consensus::VerifiedFixedConsensusTransitionV0;
use naome_consensus::{
    ConsensusAncestryId, ConsensusEnvelopeVerifyError, ConsensusStateCommitment, ConsensusValueV0,
};
use naome_ledger::LedgerError;
use naome_proof::{ArtifactId, ArtifactPayload, ProofCertificate, ProofStep};
use serde_json::json;

use crate::support::*;

#[test]
fn valid_consensus_signatures_do_not_authorize_a_mathematically_invalid_artifact() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let valid = fixture.proof(&[], 0, 1);
    let ArtifactPayload::Proof(axiom) =
        ArtifactPayload::from_canonical_bytes(&valid.payload).unwrap()
    else {
        panic!("proof fixture");
    };
    let invalid = ProofCertificate::new(vec![
        axiom.steps()[0].clone(),
        ProofStep::ModusPonens {
            premise: 0,
            implication: 0,
        },
    ])
    .unwrap()
    .into_unchecked_normal_form();
    let payload = ArtifactPayload::Proof(invalid.certificate().clone()).to_canonical_bytes();
    // This is canonically encoded but fails mathematical inference checking,
    // independently of any claimed artifact address or consensus proof.
    assert!(matches!(
        ArtifactDag::new().apply_canonical_artifact_bytes(payload.clone()),
        Err(LedgerError::ProofCheck { .. })
    ));
    let branch = fixture.genesis();
    let round = branch.begin_round_zero().unwrap();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(ArtifactId::from_bytes([0xab; 32]))
        .unwrap();
    let mut malicious = valid.clone();
    malicious.value = round.value_for_artifact_block(block);
    malicious.payload = payload;
    malicious.envelope = envelope(
        &malicious,
        &fixture.keys[malicious.proposer],
        &[&fixture.keys[0], &fixture.keys[1], &fixture.keys[2]],
        2,
    );
    assert!(matches!(
        round.decode_and_verify(&malicious.envelope, malicious.payload.clone()),
        Err(ConsensusEnvelopeVerifyError::ArtifactValidation(
            ArtifactBlockApplyError::Admission {
                source: LedgerError::ProofCheck { .. }
            }
        ))
    ));
    malicious.write(&layout, "invalid");
    valid.write(&layout, "valid");
    let mut process = Process::start(&layout, &fixture.config("create"));
    let state = process.ready();
    let images = layout.images();
    assert_eq!(
        process.request(Proof::command(1, "invalid"))["code"],
        "proof_verification"
    );
    assert_eq!(process.status(), state);
    assert_eq!(layout.images(), images);
    assert_eq!(
        process.request(Proof::command(2, "valid"))["outcome"]["kind"],
        "finalized"
    );
    process.shutdown();
}

#[test]
fn complete_proof_rejections_preserve_authority_before_valid_retry_and_on_historical_duplicates() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let first = fixture.proof(&[], 0, 1);
    let second = fixture.proof(&[&first], 0, 2);
    let above_limit = fixture.proof(&[], 9, 1);
    first.write(&layout, "first");
    second.write(&layout, "gap");
    above_limit.write(&layout, "above");
    let proposer = &fixture.keys[first.proposer];
    let enough = [&fixture.keys[0], &fixture.keys[1], &fixture.keys[2]];
    let foreign = SigningKey::from_bytes(&[0xf3; 32]);
    let mut cases = vec![
        (
            "insufficient",
            envelope(&first, proposer, &[&fixture.keys[0], &fixture.keys[1]], 2),
            "proof_verification",
        ),
        (
            "wrong_role",
            envelope(&first, proposer, &enough, 1),
            "proof_verification",
        ),
        (
            "wrong_proposer",
            envelope(&first, &fixture.keys[(first.proposer + 1) % 4], &enough, 2),
            "proof_verification",
        ),
        (
            "unknown_signer",
            envelope(
                &first,
                proposer,
                &[&fixture.keys[0], &fixture.keys[1], &foreign],
                2,
            ),
            "proof_verification",
        ),
    ];
    assert_eq!(
        fixture.entries[0].agreement_weight().units()
            + fixture.entries[1].agreement_weight().units(),
        4
    );
    assert_eq!(
        fixture
            .entries
            .iter()
            .map(|entry| entry.agreement_weight().units())
            .sum::<u128>(),
        6
    );
    let mut bad_signature = first.envelope.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    cases.push(("bad_signature", bad_signature, "proof_verification"));
    let mut bad_authorization = first.envelope.clone();
    bad_authorization[ConsensusValueV0::BYTE_LENGTH + 116 + 32] ^= 1;
    cases.push(("bad_authorization", bad_authorization, "proof_verification"));
    let mut trailing = first.envelope.clone();
    trailing.push(0);
    cases.push(("trailing", trailing, "proof_verification"));
    let mut context = first.envelope.clone();
    context[32] ^= 1;
    cases.push(("foreign_context", context, "envelope_context"));
    let mut zero_height = first.envelope.clone();
    zero_height[68..76].fill(0);
    cases.push(("zero_height", zero_height, "envelope_value"));
    let mut false_state = first.clone();
    false_state.value = ConsensusValueV0::try_new(
        first.value.context(),
        first.value.height(),
        first.value.parent_ancestry_id(),
        first.value.artifact_block(),
        ConsensusStateCommitment::from_bytes([0x55; 32]),
    )
    .unwrap();
    cases.push((
        "false_state",
        envelope(&false_state, proposer, &enough, 2),
        "proof_verification",
    ));
    let mut false_parent = first.clone();
    false_parent.value = ConsensusValueV0::try_new(
        first.value.context(),
        first.value.height(),
        ConsensusAncestryId::from_bytes([0x56; 32]),
        first.value.artifact_block(),
        first.value.post_consensus_state_commitment(),
    )
    .unwrap();
    cases.push((
        "false_parent",
        envelope(&false_parent, proposer, &enough, 2),
        "proof_verification",
    ));
    for (name, bytes, _) in &cases {
        layout.write(&format!("{name}.envelope"), bytes);
        layout.write(&format!("{name}.payload"), &first.payload);
    }
    layout.write("wrong_payload.envelope", &first.envelope);
    layout.write("wrong_payload.payload", &second.payload);
    let mut process = Process::start(&layout, &fixture.config("create"));
    let original = process.ready();
    let images = layout.images();
    for (name, _, code) in &cases {
        let response = process.request(Proof::command(10, name));
        assert_eq!(response["event"], "command_rejected", "{name}: {response}");
        assert_eq!(response["code"], *code, "{name}");
        assert_eq!(layout.images(), images, "{name}");
    }
    for (name, code) in [
        ("gap", "parent_unavailable"),
        ("above", "proof_verification"),
        ("wrong_payload", "proof_verification"),
    ] {
        let response = process.request(Proof::command(11, name));
        assert_eq!(response["code"], code, "{name}: {response}");
        assert_eq!(response["event"], "command_rejected");
        assert_eq!(layout.images(), images);
    }
    assert_eq!(process.status(), original);
    assert_eq!(
        process.request(Proof::command(12, "first"))["outcome"]["kind"],
        "finalized"
    );
    assert_eq!(
        process.request(Proof::command(13, "gap"))["outcome"]["kind"],
        "finalized"
    );
    let selected = process.status();
    let selected_images = layout.images();
    for name in [
        "bad_signature",
        "bad_authorization",
        "insufficient",
        "wrong_payload",
        "above",
    ] {
        assert_eq!(
            process.request(Proof::command(14, name))["event"],
            "command_rejected",
            "{name}"
        );
        assert_eq!(layout.images(), selected_images);
    }
    assert_eq!(process.status(), selected);
    process.shutdown();
}

#[test]
fn strict_public_configuration_rejects_invalid_sets_and_signer_fields_before_file_creation() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let valid = fixture.config("create");
    let empty = format!(
        "{}validators = []\n[directories]{}",
        valid.split("[[validators]]").next().unwrap(),
        valid.split("[directories]").nth(1).unwrap()
    );
    let first_key = hex(fixture.entries[0].consensus_key().as_bytes());
    let second_key = hex(fixture.entries[1].consensus_key().as_bytes());
    let invalid = [
        (
            valid.replacen("version = 0", "version = 1", 1),
            "config_version",
        ),
        (
            format!("signing_seed_file = \"forbidden.seed\"\n{valid}"),
            "config_schema",
        ),
        (format!("unknown = 0\n{valid}"), "config_schema"),
        (empty, "fixed_set"),
        (valid.replace(&second_key, &first_key), "fixed_set"),
        (
            valid.replace("weight = \"3\"", "weight = \"0\""),
            "fixed_set",
        ),
        (
            valid.replace("weight = \"3\"", "weight = \"03\""),
            "config_decimal",
        ),
        (
            valid.replace(
                "weight = \"3\"",
                "weight = \"340282366920938463463374607431768211456\"",
            ),
            "config_decimal_range",
        ),
        (
            valid.replace("finality_max_round = \"8\"", "finality_max_round = \"0\""),
            "finality_replay_limit",
        ),
        (
            valid.replace(&first_key, &first_key.to_uppercase()),
            "config_hex32",
        ),
        (
            valid.replace("mode = \"create\"", "mode = \"CREATE\""),
            "config_schema",
        ),
        (
            valid.replace(
                "finality_anchor = \"finality-anchor\"",
                "finality_anchor = \"missing\"",
            ),
            "authority_directory",
        ),
    ];
    for (config, code) in invalid {
        let mut process = Process::start(&layout, &config);
        assert_eq!(process.event("error")["code"], code);
        assert!(!process.exit().success());
        assert!(layout.images().is_empty(), "preflight {code}");
        assert!(
            process
                .observed
                .iter()
                .all(|value| value["event"] != "ready")
        );
    }
    let mut process = Process::start(&layout, &valid);
    process.ready();
    process.shutdown();
}

#[test]
fn strict_command_objects_and_record_bounds_do_not_mutate_history() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let mut process = Process::start(&layout, &fixture.config("create"));
    let state = process.ready();
    let images = layout.images();
    for invalid in [
        r#"["status",1]"#,
        r#"null"#,
        r#"{}"#,
        r#"{"command":0,"id":1}"#,
        r#"{"command":"status","id":1,"id":2}"#,
        r#"{"command":"status","command":"shutdown","id":1}"#,
        r#"{"command":"status","id":1,"unknown":true}"#,
        r#"{"command":"status","id":-1}"#,
        r#"{"command":"status","id":1.0}"#,
        r#"{"command":"status","id":1} {}"#,
        r#"{"command":"record","id":1,"height":"1"}"#,
        r#"{"command":"import","id":1,"envelope_file":"missing"}"#,
    ] {
        process.write(format!("{invalid}\n").as_bytes());
        let rejected = process.event("command_rejected");
        assert!(rejected["id"].is_null());
        assert_eq!(rejected["code"], "command_schema");
        assert_eq!(layout.images(), images);
    }
    for (height, code) in [
        (0, "record_height"),
        (1, "record_unavailable"),
        (u64::MAX, "record_unavailable"),
    ] {
        assert_eq!(
            process.request(json!({"command": "record", "id": 20, "height": height}))["code"],
            code
        );
    }
    assert_eq!(process.status(), state);
    process.shutdown();
    assert_eq!(layout.images(), images);
}

#[test]
#[cfg(unix)]
fn bounded_regular_sources_reject_symlinks_fifos_directories_and_oversized_envelopes() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let proof = fixture.proof(&[], 0, 1);
    proof.write(&layout, "proof");
    symlink(
        layout.root.join("proof.envelope"),
        layout.root.join("link.envelope"),
    )
    .unwrap();
    File::create(layout.root.join("oversized.envelope"))
        .unwrap()
        .set_len(VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH as u64 + 1)
        .unwrap();
    layout.write(
        "short.envelope",
        &proof.envelope[..ConsensusValueV0::BYTE_LENGTH],
    );
    assert!(
        spawn(Command::new("mkfifo").arg(layout.root.join("fifo")))
            .wait()
            .unwrap()
            .success()
    );
    let mut process = Process::start(&layout, &fixture.config("create"));
    process.ready();
    let images = layout.images();
    for (source, code) in [
        ("link.envelope", "file_open"),
        ("fifo", "file_not_regular"),
        ("finality-journal", "file_not_regular"),
        ("oversized.envelope", "file_too_large"),
        ("short.envelope", "envelope_length"),
        ("missing.envelope", "file_open"),
    ] {
        let response = process.request(json!({"command": "import", "id": 1, "envelope_file": source, "payload_file": "proof.payload"}));
        assert_eq!(response["event"], "command_rejected");
        assert_eq!(response["code"], code);
        assert_eq!(layout.images(), images);
    }
    assert_eq!(
        process.request(Proof::command(2, "proof"))["outcome"]["kind"],
        "finalized"
    );
    process.shutdown();
    assert!(!fs::read(layout.journal()).unwrap().is_empty());
}
