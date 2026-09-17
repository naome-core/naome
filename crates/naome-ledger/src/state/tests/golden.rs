use super::*;

// Fixed public test seeds and secrets only. These bytes are regression vectors,
// never credentials for an operational genesis.
#[test]
fn complete_v1_wire_and_identifier_vectors() {
    let mut output = String::new();
    fn vector(out: &mut String, name: &str, bytes: &[u8]) {
        use std::fmt::Write;
        write!(out, "{name} {} ", bytes.len()).unwrap();
        for byte in bytes {
            write!(out, "{byte:02x}").unwrap();
        }
        out.push('\n');
    }
    let mut state = ResearchState::new(genesis());
    vector(&mut output, "genesis", &state.genesis().encode());
    vector(&mut output, "genesis-id", state.genesis().id().as_bytes());
    vector(&mut output, "initial-state", state.commitment().as_bytes());
    let report =
        SignedTimeReport::sign(state.genesis(), state.head(), 1, 100, &validator(0)).unwrap();
    vector(&mut output, "signed-time", &report.encode());
    vector(&mut output, "time-certificate", &time(&state, 100).encode());
    let body = OperationBody::Submit {
        purpose: "test a formal target".into(),
        question: question(&state, "forall(x,equal(x,x))"),
    };
    vector(&mut output, "submit-body", &body.encode().unwrap());
    let action = signed(&state, 4, body);
    vector(&mut output, "signed-submit", &action.encode());
    vector(&mut output, "submit-id", action.id().as_bytes());
    let record = apply(&mut state, 100, vec![action]);
    vector(&mut output, "submit-record", &record.encode().unwrap());
    vector(&mut output, "submit-record-id", record.id().as_bytes());
    let round = open_and_approve(&mut state);
    vector(&mut output, "solution-round", round.as_bytes());
    let package = root_package(&state, 4);
    vector(&mut output, "original-package", &package.encode().unwrap());
    vector(
        &mut output,
        "original-hash",
        package.original_hash().as_bytes(),
    );
    let original = SignedOriginal::sign(state.genesis(), round, package, &account(4)).unwrap();
    vector(&mut output, "signed-original", &original.encode().unwrap());
    let secret = [7; 32];
    let commitment = CommitmentId::for_original(
        state.genesis(),
        round,
        author(4),
        original.original_hash(),
        &secret,
    );
    vector(&mut output, "commitment-id", commitment.as_bytes());
    let commit = signed(&state, 4, OperationBody::Commit { round, commitment });
    vector(&mut output, "signed-commit", &commit.encode());
    let utc = state.time();
    apply(&mut state, utc, vec![commit]);
    start_reveal(&mut state);
    let reveal = signed(
        &state,
        4,
        OperationBody::Reveal {
            round,
            secret,
            original,
        },
    );
    vector(&mut output, "signed-reveal", &reveal.encode());
    let utc = state.time();
    apply(&mut state, utc, vec![reveal]);
    let deadline = state.active().unwrap().deadline.unwrap();
    apply(&mut state, deadline, vec![]);
    let settlement = apply(&mut state, deadline, vec![]);
    vector(
        &mut output,
        "settlement-record",
        &settlement.encode().unwrap(),
    );
    let FamilyResult::Completed {
        normalization_receipt,
        ..
    } = state.families().values().next().unwrap()
    else {
        panic!("completed vector")
    };
    vector(&mut output, "normalization-receipt", normalization_receipt);
    vector(&mut output, "final-state", state.commitment().as_bytes());
    if let Some(path) = std::env::var_os("NAOME_REGENERATE_RESEARCH_VECTORS") {
        std::fs::write(path, &output).unwrap();
        return;
    }
    assert_eq!(output, include_str!("golden-v1.txt"));
}

#[test]
fn signed_old_attempt_reveal_never_resolves_new_attempt() {
    let mut state = ResearchState::new(genesis());
    submit(&mut state, "forall(x,equal(x,x))");
    let old_round = open_and_approve(&mut state);
    let original = commit_original(&mut state, 4, old_round, [7; 32]);
    start_reveal(&mut state);
    finish(&mut state);
    assert_eq!(state.balances().paid_completions(), 0);
    submit(&mut state, "forall(x,equal(x,x))");
    let new_round = open_and_approve(&mut state);
    assert_ne!(old_round, new_round);
    start_reveal(&mut state);
    let old = signed(
        &state,
        4,
        OperationBody::Reveal {
            round: old_round,
            secret: [7; 32],
            original,
        },
    );
    let before = state.commitment();
    assert!(
        state
            .prepare_record(time(&state, state.time()), vec![old])
            .is_err()
    );
    assert_eq!(state.commitment(), before);
    assert!(state.library().is_empty());
}
