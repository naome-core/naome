mod computation;
use super::*;

#[test]
fn information_options_are_exact_and_do_not_consume_interest_text() {
    for option in ["--version", "-V"] {
        assert_eq!(
            information(&[OsString::from(option)]),
            Some(format!("naome {}", env!("CARGO_PKG_VERSION")))
        );
    }
    for option in ["--help", "-h"] {
        assert!(
            information(&[OsString::from(option)])
                .unwrap()
                .contains("naome start")
        );
    }
    for arguments in [vec!["interest", "--version"], vec!["--help", "start"]] {
        assert!(
            information(
                &arguments
                    .into_iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>()
            )
            .is_none()
        );
    }
}

#[test]
fn output_option_does_not_consume_literal_interest() {
    for (args, json) in [
        (vec!["interest", "--json"], false),
        (vec!["--json", "interest", "--json"], true),
    ] {
        let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
        let parsed = Arguments::parse(&args).unwrap();
        assert_eq!(parsed.text, Some("--json"));
        assert_eq!(parsed.json, json);
    }
    for args in [vec!["status", "--json"], vec!["--json"], vec!["interest"]] {
        let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
        assert!(Arguments::parse(&args).is_err());
    }
}

#[test]
fn startup_handoff_is_explicit_and_cannot_change_other_operator_commands() {
    let args = ["--json", "--startup-handoff", "start"].map(OsString::from);
    let parsed = Arguments::parse(&args).unwrap();
    assert!(parsed.json && parsed.startup_handoff);
    assert_eq!(parsed.command, "start");
    for command in ["stop", "status"] {
        let args = ["--json", "--startup-handoff", command].map(OsString::from);
        assert!(Arguments::parse(&args).is_err());
    }
    let ordinary = ["--json", "start"].map(OsString::from);
    assert!(!Arguments::parse(&ordinary).unwrap().startup_handoff);
    let literal = ["interest", "--startup-handoff"].map(OsString::from);
    assert_eq!(
        Arguments::parse(&literal).unwrap().text,
        Some("--startup-handoff")
    );
}

#[test]
fn untrusted_interest_cannot_style_or_rewrite_operator_rows() {
    let status = Status {
        running: false,
        computation: crate::resources::ComputationState::Stopped,
        computation_reason: None,
        accepted_proofs: 3,
        proof_verification: super::super::ProofVerification::NotRun,
        interest: "λ 🦀\n\r\t\x1b[32m\x1b]8;;link\x07\u{009b}2J\u{202e}x\n".into(),
    };
    let rendered = human("status", &status, false);
    assert!(rendered.contains("    │ λ 🦀\n"));
    assert!(
        rendered.contains("\\r\\t\\u{1b}[32m\\u{1b}]8;;link\\u{7}\\u{9b}2J\\u{202e}x\n    │ \n")
    );
    assert!(!rendered.chars().any(|c| c.is_control() && c != '\n'));
    assert_eq!(
        serde_json::from_str::<Status>(&serde_json::to_string(&status).unwrap())
            .unwrap()
            .interest,
        status.interest
    );
}
