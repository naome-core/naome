use super::*;

#[test]
fn pause_and_resume_are_lifecycle_commands_with_explicit_json_output() {
    for command in ["pause", "resume"] {
        let arguments = ["--json", command].map(OsString::from);
        let parsed = Arguments::parse(&arguments).unwrap();
        assert_eq!(parsed.command, command);
        assert!(parsed.json);
        assert!(Arguments::parse(&[command, "extra"].map(OsString::from)).is_err());
        let status = Status {
            running: true,
            computation: crate::resources::ComputationState::Paused,
            accepted_proofs: 3,
            proof_verification: super::super::ProofVerification::Checked,
            interest: String::new(),
        };
        let rendered = human(command, &status, false);
        assert!(rendered.contains("● Running"));
        assert!(rendered.contains("Paused (network remains available)"));
    }
}
