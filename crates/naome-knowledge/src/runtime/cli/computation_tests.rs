use super::*;

#[test]
fn current_lifecycle_surface_and_automatic_pause_reason_are_explicit() {
    for command in ["start", "stop", "status"] {
        let arguments = ["--json", command].map(OsString::from);
        assert_eq!(Arguments::parse(&arguments).unwrap().command, command);
    }
    let status = Status {
        running: true,
        computation: crate::resources::ComputationState::Paused,
        computation_reason: Some("operating system power saving".into()),
        accepted_proofs: 3,
        proof_verification: super::super::ProofVerification::Checked,
        interest: String::new(),
    };
    let rendered = human("status", &status, false);
    assert!(rendered.contains("● Running"));
    assert!(rendered.contains("Paused automatically (network remains available)"));
    assert!(rendered.find("power saving").unwrap() < rendered.find("Interest").unwrap());
}
