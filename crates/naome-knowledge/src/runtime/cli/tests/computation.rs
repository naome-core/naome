use super::*;

#[test]
fn current_lifecycle_surface_and_automatic_pause_reason_are_explicit() {
    for command in ["start", "stop", "status"] {
        let arguments = ["--json", command].map(OsString::from);
        let parsed = Arguments::parse(&arguments).unwrap();
        assert_eq!(parsed.command, command);
        assert!(parsed.json);
        assert!(Arguments::parse(&[command, "extra"].map(OsString::from)).is_err());
    }
    let status = Status {
        wallet: None,
        running: true,
        computation: crate::resources::ComputationState::Paused,
        computation_reason: Some("operating system power saving".into()),
        accepted_proofs: 3,
        proof_verification: crate::runtime::ProofVerification::Checked,
        interest: String::new(),
    };
    let rendered = human("status", &status, false);
    assert!(rendered.contains("● Running"));
    assert!(rendered.contains("Paused automatically (network remains available)"));
    assert!(rendered.find("power saving").unwrap() < rendered.find("Interest").unwrap());
}

#[test]
fn pause_guidance_uses_only_reported_conditions_and_preserves_terminal_safety() {
    let mut status = Status {
        wallet: None,
        running: true,
        computation: crate::resources::ComputationState::Paused,
        computation_reason: None,
        accepted_proofs: 0,
        proof_verification: crate::runtime::ProofVerification::Checked,
        interest: String::new(),
    };
    for (reason, guidance) in [
        ("disk pressure", "Free disk space"),
        ("memory pressure", "Reduce memory use"),
        ("node process tree memory pressure", "Reduce memory use"),
        ("operating system memory pressure", "Reduce memory use"),
        ("operating system power saving", "power-saving setting"),
        ("operating system thermal pressure", "cool down"),
        ("sustained external CPU pressure", "CPU-intensive work"),
        ("hardware observation unavailable", "retried automatically"),
    ] {
        status.computation_reason = Some(reason.into());
        let output = human("status", &status, false);
        assert!(
            output.contains(reason) && output.contains(guidance),
            "{output}"
        );
        assert!(output.contains("resumes automatically after stable recovery"));
    }
    status.computation_reason = Some("unknown\x1b[31mcondition".into());
    let output = human("status", &status, false);
    assert!(output.contains("unknown\\u{1b}[31mcondition"));
    assert!(!output.contains("Free disk space") && !output.contains("Reduce memory use"));
    status.computation = crate::resources::ComputationState::Running;
    status.computation_reason = None;
    assert!(!human("status", &status, false).contains("resumes automatically"));
}
