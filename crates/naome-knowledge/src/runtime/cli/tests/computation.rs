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
        running: true,
        computation: crate::resources::ComputationState::Paused,
        computation_reason: Some(crate::PauseReason::PowerSaving),
        accepted_artifacts: 3,
        artifact_verification: crate::runtime::ArtifactVerification::Checked,
    };
    let rendered = human("status", &status, false);
    assert!(rendered.contains("● Running"));
    assert!(rendered.contains("Paused automatically (network remains available)"));
    assert!(rendered.contains("power saving"));
}

#[test]
fn pause_guidance_uses_only_reported_conditions() {
    let mut status = Status {
        running: true,
        computation: crate::resources::ComputationState::Paused,
        computation_reason: None,
        accepted_artifacts: 0,
        artifact_verification: crate::runtime::ArtifactVerification::Checked,
    };
    for (reason, guidance) in [
        (crate::PauseReason::DiskPressure, "Free disk space"),
        (crate::PauseReason::MemoryPressure, "Reduce memory use"),
        (
            crate::PauseReason::ProcessTreeMemoryPressure,
            "Reduce memory use",
        ),
        (
            crate::PauseReason::SystemMemoryPressure,
            "Reduce memory use",
        ),
        (crate::PauseReason::PowerSaving, "power-saving setting"),
        (crate::PauseReason::ThermalPressure, "cool down"),
        (
            crate::PauseReason::ExternalCpuPressure,
            "CPU-intensive work",
        ),
        (
            crate::PauseReason::HardwareObservationUnavailable,
            "retried automatically",
        ),
    ] {
        status.computation_reason = Some(reason);
        let output = human("status", &status, false);
        assert!(output.contains(guidance), "{output}");
        assert!(output.contains("resumes automatically after stable recovery"));
    }
    assert!(
        serde_json::from_value::<crate::PauseReason>(serde_json::json!(0x0004_ffffu32)).is_err()
    );
    status.computation = crate::resources::ComputationState::Running;
    status.computation_reason = None;
    assert!(!human("status", &status, false).contains("resumes automatically"));
}
