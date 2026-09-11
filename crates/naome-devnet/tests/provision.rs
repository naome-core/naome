#![cfg(unix)]
use naome_storage::{CandidateBranchRecoveryBundleLimits, CandidateBranchRecoveryBundleV0};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().join(format!(
            "naome-devnet-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn plan(&self, height: usize) -> PathBuf {
        let path = self.0.join("plan.json");
        fs::write(&path, serde_json::to_vec(&json!({"version":0,"heights":height,
            "validator_addresses":(4100..4104).map(|p|format!("/ip4/127.0.0.1/tcp/{p}")).collect::<Vec<_>>(),
            "publisher_addresses":(4104..4106).map(|p|format!("/ip4/127.0.0.1/tcp/{p}")).collect::<Vec<_>>() })).unwrap()).unwrap();
        path
    }
    fn init(&self, height: usize) -> Output {
        Command::new(env!("CARGO_BIN_EXE_naome-devnet"))
            .arg("init")
            .arg(self.plan(height))
            .arg(self.0.join("deployment"))
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn provisioning_refuses_invalid_bounds_and_existing_output_and_keeps_keys_private() {
    let f = Fixture::new();
    assert!(!f.init(129).status.success());
    assert!(!f.0.join("deployment").exists());
    let result = f.init(4);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let root = f.0.join("deployment");
    let before = fs::read(root.join("validator-0/signing.seed")).unwrap();
    assert!(!f.init(4).status.success());
    assert_eq!(
        before,
        fs::read(root.join("validator-0/signing.seed")).unwrap()
    );
    assert_eq!(
        fs::metadata(root.join("validator-0/signing.seed"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let public = fs::read_to_string(root.join("deployment.json")).unwrap();
    assert!(
        !public.contains(
            &before
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    );
    for role in ["publisher-0", "publisher-1"] {
        assert!(!root.join(role).join("signing.seed").exists());
    }
    for i in 0..4 {
        assert_eq!(
            fs::read_dir(root.join(format!("validator-{i}/candidates")))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fs::read_dir(root.join(format!("validator-{i}/payloads")))
                .unwrap()
                .count(),
            0
        );
    }
}

#[test]
fn publisher_generates_canonical_full_capacity_bundle_without_validator_source_access() {
    let f = Fixture::new();
    assert!(f.init(128).status.success());
    let root = f.0.join("deployment");
    let publisher = root.join("publisher-0");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_naome-devnet"))
            .arg("publish")
            .arg(&publisher)
            .arg("128")
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let summary: Value = serde_json::from_slice(&first.stdout).unwrap();
    let bytes = fs::read(publisher.join("producer/source-128.bundle")).unwrap();
    let bundle = CandidateBranchRecoveryBundleV0::from_canonical_bytes(
        &bytes,
        CandidateBranchRecoveryBundleLimits::new(128, 8_388_608, 8_454_144).unwrap(),
    )
    .unwrap();
    assert_eq!(bundle.block_count(), 128);
    assert_eq!(
        summary["head"],
        bundle
            .target_block_id()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let repeat = run();
    assert!(
        repeat.status.success(),
        "{}",
        String::from_utf8_lossy(&repeat.stderr)
    );
    assert_eq!(
        summary,
        serde_json::from_slice::<Value>(&repeat.stdout).unwrap()
    );
    assert!(!publisher.join("producer/staging").exists());
    for i in 0..4 {
        assert_eq!(
            fs::read_dir(root.join(format!("validator-{i}/candidates")))
                .unwrap()
                .count(),
            0
        );
        assert!(!root.join(format!("validator-{i}/offer.json")).exists());
    }
}

#[test]
fn duplicate_endpoints_and_symlinked_plan_are_rejected_before_provisioning() {
    let f = Fixture::new();
    let plan = f.plan(4);
    let mut value: Value = serde_json::from_slice(&fs::read(&plan).unwrap()).unwrap();
    value["publisher_addresses"][0] = value["validator_addresses"][0].clone();
    fs::write(&plan, serde_json::to_vec(&value).unwrap()).unwrap();
    let invoke = |p: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_naome-devnet"))
            .arg("init")
            .arg(p)
            .arg(f.0.join("deployment"))
            .status()
            .unwrap()
    };
    assert!(!invoke(&plan).success());
    let link = f.0.join("link.json");
    std::os::unix::fs::symlink(&plan, &link).unwrap();
    assert!(!invoke(&link).success());
    assert!(!f.0.join("deployment").exists());
}
