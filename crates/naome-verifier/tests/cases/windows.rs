use std::{
    fs::{self, File},
    os::windows::fs::symlink_file,
};

use naome_consensus::{ConsensusValueV0, VerifiedFixedConsensusTransitionV0};
use serde_json::json;

use crate::{
    archive::{config, identities},
    support::*,
};

#[test]
fn windows_sources_reject_reparse_devices_directories_and_oversize_without_state_change() {
    let fixture = Fixture::new();
    let layout = Layout::new();
    let proof = fixture.proof(&[], 0, 1);
    proof.write(&layout, "proof");
    symlink_file(
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
    let mut process = Process::start(&layout, &fixture.config("create"));
    process.ready();
    let images = layout.images();
    for (source, code) in [
        ("link.envelope", "file_not_regular"),
        ("NUL", "file_not_regular"),
        ("CON", "file_not_regular"),
        ("COM1", "file_not_regular"),
        (r"\\.\pipe\naome-verifier-never-open", "file_not_regular"),
        (
            r"\\localhost\pipe\naome-verifier-never-open",
            "file_not_regular",
        ),
        ("finality-journal", "file_not_regular"),
        ("oversized.envelope", "file_too_large"),
        ("short.envelope", "envelope_length"),
        ("missing.envelope", "file_open"),
    ] {
        let rejected = process.request(json!({"command":"import","id":1,"envelope_file":source,"payload_file":"proof.payload"}));
        assert_eq!(rejected["event"], "command_rejected", "{source}");
        assert_eq!(rejected["code"], code, "{source}");
        assert_eq!(layout.images(), images);
    }
    assert_eq!(
        process.request(Proof::command(2, "proof"))["outcome"]["kind"],
        "finalized"
    );
    process.shutdown();
}

#[test]
fn windows_seed_acl_rejections_precede_authority_creation_and_expose_no_seed() {
    let fixture = Fixture::new();
    let [(_, seed), _, _] = identities();
    for mode in ["broad", "inherited-broad", "wrong-owner", "null", "deny"] {
        let layout = Layout::new();
        let configuration = config(&fixture, &layout, "create", seed, &[]);
        let path = layout.root.join("noise.seed");
        seed_acl(&path, mode);
        let mut rejected = Process::start(&layout, &configuration);
        assert_eq!(
            rejected.event("error")["code"],
            "seed_permissions",
            "{mode}"
        );
        assert!(!rejected.exit().success());
        assert!(!layout.journal().exists());
        assert!(!layout.anchor().exists());
        assert_eq!(fs::read(&path).unwrap(), seed);
        assert!(
            !serde_json::to_string(&rejected.observed)
                .unwrap()
                .contains(&hex(&seed))
        );
    }
    // The same native adapter must accept owner-only access and release both
    // owners so strict reopen can validate the complete unchanged pair.
    let layout = Layout::new();
    let mut accepted = Process::start(&layout, &config(&fixture, &layout, "create", seed, &[]));
    let state = accepted.ready();
    accepted.shutdown();
    let images = layout.images();
    let mut reopened = Process::start(&layout, &config(&fixture, &layout, "open", seed, &[]));
    assert_eq!(reopened.ready(), state);
    reopened.shutdown();
    assert_eq!(layout.images(), images);
}
