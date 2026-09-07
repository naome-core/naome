use super::*;
use sha2::{Digest, Sha256};

fn redigest(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let mut hasher = Sha256::new();
    hasher.update(b"naome:candidate-branch-recovery-bundle-digest:v0\0");
    hasher.update(&bytes[..end]);
    bytes[end..].copy_from_slice(&hasher.finalize());
}

#[test]
fn bundle_staging_rejects_framing_context_selectors_and_fully_framed_invalid_payload_before_writes()
{
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 2, 0);
    let anchored = Transfer::new(&fixture, 2, 1);
    let layout = Layout::new();
    let config = source_config(&layout, fixture.config(&layout, 1, "create", None, false));
    let mut node = Process::start(&layout, &config);
    node.ready();
    initial_arm(&mut node);
    let authority = layout.images();
    let sources = source_images(&layout);
    let state = result(&mut node, json!({"command":"status","id":1}));
    for (mode, code) in [
        ("digest", "bundle_decode"),
        ("truncated", "bundle_decode"),
        ("chain", "chain_id"),
        ("anchor_root", "anchor_root"),
        ("payload", "branch_validation"),
        ("anchor", "unexpected_anchor"),
        ("target", "unexpected_target"),
        ("unselected_anchor", "anchor_not_selected"),
    ] {
        let mut input = transfer.command(true);
        let mut bytes = transfer.bytes.clone();
        let header = b"naome:candidate-branch-recovery-bundle:v0\0".len();
        match mode {
            "digest" => *bytes.last_mut().unwrap() ^= 1,
            "truncated" => bytes.truncate(10),
            "chain" => {
                bytes[header] ^= 1;
                redigest(&mut bytes);
            }
            "anchor_root" => {
                bytes[header + 64] ^= 1;
                let root = naome_chain::ArtifactSetRoot::from_bytes(
                    bytes[header + 64..header + 96].try_into().unwrap(),
                );
                let mut parent = transfer.blocks[0].parent_block_id();
                let mut offset = header + 4 * 32 + 4 + 8;
                for (index, block) in transfer.blocks.iter().enumerate() {
                    let changed = ArtifactBlock::new(
                        parent,
                        if index == 0 {
                            root
                        } else {
                            block.previous_artifact_set_root()
                        },
                        block.resulting_artifact_set_root(),
                        block.artifact_id(),
                    );
                    bytes[offset..offset + naome_chain::ARTIFACT_BLOCK_BYTES]
                        .copy_from_slice(&changed.to_canonical_bytes());
                    parent = changed.id();
                    offset +=
                        naome_chain::ARTIFACT_BLOCK_BYTES + 4 + transfer.payloads[index].len();
                }
                bytes[header + 96..header + 128].copy_from_slice(parent.as_bytes());
                input["target"] = json!(hex(parent.as_bytes()));
                redigest(&mut bytes);
                assert_eq!(
                    Bundle::from_canonical_bytes(
                        &bytes,
                        Limits::new(16, u64::MAX, u64::MAX).unwrap()
                    )
                    .unwrap()
                    .canonical_bytes(),
                    bytes
                );
            }
            "payload" => {
                let payload_start = header + 4 * 32 + 4 + 8 + naome_chain::ARTIFACT_BLOCK_BYTES + 4;
                bytes[payload_start] = 0xff;
                redigest(&mut bytes);
                // Valid framing/digest must reach complete branch replay.
                assert_eq!(
                    Bundle::from_canonical_bytes(
                        &bytes,
                        Limits::new(16, u64::MAX, u64::MAX).unwrap()
                    )
                    .unwrap()
                    .canonical_bytes(),
                    bytes
                );
            }
            "anchor" => input["anchor"] = json!("01".repeat(32)),
            "target" => input["target"] = json!("01".repeat(32)),
            "unselected_anchor" => {
                bytes = anchored.bytes.clone();
                input = anchored.command(true);
            }
            _ => unreachable!(),
        }
        layout.write("branch.bundle", &bytes);
        let outcome = result(&mut node, input);
        no_staging_writes(&outcome, code);
        assert_eq!(outcome["encoded_bytes"], bytes.len().to_string());
        assert_eq!(outcome["state"], state);
        assert_eq!(layout.images(), authority);
        assert_eq!(source_images(&layout), sources);
        assert_eq!(fs::read(layout.root.join("branch.bundle")).unwrap(), bytes);
    }
    layout.write("branch.bundle", &transfer.bytes);
    assert_eq!(
        result(&mut node, transfer.command(true))["event"],
        "bundle_staged"
    );
    assert_eq!(layout.images(), authority);
    node.shutdown();
}

#[test]
fn bundle_export_and_stage_corruption_poison_only_the_affected_source_and_strict_reopen_refuses() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 1, 0);
    for candidate in [true, false] {
        let layout = Layout::new();
        layout.write("branch.bundle", &transfer.bytes);
        let config = source_config(&layout, fixture.config(&layout, 1, "create", None, false));
        let mut node = Process::start(&layout, &config);
        node.ready();
        initial_arm(&mut node);
        assert_eq!(
            result(&mut node, transfer.command(true))["event"],
            "bundle_staged"
        );
        let path = layout.root.join(if candidate {
            "candidates/artifact-block-candidate-store.log"
        } else {
            "payloads/artifact-payload-store.log"
        });
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(path, bytes).unwrap();
        let damaged = source_images(&layout);
        let authority = layout.images();
        let state = result(&mut node, json!({"command":"status","id":1}));
        let mut input = transfer.command(false);
        input["bundle_file"] = json!("damaged.bundle");
        let outcome = result(&mut node, input);
        assert_eq!(outcome["event"], "bundle_export_failed");
        assert_eq!(
            outcome["code"],
            if candidate {
                "candidate_read"
            } else {
                "payload_read"
            }
        );
        assert_eq!(outcome["output_created"], false);
        assert!(!layout.root.join("damaged.bundle").exists());
        assert_eq!(outcome["state"], state);
        assert!(
            outcome["sources"][if candidate {
                "candidate_entries"
            } else {
                "payload_entries"
            }]
            .is_null()
        );
        assert_eq!(
            outcome["sources"][if candidate {
                "payload_entries"
            } else {
                "candidate_entries"
            }],
            1
        );
        let outcome = result(&mut node, transfer.command(true));
        no_staging_writes(
            &outcome,
            if candidate {
                "candidate_preflight"
            } else {
                "payload_preflight"
            },
        );
        assert_eq!(outcome["state"], state);
        assert_eq!(source_images(&layout), damaged);
        assert_eq!(layout.images(), authority);
        node.shutdown();
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        assert_eq!(
            reopened.event("error")["code"],
            if candidate {
                "source_candidates_open"
            } else {
                "source_payloads_open"
            }
        );
        assert!(!reopened.exit().success());
        assert_eq!(source_images(&layout), damaged);
        assert_eq!(layout.images(), authority);
    }
}

#[test]
fn bundle_stage_reports_existing_candidate_acknowledgement_before_commit_refusal_then_explicit_restart_retry()
 {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 2, 0);
    let layout = Layout::new();
    layout.write("branch.bundle", &transfer.bytes);
    let config = source_config(&layout, fixture.config(&layout, 1, "create", None, false))
        .replace("[sources]\nmode = \"create\"", "[sources]\nmode = \"open\"");
    {
        let _guard = PARENT_JOURNALS.read().unwrap();
        let mut candidates = ArtifactBlockCandidateStore::create(
            layout.root.join("candidates"),
            fixture.definition,
            ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
        )
        .unwrap();
        assert_eq!(
            candidates.insert(&transfer.blocks[0]).unwrap(),
            ArtifactBlockCandidateInsertOutcome::Inserted
        );
        drop(
            CanonicalArtifactPayloadStore::create(
                layout.root.join("payloads"),
                ArtifactPayloadStoreLimits::new(16, 1_048_576).unwrap(),
            )
            .unwrap(),
        );
    }
    let mut node = Process::start(&layout, &config);
    node.ready();
    initial_arm(&mut node);
    let healthy = source_images(&layout);
    let path = layout
        .root
        .join("candidates/artifact-block-candidate-store.log");
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(0);
    fs::write(&path, bytes).unwrap();
    let damaged = source_images(&layout);
    let authority = layout.images();
    let state = result(&mut node, json!({"command":"status","id":1}));
    let outcome = result(&mut node, transfer.command(true));
    assert_eq!(outcome["event"], "bundle_stage_failed");
    assert_eq!(outcome["code"], "candidate_commit");
    assert_eq!(outcome["candidate_acknowledged_count"], 1);
    assert_eq!(outcome["candidate_inserted_count"], 0);
    assert_eq!(outcome["payload_acknowledged_count"], 0);
    assert_eq!(outcome["payload_inserted_count"], 0);
    assert_eq!(outcome["bundle_bytes_discarded"], true);
    assert_eq!(outcome["encoded_bytes"], transfer.bytes.len().to_string());
    assert!(outcome["sources"]["candidate_entries"].is_null());
    assert_eq!(outcome["sources"]["payload_entries"], 0);
    assert_eq!(outcome["state"], state);
    assert_eq!(source_images(&layout), damaged);
    assert_eq!(layout.images(), authority);
    assert_eq!(
        fs::read(layout.root.join("branch.bundle")).unwrap(),
        transfer.bytes
    );
    node.shutdown();
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    reopened.ready();
    initial_arm(&mut reopened);
    assert_eq!(
        source_images(&layout),
        healthy,
        "ordinary source open truncates only the incomplete tail"
    );
    assert_eq!(
        result(&mut reopened, json!({"command":"sources_status","id":2}))["candidate_entries"],
        1
    );
    let outcome = result(&mut reopened, transfer.command(true));
    assert_eq!(outcome["event"], "bundle_staged");
    assert_eq!(outcome["candidate_block_count"], 2);
    assert_eq!(outcome["candidate_inserted_count"], 1);
    assert_eq!(outcome["payload_inserted_count"], 2);
    assert_eq!(layout.images(), authority);
    reopened.shutdown();
    let sources = source_images(&layout);
    let mut reopened = Process::start(&layout, &config.replace("create", "open"));
    reopened.ready();
    let status = result(&mut reopened, json!({"command":"sources_status","id":3}));
    assert_eq!(status["candidate_entries"], 2);
    assert_eq!(status["payload_entries"], 2);
    reopened.shutdown();
    assert_eq!(source_images(&layout), sources);
    assert_eq!(layout.images(), authority);
}

#[test]
fn bundle_export_rejects_a_fork_behind_current_selected_head_without_creating_output() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 2, 0);
    let sibling = Proof::new(&fixture, false, 3, Role::Precommit);
    let layout = Layout::new();
    layout.write("branch.bundle", &transfer.bytes);
    let config = source_config(&layout, fixture.config(&layout, 1, "create", None, false));
    let mut node = Process::start(&layout, &config);
    node.ready();
    initial_arm(&mut node);
    assert_eq!(
        result(&mut node, transfer.command(true))["event"],
        "bundle_staged"
    );
    select(&mut node, &layout, &[&sibling]);
    let authority = layout.images();
    let sources = source_images(&layout);
    let state = result(&mut node, json!({"command":"status","id":1}));
    let mut input = transfer.command(false);
    input["bundle_file"] = json!("fork.bundle");
    let outcome = result(&mut node, input);
    assert_eq!(outcome["code"], "divergent_ancestry");
    assert_eq!(outcome["output_created"], false);
    assert_eq!(outcome["state"], state);
    assert!(!layout.root.join("fork.bundle").exists());
    assert_eq!(layout.images(), authority);
    assert_eq!(source_images(&layout), sources);
    node.shutdown();
}

#[test]
fn bundle_export_requires_complete_retained_sources_and_replays_resulting_commitments() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 1, 0);
    for (mode, code) in [
        ("missing_candidate", "candidate_missing"),
        ("missing_payload", "payload_missing"),
        ("invalid_result", "branch_validation"),
    ] {
        let layout = Layout::new();
        let config = source_config(&layout, fixture.config(&layout, 1, "create", None, false))
            .replace("[sources]\nmode = \"create\"", "[sources]\nmode = \"open\"");
        let original = transfer.blocks[0];
        let block = if mode == "invalid_result" {
            ArtifactBlock::new(
                original.parent_block_id(),
                original.previous_artifact_set_root(),
                naome_chain::ArtifactSetRoot::from_bytes([0x19; 32]),
                original.artifact_id(),
            )
        } else {
            original
        };
        {
            let _guard = PARENT_JOURNALS.read().unwrap();
            let mut candidates = ArtifactBlockCandidateStore::create(
                layout.root.join("candidates"),
                fixture.definition,
                ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
            )
            .unwrap();
            let mut payloads = CanonicalArtifactPayloadStore::create(
                layout.root.join("payloads"),
                ArtifactPayloadStoreLimits::new(16, 1_048_576).unwrap(),
            )
            .unwrap();
            if mode != "missing_candidate" {
                assert_eq!(
                    candidates.insert(&block).unwrap(),
                    ArtifactBlockCandidateInsertOutcome::Inserted
                );
            }
            if mode != "missing_payload" {
                assert_eq!(
                    payloads
                        .insert(
                            ArtifactDag::new()
                                .apply_canonical_artifact_bytes(transfer.payloads[0].clone())
                                .unwrap()
                        )
                        .unwrap(),
                    ArtifactPayloadInsertOutcome::Inserted
                );
            }
        }
        let mut node = Process::start(&layout, &config);
        node.ready();
        initial_arm(&mut node);
        let authority = layout.images();
        let sources = source_images(&layout);
        let state = result(&mut node, json!({"command":"status","id":1}));
        let mut input = transfer.command(false);
        input["target"] = json!(hex(block.id().as_bytes()));
        let outcome = result(&mut node, input);
        assert_eq!(outcome["event"], "bundle_export_failed");
        assert_eq!(outcome["code"], code);
        assert_eq!(outcome["output_created"], false);
        assert_eq!(outcome["state"], state);
        assert!(!outcome["sources"]["candidate_entries"].is_null());
        assert!(!outcome["sources"]["payload_entries"].is_null());
        assert!(!layout.root.join("branch.bundle").exists());
        assert_eq!(source_images(&layout), sources);
        assert_eq!(layout.images(), authority);
        node.shutdown();
    }
}
