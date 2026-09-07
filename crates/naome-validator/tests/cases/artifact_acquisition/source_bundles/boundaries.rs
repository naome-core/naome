use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

#[test]
fn bundle_schema_source_availability_full_width_limits_and_regular_file_boundaries() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 1, 0);
    let layout = Layout::new();
    let config = fixture.config(&layout, 1, "create", None, false);
    let mut node = Process::start(&layout, &config);
    node.ready();
    initial_arm(&mut node);
    let authority = layout.images();
    for stage in [false, true] {
        let mut input = transfer.command(stage);
        input["target"] = json!("invalid");
        input["max_blocks"] = json!(0);
        reject(&mut node, input, "sources_disabled");
    }
    node.shutdown();
    assert_eq!(layout.images(), authority);
    let config = source_config(&layout, config.replace("create", "open"));
    let mut node = Process::start(&layout, &config);
    node.ready();
    initial_arm(&mut node);
    let state = result(&mut node, json!({"command":"status","id":1}));
    let sources = source_images(&layout);
    for stage in [false, true] {
        let template = transfer.command(stage);
        for field in [
            "height",
            "winner",
            "payload_file",
            "candidate_directory",
            "retry",
        ] {
            let mut input = template.clone();
            input[field] = json!("extra");
            reject(&mut node, input, "command_schema");
        }
        if !stage {
            let mut input = template.clone();
            input["anchor"] = json!("00".repeat(32));
            reject(&mut node, input, "command_schema");
        }
        for field in [
            "target",
            "bundle_file",
            "max_blocks",
            "max_payload_bytes",
            "max_bundle_bytes",
        ] {
            let mut input = template.clone();
            input.as_object_mut().unwrap().remove(field);
            reject(&mut node, input, "command_schema");
        }
        reject(&mut node, json!([template.clone()]), "command_schema");
        for field in ["max_blocks", "max_payload_bytes", "max_bundle_bytes"] {
            for value in [json!(-1), json!("1"), json!(1.5), json!(null)] {
                let mut input = template.clone();
                input[field] = value;
                reject(&mut node, input, "command_schema");
            }
            let encoded = serde_json::to_string(&template).unwrap();
            let duplicated = format!("{{\"{field}\":1,{}\n", &encoded[1..]);
            node.write(duplicated.as_bytes());
            assert_eq!(node.event("command_rejected")["code"], "command_schema");
            let mut input = template.clone();
            input[field] = json!(0);
            reject(&mut node, input, "bundle_limits");
        }
        for target in [
            "short".into(),
            "AB".repeat(32),
            format!("0x{}", "ab".repeat(32)),
        ] {
            let mut input = template.clone();
            input["target"] = json!(target);
            reject(&mut node, input, "source_block_id");
        }
        if stage {
            let mut input = template.clone();
            input["anchor"] = json!("invalid");
            reject(&mut node, input, "source_block_id");
        }
    }
    let mut full = transfer.command(true);
    for field in ["max_blocks", "max_payload_bytes", "max_bundle_bytes"] {
        full[field] = json!(u64::MAX);
    }
    if usize::BITS < 64 {
        reject(&mut node, full.clone(), "bundle_block_limit");
        full["max_blocks"] = json!(usize::MAX);
    }
    reject(&mut node, full.clone(), "file_open");
    fs::create_dir(layout.root.join("directory")).unwrap();
    assert!(
        spawn(std::process::Command::new("mkfifo").arg(layout.root.join("fifo")))
            .wait()
            .unwrap()
            .success()
    );
    layout.write("branch.bundle", &transfer.bytes);
    symlink(
        layout.root.join("branch.bundle"),
        layout.root.join("linked"),
    )
    .unwrap();
    for (path, code) in [
        ("directory", "file_not_regular"),
        ("fifo", "file_not_regular"),
        ("linked", "file_open"),
    ] {
        let mut input = full.clone();
        input["bundle_file"] = json!(path);
        reject(&mut node, input, code);
    }
    layout.write("oversized", vec![0; transfer.bytes.len() + 1]);
    let mut input = transfer.command(true);
    input["bundle_file"] = json!("oversized");
    reject(&mut node, input, "file_too_large");
    assert_eq!(source_images(&layout), sources);
    assert_eq!(layout.images(), authority);
    assert_eq!(result(&mut node, json!({"command":"status","id":2})), state);
    let staged = result(&mut node, full);
    assert_eq!(staged["event"], "bundle_staged");
    assert_eq!(staged["state"], state);
    let mut export = transfer.command(false);
    export["bundle_file"] = json!("full.bundle");
    for field in ["max_blocks", "max_payload_bytes", "max_bundle_bytes"] {
        export[field] = json!(u64::MAX);
    }
    export["max_blocks"] = json!(usize::MAX);
    assert_eq!(result(&mut node, export)["event"], "bundle_exported");
    assert_eq!(
        fs::read(layout.root.join("full.bundle")).unwrap(),
        transfer.bytes
    );
    assert_eq!(
        fs::metadata(layout.root.join("full.bundle"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(layout.images(), authority);
    node.shutdown();
}

#[test]
fn bundle_export_create_new_preserves_existing_files_authorities_sources_symlinks_and_fifos() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 1, 0);
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
    let authority = layout.images();
    let sources = source_images(&layout);
    let state = result(&mut node, json!({"command":"status","id":1}));
    layout.write("existing", b"operator-owned");
    fs::create_dir(layout.root.join("directory")).unwrap();
    symlink(layout.root.join("existing"), layout.root.join("linked")).unwrap();
    symlink(layout.root.join("absent"), layout.root.join("dangling")).unwrap();
    assert!(
        spawn(std::process::Command::new("mkfifo").arg(layout.root.join("fifo")))
            .wait()
            .unwrap()
            .success()
    );
    let authority_path = authority[0].0.to_str().unwrap();
    for path in [
        "existing",
        "directory",
        "linked",
        "dangling",
        "fifo",
        "branch.bundle",
        "candidates/artifact-block-candidate-store.log",
        "payloads/artifact-payload-store.log",
        "absent/branch.bundle",
        authority_path,
    ] {
        let mut input = transfer.command(false);
        input["bundle_file"] = json!(path);
        let refused = result(&mut node, input);
        assert_eq!(refused["event"], "bundle_export_failed");
        assert_eq!(refused["code"], "bundle_file_create", "{path}: {refused}");
        assert_eq!(refused["output_created"], false);
        assert_eq!(refused["state"], state);
        assert_eq!(layout.images(), authority);
        assert_eq!(source_images(&layout), sources);
        assert_eq!(
            fs::read(layout.root.join("existing")).unwrap(),
            b"operator-owned"
        );
        assert_eq!(
            fs::read(layout.root.join("branch.bundle")).unwrap(),
            transfer.bytes
        );
        assert!(!layout.root.join("absent").exists());
    }
    let mut input = transfer.command(false);
    input["bundle_file"] = json!("exported.bundle");
    assert_eq!(result(&mut node, input)["event"], "bundle_exported");
    node.shutdown();
}

#[test]
fn bundle_staging_preflights_whole_candidate_payload_entry_and_byte_capacity() {
    let fixture = Fixture::new();
    let transfer = Transfer::new(&fixture, 2, 0);
    for (field, value, code) in [
        ("candidate_entries", 1, "candidate_capacity"),
        ("payload_entries", 1, "payload_capacity"),
        (
            "payload_bytes",
            transfer.payloads.iter().map(Vec::len).sum::<usize>() - 1,
            "payload_capacity",
        ),
    ] {
        let layout = Layout::new();
        layout.write("branch.bundle", &transfer.bytes);
        let original = if field == "payload_bytes" {
            1_048_576
        } else {
            16
        };
        let config = source_config(&layout, fixture.config(&layout, 1, "create", None, false))
            .replace(
                &format!("{field} = \"{original}\""),
                &format!("{field} = \"{value}\""),
            );
        let mut node = Process::start(&layout, &config);
        node.ready();
        initial_arm(&mut node);
        let authority = layout.images();
        let sources = source_images(&layout);
        let state = result(&mut node, json!({"command":"status","id":1}));
        let rejected = result(&mut node, transfer.command(true));
        no_staging_writes(&rejected, code);
        assert_eq!(rejected["state"], state);
        assert_eq!(source_images(&layout), sources);
        assert_eq!(layout.images(), authority);
        node.shutdown();
        let mut reopened = Process::start(&layout, &config.replace("create", "open"));
        reopened.ready();
        let status = result(&mut reopened, json!({"command":"sources_status","id":2}));
        assert_eq!(status["candidate_entries"], 0);
        assert_eq!(status["payload_entries"], 0);
        reopened.shutdown();
        assert_eq!(source_images(&layout), sources);
        assert_eq!(layout.images(), authority);
    }
}
