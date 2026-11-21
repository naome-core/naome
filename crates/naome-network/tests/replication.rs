use anyhow::{Context, Result, ensure};
use naome_protocol::{
    evaluation::{Standing, assess, deposit_receipt},
    fixture,
    learning::{Example, LabelStanding, TrainingRequest},
    profile::{self, Document, Kind, MEASUREMENT_PROFILE, READ_ONLY},
    store::Archive,
    wire::{Format, Id, Record},
};
use serde_json::{Value, json};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_naome");
// Pinned against the actual archive produced by faf37db.
const LEGACY_HEAD: &str = "1:1:b7826ed27f6f1fdc30fad29e48727cc2fef11b9c7316669f3fef7018700ef0a9";
const LEGACY_READING: &str = "1:0:83b3ce65fc517bdc0621659230972548a0f75dce9446ae55a472db88f488cac7";
const LEGACY_RECEIPT: &str = "1:0:ee829956a6e4e9a2469d51ed8385c85b493ca9f286c6ea132d85fa05c16bded4";
const LEGACY_SIGNATURE: &str =
    "1:0:c51a2b0c66d48c7b608cc00e1ab56770aff38ea3fead9da94a7b8788f0d92e3c";

fn cli(dir: &Path, args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN)
        .arg("--json")
        .arg("--directory")
        .arg(dir)
        .args(args)
        .output()?;
    ensure!(
        output.status.success(),
        "naome {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

struct Node {
    path: PathBuf,
    peer: String,
    address: String,
    reservation: Option<TcpListener>,
    running: bool,
}
impl Node {
    fn init(path: PathBuf) -> Result<Self> {
        let init = cli(&path, &["archive", "init"])?;
        assert_eq!(cli(&path, &["status"])?["running"], false);
        let reservation = TcpListener::bind("127.0.0.1:0")?;
        Ok(Self {
            address: format!("/ip4/127.0.0.1/tcp/{}", reservation.local_addr()?.port()),
            path,
            peer: init["peer_id"].as_str().context("peer ID")?.into(),
            reservation: Some(reservation),
            running: false,
        })
    }

    fn config(&self, peers: &[&Node], review: Option<&TrainingRequest>) -> Result<()> {
        let peers: Vec<_> = peers
            .iter()
            .map(|n| json!({"id":n.peer,"address":n.address}))
            .collect();
        fs::write(
            self.path.join("node.json"),
            serde_json::to_vec_pretty(
                &json!({"listen":self.address,"peers":peers,"review":review,"trace_object_frames":true}),
            )?,
        )?;
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        drop(self.reservation.take());
        let reply = cli(&self.path, &["start"])?;
        self.running = true;
        assert_eq!(reply["running"], true);
        assert_eq!(reply["peer_id"], self.peer);
        assert_eq!(reply["listen_addresses"], json!([self.address]));
        assert!(reply["pid"].as_u64().is_some());
        assert_eq!(cli(&self.path, &["status"])?["pid"], reply["pid"]);
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        assert_eq!(cli(&self.path, &["stop"])?["running"], false);
        assert_eq!(cli(&self.path, &["status"])?["pid"], Value::Null);
        self.running = false;
        Ok(())
    }

    fn wait_status(&self, check: impl Fn(&Value) -> bool) -> Result<Value> {
        let start = Instant::now();
        loop {
            let state = cli(&self.path, &["status"])?;
            if check(&state) {
                return Ok(state);
            }
            ensure!(
                start.elapsed() < Duration::from_secs(30),
                "unexpected status: {state}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn archive(&self) -> Result<Archive> {
        Archive::open(self.path.join("archive.sqlite"))
    }

    fn publish(&self, head: Id) -> Result<()> {
        assert_eq!(
            cli(&self.path, &["archive", "publish", &head.to_string()])?,
            json!(head)
        );
        Ok(())
    }

    fn wait(&mut self, condition: impl Fn(&Value) -> bool) -> Result<Value> {
        let start = Instant::now();
        loop {
            let events = fs::read_to_string(self.path.join("events.jsonl"))?;
            if let Some(event) = events
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .find(&condition)
            {
                return Ok(event);
            }
            ensure!(
                start.elapsed() < Duration::from_secs(90),
                "event timeout in {}: {}\n{}",
                self.path.display(),
                events,
                fs::read_to_string(self.path.join("node.log"))?
            );
            std::thread::sleep(Duration::from_millis(60));
        }
    }

    fn mirrored(&mut self, head: Id, supplier: &Node) -> Result<()> {
        self.wait(|e| e["mirrored"] == json!(head) && e["supplier"] == supplier.peer)?;
        ensure!(
            cli(&self.path, &["archive", "heads"])?
                .as_array()
                .context("released heads")?
                .contains(&json!(head)),
            "missing durable release"
        );
        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.running {
            let _ = cli(&self.path, &["stop"]);
        }
    }
}

fn exercise(path: &Path) -> Result<()> {
    let mut a = Node::init(path.join("A"))?;
    let mut b = Node::init(path.join("B"))?;
    let mut c = Node::init(path.join("C"))?;
    let author = a.archive()?;
    let case = fixture::seed(&author, Format::A)?;

    let legacy = Archive::memory()?;
    let legacy_case = fixture::seed_legacy(&legacy, Format::A)?;
    assert_eq!(legacy_case.published, LEGACY_HEAD.parse()?);
    assert_eq!(legacy_case.receipts[2], LEGACY_RECEIPT.parse()?);
    let legacy_snapshot = legacy.head(legacy_case.published)?;
    let bundle = path.join("original-calibration.json");
    fs::write(
        &bundle,
        serde_json::to_vec(&legacy.export(&legacy_snapshot, "read")?)?,
    )?;
    let imported = cli(
        &a.path,
        &["archive", "import", bundle.to_str().context("bundle path")?],
    )?;
    assert_eq!(imported, json!(legacy_case.published));
    let legacy_reading: Id = LEGACY_READING.parse()?;
    let legacy_sig: Id = LEGACY_SIGNATURE.parse()?;
    let legacy_key = legacy.read(&legacy_snapshot, legacy_sig, "read")?;
    let reading = author
        .read(
            &author.head(case.published)?,
            case.queries[2].arguments[0],
            "read",
        )?
        .roles("reading")
        .next()
        .context("first gauge reading")?;
    assert_ne!(reading, legacy_reading);
    let affected = case.labels[2];
    let control = case.control_label;
    let review = TrainingRequest {
        feature_cutoff: case.feature_cutoff,
        label_head: case.published,
        policy: case.policy,
        standing: LabelStanding::Current,
        examples: [affected, control]
            .into_iter()
            .map(|label| Example {
                features: vec![case.policy],
                label,
                partition: "train".into(),
            })
            .collect(),
        mappings: vec![],
        forecast_plan: None,
        project: None,
        independent_roles: Default::default(),
        binary: true,
    };
    a.config(&[&b], None)?;
    b.config(&[&a, &c], None)?;
    c.config(&[&b], Some(&review))?;
    a.start()?;
    b.start()?;
    a.publish(case.published)?;
    a.publish(legacy_case.published)?;
    b.mirrored(case.published, &a)?;
    b.mirrored(legacy_case.published, &a)?;
    let publisher = a.wait_status(|s| {
        s["connected_peers"] == json!([b.peer]) && s["sync"]["state"] == "caught_up"
    })?;
    a.stop()?;
    c.start()?;
    c.mirrored(case.published, &b)?;
    c.mirrored(legacy_case.published, &b)?;
    let relay_status = c.wait_status(|s| {
        s["connected_peers"] == json!([b.peer])
            && s["sync"]["state"] == "caught_up"
            && s["sync"]["available_heads"]
                .as_array()
                .is_some_and(|heads| heads.contains(&json!(case.published)))
    })?;
    let discovered = cli(
        &c.path,
        &[
            "archive",
            "search",
            &case.published.to_string(),
            "--subject",
            "bar-7",
            "--scope",
            "transition-1",
            "--kind",
            "occurrence",
            "--budget",
            "512",
        ],
    )?;
    assert!(
        discovered["ids"]
            .as_array()
            .context("search results")?
            .contains(&json!(reading))
    );
    let original_review = c.wait(|e| e["extraction"]["included"] == json!([affected, control]))?;
    let reader = c.archive()?;
    let published = reader.head(case.published)?;
    let legacy_view = reader.head(legacy_case.published)?;
    let legacy_bytes = reader.resolve(&legacy_view, legacy_reading, "read")?;
    let current_bytes = reader.resolve(&published, reading, "read")?;
    assert_eq!(legacy_bytes.len(), 255);
    assert_eq!(
        Record::decode(&current_bytes, Format::A)?.profile,
        Id::blob(MEASUREMENT_PROFILE)
    );
    assert_eq!(
        reader.read(&published, reading, "read")?,
        reader.read(&legacy_view, legacy_reading, "read")?
    );
    let legacy_frame = b.wait(|e| e["object_frame"] == json!(legacy_reading))?;
    let typed_frame = b.wait(|e| e["object_frame"] == json!(reading))?;
    for (event, data) in [
        (&legacy_frame, &legacy_bytes),
        (&typed_frame, &current_bytes),
    ] {
        assert_eq!(event["object_bytes"], json!(data.len()));
        assert_eq!(event["frame_bytes"], json!(data.len() + 5));
    }
    assert_eq!(current_bytes.len(), 180);
    let legacy_attestation = reader.read(&legacy_view, legacy_sig, "read")?;
    assert_eq!(legacy_attestation, legacy_key);
    let expected_key = hex::encode(fixture::fixture_key(4).verifying_key().as_bytes());
    profile::verify_attestation(
        &legacy_attestation,
        legacy_case.receipts[2],
        "transition-1",
        "assessor",
        "research-policy-1",
        &[expected_key.clone()].into(),
    )?;
    assert!(
        profile::verify_attestation(
            &legacy_attestation,
            case.receipts[2],
            "transition-1",
            "assessor",
            "research-policy-1",
            &[expected_key].into()
        )
        .is_err()
    );
    let receipt = reader.read(&published, case.receipts[2], "read")?;
    let query = receipt.field("original_query")?;
    let original_horizon = reader.head(receipt.one("snapshot")?)?;
    let replay = assess(&reader, &original_horizon, &query)?;
    assert_eq!(replay.result, Some(Standing::Supported));
    assert_eq!(
        deposit_receipt(&reader, &original_horizon, &query, &replay, Format::A)?,
        case.receipts[2]
    );

    a.start()?;
    // All three nodes now run. Two independent small datasets also exercise
    // the second native encoding and exact recovery of measured integers.
    let mut samples = Vec::new();
    for (subject, unit, values) in [
        ("synthetic soil temperature", "mK", [285100, 285200, 285150]),
        ("synthetic photon counter", "counts", [24, 27, 21]),
    ] {
        samples.push(fixture::put(
            &author,
            Format::B,
            Kind::Occurrence,
            subject,
            "bench-2",
            json!({"source":"synthetic","unit":unit,"values":values}),
            vec![],
        )?);
    }
    let read_only = Id::blob(READ_ONLY);
    let raw_blob = [0, 255, 0, 42];
    let blob = author.blob(&raw_blob, read_only)?;
    let restricted = author.document(
        &Document::new(
            Kind::Occurrence,
            "restricted specimen",
            "bench-2",
            json!({"source":"synthetic"}),
            vec![profile::link("payload", blob)],
        )?,
        Format::B,
        read_only,
    )?;
    let sample_head = author
        .snapshot("additional samples", [case.published].into())?
        .id()?;
    a.publish(sample_head)?;
    b.mirrored(sample_head, &a)?;
    c.mirrored(sample_head, &b)?;
    let gossip = c.wait(|event| event["hint"] == json!(sample_head) && event["via"] == b.peer)?;
    for &id in &samples {
        assert_eq!(
            reader.resolve(&reader.head(sample_head)?, id, "read")?,
            author.resolve(&author.head(sample_head)?, id, "read")?
        );
    }
    let sample_view = reader.head(sample_head)?;
    assert_eq!(reader.resolve(&sample_view, blob, "read")?, raw_blob);
    assert!(reader.resolve(&sample_view, blob, "train").is_err());
    assert_eq!(
        reader
            .read(&sample_view, restricted, "read")?
            .one("payload")?,
        blob
    );
    assert!(reader.read(&sample_view, restricted, "train").is_err());
    let blob_frame = b.wait(|e| e["object_frame"] == json!(blob))?;
    assert_eq!(blob_frame["frame_bytes"], json!(raw_blob.len() + 37));
    c.stop()?;
    let notice = fixture::notice(&author, Format::A, case.calibration, 80, 1)?;
    let corrected = author.snapshot("West", [sample_head].into())?.id()?;
    a.publish(corrected)?;
    b.mirrored(corrected, &a)?;
    b.wait(|e| e["announced"] == json!(corrected))?;
    assert!(!reader.releases()?.contains(&corrected));
    a.stop()?;
    c.start()?;
    c.mirrored(corrected, &b)?;
    let recovered = c.wait(|e| {
        e["queued"] == json!(corrected) && e["source"] == "catalog" && e["supplier"] == b.peer
    })?;
    let latest = c.wait(|e| {
        e["extraction"]["withheld"][affected.to_string()]
            == "label requires reassessment at the requested notice horizon"
    })?;

    let recovered_status = c.wait_status(|s| {
        s["connected_peers"] == json!([b.peer])
            && s["sync"]["state"] == "caught_up"
            && s["sync"]["available_heads"]
                .as_array()
                .is_some_and(|heads| heads.contains(&json!(corrected)))
    })?;
    let view = reader.head(corrected)?;
    let assessment = assess(&reader, &view, &query)?;
    assert_eq!(assessment.result, Some(Standing::Refuted));
    assert!(assessment.applicable_notices.contains(&notice));
    let corrected_receipt = deposit_receipt(&reader, &view, &query, &assessment, Format::A)?;
    let impact = reader.impact(&view, notice, &[], 10_000)?;
    assert!(impact.by_kind["label"].contains(&affected));
    assert!(!impact.by_kind["label"].contains(&control));
    assert!(impact.frontier.is_empty());
    let historical = assess(&reader, &original_horizon, &query)?;
    assert_eq!(
        deposit_receipt(&reader, &original_horizon, &query, &historical, Format::A)?,
        case.receipts[2]
    );
    let legacy_origin = reader.head(legacy_case.s0)?;
    let legacy_query = &legacy_case.queries[2];
    let legacy_replay = assess(&reader, &legacy_origin, legacy_query)?;
    assert_eq!(legacy_replay.result, Some(Standing::Supported));
    assert_eq!(
        deposit_receipt(
            &reader,
            &legacy_origin,
            legacy_query,
            &legacy_replay,
            Format::A
        )?,
        LEGACY_RECEIPT.parse()?
    );
    assert_eq!(
        reader.read(&legacy_view, legacy_sig, "read")?,
        legacy_attestation
    );
    let manifest: Id = serde_json::from_value(latest["extraction"]["manifest"].clone())?;
    let audit = reader.snapshot("C audit", [corrected].into())?;
    let durable = reader.read(&audit, manifest, "read")?;
    let review_receipt = reader.read(
        &audit,
        serde_json::from_value(latest["review_receipt"].clone())?,
        "read",
    )?;
    assert_eq!(review_receipt.one("extraction")?, manifest);
    assert_eq!(
        review_receipt.roles("withheld-label").collect::<Vec<_>>(),
        [affected]
    );
    assert_eq!(durable.roles("label").collect::<Vec<_>>(), [control]);
    assert!(
        review_receipt
            .inputs
            .iter()
            .any(|e| e.target == affected && e.qualifier.contains("requires reassessment"))
    );
    assert_eq!(
        reader
            .read(&view, control, "read")?
            .field::<String>("value")?,
        "supported"
    );

    let summary = json!({
        "cli":{"publisher":publisher,"recipient_with_A_offline":relay_status,"after_restart":recovered_status,"search":discovered},
        "peers":{"A":a.peer,"B":b.peer,"C":c.peer}, "initial_head":case.published,"initial_members":published.objects.len(),
        "additional_head":sample_head,"additional_datasets":samples,"corrected_head":corrected,"corrected_members":view.objects.len(),
        "notice":notice, "original_receipt":case.receipts[2], "corrected_receipt":corrected_receipt,
        "original_judgment":historical.result, "corrected_judgment":assessment.result,"applicable_notices":assessment.applicable_notices,
        "affected_label":affected,"control_label":control,"original_review":original_review,"corrected_review":latest,
        "audit_head":audit.id()?,"online_gossip":gossip,"recovered_from":recovered,
        "measurement":{"subject":"bar-7","scope":"transition-1","gauge":"A","positions_um":[10000,10260],
            "legacy_stored_bytes":legacy_bytes.len(),"typed_stored_bytes":current_bytes.len(),
            "legacy_record_v2_response":legacy_frame,"typed_record_v2_response":typed_frame},
        "legacy_receipt_unchanged":legacy_case.receipts[2],"legacy_verified_signature":legacy_sig,
        "restricted_binary_blob_response":blob_frame
    });
    fs::write(
        path.join("result.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    c.stop()?;
    b.stop()?;
    Ok(())
}

#[test]
fn three_processes_mirror_correct_and_recover() -> Result<()> {
    let scratch = tempfile::tempdir()?;
    let root = match std::env::var_os("REP_TRIAL_DIRECTORY") {
        Some(path) => {
            let path = PathBuf::from(path);
            fs::create_dir(&path)?;
            path
        }
        None => scratch.path().into(),
    };
    exercise(&root).with_context(|| format!("three-node evidence in {}", root.display()))
}

#[test]
fn lifecycle_serializes_starts_and_reports_failed_readiness() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("isolated");
    assert_eq!(cli(&path, &["status"])?["running"], false);
    assert!(!path.exists());

    let mut node = Node::init(path)?;
    node.config(&[], None)?;
    // The reservation occupies the configured TCP address. No ready result
    // may escape from the child while its listener cannot bind.
    let failed = Command::new(BIN)
        .env("NAOME_NODE_DIR", &node.path)
        .args(["start", "--json"])
        .output()?;
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert!(serde_json::from_slice::<Value>(&failed.stderr)?["error"].is_string());
    assert_eq!(cli(&node.path, &["status"])?["running"], false);
    drop(node.reservation.take());

    let start = || {
        Command::new(BIN)
            .env("NAOME_NODE_DIR", &node.path)
            .args(["start", "--json"])
            .stdout(std::process::Stdio::piped())
            .spawn()
    };
    let first = start()?;
    let second = start()?;
    node.running = true;
    let first = first.wait_with_output()?;
    let second = second.wait_with_output()?;
    assert!(first.status.success() && second.status.success());
    let first: Value = serde_json::from_slice(&first.stdout)?;
    let second: Value = serde_json::from_slice(&second.stdout)?;
    assert_eq!(first["pid"], second["pid"]);
    assert_eq!(first["peer_id"], node.peer);
    assert_eq!(second["sync"]["state"], "standalone");
    assert_eq!(second["listen_addresses"], json!([node.address]));
    node.stop()?;
    assert_eq!(cli(&node.path, &["stop"])?["running"], false);
    Ok(())
}
