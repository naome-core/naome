use anyhow::{Context, Result, ensure};
use naome_protocol::{
    evaluation::{Standing, assess, deposit_receipt},
    fixture,
    learning::{Example, LabelStanding, TrainingRequest},
    profile::Kind,
    store::Archive,
    wire::{Format, Id},
};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_rep-node");

struct Node {
    path: PathBuf,
    peer: String,
    address: String,
    reservation: Option<TcpListener>,
    process: Option<Child>,
}
impl Node {
    fn init(path: PathBuf) -> Result<Self> {
        let init = Command::new(BIN)
            .arg("--directory")
            .arg(&path)
            .arg("init")
            .output()?;
        ensure!(
            init.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let reservation = TcpListener::bind("127.0.0.1:0")?;
        Ok(Self {
            address: format!("/ip4/127.0.0.1/tcp/{}", reservation.local_addr()?.port()),
            path,
            peer: String::from_utf8(init.stdout)?.trim().into(),
            reservation: Some(reservation),
            process: None,
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
                &json!({"listen":self.address,"peers":peers,"review":review}),
            )?,
        )?;
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        drop(self.reservation.take());
        let log = |name| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.path.join(name))
        };
        self.process = Some(
            Command::new(BIN)
                .arg("--directory")
                .arg(&self.path)
                .arg("run")
                .arg(self.path.join("node.json"))
                .stdout(log("events.jsonl")?)
                .stderr(log("node.log")?)
                .spawn()?,
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        let mut child = self.process.take().context("process was not started")?;
        ensure!(
            child.try_wait()?.is_none(),
            "node exited early in {}",
            self.path.display()
        );
        child.kill()?;
        child.wait()?;
        Ok(())
    }

    fn archive(&self) -> Result<Archive> {
        Archive::open(self.path.join("archive.sqlite"))
    }

    fn publish(&self, head: Id) -> Result<()> {
        let r = Command::new(BIN)
            .arg("--directory")
            .arg(&self.path)
            .arg("publish")
            .arg(head.to_string())
            .output()?;
        ensure!(
            r.status.success(),
            "publish: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        Ok(())
    }

    fn wait(&mut self, condition: impl Fn(&Value) -> bool) -> Result<Value> {
        let start = Instant::now();
        loop {
            ensure!(
                self.process
                    .as_mut()
                    .context("node stopped")?
                    .try_wait()?
                    .is_none(),
                "node exited in {}",
                self.path.display()
            );
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
            self.archive()?.releases()?.contains(&head),
            "missing durable release"
        );
        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn exercise(path: &Path) -> Result<()> {
    let mut a = Node::init(path.join("A"))?;
    let mut b = Node::init(path.join("B"))?;
    let mut c = Node::init(path.join("C"))?;
    let author = a.archive()?;
    let case = fixture::seed(&author, Format::A)?;
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
    b.mirrored(case.published, &a)?;
    a.stop()?;
    c.start()?;
    c.mirrored(case.published, &b)?;
    let original_review = c.wait(|e| e["extraction"]["included"] == json!([affected, control]))?;
    let reader = c.archive()?;
    let published = reader.head(case.published)?;
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
        "peers":{"A":a.peer,"B":b.peer,"C":c.peer}, "initial_head":case.published,"initial_members":published.objects.len(),
        "additional_head":sample_head,"additional_datasets":samples,"corrected_head":corrected,"corrected_members":view.objects.len(),
        "notice":notice, "original_receipt":case.receipts[2], "corrected_receipt":corrected_receipt,
        "original_judgment":historical.result, "corrected_judgment":assessment.result,"applicable_notices":assessment.applicable_notices,
        "affected_label":affected,"control_label":control,"original_review":original_review,"corrected_review":latest,
        "audit_head":audit.id()?,"online_gossip":gossip,"recovered_from":recovered
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
