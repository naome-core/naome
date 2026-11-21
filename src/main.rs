use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use naome_protocol::{
    evaluation, executor, fixture, kit, learning,
    profile::{self, Document, Kind, PUBLIC},
    store::{Archive, Bundle},
    wire::{Format, Id, MAX_BYTES, Record},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "Store, exchange and evaluate immutable research evidence"
)]
struct Cli {
    /// Local custody database. The operator controls this file and its disclosure policy.
    #[arg(long, global = true, default_value = "evidence.sqlite")]
    db: PathBuf,
    #[arg(long, global = true, value_enum, default_value = "a")]
    format: Format,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Show supported formats, evaluators and independently pinned kit digests.
    Capabilities,
    /// Run all cases in an externally pinned bootstrap package.
    Kit { file: PathBuf, sha256: String },
    /// Run the full synthetic two-archive trial in a fresh directory.
    Trial { directory: PathBuf },
    /// Run public conformance queries in a clean archive per exchange file.
    Suite { directory: PathBuf },
    /// Compare an external submission with the adjudicated answer key.
    Grade {
        answer_key: PathBuf,
        submission: PathBuf,
    },
    /// Create or open a custody database.
    Init,
    /// Capture an arbitrary stream as an ordered, digest-checked chunk manifest.
    Capture {
        file: PathBuf,
        media: String,
        #[arg(long, default_value_t = 1048576)]
        chunk_size: usize,
        #[arg(long)]
        access: Option<Id>,
    },
    /// Verify and recover a complete chunked payload into a new file.
    Recover {
        head: Id,
        descriptor: Id,
        output: PathBuf,
        #[arg(long)]
        bytes: u64,
    },
    /// Evaluate the finite-world expected reduction in decision loss for an observation.
    Value { model: PathBuf },
    /// Select an observational plan under an explicit objective and unit-specific ceilings.
    Select { head: Id, request: PathBuf },
    /// Execute a registered local payload-verification attempt and deposit its signed readback.
    Execute {
        head: Id,
        request: PathBuf,
        public_key: String,
        witness_key: PathBuf,
    },
    /// Deposit exact payload bytes.
    Blob {
        file: PathBuf,
        #[arg(long)]
        access: Option<Id>,
    },
    /// Deposit an opaque canonical wire record.
    Wire { file: PathBuf },
    /// Deposit a research-profile JSON document.
    Put {
        file: PathBuf,
        #[arg(long)]
        access: Option<Id>,
    },
    /// Seal the currently known inventory, retaining any named parent heads.
    Snapshot {
        source: String,
        #[arg(long)]
        parent: Vec<Id>,
    },
    /// Inspect typed research fields at a fixed snapshot.
    Show {
        head: Id,
        id: Id,
        #[arg(long, default_value = "read")]
        purpose: String,
    },
    /// Write verified, permitted bytes. The output path must be new.
    Resolve {
        head: Id,
        id: Id,
        output: PathBuf,
        #[arg(long, default_value = "read")]
        purpose: String,
    },
    /// Discover typed records within a bounded inventory page.
    Discover {
        head: Id,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        after: Option<Id>,
        #[arg(long, default_value_t = 100)]
        budget: usize,
    },
    /// Trace required input edges and the unresolved frontier.
    Explain {
        head: Id,
        id: Id,
        #[arg(long, default_value_t = 1000)]
        budget: usize,
        #[arg(long, default_value_t = 32)]
        depth: usize,
        #[arg(long, default_value = "read")]
        purpose: String,
    },
    /// Evaluate a query and persist its immutable receipt.
    Assess { head: Id, query: PathBuf },
    /// Serialize a bounded inventory with its permitted objects for offline exchange.
    Export {
        head: Id,
        #[arg(long)]
        after: Option<Id>,
        #[arg(long)]
        limit: Option<usize>,
        output: PathBuf,
        #[arg(long, default_value = "read")]
        purpose: String,
    },
    /// Verify and reconcile an exchange file atomically.
    Import { file: PathBuf },
    /// Sign a minimal scoring-hull disclosure and write its packet to a new file.
    Project {
        head: Id,
        receipt: Id,
        key: PathBuf,
        output: PathBuf,
    },
    /// Produce an auditable native-format mapping and exchange inventory.
    Migrate { head: Id, issuer: String },
    /// Check endpoints and dependency rewrites of a native-format mapping.
    Mapping { head: Id, id: Id },
    /// Trace a correction through labels, manifests and descendants.
    Impact {
        head: Id,
        notice: Id,
        #[arg(long)]
        mapping: Vec<Id>,
        #[arg(long, default_value_t = 10000)]
        budget: usize,
    },
    /// Record a scoped adoption or rejection from a registered, independently witnessed paired trial.
    Adopt {
        head: Id,
        request: PathBuf,
        controller_key: String,
    },
    /// Derive a scoped learning label from an immutable receipt.
    Label {
        head: Id,
        receipt: Id,
        origin: String,
        #[arg(long)]
        check: Option<String>,
        #[arg(long)]
        condition: Option<Id>,
    },
    /// Extract a dated, permission-checked training manifest.
    Train { request: PathBuf },
    /// Create an Ed25519 signing seed in a new private file.
    Keygen { output: PathBuf },
    /// Attest to the exact original record under a role and scope.
    Sign {
        head: Id,
        id: Id,
        key: PathBuf,
        role: String,
        scope: String,
    },
    /// Verify detached attestation bytes under an explicit trusted public key.
    Verify {
        head: Id,
        attestation: Id,
        target: Id,
        role: String,
        scope: String,
        public_key: String,
    },
    /// Define a unit-specific shared resource pool.
    Resource { unit: String, capacity: u64 },
    /// Reserve one authorised attempt before a facility executes it.
    Reserve {
        head: Id,
        request: PathBuf,
        public_key: String,
    },
    /// Reconcile an ambiguous attempt against a signed occurrence witness.
    Readback {
        head: Id,
        attempt: String,
        occurrence: Id,
        signature: Id,
        public_key: String,
    },
    /// Revoke a local executor authority.
    Revoke { authority: Id },
    /// Erase a payload and persist its local withdrawal marker.
    Withdraw { id: Id },
}
fn load(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut b = vec![];
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut b)?;
    ensure!(b.len() <= limit, "file budget exhausted");
    Ok(b)
}
fn input<T: DeserializeOwned>(p: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&load(p, MAX_BYTES)?)?)
}
fn print<T: Serialize>(v: T) -> Result<()> {
    serde_json::to_writer_pretty(std::io::stdout().lock(), &v)?;
    println!();
    Ok(())
}
fn publish<T>(path: &Path, write: impl FnOnce(&mut File) -> Result<T>) -> Result<T> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    let result = write(staged.as_file_mut())?;
    staged.as_file().sync_all()?;
    staged.persist_noclobber(path)?;
    Ok(result)
}
fn output(path: &Path, data: &[u8]) -> Result<()> {
    publish(path, |f| Ok(f.write_all(data)?))
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    let f = cli.format;
    let public = Id::blob(PUBLIC);
    match &cli.command {
        Command::Capabilities => {
            return print(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "capabilities": ["carrier","profile-reader","evaluator","local-executor-reservations"],
                "kits": {"A":kit::pin(Format::A),"B":kit::pin(Format::B)},
                "profile": Id::blob(profile::PROFILE),
                "measurement_profile": Id::blob(profile::MEASUREMENT_PROFILE),
                "public": public,
                "evaluators": ["simultaneous-bounds","certified-hull","signed-tests","typed-outcome","delegated","recorded-difference","least-zero","domain-inclusion","source-independence","sample-description","survey-identification","unit-grid-map"],
            }));
        }
        Command::Kit { file, sha256 } => {
            let cases = kit::test(&load(file, MAX_BYTES)?, sha256)?;
            print(&cases)?;
            ensure!(cases.iter().all(|c| c.matches), "vector mismatch");
            return Ok(());
        }
        Command::Suite { directory } => {
            return print(naome_protocol::conformance::run(
                directory,
                &input(&directory.join("cases.json"))?,
            )?);
        }
        Command::Grade {
            answer_key,
            submission,
        } => {
            let g = naome_protocol::conformance::grade(&input(answer_key)?, &input(submission)?)?;
            print(&g)?;
            ensure!(g.correct == g.total, "conformance disagreement");
            return Ok(());
        }
        Command::Trial { directory } => return print(fixture::trial(directory)?),
        Command::Keygen { output: path } => {
            let mut seed = [0; 32];
            getrandom::fill(&mut seed)
                .map_err(|e| anyhow::anyhow!("operating system randomness: {e}"))?;
            let key = SigningKey::from_bytes(&seed);
            output(path, &seed)?;
            return print(hex::encode(key.verifying_key().to_bytes()));
        }
        _ => (),
    }
    let mut db = Archive::open(cli.db)?;
    match cli.command {
        Command::Value { model } => {
            print(input::<naome_protocol::investigation::ObservationModel>(&model)?.evaluate()?)
        }
        Command::Capture {
            file,
            media,
            chunk_size,
            access,
        } => print(db.capture(
            File::open(file)?,
            &media,
            chunk_size,
            access.unwrap_or(public),
            f,
        )?),
        Command::Recover {
            head,
            descriptor,
            output: path,
            bytes,
        } => {
            let s = db.head(head)?;
            print(publish(&path, |file| {
                db.materialize(&s, descriptor, "read", bytes, file)
            })?)
        }
        Command::Select { head, request } => {
            print(db.select(&db.head(head)?, &input(&request)?, f)?)
        }
        Command::Execute {
            head,
            request,
            public_key,
            witness_key,
        } => {
            let seed: [u8; 32] = load(&witness_key, 32)?
                .try_into()
                .ok()
                .context("expected raw signing seed")?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            print(db.execute_payload_check(
                &db.head(head)?,
                &input(&request)?,
                &[public_key].into(),
                &SigningKey::from_bytes(&seed),
                now,
                f,
            )?)
        }
        Command::Init => print(json!({"profile":Id::blob(profile::PROFILE),"public":public})),
        Command::Blob { file, access } => {
            print(db.blob(&load(&file, MAX_BYTES)?, access.unwrap_or(public))?)
        }
        Command::Wire { file } => {
            let bytes = load(&file, MAX_BYTES)?;
            let r = Record::decode(&bytes, f)?;
            print(db.record(&r, f)?)
        }
        Command::Put { file, access } => {
            print(db.document(&input::<Document>(&file)?, f, access.unwrap_or(public))?)
        }
        Command::Snapshot { source, parent } => {
            print(db.snapshot(&source, parent.into_iter().collect())?.id()?)
        }
        Command::Show { head, id, purpose } => print(db.read(&db.head(head)?, id, &purpose)?),
        Command::Resolve {
            head,
            id,
            output: path,
            purpose,
        } => output(&path, &db.resolve(&db.head(head)?, id, &purpose)?),
        Command::Discover {
            head,
            kind,
            subject,
            scope,
            after,
            budget,
        } => {
            let kind = kind
                .map(|s| serde_json::from_value::<Kind>(s.into()))
                .transpose()?;
            print(db.discover(
                &db.head(head)?,
                kind,
                subject.as_deref(),
                scope.as_deref(),
                "read",
                budget,
                after,
            )?)
        }
        Command::Explain {
            head,
            id,
            budget,
            depth,
            purpose,
        } => print(db.argument_graph(&db.head(head)?, id, &purpose, budget, depth)?),
        Command::Assess { head, query } => {
            let s = db.head(head)?;
            let q = input(&query)?;
            let r = evaluation::assess(&db, &s, &q)?;
            let id = evaluation::deposit_receipt(&db, &s, &q, &r, f)?;
            print(json!({"id":id,"receipt":r}))
        }
        Command::Export {
            head,
            output: path,
            purpose,
            after,
            limit,
        } => {
            let s = db.head(head)?;
            let packet = if limit.is_some() || after.is_some() {
                db.export_page(&s, &purpose, after, limit.unwrap_or(usize::MAX))?
            } else {
                db.export(&s, &purpose)?
            };
            output(&path, &serde_json::to_vec(&packet)?)?;
            print(
                json!({"head":packet.head,"continuation":packet.continuation,"packets":packet.packets.len()}),
            )
        }
        Command::Import { file } => print(db.import(&serde_json::from_slice::<Bundle>(&load(
            &file,
            256 * 1024 * 1024,
        )?)?)?),
        Command::Project {
            head,
            receipt,
            key,
            output: path,
        } => {
            let seed: [u8; 32] = load(&key, 32)?
                .try_into()
                .ok()
                .context("expected raw signing seed")?;
            let disclosure =
                db.project_hull(&db.head(head)?, receipt, &SigningKey::from_bytes(&seed), f)?;
            output(&path, &serde_json::to_vec(&disclosure.packet)?)?;
            print(
                json!({"head":disclosure.packet.head,"queries":disclosure.queries,"private_mapping":disclosure.private_mapping}),
            )
        }
        Command::Migrate { head, issuer } => print(db.migrate(&db.head(head)?, f, &issuer)?),
        Command::Mapping { head, id } => print(db.verify_mapping(&db.head(head)?, id)?),
        Command::Impact {
            head,
            notice,
            mapping,
            budget,
        } => print(db.impact(&db.head(head)?, notice, &mapping, budget)?),
        Command::Adopt {
            head,
            request,
            controller_key,
        } => print(db.adoption(
            &db.head(head)?,
            &input(&request)?,
            &[controller_key].into(),
            f,
        )?),
        Command::Label {
            head,
            receipt,
            origin,
            check,
            condition,
        } => print(db.label(
            &db.head(head)?,
            receipt,
            &origin,
            check.as_deref(),
            condition,
            f,
        )?),
        Command::Train { request } => {
            print(db.training_manifest(&input::<learning::TrainingRequest>(&request)?, f)?)
        }
        Command::Sign {
            head,
            id,
            key,
            role,
            scope,
        } => {
            db.resolve(&db.head(head)?, id, "read")?;
            let bytes: [u8; 32] = load(&key, 32)?
                .try_into()
                .ok()
                .context("expected raw 32-byte seed")?;
            print(db.document(
                &profile::attest(
                    id,
                    &scope,
                    &role,
                    "research-policy-1",
                    &SigningKey::from_bytes(&bytes),
                )?,
                f,
                public,
            )?)
        }
        Command::Verify {
            head,
            attestation,
            target,
            role,
            scope,
            public_key,
        } => {
            let s = db.head(head)?;
            db.resolve(&s, target, "read")?;
            profile::verify_attestation(
                &db.read(&s, attestation, "read")?,
                target,
                &scope,
                &role,
                "research-policy-1",
                &[public_key].into(),
            )?;
            print("pass")
        }
        Command::Resource { unit, capacity } => db.resource(&unit, capacity),
        Command::Reserve {
            head,
            request,
            public_key,
        } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            print(db.reserve(
                &db.head(head)?,
                &input::<executor::Request>(&request)?,
                &BTreeSet::from([public_key]),
                now,
            )?)
        }
        Command::Readback {
            head,
            attempt,
            occurrence,
            signature,
            public_key,
        } => db.reconcile_attempt(
            &db.head(head)?,
            &attempt,
            occurrence,
            signature,
            &[public_key].into(),
        ),
        Command::Revoke { authority } => db.revoke(authority),
        Command::Withdraw { id } => db.withdraw(id),
        _ => unreachable!(),
    }
}
