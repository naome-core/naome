//! A separate, signed one-shot qualification allowance, never a node lifetime cap.

use super::{Control, Node, ProviderOutcome, Reservation, Step, engine::Operation};
use crate::{
    journal::read_bounded,
    state::{Id, hash, hex},
};
use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CALLS: u64 = 6;
const SECONDS: i64 = 600;
const DOMAIN: &[u8] = b"naome:siwc:sample-grant:v1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    version: u32,
    profile: Id,
    started: i64,
    deadline: i64,
    greatest_seen: i64,
    admitted: u64,
    reservations: Vec<Id>,
    checked_through: u64,
    closed: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedGrant {
    body: Grant,
    signature: Vec<u8>,
}

struct Guard {
    path: std::path::PathBuf,
    _lock: File,
}
impl Guard {
    fn open(path: &Path) -> Result<Self, String> {
        if !path.is_absolute()
            || path.parent().is_none_or(|p| !p.is_dir())
            || fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(
                "Sample grant requires an absolute ordinary file with an existing parent".into(),
            );
        }
        let lock_path = path.with_extension("sample-lock");
        if fs::symlink_metadata(&lock_path)
            .is_ok_and(|m| !m.is_file() || m.file_type().is_symlink())
        {
            return Err("Invalid sample lock path".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options
            .open(&lock_path)
            .map_err(|_| "Cannot open sample grant lock")?;
        lock.try_lock()
            .map_err(|_| "Sample grant is already being supervised")?;
        Ok(Self {
            path: path.into(),
            _lock: lock,
        })
    }
    fn save(&self, node: &Node, body: &Grant, new: bool) -> Result<(), String> {
        let signed = SignedGrant {
            body: body.clone(),
            signature: node.key.sign(&hash(DOMAIN, body)).to_bytes().to_vec(),
        };
        let bytes = serde_json::to_vec(&signed).map_err(|_| "Cannot encode sample allowance")?;
        if new {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&self.path).map_err(
                |_| "Sample grant already exists or cannot be created; no implicit reset",
            )?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "Cannot persist sample grant")?;
            return super::index::sync_directory(
                self.path.parent().ok_or("Sample parent missing")?,
            );
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| "Sample persistence randomness unavailable")?;
        let temporary = self
            .path
            .with_file_name(format!(".sample-{}", hex(&random)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options
                .open(&temporary)
                .map_err(|_| "Cannot create sample replacement")?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "Cannot persist sample allowance")?;
            drop(file);
            fs::rename(&temporary, &self.path).map_err(|_| "Cannot select sample replacement")?;
            super::index::sync_directory(self.path.parent().ok_or("Sample parent missing")?)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    fn load(&self, node: &Node) -> Result<Grant, String> {
        let signed: SignedGrant = read_bounded(&self.path, 4096)?;
        let signature =
            Signature::from_slice(&signed.signature).map_err(|_| "Invalid sample signature")?;
        node.key
            .verifying_key()
            .verify(&hash(DOMAIN, &signed.body), &signature)
            .map_err(|_| "Sample allowance signature mismatch")?;
        let body = signed.body;
        if body.version != 1
            || body.profile != node.profile.id()
            || body.started.checked_add(SECONDS) != Some(body.deadline)
            || body.greatest_seen < body.started
            || body.admitted > CALLS
            || body.reservations.len() as u64 != body.admitted
            || body
                .reservations
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != body.reservations.len()
            || body.closed.as_ref().is_some_and(|s| s.len() > 256)
        {
            return Err("Sample allowance identity or counters mismatch".into());
        }
        Ok(body)
    }
}

impl Node {
    fn sample_policy(&self) -> Result<(), String> {
        use super::budget::Period;
        if self.config.provider.responses.is_none()
            || self.config.budgets.research.amount != 1500
            || self.config.budgets.research.period != Period::Day
            || self.config.budgets.discoveries.amount != 2
            || self.config.budgets.discoveries.period != Period::Hour
            || self.config.budgets.evaluations.amount != 2
            || self.config.budgets.evaluations.period != Period::Hour
        {
            return Err("Qualification requires direct SIWC, research 1500/day, discovery 2/hour and evaluation 2/hour".into());
        }
        Ok(())
    }
    /// Explicitly create once after browser consent. An existing grant is never
    /// overwritten; restarting the sample uses this exact signed allowance.
    pub fn prepare_sample(&self, path: &Path) -> Result<Value, String> {
        self.prepare_sample_at(path, wall_time()?)
    }
    fn prepare_sample_at(&self, path: &Path, now: i64) -> Result<Value, String> {
        self.sample_policy()?;
        if self.state.attempts != 0 || self.state.finalized != 0 {
            return Err("A new qualification allocation requires a fresh node with no previous provider attempts or results".into());
        }
        let guard = Guard::open(path)?;
        let body = Grant {
            version: 1,
            profile: self.profile.id(),
            started: now,
            deadline: now.checked_add(SECONDS).ok_or("Sample deadline overflow")?,
            greatest_seen: now,
            admitted: 0,
            reservations: vec![],
            checked_through: self.checkpoint().count,
            closed: None,
        };
        guard.save(self, &body, true)?;
        Ok(report(&body, "prepared_after_operator_consent"))
    }
    pub fn run_sample(&mut self, path: &Path, control: &Control) -> Result<Value, String> {
        self.sample_policy()?;
        let guard = Guard::open(path)?;
        let mut grant = guard.load(self)?;
        self.recover_provider()?;
        self.reconcile_sample(&mut grant)?;
        guard.save(self, &grant, false)?;
        if grant.closed.is_some() || grant.admitted == CALLS {
            return self.sample_report(&grant, "closed");
        }
        let now = wall_time()?;
        if now < grant.greatest_seen || now >= grant.deadline {
            grant.closed = Some("sample_deadline_or_clock_rollback".into());
            guard.save(self, &grant, false)?;
            return self.sample_report(&grant, "closed");
        }
        let remaining = Duration::from_secs(grant.deadline.saturating_sub(now) as u64);
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher_finished = finished.clone();
        let watcher_control = control.clone();
        let watcher = std::thread::spawn(move || {
            let deadline = Instant::now() + remaining;
            while !watcher_finished.load(std::sync::atomic::Ordering::Acquire) {
                if Instant::now() >= deadline {
                    watcher_control.stop();
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let account = self
            .config
            .provider
            .responses
            .as_ref()
            .ok_or("Direct account absent")?;
        let preflight =
            crate::chatgpt::preflight(account, &self.config.provider.model, control.cancellation());
        let result = match preflight {
            Err(reason) => {
                grant.closed = Some("selected_account_model_preflight_failed".into());
                guard.save(self, &grant, false).and(Err(reason))
            }
            Ok(_) => {
                let mut provider = self.config.provider.clone();
                self.sample_loop(
                    &guard,
                    &mut grant,
                    control,
                    wall_time,
                    |reservation, control, seconds| {
                        provider.timeout_seconds = provider.timeout_seconds.min(seconds).max(1);
                        crate::chatgpt::request(
                            &provider,
                            &reservation.prompt_text,
                            reservation.schema.clone(),
                            control.cancellation(),
                        )
                    },
                )
            }
        };
        finished.store(true, std::sync::atomic::Ordering::Release);
        watcher
            .join()
            .map_err(|_| "Sample deadline supervisor failed")?;
        result
    }
    fn sample_loop<C, F>(
        &mut self,
        guard: &Guard,
        grant: &mut Grant,
        control: &Control,
        mut clock: C,
        mut request: F,
    ) -> Result<Value, String>
    where
        C: FnMut() -> Result<i64, String>,
        F: FnMut(&Reservation, &Control, u64) -> ProviderOutcome,
    {
        loop {
            self.reconcile_sample(grant)?;
            let now = clock()?;
            if control.stopped()
                || now < grant.greatest_seen
                || now >= grant.deadline
                || grant.admitted >= CALLS
                || grant.closed.is_some()
            {
                if grant.closed.is_none() {
                    grant.closed = Some(
                        if control.stopped() {
                            "operator_stop"
                        } else if grant.admitted >= CALLS {
                            "six_requests_consumed"
                        } else {
                            "sample_deadline_or_clock_rollback"
                        }
                        .into(),
                    );
                }
                guard.save(self, grant, false)?;
                return self.sample_report(grant, "closed");
            }
            grant.greatest_seen = now;
            guard.save(self, grant, false)?;
            match self.step(now)? {
                Step::Admitted(reservation) => {
                    grant.admitted = grant
                        .admitted
                        .checked_add(1)
                        .ok_or("Sample call counter exhausted")?;
                    grant.reservations.push(reservation.id());
                    guard.save(self, grant, false)?;
                    let remaining = grant.deadline.saturating_sub(clock()?).max(0) as u64;
                    let outcome = if remaining == 0 || control.stopped() {
                        ProviderOutcome {
                            reply: None,
                            error: Some(
                                "Sample stopped after durable reservation before contact".into(),
                            ),
                            known_usage: json!({"complete":false}),
                            provenance: json!({"sample_uncontacted":true}),
                            retained_raw_response: None,
                        }
                    } else {
                        request(&reservation, control, remaining)
                    };
                    let failed = outcome.error.is_some();
                    self.record_response(&reservation, outcome)?;
                    self.recover_provider()?;
                    let semantic_failure = matches!(
                        self.operation(self.checkpoint().count.saturating_sub(1))?,
                        Operation::Finish { error: Some(_), .. }
                    );
                    if failed || semantic_failure || self.state.usage_unknown.is_some() {
                        grant.closed = Some("first_failed_or_ambiguous_attempt".into());
                        guard.save(self, grant, false)?;
                        return self.sample_report(grant, "closed");
                    }
                    if self.state.finalized > 0 {
                        grant.closed = Some("first_checked_local_finalization".into());
                        guard.save(self, grant, false)?;
                        return self.sample_report(grant, "complete_local_pipeline");
                    }
                }
                Step::Progress => {}
                Step::Wait { until, reason } => {
                    if self.state.usage_unknown.is_some() || until.is_none() {
                        grant.closed = Some(format!("waiting_{reason:?}"));
                        guard.save(self, grant, false)?;
                        return self.sample_report(grant, "inconclusive");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
    fn sample_report(&self, grant: &Grant, state: &str) -> Result<Value, String> {
        Ok(
            json!({"sample":report(grant,state),"node":self.status("sample_quiescent")?,
            "qualification":"One bounded local route/account observation; no network, security or general account-eligibility claim"}),
        )
    }
    fn reconcile_sample(&self, grant: &mut Grant) -> Result<(), String> {
        let count = self.checkpoint().count;
        if count < grant.checked_through || count.saturating_sub(grant.checked_through) > 4096 {
            grant.closed = Some("sample_history_changed_outside_bounded_supervision".into());
            return Ok(());
        }
        for ordinal in grant.checked_through..count {
            match self.operation(ordinal)? {
                Operation::Reserve { reservation }
                    if !grant.reservations.contains(&reservation.id()) =>
                {
                    grant.closed = Some("untracked_or_crashed_provider_reservation".into());
                }
                Operation::Response {
                    reservation,
                    outcome,
                    semantic_error,
                    ..
                } if grant.reservations.contains(&reservation) => {
                    if outcome.error.is_some() || semantic_error.is_some() {
                        grant.closed = Some("first_failed_or_ambiguous_attempt".into());
                    }
                }
                Operation::Finish {
                    reservation,
                    error: Some(_),
                } if grant.reservations.contains(&reservation) => {
                    grant.closed = Some("first_failed_or_ambiguous_attempt".into());
                }
                _ => {}
            }
        }
        grant.checked_through = count;
        if self.state.usage_unknown.is_some()
            || self.state.in_flight.is_some()
            || self.state.received.is_some()
        {
            grant.closed = Some("first_failed_or_ambiguous_attempt".into());
        }
        if self.state.finalized > 0 {
            grant.closed = Some("first_checked_local_finalization".into());
        }
        Ok(())
    }
}
fn report(grant: &Grant, state: &str) -> Value {
    json!({"version":1,"state":state,"profile":hex(&grant.profile),"started":grant.started,"deadline":grant.deadline,
        "admitted_requests":grant.admitted,"request_limit":CALLS,"seconds_limit":SECONDS,"closed_reason":grant.closed,
        "counts_include":"all phases, failed attempts and restarts; no automatic retry or implicit reset"})
}
fn wall_time() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Sample wall clock unavailable")?
        .as_secs()
        .try_into()
        .map_err(|_| "Sample clock exhausted".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chatgpt::ResponsesConfig, provider::ProviderReply};
    const NOW: i64 = (1_790_841_600 / 3600) * 3600 + 3500;
    struct Fixture {
        root: std::path::PathBuf,
        config: super::super::Config,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "naome-sample-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let path = super::super::prepare_direct(
                &root.join("prepared"),
                ResponsesConfig {
                    version: 1,
                    credential_directory: root.join("no-credentials"),
                    account_id: "a".repeat(64),
                },
                "gpt-6-luna",
            )
            .unwrap();
            let mut config = super::super::read_config(&path).unwrap();
            config.budgets.research.amount = 1500;
            config.budgets.discoveries.amount = 2;
            config.budgets.evaluations.amount = 2;
            Self { root, config }
        }
        fn node(&self) -> Node {
            Node::initialize(self.config.clone(), NOW).unwrap()
        }
        fn path(&self) -> std::path::PathBuf {
            self.root.join("one-canonical-grant.json")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn complete(value: Value) -> ProviderOutcome {
        let total = json!({"inputTokens":1,"outputTokens":1,"totalTokens":2,"cachedInputTokens":0,"reasoningOutputTokens":0});
        let mut row = total.clone();
        row["responseId"] = json!("public-offline-sample");
        let usage = json!({"complete":true,"total":total,"responseUsage":[row]});
        ProviderOutcome::from_provider_result(
            Ok(ProviderReply {
                raw_response: value.to_string(),
                value,
                usage: usage.clone(),
                computation: vec![],
            }),
            usage,
            json!({"offline":true}),
            None,
        )
    }
    #[test]
    fn six_requests_across_a_window_boundary_persist_and_cannot_reset() {
        let f = Fixture::new();
        let mut node = f.node();
        node.prepare_sample_at(&f.path(), NOW).unwrap();
        assert!(node.prepare_sample_at(&f.path(), NOW).is_err());
        let guard = Guard::open(&f.path()).unwrap();
        let mut grant = guard.load(&node).unwrap();
        let mut ticks = 0;
        let mut discoveries = 0;
        let mut calls = 0;
        let report=node.sample_loop(&guard,&mut grant,&Control::default(),||{ticks+=1;Ok(NOW+ticks*10)},|r,_,_|{
            calls+=1;match r.phase {
                super::super::budget::Phase::Discover=>{discoveries+=1;let mut formula=json!({"op":"forall","variable":0,"body":{"op":"equal","left":0,"right":0}});for _ in 0..discoveries {formula=json!({"op":"not","body":formula});}complete(json!({"title":"Bounded sample","context":"No model call fixture","formula_json":formula.to_string(),"definitions":[]}))},
                super::super::budget::Phase::Evaluate=>complete(json!({"question_id":hex(&r.target.unwrap()),"yes":false})),
                _=>unreachable!(),
            }
        }).unwrap();
        assert_eq!(calls, 6);
        assert_eq!(report["sample"]["admitted_requests"], 6);
        drop(guard);
        drop(node);
        let mut node = Node::open(f.config.clone()).unwrap();
        let report = node.run_sample(&f.path(), &Control::default()).unwrap();
        assert_eq!(report["sample"]["admitted_requests"], 6);
        assert!(!f.root.join("no-credentials").exists());
    }
    #[test]
    fn crash_after_known_failure_before_grant_close_makes_no_further_request() {
        let f = Fixture::new();
        let mut node = f.node();
        node.prepare_sample_at(&f.path(), NOW).unwrap();
        let guard = Guard::open(&f.path()).unwrap();
        let mut grant = guard.load(&node).unwrap();
        let Step::Admitted(r) = node.step(NOW).unwrap() else {
            panic!("reservation required")
        };
        grant.admitted = 1;
        grant.reservations.push(r.id());
        guard.save(&node, &grant, false).unwrap();
        let mut outcome = complete(json!({}));
        outcome.error = Some("known terminal failure".into());
        outcome.reply = None;
        node.record_response(&r, outcome).unwrap();
        node.recover_provider().unwrap();
        assert!(grant.closed.is_none());
        drop(guard);
        drop(node);
        let mut node = Node::open(f.config.clone()).unwrap();
        let report = node.run_sample(&f.path(), &Control::default()).unwrap();
        assert_eq!(report["sample"]["admitted_requests"], 1);
        assert_eq!(
            report["sample"]["closed_reason"],
            "first_failed_or_ambiguous_attempt"
        );
        assert!(!f.root.join("no-credentials").exists());
    }
    #[test]
    fn untracked_crash_reservation_and_tampered_allowance_cannot_contact() {
        let f = Fixture::new();
        let mut node = f.node();
        node.prepare_sample_at(&f.path(), NOW).unwrap();
        let Step::Admitted(_) = node.step(NOW).unwrap() else {
            panic!("reservation required")
        };
        drop(node);
        let mut node = Node::open(f.config.clone()).unwrap();
        let report = node.run_sample(&f.path(), &Control::default()).unwrap();
        assert_eq!(report["sample"]["admitted_requests"], 0);
        assert!(report["sample"]["closed_reason"].is_string());
        assert!(!f.root.join("no-credentials").exists());
        let mut value: Value = serde_json::from_slice(&fs::read(f.path()).unwrap()).unwrap();
        value["body"]["admitted"] = json!(0);
        value["body"]["closed"] = Value::Null;
        fs::write(f.path(), serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(node.run_sample(&f.path(), &Control::default()).is_err());
    }
    #[test]
    fn crash_after_checked_finalization_before_grant_close_stops_before_preflight() {
        use super::super::{Action, SignedAction, budget::Phase};
        use crate::{
            formal::{AnswerFile, FormulaInput, Outcome},
            state::Question,
        };
        let f = Fixture::new();
        let mut node = f.node();
        let question = Question {
            title: "Exact reflexivity".into(),
            context: "Qualification crash gap".into(),
            formula: FormulaInput::Forall {
                variable: 0,
                body: Box::new(FormulaInput::Equal { left: 0, right: 0 }),
            },
            definitions: vec![],
        };
        let id = question.id().unwrap();
        node.submit(SignedAction::sign(
            node.profile.id(),
            1,
            Action::Publish { question },
            &node.key,
        ))
        .unwrap();
        node.submit(SignedAction::sign(
            node.profile.id(),
            2,
            Action::Evaluate {
                question: id,
                yes: true,
            },
            &node.key,
        ))
        .unwrap();
        node.tick(NOW).unwrap();
        node.prepare_sample_at(&f.path(), NOW).unwrap();
        let guard = Guard::open(&f.path()).unwrap();
        let mut grant = guard.load(&node).unwrap();
        let r = node
            .reserve(
                Phase::Solve,
                Some(id),
                NOW,
                "Solve exact reflexivity".into(),
                crate::run::solve_schema(),
            )
            .unwrap();
        grant.admitted = 1;
        grant.reservations.push(r.id());
        guard.save(&node, &grant, false).unwrap();
        let file=AnswerFile {source:"foundation = \"naome:zfc\"\nstatement = forall(x0, equal(x0, x0))\nproof:\n p0 = equality_reflexivity(x0)\n p1 = generalization(p0, x0)\n return p1\n".into(),dependencies:vec![]};
        node.record_response(&r,complete(json!({"question_id":hex(&id),"outcome":Outcome::Proof,"source":file.source,"dependencies":file.dependencies}))).unwrap();
        node.recover_provider().unwrap();
        assert_eq!(node.state.finalized, 1);
        assert!(grant.closed.is_none());
        drop(guard);
        drop(node);
        let mut node = Node::open(f.config.clone()).unwrap();
        let report = node.run_sample(&f.path(), &Control::default()).unwrap();
        assert_eq!(
            report["sample"]["closed_reason"],
            "first_checked_local_finalization"
        );
        assert_eq!(report["node"]["local_credit"], 1);
        assert!(!f.root.join("no-credentials").exists());
    }
}
