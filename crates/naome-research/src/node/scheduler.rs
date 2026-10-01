//! Fair, persistent phase selection and interruptible local lifecycle control.

use super::{
    ActionReceipt, Node, Reservation, SignedAction,
    budget::Phase,
    context::{Reference, StoredArtifact},
    engine::Operation,
    model::PAGE_SIZE,
    store::index_key,
};
use crate::{provider::AppServer, run::FORMAL_INSTRUCTIONS, state::hex};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, VecDeque},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Default)]
pub struct Control {
    stopped: Arc<AtomicBool>,
    wake: Arc<(Mutex<u64>, Condvar)>,
    submissions: Arc<Mutex<VecDeque<QueuedAction>>>,
    admission: Arc<Mutex<()>>,
}
struct QueuedAction {
    signed: SignedAction,
    reply: Sender<Result<ActionReceipt, String>>,
}
impl Control {
    pub fn stop(&self) {
        let _admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        self.stopped.store(true, Ordering::SeqCst);
        let queued = self
            .submissions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect::<Vec<_>>();
        for action in queued {
            let _ = action
                .reply
                .send(Err("node stopped before local action selection".into()));
        }
        self.notify();
    }
    /// Wake a dormant node after local work or an operator state change.
    pub fn notify(&self) {
        let (generation, condition) = &*self.wake;
        let mut value = generation.lock().unwrap_or_else(|e| e.into_inner());
        *value = value.wrapping_add(1);
        condition.notify_all();
    }
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
    /// Shared cancellation for the operator's OAuth/HTTP operation.
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.stopped.clone()
    }
    /// A bounded mailbox wakes the single writer without granting another
    /// process direct access to the store or provider admission ledger.
    pub fn submit(
        &self,
        signed: SignedAction,
    ) -> Result<Receiver<Result<ActionReceipt, String>>, String> {
        if self.stopped()
            || serde_json::to_vec(&signed)
                .map_err(|e| e.to_string())?
                .len()
                > 256 * 1024
        {
            return Err("stopped node or local action byte bound".into());
        }
        let (reply, receiver) = mpsc::channel();
        let mut queue = self.submissions.lock().unwrap_or_else(|e| e.into_inner());
        if self.stopped() {
            return Err("node stopped".into());
        }
        if queue.len() == 16 {
            return Err("local action mailbox full; retry after progress".into());
        }
        queue.push_back(QueuedAction { signed, reply });
        drop(queue);
        self.notify();
        Ok(receiver)
    }
    fn generation(&self) -> u64 {
        *self.wake.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn wait(&self, generation: u64, timeout: Option<Duration>) {
        let (mutex, condition) = &*self.wake;
        let guard = mutex.lock().unwrap_or_else(|e| e.into_inner());
        let unchanged = |value: &mut u64| *value == generation && !self.stopped();
        if let Some(timeout) = timeout {
            drop(
                condition
                    .wait_timeout_while(guard, timeout, unchanged)
                    .unwrap_or_else(|e| e.into_inner()),
            );
        } else {
            drop(
                condition
                    .wait_while(guard, unchanged)
                    .unwrap_or_else(|e| e.into_inner()),
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WaitReason {
    BudgetRenewal,
    RetryBackoff,
    ClockRollback,
    AccountingUnknown,
    Dormant,
}

#[derive(Debug)]
pub enum Step {
    Admitted(Box<Reservation>),
    Progress,
    Wait {
        until: Option<i64>,
        reason: WaitReason,
    },
}

impl Node {
    /// One bounded operation. A returned reservation has already been synced;
    /// no provider may be started before this method admits it.
    pub fn step(&mut self, now: i64) -> Result<Step, String> {
        // Every observed forward instant raises the durable high-water mark,
        // including an idle wait. A later new local target cannot turn a clock
        // rollback into affordable admission after a restart.
        if !self.observe(now)? {
            return Ok(Step::Wait {
                until: Some(self.state.clock),
                reason: WaitReason::ClockRollback,
            });
        }
        if !self.recover_provider()? {
            return Ok(Step::Wait {
                until: None,
                reason: WaitReason::AccountingUnknown,
            });
        }
        let mut earliest: Option<(i64, WaitReason)> = None;
        let mut wait_for = |time: i64, reason| {
            if earliest.is_none_or(|(old, _)| time < old) {
                earliest = Some((time, reason));
            }
        };
        for offset in 0..3 {
            let phase = match (self.state.phase_cursor as usize + offset) % 3 {
                0 => Phase::Discover,
                1 => Phase::Evaluate,
                _ => Phase::Solve,
            };
            let potential = match phase {
                Phase::Discover => true,
                Phase::Evaluate => self.state.unreviewed > 0,
                Phase::Solve => !self.state.leases.is_empty() || self.state.eligible > 0,
            };
            if !potential || self.config.budgets.allowance(phase).amount == 0 {
                continue;
            }
            if !self.state.available(&self.config, phase) {
                wait_for(
                    self.state.bucket(phase).window.end,
                    WaitReason::BudgetRenewal,
                );
                continue;
            }
            let backoff = self.state.backoff_until[super::engine::phase_index(phase)];
            if now < backoff {
                wait_for(backoff, WaitReason::RetryBackoff);
                continue;
            }
            let target = match phase {
                Phase::Discover => None,
                Phase::Evaluate => {
                    let start = self.state.evaluated_cursor.min(self.state.questions);
                    let end = self
                        .state
                        .questions
                        .min(start.saturating_add(PAGE_SIZE as u64));
                    let mut chosen = None;
                    for ordinal in start..end {
                        let id = self
                            .store
                            .get(index_key("question-ordinal", &ordinal))?
                            .ok_or("evaluation ordinal gap")?;
                        let entry = self.entry(id)?.ok_or("evaluation index absent")?;
                        if entry.evaluated.is_none() && entry.finalized.is_none() {
                            chosen = Some(id);
                            break;
                        }
                    }
                    if chosen.is_none() {
                        let operation = Operation::Scan {
                            cursor: if end == self.state.questions { 0 } else { end },
                        };
                        let (next, changes) = self.derive(&operation)?;
                        self.commit(operation, next, changes)?;
                        return Ok(Step::Progress);
                    }
                    chosen
                }
                Phase::Solve => {
                    if self.state.leases.is_empty() || now >= self.state.next_tick {
                        self.observe(now)?;
                        self.tick(now)?;
                        return Ok(Step::Progress);
                    }
                    Some(
                        self.state.leases[self.state.solve_cursor % self.state.leases.len()]
                            .question,
                    )
                }
            };
            let (prompt, schema) = self.prompt(phase, target)?;
            return self
                .reserve(phase, target, now, prompt, schema)
                .map(|reservation| Step::Admitted(Box::new(reservation)));
        }
        if let Some((until, reason)) = earliest {
            Ok(Step::Wait {
                until: Some(until),
                reason,
            })
        } else {
            Ok(Step::Wait {
                until: None,
                reason: WaitReason::Dormant,
            })
        }
    }

    fn prompt(
        &self,
        phase: Phase,
        target: Option<crate::state::Id>,
    ) -> Result<(String, Value), String> {
        if phase == Phase::Discover {
            return Ok((
                format!(
                    "{FORMAL_INSTRUCTIONS}\nTASK discovery. Bounded interest projection: {}. Propose exactly one closed mathematical question. formula_json is a serialized strict AST: equal(left,right), member(element,set), not(body), implies(left,right), forall(variable,body), with u32 variables, max256 nodes and depth32. Example {{\"op\":\"forall\",\"variable\":0,\"body\":{{\"op\":\"equal\",\"left\":0,\"right\":0}}}}. title and context are semantic explanations; definitions are optional conservative .nao definitions, never proof assumptions. Return the discovery JSON only.",
                    text_projection(
                        &format!(
                            "{}\n{}",
                            self.config.interests.topics.join("\n"),
                            self.config.interests.context
                        ),
                        4096
                    )
                ),
                crate::run::discovery_schema(),
            ));
        }
        let id = target.ok_or("missing prompt target")?;
        let question = self.question(id)?.ok_or("prompt question absent")?;
        let interests = text_projection(
            &format!(
                "{}\n{}",
                self.config.interests.topics.join("\n"),
                self.config.interests.context
            ),
            4096,
        );
        let title = text_projection(&question.title, 512);
        let context = text_projection(&question.context, 2048);
        if phase == Phase::Evaluate {
            return Ok((
                format!(
                    "{FORMAL_INSTRUCTIONS}\nTASK evaluation. Interest projection: {interests}. Exactly one question_id {}. Title: {}. Context: {}. Exact statement: {}. Return that exact question_id and one Boolean yes. YES requests research effort; it does not establish mathematical truth. No list or additional question is permitted.",
                    hex(&id),
                    title,
                    context,
                    question.formula.to_nao()?
                ),
                json!({"type":"object","additionalProperties":false,"required":["question_id","yes"],"properties":{"question_id":{"type":"string"},"yes":{"type":"boolean"}}}),
            ));
        }
        let available = self.available_artifacts()?;
        let entry = self
            .entry(id)?
            .ok_or("definition projection question absent")?;
        let Operation::Action { artifacts, .. } = self.operation(entry.published)? else {
            return Err("definition projection publication mismatch".into());
        };
        let definitions = artifacts
            .iter()
            .map(artifact_projection)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            format!(
                "{FORMAL_INSTRUCTIONS}\nTASK solve. Interest projection: {interests}. Exact pending question_id {}. Title: {}. Context: {}. Exact statement: {}. Conservative definitions: {}. Bounded checked artifact projection: {}. Use an available proof_id exactly in cite(\"proof_id\"). Import a definition_id under definitions: with alias = \"definition_id\". A preview marked complete=false is partial context, never a replacement for selected canonical bytes. Return the exact question_id, outcome proof or refutation, source and ordered necessary dependencies. Omit already selected helpers. Token usage is reported consumption; local credit depends only on exact checked proof possession.",
                hex(&id),
                title,
                context,
                question.formula.to_nao()?,
                serde_json::to_string(&definitions).map_err(|e| e.to_string())?,
                available
            ),
            crate::run::solve_schema(),
        ))
    }

    /// A small recent projection plus exact indexed lookup supports reuse
    /// without loading the whole historical ArtifactState.
    pub fn available_artifacts(&self) -> Result<Value, String> {
        let mut rows = vec![];
        let mut bytes = 0;
        let mut seen = BTreeSet::new();
        for ordinal in
            (self.store.checkpoint.count.saturating_sub(16)..self.store.checkpoint.count).rev()
        {
            if let Operation::Action { artifacts, .. } = self.operation(ordinal)? {
                for artifact in artifacts {
                    if rows.len() == 8 {
                        return Ok(json!(rows));
                    }
                    if !seen.insert(artifact.id) {
                        continue;
                    }
                    // Only selected representatives are advertised.
                    if self.artifact(Reference::Artifact(artifact.id))?.is_none() {
                        continue;
                    }
                    let projection = artifact_projection(&artifact)?;
                    let size = serde_json::to_vec(&projection)
                        .map_err(|e| e.to_string())?
                        .len();
                    if bytes + size > 6 * 1024 {
                        continue;
                    }
                    bytes += size;
                    rows.push(projection);
                }
            }
        }
        Ok(json!(rows))
    }
    pub fn artifact_source(&self, id: crate::state::Id) -> Result<Option<String>, String> {
        Ok(self
            .artifact(Reference::Artifact(id))?
            .map(|artifact| artifact.source))
    }

    /// The caller owns the clock and provider boundary. Tests can inject both;
    /// production uses the configured direct request or explicit legacy adapter.
    pub fn run_with<C, F>(
        &mut self,
        control: &Control,
        mut clock: C,
        mut request: F,
    ) -> Result<Value, String>
    where
        C: FnMut() -> Result<i64, String>,
        F: FnMut(&Reservation, &Control) -> super::ProviderOutcome,
    {
        loop {
            let generation = control.generation();
            if control.stopped() {
                return self.status("stopped");
            }
            let queued = control
                .submissions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front();
            if let Some(QueuedAction { signed, reply }) = queued {
                let result = self.submit(signed);
                let storage_fault = self.store.failed();
                let reason = result.as_ref().err().cloned();
                let _ = reply.send(result);
                if storage_fault {
                    return Err(reason.unwrap_or_else(|| "node storage fault".into()));
                }
                continue;
            }
            let now = clock()?;
            let step = {
                let _admission = control.admission.lock().unwrap_or_else(|e| e.into_inner());
                if control.stopped() {
                    return self.status("stopped");
                }
                self.step(now)?
            };
            match step {
                Step::Admitted(reservation) => {
                    if control.stopped() {
                        // A synced but uncontacted reservation stays consumed;
                        // do not pretend a crashed process never contacted it.
                        return self.status("stopped_with_reservation");
                    }
                    let outcome = request(&reservation, control);
                    self.record_response(&reservation, outcome)?;
                    self.recover_provider()?;
                }
                Step::Progress => {}
                Step::Wait { until, .. } => {
                    let timeout = until.map(|time| {
                        Duration::from_secs(time.saturating_sub(now).clamp(1, 30) as u64)
                    });
                    control.wait(generation, timeout);
                }
            }
        }
    }
    pub fn run(&mut self, control: &Control) -> Result<Value, String> {
        if control.stopped() {
            return self.status("stopped");
        }
        let provider = self.config.provider.clone();
        if let Some(account) = &provider.responses {
            if [
                self.config.budgets.research.amount,
                self.config.budgets.discoveries.amount,
                self.config.budgets.evaluations.amount,
            ]
            .iter()
            .any(|n| *n != 0)
            {
                crate::chatgpt::preflight(account, &provider.model, control.cancellation())?;
            }
            return self.run_with(control, wall_time, |reservation, control| {
                crate::chatgpt::request(
                    &provider,
                    &reservation.prompt_text,
                    reservation.schema.clone(),
                    control.cancellation(),
                )
            });
        }
        self.run_with(
            control,
            wall_time,
            |reservation, control| match AppServer::start(&provider) {
                Err(error) => super::ProviderOutcome {
                    reply: None,
                    error: Some(error.to_string()),
                    known_usage: json!({"complete":false}),
                    provenance: json!({"startup_failed":true}),
                    retained_raw_response: None,
                },
                Ok(mut server) => {
                    server.set_cancel(control.stopped.clone());
                    let result = server
                        .request_accounted(&reservation.prompt_text, reservation.schema.clone());
                    super::ProviderOutcome::from_provider_result(
                        result,
                        server.observed_usage(),
                        server.info(),
                        server.observed_response(),
                    )
                }
            },
        )
    }
}

fn artifact_projection(artifact: &StoredArtifact) -> Result<Value, String> {
    match naome_proof::ArtifactPayload::from_canonical_bytes(&artifact.bytes)
        .map_err(|e| e.to_string())?
    {
        naome_proof::ArtifactPayload::Proof(_) => Ok(
            json!({"kind":"proof","proof_id":hex(&artifact.reference_id),"source_preview":text_projection(&artifact.source,512)}),
        ),
        naome_proof::ArtifactPayload::Definition(definition) => {
            let body = definition
                .body()
                .clone()
                .into_primitive()
                .map_err(|e| e.to_string())?
                .to_source();
            let kind = match definition.kind() {
                naome_proof::DefinitionKind::Relation { arity } => {
                    json!({"type":"relation","arity":arity})
                }
                naome_proof::DefinitionKind::Function { input_arity } => {
                    json!({"type":"function","input_arity":input_arity})
                }
            };
            Ok(
                json!({"kind":"definition","definition_id":hex(&artifact.reference_id),"graph":kind,"canonical_body_preview":text_projection(&body,192)}),
            )
        }
    }
}

/// Charge serialized character bytes, including JSON escapes. Previews are
/// explicitly marked incomplete; they never replace immutable proof context.
fn text_projection(value: &str, maximum: usize) -> Value {
    let mut text = String::new();
    let mut bytes = 2;
    for character in value.chars() {
        let size = serde_json::to_string(&character)
            .expect("character serializes")
            .len()
            - 2;
        if bytes + size > maximum {
            break;
        }
        text.push(character);
        bytes += size;
    }
    json!({"text":text,"complete":text.len()==value.len()})
}
pub(super) fn wall_time() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs()
        .try_into()
        .map_err(|_| "wall clock exhausted".into())
}
