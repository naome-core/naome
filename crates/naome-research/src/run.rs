//! Finite participant-local discovery, vote and solve orchestration.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    formal::{AnswerFile, FormulaInput, Outcome},
    journal::{Journal, read_bounded, write_new},
    provider::{AppServer, ProviderConfig, ProviderError, ProviderErrorKind, ProviderReply},
    state::{
        Action, Genesis, Id, PoolConfig, Question, ResearchState, SignedAction, SignedGenesis,
        hash, hex,
    },
};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interests {
    pub topics: Vec<String>,
    pub context: String,
}
impl Interests {
    fn validate(&self) -> Result<(), String> {
        if self.topics.is_empty()
            || self.topics.len() > 16
            || self.topics.iter().any(|t| t.is_empty() || t.len() > 256)
            || self.context.len() > 2048
        {
            return Err("interest projection exceeds bounds".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantConfig {
    pub label: String,
    pub signing_key_file: PathBuf,
    pub interests_file: PathBuf,
    pub provider: ProviderConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunConfig {
    pub directory: PathBuf,
    pub run_label: String,
    pub coordinator_key_file: PathBuf,
    pub participants: Vec<ParticipantConfig>,
    pub pool: PoolConfig,
    pub max_calls: usize,
    pub max_seconds: u64,
    /// Explicit exception only for a consenting user's bounded local sample.
    pub shared_plan_sample: bool,
    pub tick_mode: TickMode,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TickMode {
    LocalTimer,
    SignedFixture,
}

impl RunConfig {
    fn validate(&self) -> Result<(), String> {
        if !(2..=8).contains(&self.participants.len())
            || !(1..=64).contains(&self.max_calls)
            || !(1..=3600).contains(&self.max_seconds)
        {
            return Err("participant, call or wall-time bound invalid".into());
        }
        let mut homes = BTreeSet::new();
        let mut interests = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for p in &self.participants {
            if p.label.is_empty() || p.label.len() > 64 {
                return Err("participant label invalid".into());
            }
            let home = fs::canonicalize(&p.provider.codex_home).map_err(|e| e.to_string())?;
            if !self.shared_plan_sample && !homes.insert(home) {
                return Err("each participant must own an isolated Codex home".into());
            }
            if !interests.insert(fs::canonicalize(&p.interests_file).map_err(|e| e.to_string())?)
                || !keys.insert(fs::canonicalize(&p.signing_key_file).map_err(|e| e.to_string())?)
            {
                return Err(
                    "participant interests and signing credentials must be separate".into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryReply {
    title: String,
    context: String,
    formula_json: String,
    definitions: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VoteReply {
    votes: Vec<VoteItem>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VoteItem {
    question_id: String,
    yes: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SolveReply {
    question_id: String,
    outcome: Outcome,
    source: String,
    dependencies: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    config: Id,
    ordinal: usize,
    task: usize,
    attempt: usize,
    participant: String,
    phase: String,
    prompt: Id,
    prompt_text: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    reservation: Reservation,
    status: String,
    usage: Value,
    provider: Value,
    error: Option<String>,
    head: Id,
    response_digest: Option<Id>,
}

enum ApplyError {
    Semantic(String),
    Storage(String),
}
impl From<String> for ApplyError {
    fn from(value: String) -> Self {
        Self::Semantic(value)
    }
}
impl From<&str> for ApplyError {
    fn from(value: &str) -> Self {
        Self::Semantic(value.into())
    }
}

pub fn read_config(path: &Path) -> Result<RunConfig, String> {
    read_bounded(path, MAX_CONFIG_BYTES)
}

pub fn live(config: &RunConfig) -> Result<Value, String> {
    if config.tick_mode != TickMode::LocalTimer {
        return Err("authentic provider execution requires local_timer ticks".into());
    }
    execute(config, |provider, prompt, schema| {
        let mut server = AppServer::start(provider)?;
        let info = server.info();
        let reply = server.request(prompt, schema)?;
        Ok((reply, json!({"account":info,"rate_limits":server.limits()})))
    })
}

/// A factory boundary permits offline typed-provider scenarios without inference.
pub fn execute<F>(config: &RunConfig, mut request: F) -> Result<Value, String>
where
    F: FnMut(&ProviderConfig, &str, Value) -> Result<(ProviderReply, Value), ProviderError> + Send,
{
    config.validate()?;
    let coordinator = key(&config.coordinator_key_file)?;
    let mut participants = Vec::new();
    for p in &config.participants {
        let signing = key(&p.signing_key_file)?;
        let interests: Interests = read_bounded(&p.interests_file, 8192)?;
        interests.validate()?;
        participants.push((signing, interests));
    }
    let mut genesis = Genesis::new(
        config.run_label.clone(),
        coordinator.verifying_key().to_bytes(),
        participants
            .iter()
            .map(|(k, _)| k.verifying_key().to_bytes())
            .collect(),
        config.pool.clone(),
    )?;
    genesis.tick_driver = match config.tick_mode {
        TickMode::LocalTimer => "local_timer",
        TickMode::SignedFixture => "signed_fixture",
    }
    .into();
    let expected = SignedGenesis::sign(genesis, &coordinator)?;
    fs::create_dir_all(&config.directory).map_err(|e| e.to_string())?;
    let journal_path = config.directory.join("history");
    let (journal, mut state) = if journal_path.exists() {
        let (j, s) = Journal::open(&journal_path)?;
        if s.genesis() != &expected {
            return Err("saved genesis does not match participant configuration".into());
        }
        (j, s)
    } else {
        (
            Journal::create(&journal_path, &expected)?,
            ResearchState::new(expected)?,
        )
    };
    let call_path = config.directory.join("provider_calls");
    fs::create_dir_all(&call_path).map_err(|e| e.to_string())?;
    let config_id = hash(b"naome:research:run-config:v1\0", config);
    let budget_file = call_path.join("config.json");
    if budget_file.exists() {
        let pinned: Id = read_bounded(&budget_file, 1024)?;
        if pinned != config_id {
            return Err("provider budget configuration is pinned; start a separately authorized run to change it".into());
        }
    } else {
        write_new(&budget_file, &config_id)?;
    }
    let mut calls = 0;
    let mut next_task = 0;
    let mut stopped = None;
    let mut retry_task = None;
    while call_path.join(format!("call-{calls:04}.json")).exists() {
        let reservation: Reservation =
            read_bounded(&call_path.join(format!("call-{calls:04}.json")), 8192)?;
        if reservation.ordinal != calls || reservation.config != config_id {
            return Err("provider reservation mismatch".into());
        }
        let receipt_file = call_path.join(format!("receipt-{calls:04}.json"));
        if !receipt_file.exists() {
            return Err("unfinished provider reservation; call budget remains consumed, inspect before resuming".into());
        }
        let receipt: Receipt = read_bounded(&receipt_file, MAX_CONFIG_BYTES)?;
        if receipt.reservation.ordinal != calls || receipt.reservation.config != config_id {
            return Err("provider receipt mismatch".into());
        }
        if reservation.attempt > 1 {
            return Err("provider retry bound exceeded".into());
        }
        next_task = if receipt.status == "backoff" {
            retry_task = Some(reservation.task);
            reservation.task
        } else {
            reservation.task + 1
        };
        if receipt.status == "stopped" {
            stopped = receipt.error;
        }
        calls += 1;
        if calls > config.max_calls {
            return Err("saved provider call budget exceeded".into());
        }
    }
    if let Some(reason) = stopped {
        return Ok(report(&state, calls, config, "stopped", Some(reason)));
    }
    let start = Instant::now();
    let mut next_tick = start + Duration::from_secs(60);
    let participant_count = config.participants.len();
    let mut attempts = BTreeSet::new();
    let mut rejections = Vec::new();
    let mut task = next_task;
    let task_limit = config.max_calls * 3 + participant_count * 3;
    while task < task_limit {
        if calls >= config.max_calls || start.elapsed().as_secs() >= config.max_seconds {
            break;
        }
        let index = task % participant_count;
        let phase = (task / participant_count) % 3;
        if phase == 0 && index == 0 {
            attempts.clear();
        }
        if phase == 2
            && index == 0
            && state.active().is_empty()
            && !state.ranked_candidates().is_empty()
        {
            if config.tick_mode == TickMode::LocalTimer {
                let remaining = next_tick.saturating_duration_since(Instant::now());
                if start.elapsed() + remaining >= Duration::from_secs(config.max_seconds) {
                    break;
                }
                thread::sleep(remaining);
                next_tick = Instant::now() + Duration::from_secs(60);
            }
            append_tick(&mut state, &journal, &coordinator)?;
        }
        let (signing, interests) = &participants[index];
        let participant = &config.participants[index];
        let (prompt, schema, target) = match phase {
            0 => (discover_prompt(interests), discovery_schema(), None),
            1 => {
                if state.questions().keys().all(|id| state.solved(*id)) {
                    task += 1;
                    continue;
                }
                (vote_prompt(interests, &state)?, vote_schema(), None)
            }
            _ => {
                let Some(target) = state
                    .active()
                    .iter()
                    .find(|id| !attempts.contains(*id))
                    .copied()
                else {
                    task += 1;
                    continue;
                };
                attempts.insert(target);
                (
                    solve_prompt(
                        interests,
                        target,
                        state
                            .questions()
                            .get(&target)
                            .ok_or("active question missing")?,
                        &state,
                    )?,
                    solve_schema(),
                    Some(target),
                )
            }
        };
        let phase_name = ["discovery", "vote", "solve"][phase].to_owned();
        let attempt = usize::from(retry_task == Some(task));
        let reservation = Reservation {
            config: config_id,
            ordinal: calls,
            task,
            attempt,
            participant: participant.label.clone(),
            phase: phase_name,
            prompt: hash(b"naome:research:prompt:v1\0", &prompt),
            prompt_text: prompt.clone(),
        };
        // Consume the reservation durably before contacting any provider.
        write_new(
            &call_path.join(format!("call-{calls:04}.json")),
            &reservation,
        )?;
        let mut bounded = participant.provider.clone();
        bounded.timeout_seconds = bounded.timeout_seconds.min(
            config
                .max_seconds
                .saturating_sub(start.elapsed().as_secs())
                .max(1),
        );
        let response = thread::scope(|scope| -> Result<_, String> {
            let (sender, receiver) = mpsc::sync_channel(1);
            let request_ref = &mut request;
            scope.spawn(move || {
                let _ = sender.send(request_ref(&bounded, &prompt, schema));
            });
            loop {
                let wait = if config.tick_mode == TickMode::LocalTimer {
                    next_tick.saturating_duration_since(Instant::now())
                } else {
                    Duration::from_secs(1)
                };
                match receiver.recv_timeout(wait) {
                    Ok(reply) => break Ok(reply),
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        break Err("provider worker ended without response".into());
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if config.tick_mode == TickMode::LocalTimer {
                            append_tick(&mut state, &journal, &coordinator)?;
                            next_tick = Instant::now() + Duration::from_secs(60);
                        }
                    }
                }
            }
        })?;
        let mut status = "accepted".to_owned();
        let mut error = None;
        let mut usage = Value::Null;
        let mut provider = Value::Null;
        let mut response_digest = None;
        match response {
            Ok((reply, info)) => {
                if reply.raw_response.len() > participant.provider.max_output_bytes
                    || serde_json::from_str::<Value>(&reply.raw_response)
                        .ok()
                        .as_ref()
                        != Some(&reply.value)
                {
                    return Err("provider response preservation contract failed; reservation remains consumed".into());
                }
                // Original final text is retained before semantic checking or any
                // durable state transition, including rejected provider outputs.
                write_new(&call_path.join(format!("response-{calls:04}.json")), &reply)?;
                response_digest = Some(hash(b"naome:research:response:v1\0", &reply.raw_response));
                usage = reply.usage;
                provider = info;
                if let Err(reason) = apply_reply(
                    phase,
                    target,
                    reply.value,
                    &mut state,
                    &journal,
                    signing,
                    &coordinator,
                ) {
                    match reason {
                        ApplyError::Semantic(reason) => {
                            status = "rejected".into();
                            error = Some(reason.clone());
                            rejections.push(reason);
                        }
                        ApplyError::Storage(reason) => {
                            return Err(format!(
                                "durable append failed; research stops with consumed reservation: {reason}"
                            ));
                        }
                    }
                }
            }
            Err(failure) => {
                status = if failure.kind == ProviderErrorKind::Transient && attempt == 0 {
                    "backoff"
                } else {
                    "stopped"
                }
                .into();
                error = Some(format!("{:?}: {}", failure.kind, failure.message));
            }
        }
        let receipt = Receipt {
            reservation,
            status: status.clone(),
            usage,
            provider,
            error: error.clone(),
            head: state.head(),
            response_digest,
        };
        write_new(
            &call_path.join(format!("receipt-{calls:04}.json")),
            &receipt,
        )?;
        calls += 1;
        if status == "stopped" {
            return Ok(report(&state, calls, config, "stopped", error));
        }
        if status == "backoff" {
            retry_task = Some(task);
            if let Some(target) = target {
                attempts.remove(&target);
            }
            if calls < config.max_calls {
                thread::sleep(Duration::from_secs(1));
            }
            continue;
        }
        retry_task = None;
        if phase == 2
            && index + 1 == participant_count
            && config.tick_mode == TickMode::SignedFixture
        {
            append_tick(&mut state, &journal, &coordinator)?;
        }
        task += 1;
    }
    let status = if calls >= config.max_calls {
        "call_budget_exhausted"
    } else if start.elapsed().as_secs() >= config.max_seconds {
        "time_budget_exhausted"
    } else {
        "complete"
    };
    Ok(json!({"run":report(&state,calls,config,status,None),"rejected_replies":rejections}))
}

fn apply_reply(
    phase: usize,
    target: Option<Id>,
    value: Value,
    state: &mut ResearchState,
    journal: &Journal,
    signing: &SigningKey,
    coordinator: &SigningKey,
) -> Result<(), ApplyError> {
    let mut actions = Vec::new();
    match phase {
        0 => {
            let reply: DiscoveryReply = serde_json::from_value(value).map_err(|e| e.to_string())?;
            if reply.formula_json.len() > 8192 {
                return Err("formula projection byte limit".into());
            }
            let formula: FormulaInput =
                serde_json::from_str(&reply.formula_json).map_err(|e| e.to_string())?;
            actions.push(Action::Publish {
                question: Question {
                    title: reply.title,
                    context: reply.context,
                    formula,
                    definitions: reply.definitions,
                },
            });
        }
        1 => {
            let reply: VoteReply = serde_json::from_value(value).map_err(|e| e.to_string())?;
            if reply.votes.len()
                != state
                    .questions()
                    .keys()
                    .filter(|id| !state.solved(**id))
                    .count()
            {
                return Err(
                    "vote reply must answer every published unanswered question exactly once"
                        .into(),
                );
            }
            let mut seen = BTreeSet::new();
            for vote in reply.votes {
                let id = parse_id(&vote.question_id)?;
                if !state.questions().contains_key(&id) || state.solved(id) || !seen.insert(id) {
                    return Err("vote substituted or duplicated question".into());
                }
                if state.vote(signing.verifying_key().to_bytes(), id) != Some(vote.yes) {
                    actions.push(Action::Vote {
                        question: id,
                        yes: vote.yes,
                    });
                }
            }
        }
        _ => {
            let reply: SolveReply = serde_json::from_value(value).map_err(|e| e.to_string())?;
            let id = parse_id(&reply.question_id)?;
            if Some(id) != target {
                return Err("solve reply substituted target".into());
            }
            actions.push(Action::Answer {
                question: id,
                outcome: reply.outcome,
                file: AnswerFile {
                    source: reply.source,
                    dependencies: reply.dependencies,
                },
            });
        }
    }
    // Validate the entire typed reply against a clone before recording any action.
    let mut next = state.clone();
    let mut events = Vec::new();
    for action in actions {
        let signed = SignedAction::sign(
            next.genesis().genesis.id(),
            next.next_nonce(signing.verifying_key().to_bytes()),
            action,
            signing,
        );
        events.push(next.confirm(signed, coordinator)?);
    }
    for event in events {
        journal.append(&event).map_err(ApplyError::Storage)?;
    }
    *state = next;
    Ok(())
}

fn report(
    state: &ResearchState,
    calls: usize,
    config: &RunConfig,
    status: &str,
    error: Option<String>,
) -> Value {
    json!({"status":status,"error":error,"provider_calls_consumed":calls,"provider_call_cap":config.max_calls,
        "shared_consenting_user_plan_sample":config.shared_plan_sample,"events":state.events().len(),"result_blocks":state.results().len(),
        "head":hex(&state.head()),"active":state.active().iter().map(|id|hex(id)).collect::<Vec<_>>(),"target":state.target(),
        "evidence":"participant-local provider execution and local serial coordinator; no public finality or scientific usefulness qualification"})
}

fn append_tick(
    state: &mut ResearchState,
    journal: &Journal,
    coordinator: &SigningKey,
) -> Result<(), String> {
    let mut next = state.clone();
    let action = SignedAction::sign(
        next.genesis().genesis.id(),
        next.next_nonce(coordinator.verifying_key().to_bytes()),
        Action::Tick,
        coordinator,
    );
    let event = next.confirm(action, coordinator)?;
    journal.append(&event)?;
    *state = next;
    Ok(())
}

fn key(path: &Path) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&read_bounded::<[u8; 32]>(
        path, 1024,
    )?))
}

pub fn parse_id(value: &str) -> Result<Id, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("question id must be 64 lowercase hex digits".into());
    }
    let mut id = [0; 32];
    for (n, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |v: u8| if v <= b'9' { v - b'0' } else { v - b'a' + 10 };
        id[n] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(id)
}

fn schema(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}
fn discovery_schema() -> Value {
    schema(
        json!({"title":{"type":"string"},"context":{"type":"string"},"formula_json":{"type":"string"},"definitions":{"type":"array","items":{"type":"string"}}}),
        &["title", "context", "formula_json", "definitions"],
    )
}
fn vote_schema() -> Value {
    schema(
        json!({"votes":{"type":"array","items":schema(json!({"question_id":{"type":"string"},"yes":{"type":"boolean"}}),&["question_id","yes"])}}),
        &["votes"],
    )
}
fn solve_schema() -> Value {
    schema(
        json!({"question_id":{"type":"string"},"outcome":{"type":"string","enum":["proof","refutation"]},"source":{"type":"string"},"dependencies":{"type":"array","items":{"type":"string"}}}),
        &["question_id", "outcome", "source", "dependencies"],
    )
}

const FORMAL_INSTRUCTIONS: &str = "You are a participant-local mathematical research assistant. You have no tools or environment access. Return only the requested strict JSON. Text is semantic context and never proof authority. Never invent axioms, assertion rules or use model judgment as proof validity. Work in Foundation naome:zfc, primitive equality/membership, not_, implies and forall. A final .nao file must use the existing checker rules. Example valid source: foundation = \"naome:zfc\"\nstatement = forall(x0, equal(x0, x0))\nproof:\n p0 = equality_reflexivity(x0)\n p1 = generalization(p0, x0)\n return p1\n. Supported proof rules: equality_reflexivity(variable), generalization(premise,variable), modus_ponens(premise,implication), simplification(A,B) yielding implies(A,implies(B,A)), frege(A,B,C) yielding implies(implies(A,implies(B,C)),implies(implies(A,B),implies(A,C))), classical_contraposition(A,B) yielding implies(implies(not_(B),not_(A)),implies(A,B)), universal_distribution(variable,A,B), vacuous_universal(A), universal_instantiation(variable,replacement,body), equality_substitution(from,to,body), zfc_axiom(quoted selector: extensionality|pairing|union|power_set|infinity|foundation|choice), cite(\"proof_id\"). cite requires an available checked source dependency; do not guess IDs. No double_negation or arbitrary axiom rule exists. A proof conclusion equals the exact question, a refutation conclusion equals its ONE syntactic negation (no automatic double-negation normalization). Definitions are conservative aliases, never arbitrary assumptions. Unsolvable or invalid output may be rejected; do not fabricate validity.";

fn discover_prompt(interests: &Interests) -> String {
    format!(
        "{FORMAL_INSTRUCTIONS}\nTASK discovery. Interest projection: {}. Propose one closed mathematical question in the available primitive language. Keep it small enough for this bounded checker exercise. formula_json is a serialized strict AST with op equal(left,right), member(element,set), not(body), implies(left,right), forall(variable,body); variables are u32 numbers, nodes max256/depth32. Example {{\"op\":\"forall\",\"variable\":0,\"body\":{{\"op\":\"equal\",\"left\":0,\"right\":0}}}}. title and context explain the question; definitions may be empty. Conservative .nao definitions only. Do not submit a proof in the discovery reply.",
        serde_json::to_string(interests).unwrap()
    )
}
fn vote_prompt(interests: &Interests, state: &ResearchState) -> Result<String, String> {
    let questions=state.questions().iter().filter(|(id,_)|!state.solved(**id)).map(|(id,q)|Ok(json!({"question_id":hex(id),"title":q.title,"context":q.context,"statement":q.formula.to_nao()?}))).collect::<Result<Vec<_>,String>>()?;
    Ok(format!(
        "{FORMAL_INSTRUCTIONS}\nTASK vote. Interest projection: {}. Questions: {}. Cast one Boolean yes/no relevance vote for EVERY listed exact question_id according to your interests. yes means it should receive research effort, not that the claim is true; no does not subtract other participants' votes.",
        serde_json::to_string(interests).unwrap(),
        serde_json::to_string(&questions).unwrap()
    ))
}
fn solve_prompt(
    interests: &Interests,
    id: Id,
    q: &Question,
    state: &ResearchState,
) -> Result<String, String> {
    let available = available_projection(state);
    Ok(format!(
        "{FORMAL_INSTRUCTIONS}\nTASK solve. Interest projection: {}. Exact published ACTIVE UNSOLVED question_id {}. Title: {}. Context: {}. Exact statement: {}. Conservative definition source context: {}. Recent already checked available artifact projection: {}. Use proof_id exactly in cite(\"proof_id\"). Import a definition under the definitions: section with alias = \"definition_id\". Return this exact question_id and a .nao proof source with outcome proof or refutation. dependencies is an ordered necessary checked .nao helper closure, may be empty. Already published helpers need not be supplied again. Answer the exact statement, never another easier claim. Private duration and computation cost have no effect on settlement.",
        serde_json::to_string(interests).unwrap(),
        hex(&id),
        q.title,
        q.context,
        q.formula.to_nao()?,
        serde_json::to_string(&q.definitions).unwrap(),
        serde_json::to_string(&available).unwrap()
    ))
}

fn available_projection(state: &ResearchState) -> Vec<crate::formal::AvailableArtifact> {
    let mut available = Vec::new();
    let mut bytes = 0;
    let mut inspected = 0;
    let mut identities = std::collections::BTreeSet::new();
    for event in state.events().iter().rev() {
        let sources: Vec<&str> = match &event.body.action.body.action {
            Action::Answer { file, .. } if event.body.result.is_some() => file
                .dependencies
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(file.source.as_str()))
                .collect(),
            Action::Publish { question } => {
                question.definitions.iter().map(String::as_str).collect()
            }
            _ => Vec::new(),
        };
        for source in sources {
            if available.len() == 8 || inspected == 16 {
                return available;
            }
            inspected += 1;
            if bytes + source.len() > 12 * 1024 {
                continue;
            }
            bytes += source.len();
            if let Some(artifact) = crate::formal::available_artifact(source, state.artifacts()) {
                let identity = match &artifact {
                    crate::formal::AvailableArtifact::Proof { proof_id, .. } => proof_id,
                    crate::formal::AvailableArtifact::Definition { definition_id, .. } => {
                        definition_id
                    }
                };
                if identities.insert(identity.clone()) {
                    available.push(artifact);
                }
            }
        }
    }
    available
}

/// Creates a bounded example configuration; users sign into each Codex home
/// themselves. The optional shared home is only an explicit local sample mode.
pub fn prepare(
    root: &Path,
    codex_home: &Path,
    model: &str,
    shared_sample: bool,
) -> Result<PathBuf, String> {
    if !root.is_absolute() || !codex_home.is_absolute() || model.is_empty() {
        return Err("absolute paths and explicit model required".into());
    }
    let codex_binary = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join(if cfg!(windows) { "codex.exe" } else { "codex" }))
        .find(|path| path.is_file())
        .ok_or("Codex CLI must be installed and available on PATH")?;
    let codex_binary = fs::canonicalize(codex_binary).map_err(|e| e.to_string())?;
    fs::create_dir(root).map_err(|e| e.to_string())?;
    let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).map_err(|e| e.to_string())?;
    let coordinator_key_file = root.join("coordinator-key.json");
    write_new(&coordinator_key_file, &seed)?;
    let mut participants = Vec::new();
    for index in 0..2 {
        getrandom::fill(&mut seed).map_err(|e| e.to_string())?;
        let signing_key_file = root.join(format!("participant-{index}-key.json"));
        write_new(&signing_key_file, &seed)?;
        let interests_file = root.join(format!("participant-{index}-interests.json"));
        let interests = if index == 0 {
            Interests {
                topics: vec!["Equality and elementary mathematical foundations".into()],
                context: "Investigate small universally quantified equality questions.".into(),
            }
        } else {
            Interests {topics:vec!["Formal refutations and elementary logic".into()],context:"Investigate a false negation of a simple closed equality theorem and its formal refutation.".into()}
        };
        write_new(&interests_file, &interests)?;
        let home = if shared_sample {
            codex_home.to_path_buf()
        } else {
            codex_home.join(format!("participant-{index}"))
        };
        if !shared_sample {
            fs::create_dir_all(&home).map_err(|e| e.to_string())?;
        }
        participants.push(ParticipantConfig {
            label: format!("participant-{index}"),
            signing_key_file,
            interests_file,
            provider: ProviderConfig {
                codex_binary: codex_binary.clone(),
                codex_home: home,
                model: model.into(),
                timeout_seconds: 90,
                max_output_bytes: 256 * 1024,
            },
        });
    }
    let config = RunConfig {
        directory: root.join("run"),
        run_label: format!(
            "local-research-{}",
            hex(&hash(b"run-label", &seed))[..12].to_owned()
        ),
        coordinator_key_file,
        participants,
        pool: PoolConfig::default(),
        max_calls: 6,
        max_seconds: 540,
        shared_plan_sample: shared_sample,
        tick_mode: TickMode::LocalTimer,
    };
    let config_path = root.join("config.json");
    write_new(&config_path, &config)?;
    Ok(config_path)
}

#[cfg(test)]
mod tests;
