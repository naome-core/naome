use super::{
    Result,
    control::{self, Request},
    files,
    setup::NodeConfig,
};
use naome_ledger::{
    AccountId, QuestionId, authentication::SignedOperation, operations::OperationBody,
};
mod budget;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    os::unix::process::CommandExt,
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<u64>,
    decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    provider: String,
    tool_calls: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assessment: Option<serde_json::Value>,
}
struct ProcessGroup(Option<rustix::process::Pid>);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
}
async fn invoke(executable: &Path, input: &[u8], seconds: u64) -> Result<Decision> {
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("PATH unavailable")?)
        .env("HOME", std::env::var_os("HOME").ok_or("HOME unavailable")?);
    if let Some(home) = std::env::var_os("CODEX_HOME") {
        command.env("CODEX_HOME", home);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    let mut child = command.spawn()?;
    let _group = ProcessGroup(
        child
            .id()
            .and_then(|id| rustix::process::Pid::from_raw(id as i32)),
    );
    let mut input_pipe = child.stdin.take().ok_or("provider stdin unavailable")?;
    let output_pipe = child.stdout.take().ok_or("provider stdout unavailable")?;
    tokio::time::timeout(Duration::from_secs(seconds), async {
        input_pipe.write_all(input).await?;
        drop(input_pipe);
        let mut output = Vec::new();
        output_pipe.take(8193).read_to_end(&mut output).await?;
        if output.len() > 8192 {
            return Err::<Decision, Box<dyn std::error::Error + Send + Sync>>(
                "agent output exceeds 8192 bytes".into(),
            );
        }
        let status = child.wait().await?;
        if !status.success() {
            return Err("agent provider failed; no vote signed".into());
        }
        let decision: Decision = serde_json::from_slice(&output)?;
        if !valid_decision(&decision) {
            return Err("invalid bounded agent decision".into());
        }
        if serde_json::from_slice::<serde_json::Value>(input).is_ok_and(|v| v["version"] == 2)
            && decision.version != Some(2)
        {
            return Err("configured v2 request requires a bound v2 assessment".into());
        }
        if let Some(assessment) = &decision.assessment
            && assessment["input_sha256"] != files::hex(&Sha256::digest(input))
        {
            return Err("agent assessment does not bind the input request".into());
        }
        Ok(decision)
    })
    .await
    .map_err(|_| "agent time limit reached; no vote signed")?
}

fn valid_decision(decision: &Decision) -> bool {
    if decision.provider.trim().is_empty()
        || decision.provider.len() > 128
        || decision
            .reason
            .as_ref()
            .is_some_and(|s| s.trim().is_empty() || s.len() > 4096)
    {
        return false;
    }
    match decision.version.unwrap_or(1) {
        1 => {
            matches!(decision.decision.as_str(), "YES" | "NO")
                && decision.reason.is_some()
                && decision.assessment.is_none()
        }
        2 => {
            matches!(decision.decision.as_str(), "YES" | "NO" | "REVIEW")
                && decision.assessment.as_ref().is_some_and(|a| {
                    a.is_object()
                        && a["input_sha256"]
                            .as_str()
                            .is_some_and(|s| files::unhex::<32>(s).is_ok())
                        && serde_json::to_vec(a).is_ok_and(|bytes| bytes.len() <= 6144)
                })
        }
        _ => false,
    }
}
fn voting(status: &serde_json::Value, genesis: &str, question: &str, attempt: u64) -> Result<()> {
    if status["genesis"] != genesis
        || status["active"]["question"] != question
        || status["active"]["attempt"] != attempt
        || status["active"]["phase"] != "Voting"
    {
        return Err("question or phase changed during agent review; no vote signed".into());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    if now
        >= status["active"]["deadline"]
            .as_u64()
            .ok_or("voting deadline unavailable")?
    {
        return Err("agent decision arrived after the voting deadline; no vote signed".into());
    }
    Ok(())
}
fn retained(
    bytes: &[u8],
    genesis: &naome_ledger::profile::Genesis,
    author: AccountId,
) -> Result<SignedOperation> {
    let operation = SignedOperation::decode(bytes)?;
    operation.verify(genesis)?;
    if operation.author() != author
        || !matches!(
            OperationBody::decode(operation.payload(), genesis)?,
            OperationBody::Vote { .. }
        )
    {
        return Err("retained agent action has the wrong author or operation kind".into());
    }
    Ok(operation)
}

fn save_report(
    path: &Path,
    report: &serde_json::Value,
    operation: Option<&SignedOperation>,
) -> Result<()> {
    if path.try_exists()?
        && let Some(operation) = operation
    {
        let bytes = files::read(path, 16384, true)?;
        let mut legacy: serde_json::Value = serde_json::from_slice(&bytes)?;
        if legacy["operation"] == files::hex(operation.id().as_bytes()) {
            if let Some(object) = legacy.as_object_mut() {
                object.remove("operation");
            }
            if &legacy == report {
                // A pre-upgrade crash could retain its report and budget.action
                // before the caller's ACTION_FILE. Preserve that exact evidence.
                return files::create_or_match(path, &bytes, true);
            }
        }
    }
    files::create_or_match(path, &serde_json::to_vec_pretty(report)?, true)
}

pub async fn run(args: &[String]) -> Result<()> {
    execute(args, false).await
}

pub async fn review(args: &[String]) -> Result<()> {
    if !matches!(args.len(), 4 | 6) {
        return Err("usage: agent-review CONFIG ACCOUNT_KEY REPORT_FILE PROVIDER_EXECUTABLE [--provider-config FILE]".into());
    }
    // No action path is consulted in review mode, including exact retry paths.
    let mut normalized = args.to_vec();
    normalized.insert(2, String::new());
    execute(&normalized, true).await
}

async fn execute(args: &[String], review_only: bool) -> Result<()> {
    if !matches!(args.len(), 5 | 7) || (args.len() == 7 && args[5] != "--provider-config") {
        return Err(
            "usage: agent-vote CONFIG ACCOUNT_KEY ACTION_FILE REPORT_FILE PROVIDER_EXECUTABLE [--provider-config FILE]"
                .into(),
        );
    }
    let config = NodeConfig::read(Path::new(&args[0]))?;
    let genesis = config.genesis()?;
    let key = files::key(Path::new(&args[1]), 1)?;
    let author = AccountId::for_key(key.verifying_key().as_bytes());
    let configured_key = files::key(&config.account_key, 1)?;
    if configured_key.verifying_key() != key.verifying_key()
        || !genesis.validators().iter().any(|v| v.owner == author)
    {
        return Err("agent review requires this node's registered validator owner".into());
    }
    // A retained signed vote is an exact retry and needs no fresh inference.
    let action_path = Path::new(&args[2]);
    if !review_only && action_path.try_exists()? {
        let bytes = files::read(action_path, 65536, true)?;
        let operation = retained(&bytes, &genesis, author)?;
        files::create_or_match(action_path, &bytes, true)?;
        let result = control::call(
            &config,
            Request::Submit {
                bytes: files::hex(&bytes),
            },
        )
        .await?;
        println!(
            "{}",
            json!({"retained_vote":files::hex(operation.id().as_bytes()),"submission":result})
        );
        return Ok(());
    }
    let status = control::call(&config, Request::Status {}).await?;
    let question_id = status["active"]["question"]
        .as_str()
        .ok_or("question ID unavailable")?
        .to_owned();
    let attempt = status["active"]["attempt"]
        .as_u64()
        .ok_or("attempt unavailable")?;
    let genesis_id = files::hex(genesis.id().as_bytes());
    voting(&status, &genesis_id, &question_id, attempt)?;
    let submission = status["active"]["submission"]
        .as_str()
        .ok_or("submission unavailable")?
        .to_owned();
    let question = control::call(&config, Request::Question { id: submission }).await?;
    let profile = String::from_utf8(files::read(&config.agenda_profile, 16384, true)?)?;
    if profile.trim().is_empty() {
        return Err("operator research profile is empty".into());
    }
    let mut input = json!({"version":1,"profile":profile,"question":question["source"],"purpose":question["purpose"],"question_id":question_id,"attempt":attempt,"genesis":genesis_id,"author":files::hex(author.as_bytes())});
    if args.len() == 7 {
        input["version"] = json!(2);
        input["formal_targets"] = question["formal_targets"].clone();
        input["foundation"] = json!(genesis.foundation());
        input["checker_profile"] = json!(genesis.checker_profile());
        // Configuration contains local runtime settings and model/policy versions.
        // It is frozen into the durable context along with model/policy versions.
        input["provider_config"] =
            serde_json::from_slice(&files::read(Path::new(&args[6]), 8192, true)?)?;
    }
    let context = files::hex(&Sha256::digest(serde_json::to_vec(&input)?));
    let limits = genesis.profile().limits();
    let budget = budget::Budget::open(
        &config.signer,
        &question_id,
        attempt,
        context,
        limits.agent_inference_attempts,
        limits.agent_tool_calls,
    )?;
    let outcome = loop {
        let (used, remaining, accepted) = budget.load()?;
        if let Some(outcome) = accepted {
            break outcome;
        }
        if used >= limits.agent_inference_attempts {
            return Err(
                "durable agent inference or tool-call limit exhausted; no vote signed".into(),
            );
        }
        input["agent_budget"] = json!({"inference_attempt":used+1,"maximum_inference_attempts":limits.agent_inference_attempts,"remaining_tool_calls":remaining});
        let bytes = serde_json::to_vec(&input)?;
        if bytes.len() > 65536 {
            return Err("agent request exceeds its 64 KiB input limit".into());
        }
        let executable = Path::new(&args[4]).canonicalize()?;
        let request = budget.reserve(used + 1, remaining, &bytes)?;
        let started = Instant::now();
        if let Ok(decision) = invoke(
            &executable,
            &bytes,
            genesis.profile().timing().agent_call_seconds,
        )
        .await
        {
            budget.complete(
                used + 1,
                request,
                decision,
                u64::try_from(started.elapsed().as_millis())?,
            )?;
        }
    };
    let latest = control::call(&config, Request::Status {}).await?;
    voting(&latest, &genesis_id, &question_id, attempt)?;
    let mut report = json!({"kind":"actual_agent_review","request_sha256":outcome.request,"question_id":question_id,"genesis":genesis_id,"decision":outcome.decision,"attempts":outcome.index,"elapsed_ms":outcome.elapsed_ms,"authority":"operator agenda vote only; no proof-validity authority"});
    if review_only || outcome.decision.decision == "REVIEW" {
        files::create_or_match(
            Path::new(&args[3]),
            &serde_json::to_vec_pretty(&report)?,
            true,
        )?;
        println!(
            "{}",
            json!({"agent_review":report,"vote_signed":false,"submission":null})
        );
        return Ok(());
    }
    let yes = match outcome.decision.decision.as_str() {
        "YES" => true,
        "NO" => false,
        _ => return Err("agent result does not authorize a vote".into()),
    };
    let body = OperationBody::Vote {
        question: QuestionId::from_bytes(files::unhex(&question_id)?),
        attempt,
        yes,
    };
    let retained_path = budget.path("action");
    let operation = if retained_path.try_exists()? {
        let bytes = files::read(&retained_path, 65536, true)?;
        let operation = retained(&bytes, &genesis, author)?;
        if operation.payload() != body.encode()?.as_slice() {
            return Err("retained agent vote context mismatch".into());
        }
        files::create_or_match(&retained_path, &bytes, true)?;
        operation
    } else {
        let nonce = latest["accounts"]
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|a| a["account"] == files::hex(author.as_bytes()))
            })
            .and_then(|a| a["next_nonce"].as_u64())
            .ok_or("registered account nonce unavailable")?;
        let operation = body.sign(&genesis, nonce, &key)?;
        files::create(&retained_path, &operation.encode(), true)?;
        operation
    };
    save_report(Path::new(&args[3]), &report, Some(&operation))?;
    files::create_or_match(action_path, &operation.encode(), true)?;
    report["operation"] = json!(files::hex(operation.id().as_bytes()));
    let result = control::call(
        &config,
        Request::Submit {
            bytes: files::hex(&operation.encode()),
        },
    )
    .await?;
    println!("{}", json!({"agent_review":report,"submission":result}));
    Ok(())
}

#[cfg(test)]
mod tests;
