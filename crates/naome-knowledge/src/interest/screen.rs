//! Reproducible finite synthetic engineering screen, never human preference labels.
use super::*;
use crate::jobs;
use std::{
    io::Write,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    split: String,
    interest: String,
    question: String,
    expected: String,
}

/// Runs supplied finite cases through the actual job service and shared model.
/// The caller supplies an isolated node directory with `decision.json` and an
/// explicit installed resource profile. Expected labels remain synthetic data.
pub async fn run(directory: &Path, cases: &Path, output: &Path) -> Result<(), String> {
    let bytes = crate::store::read_bounded(cases, 256 * 1024).map_err(|e| e.to_string())?;
    let cases: Vec<Case> = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if cases.is_empty() || cases.len() > 64 {
        return Err("screen requires 1..64 cases".into());
    }
    let installed = crate::decision::liquid::Installed::load(directory)?
        .ok_or("screen requires a configured real model")?;
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    let mut settings = jobs::Settings::default();
    settings.interest.limits.horizon_ms = 120_000;
    let (mut service, client, _) = jobs::Service::open(directory, settings, 0)?;
    let result = async {
        for (index, case) in cases.iter().enumerate() {
            let question = naome_authoring::CompiledQuestion::compile(&case.question).map_err(|e| format!("case {}: {e}", case.id))?;
            let input = Input { interest:case.interest.clone(), owner_revision:index as u64,
                owner_digest:crate::decision::digest(&("synthetic-owner", index, &case.interest)),
                model:installed.identity(), policy:POLICY.into() };
            let request = input.request(&question);
            let epoch = crate::decision::digest(&(&input, &case.id));
            let binding = jobs::Binding::new([0;32], [0;32]).with_selection(crate::object::id_bytes(&epoch)?);
            let mut ticket = client.submit(jobs::Input::Interest { question:case.question.clone(), assessment:input.clone(),
                purpose:jobs::Purpose::Assessment, root:None }, binding)?;
            let began = Instant::now();
            let completion = tokio::time::timeout(Duration::from_secs(125), ticket.completed()).await.map_err(|_| "screen job receipt timeout")??;
            let wall_ms = began.elapsed().as_millis();
            let (selection, distribution, error) = match completion.result {
                Ok(jobs::Output::Decision(distribution)) => {
                    let selection = input.assess(&request, &distribution)?;
                    (Some(selection), Some(distribution), None)
                },
                Err(error) => (None, None, Some(error)),
                _ => return Err("screen did not use actual model inference".into()),
            };
            let value = serde_json::json!({"case":case.id,"split":case.split,"label_source":"author_synthetic",
                "expected":case.expected,"selection":selection,"state":format!("{:?}",completion.state),"error":error,
                "question_source":crate::hex(question.source_hash()),"question_resolution":crate::hex(question.resolution_id()),
                "owner_revision":input.owner_revision,"owner_digest":input.owner_digest,"policy":POLICY,"selection_epoch":epoch,
                "model_repository":crate::decision::liquid::MODEL,"model_revision":crate::decision::liquid::REVISION,
                "adapter":crate::decision::liquid::ADAPTER,"configuration":installed.configuration,
                "request":request,"distribution":distribution,"wall_ms":wall_ms,
                "spent_ms":completion.spent_ms,"reserved_units":completion.reserved_units});
            writeln!(output, "{value}").and_then(|_| output.flush()).map_err(|e| e.to_string())?;
            client.acknowledge(completion.id)?;
        }
        Ok(())
    }.await;
    let cleanup = service.shutdown().await;
    result.and(cleanup)
}
