//! Finite developer measurement of the generic contract, without admission.
use super::{
    Request, liquid,
    runtime::{Access, Failure},
};
use serde::Deserialize;
use std::{
    io::Write,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    request: Request,
}

/// Explicit development batches use isolated directories, one physical lease,
/// one Access and its native resource/deadline supervision. This is model
/// measurement, not the production job service or a second admission path.
pub async fn run(directory: &Path, cases: &Path, output: &Path) -> Result<(), String> {
    for name in ["identity.key", "research", "graph"] {
        if directory
            .join(name)
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            return Err("decision screen requires an isolated measurement directory".into());
        }
    }
    let owner = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("decision-screen-owner"))
        .map_err(|e| e.to_string())?;
    owner
        .try_lock()
        .map_err(|e| format!("decision screen directory already in use: {e}"))?;
    let bytes = crate::store::read_bounded(cases, 16 * 1024 * 1024).map_err(|e| e.to_string())?;
    let mut entries = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let case: Case = serde_json::from_slice(line).map_err(|e| e.to_string())?;
        case.request.validate()?;
        if case.id.is_empty() || case.id.len() > 256 || !ids.insert(case.id.clone()) {
            return Err("decision screen case identity differs".into());
        }
        entries.push(case);
        if entries.len() > 1024 {
            return Err("decision screen case limit".into());
        }
    }
    if entries.is_empty() {
        return Err("decision screen is empty".into());
    }
    let installed =
        liquid::Installed::load(directory)?.ok_or("screen requires a configured model")?;
    let identity = installed.identity();
    let access = Access::new(Some(installed.backend()));
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    let result = async {
        let until = tokio::time::Instant::now() + Duration::from_secs(1800);
        for case in entries {
            if tokio::time::Instant::now() >= until {
                return Err("decision screen original deadline".into());
            }
            if liquid::Installed::load(directory)?.as_ref() != Some(&installed) {
                return Err("decision screen model context changed".into());
            }
            let slot = if access.has_session() {
                None
            } else {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .read(true)
                    .write(true)
                    .open(directory.join("decision-screen-slot"))
                    .map_err(|e| e.to_string())?;
                file.try_lock()
                    .map_err(|e| format!("decision screen physical lease: {e}"))?;
                Some(file)
            };
            let (keep, cancel) = tokio::sync::oneshot::channel();
            let began = Instant::now();
            let response = access
                .infer(
                    case.request.clone(),
                    &identity,
                    slot,
                    cancel,
                    until.min(tokio::time::Instant::now() + Duration::from_secs(120)),
                )
                .await;
            drop(keep);
            let uncertain = matches!(response, Err(Failure::Uncertain(_)));
            let (distribution, error) = match response {
                Ok(value) => (Some(value), None),
                Err(error) => (None, Some(format!("{error:?}"))),
            };
            let value = serde_json::json!({"id":case.id,"request":case.request,
                "distribution":distribution,"error":error,"wall_ms":began.elapsed().as_millis(),
                "model_repository":liquid::MODEL,"model_revision":liquid::REVISION,
                "adapter":liquid::ADAPTER,"configuration":installed.configuration,
                "model":identity,"evidence":"development model measurement; no admission"});
            writeln!(output, "{value}")
                .and_then(|_| output.flush())
                .map_err(|e| e.to_string())?;
            if uncertain {
                return Err("decision screen physical cleanup is unconfirmed".into());
            }
        }
        Ok(())
    }
    .await;
    let cleanup = access.shutdown().await;
    result.and(cleanup)
}
