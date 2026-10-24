//! Native protocol/custody doubles. Never selected by ordinary node configuration.
use super::{
    Alternative, Request,
    runtime::{Access, Backend, Failure},
};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    time::{Duration, Instant},
};

const FIXTURE: &str = r#"
import json, os, signal, subprocess, sys, time
start=json.loads(sys.stdin.readline())
print(json.dumps({'kind':'ready','model':start['model'],'pid':os.getpid(),'runtime':{'fixture':'x'*8000 if start['mode']=='metadata' else 'deterministic'}}),flush=True)
for line in sys.stdin:
    frame=json.loads(line)
    with open(start['log'],'a') as output: output.write(str(os.getpid())+'\n')
    mode=start['mode']
    if mode=='crash': os._exit(7)
    if mode in ('hang','parent_loss'):
        descendant=subprocess.Popen([sys.executable,'-c','while True: pass'],
            pass_fds=(int(os.environ['NAOME_DECISION_SLOT_FD']),))
        if mode=='parent_loss': os.kill(int(os.environ['NAOME_DECISION_GUARDIAN_PID']),signal.SIGKILL)
        while True: pass
    if mode=='memory': allocation=bytearray(80*1024*1024); time.sleep(10)
    if mode=='hang':
        while True: pass
    if mode=='oversized':
        print('x'*300000,flush=True)
        continue
    if frame['input']['state']=='wait': time.sleep(2)
    probabilities=[-0.1,1.1] if mode=='invalid' else [0.9,0.1]
    print(json.dumps({'kind':'answer','sequence':frame['sequence'],'distribution':{
        'request':frame['request'],'model':start['model'],
        'probabilities':[{'option':o['id'],'probability':p} for o,p in zip(frame['input']['alternatives'],probabilities)],
        'input_tokens':10,'elapsed_ms':1,'peak_rss_bytes':1,'accelerator_bytes':0,'truncated':False}}),flush=True)
"#;

fn lease(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.try_lock()
        .map_err(|e| format!("probe physical lease: {e}"))?;
    Ok(file)
}

fn request(state: &str) -> Request {
    Request {
        state: state.into(),
        instruction: "Choose one.".into(),
        alternatives: ["one", "two"]
            .into_iter()
            .map(|id| Alternative {
                id: id.into(),
                description: id.into(),
            })
            .collect(),
    }
}

fn backend(python: &Path, directory: &Path, mode: &str) -> Backend {
    let identity = super::digest(&("native-protocol-double", mode));
    Backend {
        identity: identity.clone(),
        executable: python.to_owned(),
        arguments: ["-I", "-u", "-c", FIXTURE]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        environment: Default::default(),
        initialization: serde_json::json!({"model":identity,"mode":mode,"log":directory.join("requests.log")}),
        memory_bytes: 64 * 1024 * 1024,
        threads: 1,
    }
}

async fn request_started(path: &Path) -> Result<(), String> {
    let until = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        if Instant::now() >= until {
            return Err("probe model did not receive request".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

/// Finite process screen for reuse, backpressure, malformed output, lost
/// consumers, deadline/cancellation and process failure without model weights.
pub async fn run(directory: &Path, python: &Path) -> Result<(), String> {
    std::fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let mut early =
        tokio::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("--decision-supervisor-v1")
            .env_clear()
            .env("NAOME_INTERNAL_DECISION", "v1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
    drop(early.stdin.take());
    let early = tokio::time::timeout(Duration::from_secs(3), early.wait_with_output())
        .await
        .map_err(|_| "pre-start cancellation reaping deadline")?
        .map_err(|e| e.to_string())?;
    let receipt: serde_json::Value =
        serde_json::from_slice(&early.stdout).map_err(|e| e.to_string())?;
    if !early.status.success() || receipt != serde_json::json!({"kind":"cleanup", "error":null}) {
        return Err("pre-start cancellation did not confirm absent custody".into());
    }
    let reuse = directory.join("reuse");
    std::fs::create_dir(&reuse).map_err(|e| e.to_string())?;
    let spec = backend(python, &reuse, "valid");
    let identity = spec.identity.clone();
    let access = Access::new(Some(spec));
    let clone = access.clone();
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let model = identity.clone();
    let slot = lease(&reuse.join("slot"))?;
    let first = tokio::spawn(async move {
        clone
            .infer(
                request("wait"),
                &model,
                Some(slot),
                cancelled,
                tokio::time::Instant::now() + Duration::from_secs(8),
            )
            .await
    });
    request_started(&reuse.join("requests.log")).await?;
    let (keep, receiver) = tokio::sync::oneshot::channel();
    let began = Instant::now();
    if !matches!(
        access
            .infer(
                request("second"),
                &identity,
                None,
                receiver,
                tokio::time::Instant::now() + Duration::from_secs(1)
            )
            .await,
        Err(Failure::Failed(_))
    ) || began.elapsed() > Duration::from_millis(250)
    {
        return Err("concurrent access was not promptly rejected".into());
    }
    drop(keep);
    first
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("first inference: {e:?}"))?;
    drop(cancel);
    let (keep, receiver) = tokio::sync::oneshot::channel();
    access
        .clone()
        .infer(
            request("second"),
            &identity,
            None,
            receiver,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .map_err(|e| format!("reused inference: {e:?}"))?;
    drop(keep);
    access.shutdown().await?;
    let requests =
        std::fs::read_to_string(reuse.join("requests.log")).map_err(|e| e.to_string())?;
    let pids: Vec<_> = requests.lines().collect();
    if pids.len() != 2 || pids[0] != pids[1] {
        return Err("clones did not reuse one model process".into());
    }
    drop(lease(&reuse.join("slot"))?);

    for mode in [
        "invalid",
        "crash",
        "oversized",
        "metadata",
        "memory",
        "parent_loss",
        "deadline",
        "cancel",
        "drop",
    ] {
        let root = directory.join(mode);
        std::fs::create_dir(&root).map_err(|e| e.to_string())?;
        let spec = backend(
            python,
            &root,
            if matches!(mode, "deadline" | "cancel") {
                "hang"
            } else if mode == "drop" {
                "valid"
            } else {
                mode
            },
        );
        let identity = spec.identity.clone();
        let access = Access::new(Some(spec));
        let (stop, receiver) = tokio::sync::oneshot::channel();
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(if mode == "deadline" { 1 } else { 8 });
        let mut future = Box::pin(access.infer(
            request(if mode == "drop" { "wait" } else { "state" }),
            &identity,
            Some(lease(&root.join("slot"))?),
            receiver,
            deadline,
        ));
        if matches!(mode, "cancel" | "drop") {
            let request_log = root.join("requests.log");
            tokio::select! {
                result=&mut future=>return Err(format!("blocked inference ended prematurely: {result:?}")),
                ready=request_started(&request_log)=>ready?,
            }
            if mode == "cancel" {
                let _ = stop.send(());
            } else {
                drop(future);
                let (keep, receiver) = tokio::sync::oneshot::channel();
                access
                    .infer(
                        request("second"),
                        &identity,
                        None,
                        receiver,
                        tokio::time::Instant::now() + Duration::from_secs(5),
                    )
                    .await
                    .map_err(|e| format!("dropped consumer recovery: {e:?}"))?;
                drop(keep);
                access.shutdown().await?;
                drop(lease(&root.join("slot"))?);
                continue;
            }
        }
        let result = future.await;
        match (mode, result) {
            ("deadline", Err(Failure::TimedOut)) | ("cancel", Err(Failure::Cancelled)) => {}
            ("invalid" | "crash" | "oversized" | "metadata", Err(Failure::Failed(_))) => {}
            ("memory", Err(Failure::Failed(error))) if error.contains("resident memory limit") => {}
            ("parent_loss", Err(Failure::Uncertain(_))) => {}
            (_, result) => return Err(format!("probe {mode}: {result:?}")),
        }
        access.shutdown().await?;
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            match lease(&root.join("slot")) {
                Ok(slot) => {
                    drop(slot);
                    break;
                }
                Err(_) if Instant::now() < until => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(error) => return Err(error),
            }
        }
    }
    println!(
        "{}",
        serde_json::json!({"event":"decision_protocol_verified","evidence":"deterministic native protocol doubles","cases":12})
    );
    Ok(())
}
