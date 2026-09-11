use naome_consensus::verified_membership::*;
use naome_node::verified_membership::MembershipNode;
use naome_runtime::verified_membership::{MembershipRuntime, MembershipRuntimeEvent};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use tokio::signal::unix::{SignalKind, signal};

use super::{Result, files, input, report::Output};

mod commands;
mod config;
use config::Config;

pub(super) fn initialize(directory: &Path, output: &Output) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(directory)
        .map_err(|_| "membership_init_directory_exists_or_unavailable")?;
    let mut public = Vec::new();
    let mut peer_id = None;
    for role in ["consensus", "approval", "network"] {
        let identity = naome_network::Keypair::generate_ed25519();
        if role == "network" {
            peer_id = Some(identity.public().to_peer_id().to_string());
        }
        let key = identity
            .try_into_ed25519()
            .map_err(|_| "membership_init_key")?;
        write_new(
            &directory.join(format!("{role}.seed")),
            key.secret().as_ref(),
        )?;
        public.push(key.public().to_bytes());
    }
    for name in ["journal", "anchor", "inbox"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(directory.join(name))
            .map_err(|_| "membership_init_subdirectory")?;
    }
    let mut digest = Sha256::new();
    digest.update(b"naome/verified-membership/organization-label\0");
    digest.update(public[0]);
    let organization: [u8; 32] = digest.finalize().into();
    let manifest = json!({"organization":hex(&organization), "consensus_key":hex(&public[0]), "approval_key":hex(&public[1]), "network_key":hex(&public[2]), "peer_id":peer_id});
    write_new(
        &directory.join("identity.json"),
        &serde_json::to_vec_pretty(&manifest).map_err(|_| "membership_init_encode")?,
    )?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| "membership_init_sync")?;
    if let Some(parent) = directory.parent() {
        File::open(if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        })
        .and_then(|file| file.sync_all())
        .map_err(|_| "membership_init_parent_sync")?;
    }
    output.finish(json!({"event":"membership_keys_created", "identity":manifest}))
}

pub(super) async fn run(path: PathBuf, output: &Output) -> Result<()> {
    let config = Config::load(&path)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "signal_registration")?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| "signal_registration")?;
    let (mut node, network) = config.open(base)?;
    if let (Some(directory), Some(count)) = (
        &config.bootstrap_history_directory,
        config.bootstrap_history_count,
    ) {
        for height in 1..=count {
            let bytes = files::bytes(
                &base.join(directory).join(format!("{height:020}.proof")),
                MembershipFinalityProof::MAX_BYTES,
            )?;
            let proof = MembershipFinalityProof::from_bytes(&bytes)
                .map_err(|_| "membership_bootstrap_decode")?;
            if proof.proposal.value.height() != height {
                return Err("membership_bootstrap_height");
            }
            if height
                <= node
                    .machine()
                    .map_err(|_| "membership_state")?
                    .branch()
                    .height()
            {
                let retained = node
                    .finalized_proof(height)
                    .map_err(|_| "membership_bootstrap_retained")?
                    .ok_or("membership_bootstrap_retained")?;
                if retained.proposal.value != proof.proposal.value {
                    return Err("membership_bootstrap_prefix");
                }
            } else {
                node.receive(MembershipPublication::Finality(proof))
                    .map_err(|_| "membership_bootstrap_verify")?;
            }
            if height % 128 == 0 {
                output.emit(json!({"event":"membership_bootstrap", "height":height}))?;
            }
            tokio::select! {
                _ = interrupt.recv() => return Err("membership_bootstrap_interrupted"),
                _ = terminate.recv() => return Err("membership_bootstrap_interrupted"),
                _ = tokio::task::yield_now() => {},
            }
        }
    }
    config.validate_local_binding(base, &node, &network)?;
    load_inbox(&mut node, &base.join(&config.inbox_directory))?;
    let mut runtime = config.runtime(node, network)?;
    let mut input = input::start()?;
    let mut input_open = true;
    let mut reported_height = runtime
        .node()
        .machine()
        .map_err(|_| "membership_state")?
        .branch()
        .height();
    output.emit(json!({"event":"membership_ready", "state":status(&runtime)?}))?;
    loop {
        if config
            .stop_height
            .is_some_and(|height| reported_height >= height)
        {
            break;
        }
        tokio::select! {
            _ = interrupt.recv() => break,
            _ = terminate.recv() => break,
            _ = output.failed() => return Err("output_failed"),
            incoming = input.recv(), if input_open => match incoming {
                Some(input::Input::Line(bytes)) => {
                    let command = match serde_json::from_slice::<commands::Command>(&bytes) {
                        Ok(command) => command,
                        Err(_) => { output.emit(json!({"event":"membership_command_error", "code":"command_decode"}))?; continue; }
                    };
                    let id = command.id();
                    match commands::execute(command, &config, base, &mut runtime) {
                        Ok((mut result, stop)) => { result["id"] = json!(id); output.emit(result)?; if stop { break; } }
                        Err("membership_inbox_persistence_failed") => return Err("membership_inbox_persistence_failed"),
                        Err(code) => output.emit(json!({"event":"membership_command_error", "id":id, "code":code}))?,
                    }
                },
                Some(input::Input::End("eof")) | None => input_open = false,
                Some(input::Input::End(code)) => return Err(code),
            },
            event = runtime.next_event() => {
                let event = event.map_err(|_| "membership_runtime_stopped")?;
                if event == MembershipRuntimeEvent::InboxChanged { save_inbox(runtime.node(), &base.join(&config.inbox_directory))?; }
                let height = runtime.node().machine().map_err(|_| "membership_state")?.branch().height();
                if height != reported_height {
                    reported_height = height;
                    save_inbox(runtime.node(), &base.join(&config.inbox_directory))?;
                    output.emit(json!({"event":"membership_finalized", "state":status(&runtime)?}))?;
                }
            },
        }
    }
    let state = status(&runtime)?;
    drop(runtime);
    output.finish(json!({"event":"membership_stopped", "state":state}))
}

fn status(runtime: &MembershipRuntime) -> Result<Value> {
    let machine = runtime.node().machine().map_err(|_| "membership_state")?;
    let branch = machine.branch();
    let snapshot = runtime
        .node()
        .snapshot()
        .map_err(|_| "membership_snapshot")?;
    let requests: Vec<_> = runtime
        .node()
        .requests()
        .keys()
        .map(|id| json!({"id":hex(id), "approvals":runtime.node().approval_count(id)}))
        .collect();
    Ok(
        json!({"profile":"verified_membership", "context":hex(&branch.context().0), "height":branch.height(), "ancestry":hex(&branch.ancestry()), "artifact_head":hex(branch.artifact().head_block_id().as_bytes()), "artifact_root":hex(branch.artifact().artifact_set_root().as_bytes()), "generation":snapshot.generation(), "membership":hex(&snapshot.id()), "members":snapshot.members().len(), "quorum":snapshot.quorum(), "active":machine.is_active(), "round":machine.round(), "phase":format!("{:?}",machine.phase()).to_lowercase(), "pending_activation":branch.membership().pending_activation(), "peer_id":runtime.network().local_peer_id().to_string(), "connected_peers":runtime.network().connected_peers().len(), "requests":requests}),
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inbox {
    requests: Vec<String>,
    approvals: Vec<String>,
    rejected: Vec<String>,
}
fn load_inbox(node: &mut MembershipNode, directory: &Path) -> Result<()> {
    if !fs::symlink_metadata(directory)
        .map_err(|_| "membership_inbox_directory")?
        .is_dir()
    {
        return Err("membership_inbox_directory");
    }
    let path = directory.join("membership-inbox.json");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("membership_inbox_metadata"),
        Ok(_) => {}
    }
    let bytes = files::bytes(&path, 4_194_304)?;
    let inbox: Inbox = serde_json::from_slice(&bytes).map_err(|_| "membership_inbox_decode")?;
    if inbox.requests.len() > naome_node::verified_membership::MAX_REQUESTS
        || inbox.approvals.len() > naome_node::verified_membership::MAX_REQUESTS * MAX_MEMBERS
        || inbox.rejected.len() > 256
    {
        return Err("membership_inbox_limit");
    }
    for id in inbox.rejected {
        node.reject_request(super::config::hex32(&id)?)
            .map_err(|_| "membership_rejection_replay")?;
    }
    for bytes in inbox.requests {
        let request = MembershipRequest::from_bytes(&unhex(&bytes, MembershipRequest::MAX_BYTES)?)
            .map_err(|_| "membership_request_decode")?;
        match node.ingest_request(request) {
            Ok(_)
            | Err(naome_node::verified_membership::MembershipNodeError::Membership(
                MembershipError::StaleRequest,
            ))
            | Err(naome_node::verified_membership::MembershipNodeError::PendingTransition) => {}
            Err(_) => return Err("membership_request_replay"),
        }
    }
    for bytes in inbox.approvals {
        let approval =
            MembershipApproval::from_bytes(&unhex(&bytes, MembershipApproval::MAX_BYTES)?)
                .map_err(|_| "membership_approval_decode")?;
        if node.requests().contains_key(&approval.request) {
            node.ingest_approval(approval)
                .map_err(|_| "membership_approval_replay")?;
        }
    }
    Ok(())
}
fn save_inbox(node: &MembershipNode, directory: &Path) -> Result<()> {
    let inbox = Inbox {
        rejected: node.rejected_requests().iter().map(|id| hex(id)).collect(),
        requests: node
            .requests()
            .values()
            .map(|request| hex(&request.to_bytes()))
            .collect(),
        approvals: node
            .approval_messages()
            .iter()
            .map(|approval| hex(&approval.to_bytes()))
            .collect(),
    };
    let bytes = serde_json::to_vec(&inbox).map_err(|_| "membership_inbox_encode")?;
    if bytes.len() > 4_194_304 {
        return Err("membership_inbox_limit");
    }
    let temporary = directory.join("membership-inbox.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(&temporary)
        .map_err(|_| "membership_inbox_open")?;
    if !file
        .metadata()
        .map_err(|_| "membership_inbox_metadata")?
        .is_file()
    {
        return Err("membership_inbox_type");
    }
    use std::os::unix::fs::MetadataExt;
    if file
        .metadata()
        .map_err(|_| "membership_inbox_metadata")?
        .nlink()
        != 1
    {
        return Err("membership_inbox_links");
    }
    file.set_len(0).map_err(|_| "membership_inbox_truncate")?;
    file.write_all(&bytes)
        .map_err(|_| "membership_inbox_write")?;
    file.sync_all().map_err(|_| "membership_inbox_sync")?;
    fs::rename(&temporary, directory.join("membership-inbox.json"))
        .map_err(|_| "membership_inbox_publish")?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| "membership_inbox_directory_sync")
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "membership_export_open")?;
    file.write_all(bytes)
        .map_err(|_| "membership_export_write")?;
    file.sync_all().map_err(|_| "membership_export_sync")?;
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))
        .and_then(|file| file.sync_all())
        .map_err(|_| "membership_export_directory_sync")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || value.len() / 2 > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("membership_hex");
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| "membership_hex")
        })
        .collect()
}
