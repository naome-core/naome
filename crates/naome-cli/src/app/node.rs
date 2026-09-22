use super::{
    Result,
    control::{self, Request},
    files,
    setup::NodeConfig,
};
use naome_ledger::{OperationId, authentication::SignedOperation};
use naome_network::{Keypair, StateNetwork, state_peer_id};
use naome_runtime::state::{StateRuntime, StateRuntimeConfig, StateRuntimeEvent};
use naome_storage::state::{StateHistory, StateSigner};
use serde_json::{Value, json};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UnixListener,
    sync::{Semaphore, mpsc, oneshot},
};
use zeroize::Zeroizing;

struct Message {
    request: Request,
    response: oneshot::Sender<Value>,
}
struct SocketGuard(std::path::PathBuf);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn serve(listener: UnixListener, sender: mpsc::Sender<Message>) -> Result<()> {
    let permits = Arc::new(Semaphore::new(16));
    loop {
        let (mut stream, _) = listener.accept().await?;
        if stream.peer_cred()?.uid() != rustix::process::geteuid().as_raw() {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let sender = sender.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let result =
                tokio::time::timeout(Duration::from_secs(2), control::read(&mut stream)).await;
            let response = match result {
                Ok(Ok(bytes)) => match serde_json::from_slice::<Request>(&bytes) {
                    Ok(request) => {
                        let (tx, rx) = oneshot::channel();
                        if sender
                            .try_send(Message {
                                request,
                                response: tx,
                            })
                            .is_err()
                        {
                            json!({"error":"control queue busy"})
                        } else {
                            match tokio::time::timeout(Duration::from_secs(5), rx).await {
                                Ok(Ok(value)) => value,
                                _ => {
                                    json!({"error":"control processing unavailable; check receipt before resending"})
                                }
                            }
                        }
                    }
                    Err(_) => json!({"error":"malformed control request"}),
                },
                _ => json!({"error":"control read failed or timed out"}),
            };
            if let Ok(bytes) = serde_json::to_vec(&response) {
                let _ = tokio::time::timeout(
                    Duration::from_secs(2),
                    control::write(&mut stream, &bytes),
                )
                .await;
            }
        });
    }
}
pub async fn run(path: &Path) -> Result<()> {
    let output = crate::output::Output::start(crate::output::Stream::Out)?;
    let errors = crate::output::Output::start(crate::output::Stream::Error)?;
    let result = run_owned(path, &output, &errors).await;
    // run_owned has released history, signing custody and the control socket.
    // Both streams share a single flush deadline even if neither reader drains.
    let deadline = Instant::now() + Duration::from_secs(2);
    let flushed = output.finish_until(deadline);
    let errors_flushed = errors.finish_until(deadline);
    result?;
    flushed?;
    errors_flushed
}
async fn run_owned(
    path: &Path,
    output: &crate::output::Output,
    errors: &crate::output::Output,
) -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let config = NodeConfig::read(path)?;
    let genesis = config.genesis()?;
    // Configuration and both registered identities are checked before any
    // authority store is opened. Crossed keys must never enter the runtime.
    if config.maximum_round > genesis.profile().limits().consensus_rounds {
        return Err("maximum round exceeds the immutable profile".into());
    }
    let key = files::key(&config.consensus_key, 2)?;
    let transport_key = files::key(&config.transport_key, 3)?;
    if !genesis.validators().iter().any(|validator| {
        validator.consensus_key == key.verifying_key().to_bytes()
            && validator.transport_key == transport_key.verifying_key().to_bytes()
    }) {
        return Err(
            "consensus and transport keys must belong to the same registered validator".into(),
        );
    }
    for directory in [
        &config.history,
        &config.history_anchor,
        &config.signer,
        &config.signer_anchor,
    ] {
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(
                "existing private authority directories are required; startup never initializes"
                    .into(),
            );
        }
    }
    if let Some(address) = config.listen_address
        && (address.port() == 0
            || address.ip().is_multicast()
            || matches!(address, std::net::SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
            || matches!(address.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()))
    {
        return Err("invalid local listener address".into());
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&config.control_socket)
        && (!metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw())
    {
        return Err("control socket path is occupied by an unexpected file".into());
    }
    if files::available(&config.history)? < genesis.profile().required_storage_bytes()? {
        return Err("insufficient free storage for this immutable profile".into());
    }
    let mut seed = Zeroizing::new(transport_key.to_bytes());
    let identity = Keypair::ed25519_from_bytes(&mut *seed)?;
    let mut network = StateNetwork::new_state(identity, &genesis)?;
    let peers = genesis
        .validators()
        .iter()
        .map(|v| state_peer_id(v.transport_key))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let remote = peers
        .iter()
        .copied()
        .filter(|p| *p != network.local_peer_id())
        .collect();
    let listen = match config.listen_address {
        Some(address) => {
            let family = if address.is_ipv4() { "ip4" } else { "ip6" };
            format!("/{family}/{}/tcp/{}", address.ip(), address.port()).parse()?
        }
        None => network
            .state_listen_address()
            .ok_or("state endpoint unavailable")?
            .clone(),
    };
    network.listen_on(listen)?;
    // Missing stores, anchors, or an unsupported format are fatal. In
    // particular, losing every store never recreates a signer with old keys.
    let history = StateHistory::open(
        &config.history,
        &config.history_anchor,
        genesis.clone(),
        config.maximum_round,
    )?;
    let signer = StateSigner::open(
        &config.signer,
        &config.signer_anchor,
        genesis.clone(),
        key,
        config.maximum_round,
    )?;
    let mut runtime_config = StateRuntimeConfig {
        allow_simulation_controls: config.simulation,
        ..StateRuntimeConfig::default()
    };
    if genesis.profile().kind() == naome_ledger::profile::TimingKind::ShortTest {
        runtime_config.tick_interval = Duration::from_millis(50);
        runtime_config.proposal_timeout = Duration::from_millis(350);
        runtime_config.prevote_timeout = Duration::from_millis(350);
        runtime_config.precommit_timeout = Duration::from_millis(350);
    }
    let mut runtime = StateRuntime::new(history, Some(signer), network, remote, runtime_config)?;
    // The signer/history locks above prove that no other owning process is live.
    // Only a same-user socket at the configured exact path may be removed.
    if let Ok(metadata) = std::fs::symlink_metadata(&config.control_socket) {
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("control socket path is occupied by an unexpected file".into());
        }
        std::fs::remove_file(&config.control_socket)?;
    }
    let listener = UnixListener::bind(&config.control_socket)?;
    std::fs::set_permissions(
        &config.control_socket,
        std::fs::Permissions::from_mode(0o600),
    )?;
    let _socket = SocketGuard(config.control_socket.clone());
    let (sender, mut receiver) = mpsc::channel(16);
    struct Server(tokio::task::JoinHandle<Result<()>>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let server = Server(tokio::spawn(serve(listener, sender)));
    output.line(&json!({"event":"started","peer":runtime.local_peer_id().to_string(),"height":runtime.state()?.height(),"genesis":files::hex(genesis.id().as_bytes())}).to_string())?;
    let mut space_checked = Instant::now();
    let outcome = loop {
        tokio::select! {
            ()=output.failed()=>break Err("stdout writer failed".into()),
            ()=errors.failed()=>break Err("stderr writer failed".into()),
            result=runtime.step()=>match result {
                Ok(StateRuntimeEvent::Finalized{height})=>output.line(&json!({"event":"finalized","height":height,"state":files::hex(runtime.state()?.commitment().as_bytes())}).to_string())?,
                Ok(StateRuntimeEvent::Rejected{peer,reason})=>errors.line(&json!({"event":"peer_input_rejected","peer":peer.to_string(),"reason":reason}).to_string())?,
                Ok(_)=>{},Err(error)=>break Err(error.into()),
            },
            message=receiver.recv()=>{
                let Some(message)=message else{break Err("control listener stopped".into());};
                let shutdown=matches!(message.request,Request::Shutdown {});
                let response=handle(&mut runtime,&peers,message.request).unwrap_or_else(|error|json!({"error":error.to_string()}));
                let _=message.response.send(response);
                if shutdown {tokio::time::sleep(Duration::from_millis(50)).await;break Ok(());}
            },
            result=tokio::signal::ctrl_c()=>{result?;break Ok(());}
            _=terminate.recv()=>break Ok(()),
        }
        if space_checked.elapsed() >= Duration::from_secs(10) {
            if files::available(&config.history)? < genesis.profile().required_storage_bytes()? {
                break Err("free storage fell below the profile floor; durable state retained, node halted".into());
            }
            space_checked = Instant::now();
        }
    };
    drop(server);
    outcome
}
fn handle(
    runtime: &mut StateRuntime,
    peers: &[naome_network::PeerId],
    request: Request,
) -> Result<Value> {
    Ok(match request {
        Request::Status {} => {
            let mut value = control::status(runtime.state()?);
            value["pending_operations"] = json!(runtime.pending_operations());
            value["consensus_position"]=json!(runtime.position()?.map(|(height,round,phase)|json!({"height":height,"round":round,"phase":format!("{phase:?}")})));
            value
        }
        Request::Shutdown {} => json!({"status":"stopping"}),
        Request::Submit { bytes } => {
            let raw = decode_bytes(
                &bytes,
                runtime.state()?.genesis().profile().limits().record_bytes as usize,
            )?;
            let operation = SignedOperation::decode(&raw)?;
            let id = runtime.submit_operation(operation)?;
            if let Some(receipt) = runtime.state()?.receipt(id) {
                json!({"status":"finalized","height":receipt.coordinate.height,"operation_index":receipt.coordinate.operation_index})
            } else {
                json!({"status":"transported","operation":files::hex(id.as_bytes())})
            }
        }
        Request::Receipt { id } => match runtime
            .state()?
            .receipt(OperationId::from_bytes(files::unhex(&id)?))
        {
            Some(receipt) => {
                json!({"status":"finalized","height":receipt.coordinate.height,"operation_index":receipt.coordinate.operation_index,"nonce":receipt.nonce})
            }
            None => {
                match runtime.operation_rejection(OperationId::from_bytes(files::unhex(&id)?)) {
                    Some(reason) => json!({"status":"rejected","reason":reason}),
                    None if runtime
                        .operation_deferred(OperationId::from_bytes(files::unhex(&id)?)) =>
                    {
                        json!({"status":"deferred","reason":"local queue yielded to active attempt work; resubmit the saved action"})
                    }
                    None => json!({"status":"not_finalized"}),
                }
            }
        },
        Request::Question { id } => super::inspect::question(
            runtime.state()?,
            OperationId::from_bytes(files::unhex(&id)?),
        )?,
        Request::History { height } => {
            json!({"height":height,"bytes":files::hex(&runtime.finality_bytes(height)?)})
        }
        Request::Proof { id } => {
            let proof = runtime
                .state()?
                .library()
                .lookup(naome_proof::ProofId::from_bytes(files::unhex(&id)?))
                .ok_or("proof not in finalized library")?;
            json!({"status":"finalized_library","proof":id,"bytes":files::hex(proof.canonical_bytes()),"author":files::hex(proof.author().as_bytes()),"recipient":files::hex(proof.recipient().as_bytes()),"height":proof.coordinate().height,"operation_index":proof.coordinate().operation_index})
        }
        Request::StartProofFetch { validator, id } => {
            let peer = *peers.get(validator).ok_or("validator index out of range")?;
            runtime
                .start_proof_fetch(peer, naome_proof::ProofId::from_bytes(files::unhex(&id)?))?;
            json!({"status":"network_fetch_started","validator":validator,"proof":id})
        }
        Request::ProofFetch { validator, id } => {
            let peer = *peers.get(validator).ok_or("validator index out of range")?;
            match runtime
                .take_proof_fetch(peer, naome_proof::ProofId::from_bytes(files::unhex(&id)?))?
            {
                None => json!({"status":"pending"}),
                Some(bytes) => {
                    json!({"status":"authenticated_network_proof","validator":validator,"proof":id,"bytes":files::hex(&bytes)})
                }
            }
        }
        Request::SetPeer { validator, enabled } => {
            runtime.set_peer_enabled(
                *peers.get(validator).ok_or("validator index out of range")?,
                enabled,
            )?;
            json!({"status":"simulation_link_updated","validator":validator,"enabled":enabled})
        }
    })
}
pub fn decode_bytes(text: &str, maximum: usize) -> Result<Vec<u8>> {
    if text.len() > maximum * 2
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid bounded hexadecimal payload".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(Into::into))
        .collect()
}
