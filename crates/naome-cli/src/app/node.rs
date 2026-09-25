use super::{
    Result,
    control::{self, Request},
    files,
    setup::NodeConfig,
};
use naome_ledger::{OperationId, authentication::SignedOperation};
use naome_runtime::state::{StateRuntime, StateRuntimeConfig, StateRuntimeEvent};
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
mod bootstrap;

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

// A connected peer can generate many rejected requests during a handoff. Keep
// a bounded diagnostic sample without letting that traffic exhaust the output
// queue and shut down an otherwise healthy signer.
struct RejectionDiagnostics {
    window: Instant,
    detailed: u8,
    suppressed: u64,
}
impl RejectionDiagnostics {
    fn new() -> Self {
        Self {
            window: Instant::now(),
            detailed: 0,
            suppressed: 0,
        }
    }
    fn flush_if_due(&mut self, errors: &crate::output::Output) -> Result<()> {
        if self.window.elapsed() >= Duration::from_secs(1) {
            if self.suppressed != 0 {
                errors.line(
                    &json!({"event":"peer_input_rejections_suppressed","count":self.suppressed})
                        .to_string(),
                )?;
            }
            self.window = Instant::now();
            self.detailed = 0;
            self.suppressed = 0;
        }
        Ok(())
    }
    fn record(
        &mut self,
        errors: &crate::output::Output,
        peer: impl ToString,
        reason: String,
    ) -> Result<()> {
        self.flush_if_due(errors)?;
        if self.detailed < 4 {
            errors.line(
                &json!({"event":"peer_input_rejected","peer":peer.to_string(),"reason":reason})
                    .to_string(),
            )?;
            self.detailed += 1;
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
        }
        Ok(())
    }
}

async fn serve(listener: UnixListener, sender: mpsc::Sender<Message>) -> Result<()> {
    let permits = Arc::new(Semaphore::new(16));
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        // A client can close while its credentials are being read. Reject
        // that socket without taking down the owning validator.
        let Ok(credentials) = stream.peer_cred() else {
            continue;
        };
        if credentials.uid() != rustix::process::geteuid().as_raw() {
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
                        let processing_timeout = if matches!(
                            &request,
                            Request::Submit { .. } | Request::Progress { .. }
                        ) {
                            Duration::from_secs(30)
                        } else {
                            Duration::from_secs(5)
                        };
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
                            match tokio::time::timeout(processing_timeout, rx).await {
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
    for directory in [
        &config.history,
        &config.history_anchor,
        &config.signer,
        &config.signer_anchor,
        &config.custody,
        &config.custody_anchor,
        &config.handoff,
        &config.handoff_anchor,
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
    if files::available(&config.history)? < genesis.profile().operating_storage_floor_bytes()? {
        return Err("insufficient free storage for this immutable profile".into());
    }
    let mut runtime_config = StateRuntimeConfig {
        allow_simulation_controls: config.simulation,
        ..StateRuntimeConfig::default()
    };
    if matches!(
        genesis.profile().kind(),
        naome_ledger::profile::TimingKind::ShortTest | naome_ledger::profile::TimingKind::CiTest
    ) {
        let roster = genesis.validators().len() as u64;
        // Rebuilding a record candidate and retry fanout on every 50 ms tick
        // is costly across a large local full-mesh roster. Network arrivals
        // still drive the runtime immediately between these periodic ticks.
        runtime_config.tick_interval = Duration::from_millis(
            if genesis.profile().kind() == naome_ledger::profile::TimingKind::CiTest {
                (roster * 8).clamp(50, 1_000)
            } else {
                50
            },
        );
        // With 50 ms of delay on each TCP chunk, the 350 ms short-test round
        // often times out before authenticated votes arrive. CI gets more
        // finalized heights per minute with a longer first round.
        let round_timeout = if genesis.profile().kind() == naome_ledger::profile::TimingKind::CiTest
        {
            // The local CI full mesh needs time for a large quorum's votes
            // and handoff evidence to traverse bounded peer queues. A
            // 256-process run reached partial agreement but changed rounds
            // before the seal spread. Only this local timing profile changes;
            // signed quorum and round limits remain the same.
            let ordinary = 1200u64
                .saturating_add(roster.saturating_sub(16) * 400)
                .min(720_000);
            let large_roster = roster.saturating_sub(64).saturating_mul(3_750);
            ordinary.max(large_roster).min(720_000)
        } else {
            350
        };
        runtime_config.proposal_timeout = Duration::from_millis(round_timeout);
        runtime_config.prevote_timeout = Duration::from_millis(round_timeout);
        runtime_config.precommit_timeout = Duration::from_millis(round_timeout);
    }
    let mut runtime = bootstrap::open(&config, runtime_config)?;
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
    let mut server = Server(tokio::spawn(serve(listener, sender)));
    output.line(&json!({"event":"started","peer":runtime.local_peer_id().to_string(),"height":runtime.state()?.height(),"genesis":files::hex(genesis.id().as_bytes())}).to_string())?;
    let mut space_checked = Instant::now();
    let mut rejected = RejectionDiagnostics::new();
    let outcome = loop {
        tokio::select! {
            result=&mut server.0=>break match result {
                Ok(Ok(()))=>Err("control listener stopped".into()),
                Ok(Err(error))=>Err(error),
                Err(error)=>Err(error.into()),
            },
            ()=output.failed()=>break Err("stdout writer failed".into()),
            ()=errors.failed()=>break Err("stderr writer failed".into()),
            result=runtime.step()=>match result {
                Ok(StateRuntimeEvent::Finalized{height})=>output.line(&json!({"event":"finalized","height":height,"state":files::hex(runtime.state()?.commitment().as_bytes())}).to_string())?,
                Ok(StateRuntimeEvent::Rejected{peer,reason})=>rejected.record(errors,peer,reason)?,
                Ok(_)=>{},Err(error)=>break Err(error.into()),
            },
            message=receiver.recv()=>{
                let Some(message)=message else{break Err("control listener stopped".into());};
                let shutdown=matches!(message.request,Request::Shutdown {});
                let response=handle(&mut runtime,message.request).unwrap_or_else(|error|json!({"error":error.to_string()}));
                let _=message.response.send(response);
                if shutdown {tokio::time::sleep(Duration::from_millis(50)).await;break Ok(());}
            },
            result=tokio::signal::ctrl_c()=>{result?;break Ok(());}
            _=terminate.recv()=>break Ok(()),
        }
        rejected.flush_if_due(errors)?;
        if space_checked.elapsed() >= Duration::from_secs(10) {
            if files::available(&config.history)?
                < genesis.profile().operating_storage_floor_bytes()?
            {
                break Err("free storage fell below the profile floor; durable state retained, node halted".into());
            }
            space_checked = Instant::now();
        }
    };
    drop(server);
    outcome
}
fn handle(runtime: &mut StateRuntime, request: Request) -> Result<Value> {
    Ok(match request {
        Request::Progress { account } => {
            let state = runtime.state()?;
            let height = state.height();
            let head = files::hex(state.head().as_bytes());
            let commitment = files::hex(state.commitment().as_bytes());
            let genesis = files::hex(state.genesis().id().as_bytes());
            let next_nonce = if let Some(account) = account {
                let id = naome_ledger::AccountId::from_bytes(files::unhex(&account)?);
                Some(
                    state
                        .next_nonce(id)
                        .ok_or("registered account nonce unavailable")?,
                )
            } else {
                None
            };
            let diagnostics = runtime.diagnostics()?;
            json!({
                "genesis": genesis,
                "height": height,
                "head": head,
                "state": commitment,
                "next_nonce": next_nonce,
                "pending_operations": runtime.pending_operations(),
                "consensus_position": runtime.position()?.map(|(height,round,phase)|json!({"height":height,"round":round,"phase":format!("{phase:?}")})),
                "local_proposer": diagnostics.local_proposer,
                "proposal_authored": diagnostics.proposal_authored,
                "observed_proposals": diagnostics.observed_proposals,
                "observed_prevotes": diagnostics.observed_prevotes,
                "observed_precommits": diagnostics.observed_precommits,
                "transport_diagnostics": {"connected_peers": diagnostics.connected_peers,"staged_connected_peers":diagnostics.staged_connected_peers,"offers":diagnostics.offers,"time_reports":diagnostics.time_reports,"queued_deliveries":diagnostics.queued_deliveries,"in_flight_deliveries":diagnostics.in_flight_deliveries,"queued_ready":diagnostics.queued_ready,"queued_terminal":diagnostics.queued_terminal,"in_flight_ready":diagnostics.in_flight_ready,"in_flight_terminal":diagnostics.in_flight_terminal,"work_ready":diagnostics.work_ready,"agreement_ready":diagnostics.agreement_ready,"ready_signatures":diagnostics.ready_signatures,"terminal_signatures":diagnostics.terminal_signatures}
            })
        }
        Request::Status {} => {
            let mut value = control::status(runtime.state()?);
            let diagnostic = runtime.diagnostics()?;
            value["pending_operations"] = json!(runtime.pending_operations());
            value["consensus_position"]=json!(runtime.position()?.map(|(height,round,phase)|json!({"height":height,"round":round,"phase":format!("{phase:?}")})));
            value["local_proposer"] = json!(diagnostic.local_proposer);
            value["proposal_authored"] = json!(diagnostic.proposal_authored);
            value["observed_proposals"] = json!(diagnostic.observed_proposals);
            value["observed_prevotes"] = json!(diagnostic.observed_prevotes);
            value["observed_precommits"] = json!(diagnostic.observed_precommits);
            value["transport_diagnostics"] = json!({"connected_peers": diagnostic.connected_peers,"staged_connected_peers":diagnostic.staged_connected_peers,"offers":diagnostic.offers,"time_reports":diagnostic.time_reports,"queued_deliveries":diagnostic.queued_deliveries,"in_flight_deliveries":diagnostic.in_flight_deliveries,"queued_ready":diagnostic.queued_ready,"queued_terminal":diagnostic.queued_terminal,"in_flight_ready":diagnostic.in_flight_ready,"in_flight_terminal":diagnostic.in_flight_terminal,"work_ready":diagnostic.work_ready,"agreement_ready":diagnostic.agreement_ready,"ready_signatures":diagnostic.ready_signatures,"terminal_signatures":diagnostic.terminal_signatures});
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
            let slot = runtime
                .state()?
                .authority()
                .units()
                .get(validator)
                .ok_or("validator index out of range")?
                .slot();
            runtime.start_proof_fetch_slot(
                slot,
                naome_proof::ProofId::from_bytes(files::unhex(&id)?),
            )?;
            json!({"status":"network_fetch_started","validator":validator,"proof":id})
        }
        Request::ProofFetch { validator, id } => {
            let slot = runtime
                .state()?
                .authority()
                .units()
                .get(validator)
                .ok_or("validator index out of range")?
                .slot();
            match runtime
                .take_proof_fetch_slot(slot, naome_proof::ProofId::from_bytes(files::unhex(&id)?))?
            {
                None => json!({"status":"pending"}),
                Some(bytes) => {
                    json!({"status":"authenticated_network_proof","validator":validator,"proof":id,"bytes":files::hex(&bytes)})
                }
            }
        }
        Request::SetPeer { validator, enabled } => {
            let slot = runtime
                .state()?
                .authority()
                .units()
                .get(validator)
                .ok_or("validator index out of range")?
                .slot();
            runtime.set_slot_enabled(slot, enabled)?;
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
