//! Source-only direct publisher. No signing identity, finality or relay policy.
use super::{
    Result, acquisition,
    config::{self, Mode},
    files, report, sources,
};
use naome_chain::ArtifactChainDefinition;
use naome_network::{
    CANDIDATE_OFFER_INTERVAL, CandidateOffer, CandidateOfferTicket, Keypair, MAX_STATIC_PEERS,
    NetworkEvent, PeerId, StaticArtifactNetwork, StaticPeer,
};
use naome_storage::{
    ArtifactChainJournal, CandidateBranchRecoveryBundleLimits, CandidateBranchRecoveryBundleV0,
    SelectedArtifactHistory, stage_candidate_branch_recovery_bundle_v0,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::signal::unix::{SignalKind, signal};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    mode: Mode,
    deployment_discriminator: String,
    identity_seed_file: PathBuf,
    listen: String,
    peers: Vec<Peer>,
    journal_directory: PathBuf,
    offer_file: PathBuf,
    sources: sources::Config,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    peer_id: String,
    address: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    candidates: Vec<String>,
    /// Optional complete source bundle staged before this offer is sent.
    bundle_file: Option<PathBuf>,
}

pub(super) async fn run(path: PathBuf, output: &report::Output) -> Result<()> {
    let bytes = files::bytes(&path, config::CONFIG_MAX_BYTES)?;
    let config: Config = toml::from_str(std::str::from_utf8(&bytes).map_err(|_| "config_utf8")?)
        .map_err(|_| "publisher_config_schema")?;
    if config.version != 0 || config.peers.is_empty() || config.peers.len() > MAX_STATIC_PEERS {
        return Err("publisher_config_limits");
    }
    let base = path.parent().ok_or("config_path")?;
    let definition = ArtifactChainDefinition::new(config::hex32(&config.deployment_discriminator)?);
    let mut seed = files::seed(&base.join(config.identity_seed_file))?;
    let identity = Keypair::ed25519_from_bytes(&mut *seed).map_err(|_| "identity_seed")?;
    let peers = config
        .peers
        .iter()
        .map(|p| {
            Ok(StaticPeer::new(
                p.peer_id.parse().map_err(|_| "peer_id")?,
                config::tcp_address(&p.address, false)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let targets: Vec<PeerId> = peers.iter().map(StaticPeer::peer_id).collect();
    let mut network = StaticArtifactNetwork::new(identity, peers).map_err(|_| "network_config")?;
    let journal_path = base.join(config.journal_directory);
    let journal = match config.mode {
        Mode::Create => ArtifactChainJournal::create(&journal_path, definition),
        Mode::Open => ArtifactChainJournal::open_verified(
            &journal_path,
            definition,
            naome_chain::ArtifactChainState::new(definition).head_block_id(),
        ),
    }
    .map_err(|_| "publisher_journal_open")?;
    if journal
        .selected_head_block_id()
        .map_err(|_| "publisher_journal")?
        != naome_chain::ArtifactChainState::new(definition).head_block_id()
    {
        return Err("publisher_journal_not_empty");
    }
    let mut sources = config
        .sources
        .prepare(base, false, &[&journal_path])?
        .open(definition)?;
    let offer_path = base.join(config.offer_file);
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "signal_registration")?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| "signal_registration")?;
    network
        .listen_on(config::tcp_address(&config.listen, true)?)
        .map_err(|_| "listen_start")?;

    let mut interval = tokio::time::interval(CANDIDATE_OFFER_INTERVAL + Duration::from_millis(100));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut current = CandidateOffer::new(definition.id(), vec![]).map_err(|_| "offer_empty")?;
    let mut accepted_manifest = Vec::new();
    let mut tickets: Vec<CandidateOfferTicket> = Vec::new();
    let mut reported_receipts = vec![None; targets.len()];
    output.emit(json!({"event":"publisher_ready"}))?;
    loop {
        tokio::select! {
            _ = output.failed() => return Err("output_write"),
            _ = interrupt.recv() => break,
            _ = terminate.recv() => break,
            _ = interval.tick() => {
                if let Ok(bytes) = files::bytes(&offer_path, 4096)
                    && bytes != accepted_manifest
                {
                    current = load_offer(base, &bytes, &journal, &mut sources)?;
                    accepted_manifest = bytes;
                    output.emit(json!({"event":"publisher_offer_loaded", "count":current.candidates().len()}))?;
                }
                for peer in &targets {
                    if !tickets.iter().any(|ticket| ticket.peer_id() == *peer)
                        && let Ok(ticket) = network.announce_candidate_offer(*peer, current.clone())
                    { tickets.push(ticket); }
                }
            },
            event = network.next_event() => match event {
                NetworkEvent::Listening { address } => output.emit(json!({"event":"listening", "address":address.to_string()}))?,
                NetworkEvent::ListenerClosed { .. } | NetworkEvent::ListenerError { .. } => return Err("publisher_listener"),
                NetworkEvent::InboundBlockRequest(inbound) => {
                    if let Err(error) = network.respond_block_from_candidate_store(inbound, &mut sources.candidates)
                        && matches!(error, naome_network::RespondError::CandidateStore(_))
                    { return Err("source_candidate_store"); }
                },
                NetworkEvent::InboundArtifactRequest(inbound) => {
                    if let Err(error) = network.respond_artifact_from_payload_store(inbound, &mut sources.payloads)
                        && matches!(error, naome_network::RespondError::PayloadStore(_))
                    { return Err("source_local_store"); }
                },
                NetworkEvent::OutboundCandidateOffer(event) => {
                    if let Some(index) = tickets.iter().position(|t| t.accepts_event(&event)) {
                        let ticket = tickets.swap_remove(index);
                        let peer = ticket.peer_id();
                        let digest = report::hex(&Sha256::digest(ticket.offer().to_wire_bytes()));
                        if ticket.complete(event).map_err(|_| "publisher_correlation")?.is_ok() {
                            let index = targets.iter().position(|target| *target == peer).ok_or("publisher_target")?;
                            if reported_receipts[index].as_ref() != Some(&digest) {
                                output.emit(json!({"event":"publisher_offer_receipted", "peer_id":peer.to_string(), "offer_sha256":digest}))?;
                                reported_receipts[index] = Some(digest);
                            }
                        }
                    }
                },
                _ => {},
            },
        }
    }
    drop((network, sources, journal));
    output.finish(json!({"event":"publisher_stopped"}))
}

fn load_offer(
    base: &Path,
    bytes: &[u8],
    journal: &ArtifactChainJournal,
    sources: &mut sources::Sources,
) -> Result<CandidateOffer> {
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|_| "publisher_offer_schema")?;
    let ids = manifest
        .candidates
        .iter()
        .map(|id| acquisition::block(id))
        .collect::<Result<Vec<_>>>()?;
    let offer = CandidateOffer::new(journal.selected_chain_id(), ids)
        .map_err(|_| "publisher_offer_candidates")?;
    if let Some(path) = manifest.bundle_file {
        // Fixed bounded local staging; no remote path or input is opened.
        let limits = CandidateBranchRecoveryBundleLimits::new(256, 8_388_608, 8_454_144)
            .map_err(|_| "publisher_bundle_limits")?;
        let bytes = files::bytes(&base.join(path), 8_454_144)?;
        let bundle = CandidateBranchRecoveryBundleV0::from_canonical_bytes(&bytes, limits)
            .map_err(|_| "publisher_bundle_decode")?;
        let (anchor, target) = (bundle.anchor_block_id(), bundle.target_block_id());
        drop(bundle);
        let _ = stage_candidate_branch_recovery_bundle_v0(
            bytes,
            anchor,
            target,
            journal,
            &mut sources.candidates,
            &mut sources.payloads,
            limits,
        )
        .map_err(|_| "publisher_bundle_stage")?;
    }
    Ok(offer)
}
