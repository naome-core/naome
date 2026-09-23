//! Startup follows selected history and durable retirement before loading keys.

use super::{NodeConfig, Result, files};
use ed25519_dalek::SigningKey;
use naome_chain::StateRecord;
use naome_consensus::ConsensusKey;
use naome_ledger::{AccountId, ResolutionId};
use naome_network::{Keypair, StateNetwork, StateTransportPair, state_peer_id};
use naome_runtime::state::{StateHandoffSetup, StateRuntime, StateRuntimeConfig};
use naome_storage::state::{
    StateHandoffJournal, StateHistory, StatePeriodCustody, StateSigner, StateStorageError,
};
use zeroize::Zeroizing;

pub(super) fn open(
    config: &NodeConfig,
    runtime_config: StateRuntimeConfig,
) -> Result<StateRuntime> {
    let genesis = config.genesis()?;
    let history = StateHistory::open(
        &config.history,
        &config.history_anchor,
        genesis.clone(),
        config.maximum_round,
    )?;
    let owner = files::key(&config.account_key, 1)?;
    let owner_id = AccountId::for_key(owner.verifying_key().as_bytes());
    StateSigner::retire_predecessors(
        &config.signer,
        &config.signer_anchor,
        &history,
        owner_id,
        config.maximum_round,
        |retired, preceding, selected, successor| {
            let cleanup = if selected.state().height() == 0 {
                retire_initial(config).map_err(StateStorageError::from)
            } else {
                let parent =
                    preceding.ok_or(StateStorageError::Invalid("retired period parent missing"))?;
                match retired {
                    Some(retired) => StatePeriodCustody::retire_for_selected_branch(
                        &config.custody,
                        &config.custody_anchor,
                        selected,
                        parent.state(),
                        &owner,
                        retired,
                    ),
                    None => StatePeriodCustody::retire_unactivated_for_selected_branch(
                        &config.custody,
                        &config.custody_anchor,
                        selected,
                        parent.state(),
                        &owner,
                    ),
                }
            };
            cleanup?;
            StatePeriodCustody::retire_unselected_offer_for_transition(
                &config.custody,
                &config.custody_anchor,
                selected.state(),
                successor,
                &owner,
            )
        },
    )?;
    let state = history.head()?.state().clone();
    if state.terminated() {
        StatePeriodCustody::retire_terminal_selected(
            &config.custody,
            &config.custody_anchor,
            &history,
            &owner,
        )?;
    }
    let candidate_family = config
        .candidate_family
        .as_deref()
        .map(|id| files::unhex(id).map(ResolutionId::from_bytes))
        .transpose()?;
    if let Some(family) = candidate_family {
        StatePeriodCustody::retire_closed_candidate_import(
            &config.custody,
            &config.custody_anchor,
            &state,
            family,
            &owner,
        )?;
    }
    let mut signer = None;
    let mut recovery_key = None;
    let pair = if let Some(keys) = state
        .authority()
        .owner(owner_id)
        .and_then(|unit| unit.keys())
        .filter(|_| !state.terminated())
    {
        let public = ConsensusKey::from_bytes(*keys.consensus());
        match StateSigner::restore_for_selected(
            &config.signer,
            &config.signer_anchor,
            &history,
            public,
            None,
            config.maximum_round,
        ) {
            Ok(retired) => {
                let journal = StateHandoffJournal::open(
                    &config.handoff,
                    &config.handoff_anchor,
                    genesis.clone(),
                    state.height() + 1,
                    config.maximum_round,
                    &history,
                )?;
                let agreement = journal
                    .agreement()
                    .ok_or("stopped current signer has no saved handoff agreement")?;
                let record = StateRecord::decode(agreement.proposal().record_bytes(), &genesis)?;
                let unit = state
                    .authority()
                    .owner(owner_id)
                    .ok_or("selected owner absent")?;
                let endpoint = if keys.endpoint() == config.primary_endpoint {
                    &config.handoff_endpoint
                } else {
                    &config.primary_endpoint
                };
                let custody = StatePeriodCustody::stage_offer(
                    &config.custody,
                    &config.custody_anchor,
                    &state,
                    unit.id(),
                    &owner,
                    endpoint.clone(),
                )?;
                let mut network = StateNetwork::new_staged(
                    identity(custody.transport_key())?,
                    &state,
                    record.handoff_plan(),
                    record.time_certificate(),
                )?;
                listen(&mut network, config, endpoint)?;
                if state.height() == 0 {
                    retire_initial(config)?;
                } else {
                    StatePeriodCustody::retire_for_selected(
                        &config.custody,
                        &config.custody_anchor,
                        &history,
                        &owner,
                        &retired,
                    )?;
                }
                signer = Some(retired);
                StateTransportPair::from_staged(network)?
            }
            Err(StateStorageError::KeyRequired) => {
                let transport = if state.height() == 0 {
                    let key = files::key(&config.consensus_key, 2)?;
                    let transport = files::key(&config.transport_key, 3)?;
                    if key.verifying_key().as_bytes() != keys.consensus()
                        || transport.verifying_key().as_bytes() != keys.transport()
                    {
                        return Err("initial keys differ from selected authority".into());
                    }
                    signer = Some(StateSigner::restore_for_selected(
                        &config.signer,
                        &config.signer_anchor,
                        &history,
                        public,
                        Some(key),
                        config.maximum_round,
                    )?);
                    transport
                } else {
                    let mut custody = StatePeriodCustody::open_for_selected(
                        &config.custody,
                        &config.custody_anchor,
                        &history,
                        &owner,
                    )?
                    .ok_or("selected authority custody missing")?;
                    signer = Some(custody.open_or_create_selected_signer(
                        &config.signer,
                        &config.signer_anchor,
                        &history,
                        config.maximum_round,
                    )?);
                    custody.transport_key().clone()
                };
                let mut network = StateNetwork::new_for_parent(identity(&transport)?, &state)?;
                listen(&mut network, config, keys.endpoint())?;
                StateTransportPair::new(network)?
            }
            Err(StateStorageError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound && state.height() > 0 =>
            {
                // A selected successor may not have opened its ordinary signer
                // yet. Custody's anchored marker forbids lost-journal recovery.
                let mut custody = StatePeriodCustody::open_for_selected(
                    &config.custody,
                    &config.custody_anchor,
                    &history,
                    &owner,
                )?
                .ok_or("selected authority custody missing")?;
                signer = Some(custody.open_or_create_selected_signer(
                    &config.signer,
                    &config.signer_anchor,
                    &history,
                    config.maximum_round,
                )?);
                let mut network =
                    StateNetwork::new_for_parent(identity(custody.transport_key())?, &state)?;
                listen(&mut network, config, keys.endpoint())?;
                StateTransportPair::new(network)?
            }
            Err(error) => return Err(error.into()),
        }
    } else if let Some(family) = candidate_family.filter(|family| {
        !state.terminated()
            && state.join_queue().contains(family)
            && state
                .join_intent(*family)
                .is_some_and(|entry| entry.expires() > state.time())
            && !state.consumed_claims().contains(family)
    }) {
        let custody = StatePeriodCustody::stage_candidate(
            &config.custody,
            &config.custody_anchor,
            &state,
            family,
            &owner,
        )?;
        let mut network = StateNetwork::new_for_parent(identity(custody.transport_key())?, &state)?;
        listen(
            &mut network,
            config,
            custody
                .candidate_offer()
                .ok_or("candidate custody offer missing")?
                .keys()
                .endpoint(),
        )?;
        StateTransportPair::new(network)?
    } else {
        let key = SigningKey::from_bytes(&*files::random()?);
        let network = StateNetwork::new_recovery_only(identity(&key)?, &state)?;
        recovery_key = Some(key);
        StateTransportPair::from_recovery(network)?
    };
    let mut peers = state
        .authority()
        .units()
        .iter()
        .filter_map(|unit| unit.keys())
        .map(|keys| state_peer_id(*keys.transport()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if let Some(network) = pair.active().or(pair.staged()) {
        peers.retain(|peer| *peer != network.local_peer_id());
    }
    let setup = StateHandoffSetup {
        owner_key: owner,
        candidate_family,
        recovery_key,
        recovery_endpoints: config.recovery_endpoints.clone(),
        signer_directory: config.signer.clone(),
        signer_anchor_directory: config.signer_anchor.clone(),
        custody_directory: config.custody.clone(),
        custody_anchor_directory: config.custody_anchor.clone(),
        handoff_directory: config.handoff.clone(),
        handoff_anchor_directory: config.handoff_anchor.clone(),
        primary_endpoint: config.primary_endpoint.clone(),
        handoff_endpoint: config.handoff_endpoint.clone(),
        initial_consensus_key_path: config.consensus_key.clone(),
        initial_transport_key_path: config.transport_key.clone(),
        primary_listen_address: config.listen_address,
        handoff_listen_address: config.handoff_listen_address,
    };
    Ok(StateRuntime::new_handoff(
        history,
        signer,
        pair,
        peers,
        runtime_config,
        setup,
    )?)
}

fn identity(key: &SigningKey) -> Result<Keypair> {
    let mut seed = Zeroizing::new(key.to_bytes());
    Ok(Keypair::ed25519_from_bytes(&mut *seed)?)
}
fn listen(network: &mut StateNetwork, config: &NodeConfig, endpoint: &str) -> Result<()> {
    let address = if endpoint == config.primary_endpoint {
        config.listen_address
    } else if endpoint == config.handoff_endpoint {
        config.handoff_listen_address
    } else {
        return Err("selected endpoint is not configured for this node".into());
    };
    let listen = match address {
        Some(address) => {
            let family = if address.is_ipv4() { "ip4" } else { "ip6" };
            format!("/{family}/{}/tcp/{}", address.ip(), address.port()).parse()?
        }
        None => network
            .state_listen_address()
            .ok_or("selected listener unavailable")?
            .clone(),
    };
    network.listen_on(listen)?;
    Ok(())
}
pub(super) fn retire_initial(config: &NodeConfig) -> std::io::Result<()> {
    for path in [&config.consensus_key, &config.transport_key] {
        match std::fs::remove_file(path) {
            Ok(()) => std::fs::File::open(
                path.parent()
                    .ok_or_else(|| std::io::Error::other("initial key parent missing"))?,
            )?
            .sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
