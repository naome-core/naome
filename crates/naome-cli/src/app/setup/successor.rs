//! Explicit one-node continuation from a completely replayed terminal run.
//! Every node independently derives the same public successor genesis. The
//! private bridge keys are moved before any new-run signer is created.

use super::{ArchivePair, NodeConfig, Result, files};
use crate::archive;
use ed25519_dalek::SigningKey;
use naome_consensus::state::StateBranch;
use naome_ledger::AccountId;
use naome_storage::state::{
    StateHandoffJournal, StateHistory, StatePendingActions, StatePeriodCustody, StateSigner,
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

pub fn run(args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err(
            "usage: continue-node PREDECESSOR_CONFIG PREDECESSOR_ARCHIVE NEW_DIRECTORY".into(),
        );
    }
    let previous = NodeConfig::read(Path::new(&args[0]))?;
    let previous_genesis = previous.genesis()?;
    let archive_root = Path::new(&args[1]).canonicalize()?;
    let mut lineage = previous.lineage.clone();
    if lineage.len() >= 32 {
        return Err("successor lineage limit reached".into());
    }
    lineage.push(ArchivePair {
        genesis: previous.genesis.clone(),
        archive: archive_root,
    });
    let pairs = references(&lineage);
    let replayed = archive::replay_lineage(&pairs)?;
    if replayed.branch.state().genesis().id() != previous_genesis.id() {
        return Err("predecessor archive genesis differs from node configuration".into());
    }
    let terminal = replayed
        .last_finality
        .as_ref()
        .ok_or("predecessor has no terminal finality")?;
    let initial = StateBranch::from_terminal_finality(terminal)?;
    let genesis = initial.state().genesis().clone();
    let previous_history = if previous.lineage.is_empty() {
        StateHistory::open(
            &previous.history,
            &previous.history_anchor,
            previous_genesis,
            previous.maximum_round,
        )?
    } else {
        let prior_pairs = references(&previous.lineage);
        let prior = archive::replay_lineage(&prior_pairs)?;
        let prior_terminal = prior
            .last_finality
            .as_ref()
            .ok_or("earlier predecessor terminal finality missing")?;
        StateHistory::open_successor(
            &previous.history,
            &previous.history_anchor,
            prior_terminal,
            previous.maximum_round,
        )?
    };
    if previous_history.head()?.commitment() != replayed.branch.commitment() {
        return Err("local selected predecessor differs from independent archive".into());
    }
    let owner = files::key(&previous.account_key, 1)?;
    let owner_id = AccountId::for_key(owner.verifying_key().as_bytes());
    let local_keys = initial
        .authority()
        .owner(owner_id)
        .and_then(|unit| unit.keys());
    let requested = Path::new(&args[2]);
    ensure_directory(requested)?;
    let root = requested.canonicalize()?;
    if files::available(&root)? < genesis.profile().operating_storage_floor_bytes()? {
        return Err("insufficient successor operating storage headroom".into());
    }
    let primary = local_keys.map_or(previous.primary_endpoint.clone(), |keys| {
        keys.endpoint().to_owned()
    });
    let handoff = if previous.primary_endpoint != primary {
        previous.primary_endpoint.clone()
    } else {
        previous.handoff_endpoint.clone()
    };
    if handoff == primary {
        return Err("successor handoff endpoint overlaps primary".into());
    }
    let config = NodeConfig {
        version: naome_ledger::profile::STATE_PROTOCOL_VERSION,
        genesis: root.join("genesis.bin"),
        history: root.join("history"),
        history_anchor: root.join("anchor-history"),
        signer: root.join("signer"),
        signer_anchor: root.join("anchor-signer"),
        custody: root.join("custody"),
        custody_anchor: root.join("anchor-custody"),
        handoff: root.join("handoff"),
        handoff_anchor: root.join("anchor-handoff"),
        consensus_key: root.join("consensus.key"),
        transport_key: root.join("transport.key"),
        account_key: previous.account_key.clone(),
        agenda_profile: root.join("agenda-profile.txt"),
        control_socket: root.join("control.sock"),
        maximum_round: previous.maximum_round,
        simulation: previous.simulation,
        primary_endpoint: primary,
        candidate_family: None,
        recovery_endpoints: previous.recovery_endpoints.clone(),
        listen_address: previous.listen_address,
        handoff_endpoint: handoff,
        handoff_listen_address: previous.handoff_listen_address,
        lineage,
    };
    files::create_or_match(&config.genesis, &genesis.encode(), false)?;
    for path in [
        &config.history,
        &config.history_anchor,
        &config.signer,
        &config.signer_anchor,
        &config.custody,
        &config.custody_anchor,
        &config.handoff,
        &config.handoff_anchor,
    ] {
        ensure_directory(path)?;
    }
    if let Some(keys) = local_keys {
        transfer_bridge_keys(
            &previous,
            &previous_history,
            &config,
            &owner,
            keys.consensus(),
            keys.transport(),
        )?;
    }
    // The new signer is created only after old custody has been retired.
    let history = if config.history.join("state.journal").try_exists()? {
        StateHistory::open_successor(
            &config.history,
            &config.history_anchor,
            terminal,
            config.maximum_round,
        )?
    } else {
        StateHistory::create_successor(
            &config.history,
            &config.history_anchor,
            terminal,
            config.maximum_round,
        )?
    };
    if history.head()?.commitment() != initial.commitment() {
        return Err("successor opening state differs from terminal bridge".into());
    }
    drop(
        if config.history.join("state-pending.journal").try_exists()? {
            StatePendingActions::open(&config.history, &config.history_anchor, genesis.clone())?
        } else {
            StatePendingActions::create(&config.history, &config.history_anchor, genesis.clone())?
        },
    );
    if let Some(keys) = local_keys {
        let consensus = files::key(&config.consensus_key, 2)?;
        let signer_file = format!("state-signer-{}.journal", files::hex(keys.consensus()));
        let signer = if config.signer.join(signer_file).try_exists()? {
            StateSigner::open_for_selected(
                &config.signer,
                &config.signer_anchor,
                &history,
                consensus,
                config.maximum_round,
            )?
        } else {
            StateSigner::create_for_selected(
                &config.signer,
                &config.signer_anchor,
                &history,
                consensus,
                config.maximum_round,
            )?
        };
        drop(signer);
        let unit = history
            .head()?
            .authority()
            .owner(owner_id)
            .ok_or("successor local owner missing")?;
        let next = StatePeriodCustody::stage_offer(
            &config.custody,
            &config.custody_anchor,
            history.head()?.state(),
            unit.id(),
            &owner,
            config.handoff_endpoint.clone(),
        )?;
        drop(next);
    }
    drop(StateHandoffJournal::open_or_create(
        &config.handoff,
        &config.handoff_anchor,
        genesis.clone(),
        1,
        config.maximum_round,
        &history,
    )?);
    drop(history);
    files::create_or_match(
        &root.join("node.json"),
        &serde_json::to_vec_pretty(&config)?,
        true,
    )?;
    println!(
        "{}",
        json!({
            "status":"successor_provisioned", "genesis":files::hex(genesis.id().as_bytes()),
            "predecessor":files::hex(previous.genesis()?.id().as_bytes()),
            "config":root.join("node.json"), "run_index":genesis.predecessor().map(|p| p.run_index()),
            "signer_ready":local_keys.is_some(),
        })
    );
    Ok(())
}

fn references(pairs: &[ArchivePair]) -> Vec<(&Path, &Path)> {
    pairs
        .iter()
        .map(|p| (p.genesis.as_path(), p.archive.as_path()))
        .collect()
}

fn ensure_directory(path: &Path) -> Result<()> {
    match files::directory(path) {
        Ok(()) => Ok(()),
        Err(error) if path.try_exists()? => {
            let meta = fs::symlink_metadata(path)?;
            if !meta.is_dir()
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.permissions().mode() & 0o077 != 0
            {
                return Err("successor private directory is not owned and restricted".into());
            }
            let _ = error;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn transfer_bridge_keys(
    previous: &NodeConfig,
    history: &StateHistory,
    successor: &NodeConfig,
    owner: &SigningKey,
    consensus_public: &[u8; 32],
    transport_public: &[u8; 32],
) -> Result<()> {
    let prepared = match StatePeriodCustody::open_for_selected(
        &previous.custody,
        &previous.custody_anchor,
        history,
        owner,
    ) {
        Ok(Some(custody)) => Some(custody),
        Ok(None) => return Err("terminal owner has no prepared successor keys".into()),
        Err(error)
            if successor.consensus_key.try_exists()? && successor.transport_key.try_exists()? =>
        {
            let _ = error;
            None
        }
        Err(error) => return Err(error.into()),
    };
    if let Some(custody) = prepared.as_ref() {
        for (path, role, key) in [
            (&successor.consensus_key, 2, custody.consensus_key()),
            (&successor.transport_key, 3, custody.transport_key()),
        ] {
            let mut bytes = Zeroizing::new(b"NSKEY001".to_vec());
            bytes.push(role);
            bytes.extend_from_slice(&key.to_bytes());
            files::create_or_match(path, &bytes, true)?;
        }
    }
    if files::key(&successor.consensus_key, 2)?
        .verifying_key()
        .as_bytes()
        != consensus_public
        || files::key(&successor.transport_key, 3)?
            .verifying_key()
            .as_bytes()
            != transport_public
    {
        return Err("transferred keys differ from sealed incoming authority".into());
    }
    drop(prepared);
    StatePeriodCustody::retire_terminal_selected(
        &previous.custody,
        &previous.custody_anchor,
        history,
        owner,
    )?;
    Ok(())
}
