//! Provision an independent observer and imported custody for a finalized claimant.

use super::{NodeConfig, Result, files};
use crate::archive::{self, Manifest};
use ed25519_dalek::SigningKey;
use naome_ledger::{AccountId, ResolutionId};
use naome_storage::state::{StateHandoffJournal, StateHistory, StatePeriodCustody};
use serde_json::json;
use std::{fs, net::SocketAddr, path::Path};

const USAGE: &str = "usage: candidate-setup DIRECTORY GENESIS EXPORT_DIRECTORY OWNER_KEY FAMILY_HEX CONSENSUS_KEY TRANSPORT_KEY PRIMARY_ENDPOINT HANDOFF_ENDPOINT RECOVERY_ENDPOINTS_JSON";

fn source_key(path: &Path, role: u8) -> Result<Option<SigningKey>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let key = files::key(path, role)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if fs::symlink_metadata(path)?.nlink() != 1 {
                    return Err("candidate source key has another hard link".into());
                }
            }
            Ok(Some(key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn remove_source(path: &Path, role: u8, expected: &SigningKey) -> Result<()> {
    let Some(current) = source_key(path, role)? else {
        return Ok(());
    };
    if current.as_bytes() != expected.as_bytes() {
        return Err("candidate source key changed during provisioning".into());
    }
    fs::remove_file(path)?;
    fs::File::open(path.parent().ok_or("candidate source parent missing")?)?.sync_all()?;
    Ok(())
}

fn endpoint(value: &str) -> Result<SocketAddr> {
    let address: SocketAddr = value.parse()?;
    if value.len() > 128
        || address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address, SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
        || matches!(address.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
        || address.to_string() != value
    {
        return Err("canonical literal candidate endpoint required".into());
    }
    Ok(address)
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    if args.len() != 10 {
        return Err(USAGE.into());
    }
    let requested = Path::new(&args[0]);
    let genesis_path = Path::new(&args[1]);
    let export = Path::new(&args[2]);
    let owner_path = Path::new(&args[3]);
    let family = ResolutionId::from_bytes(files::unhex(&args[4])?);
    let consensus_path = Path::new(&args[5]);
    let transport_path = Path::new(&args[6]);
    let primary = endpoint(&args[7])?;
    let handoff = endpoint(&args[8])?;
    if primary == handoff {
        return Err("candidate primary and handoff endpoints must differ".into());
    }
    let recovery_endpoints: Vec<String> =
        serde_json::from_slice(&files::read(Path::new(&args[9]), 4096, false)?)?;
    if recovery_endpoints.is_empty() || recovery_endpoints.len() > 10 {
        return Err("one through ten recovery endpoints required".into());
    }
    let mut recovery_seen = std::collections::BTreeSet::new();
    for value in &recovery_endpoints {
        let address = endpoint(value)?;
        if address == primary || address == handoff || !recovery_seen.insert(address) {
            return Err("recovery endpoints must be distinct from candidate endpoints".into());
        }
    }
    let owner = files::key(owner_path, 1)?;
    let consensus = source_key(consensus_path, 2)?;
    let transport = source_key(transport_path, 3)?;
    let owner_path = owner_path.canonicalize()?;
    let consensus_canonical = consensus
        .as_ref()
        .map(|_| consensus_path.canonicalize())
        .transpose()?;
    let transport_canonical = transport
        .as_ref()
        .map(|_| transport_path.canonicalize())
        .transpose()?;
    if consensus_canonical.as_ref() == Some(&owner_path)
        || transport_canonical.as_ref() == Some(&owner_path)
        || (consensus_canonical.is_some() && consensus_canonical == transport_canonical)
    {
        return Err("candidate source keys must be distinct files".into());
    }
    let resume = requested.join("node.json").try_exists()?;
    if !resume && (consensus.is_none() || transport.is_none()) {
        return Err("candidate source keys are required before first import".into());
    }

    // Verify the entire exported chain before creating any authority store.
    let replayed = archive::replay(genesis_path, export, None)?;
    let state = replayed.branch.state();
    let genesis = state.genesis().clone();
    let manifest: Manifest =
        serde_json::from_slice(&files::read(&export.join("manifest.json"), 16384, false)?)?;
    if manifest.maximum_round == 0 {
        return Err("candidate archive requires a nonzero maximum round".into());
    }
    let claim = state
        .claims()
        .get(&family)
        .ok_or("candidate has no finalized claim")?;
    let account = AccountId::for_key(owner.verifying_key().as_bytes());
    let entry = state
        .join_intent(family)
        .ok_or("candidate has no finalized intent")?;
    if claim.author != account
        || claim.completion_ordinal != entry.intent().completion_ordinal()
        || entry.expires() <= state.time()
        || state.consumed_claims().contains(&family)
        || !state.join_queue().contains(&family)
        || state.authority().owner(account).is_some()
    {
        return Err("candidate claim or intent is no longer eligible".into());
    }
    if consensus
        .as_ref()
        .is_some_and(|key| entry.intent().consensus_key() != key.verifying_key().as_bytes())
        || transport
            .as_ref()
            .is_some_and(|key| entry.intent().transport_key() != key.verifying_key().as_bytes())
        || entry.intent().endpoint() != primary.to_string()
    {
        return Err("candidate keys or primary endpoint differ from finalized intent".into());
    }
    if state.authority().units().iter().any(|unit| {
        unit.keys()
            .is_some_and(|keys| keys.endpoint() == handoff.to_string())
    }) {
        return Err("candidate handoff endpoint overlaps selected authority".into());
    }

    if !resume {
        files::directory(requested)?;
    }
    let root = requested.canonicalize()?;
    if !resume && files::available(&root)? < genesis.profile().required_storage_bytes()? {
        return Err("candidate observer requires more free storage".into());
    }
    let config = NodeConfig {
        version: 5,
        genesis: root.join("genesis.bin"),
        history: root.join("history"),
        history_anchor: root.join("anchor-history"),
        signer: root.join("signer"),
        signer_anchor: root.join("anchor-signer"),
        custody: root.join("custody"),
        custody_anchor: root.join("anchor-custody"),
        handoff: root.join("handoff"),
        handoff_anchor: root.join("anchor-handoff"),
        // Candidate keys are held only by anchored custody after import.
        consensus_key: root.join("unused-consensus.key"),
        transport_key: root.join("unused-transport.key"),
        account_key: owner_path,
        agenda_profile: root.join("agenda-profile.txt"),
        control_socket: root.join("control.sock"),
        maximum_round: manifest.maximum_round,
        simulation: false,
        primary_endpoint: primary.to_string(),
        candidate_family: Some(files::hex(family.as_bytes())),
        recovery_endpoints,
        listen_address: None,
        handoff_endpoint: handoff.to_string(),
        handoff_listen_address: None,
    };
    if resume {
        let actual = NodeConfig::read(&root.join("node.json"))?;
        if serde_json::to_value(&actual)? != serde_json::to_value(&config)?
            || actual.genesis()?.encode() != genesis.encode()
        {
            return Err("candidate configuration differs from requested import".into());
        }
        let history = StateHistory::open(
            &actual.history,
            &actual.history_anchor,
            genesis.clone(),
            actual.maximum_round,
        )?;
        if history.head()?.commitment() != replayed.branch.commitment() {
            return Err("candidate selected history differs from verified export".into());
        }
        let staged = StatePeriodCustody::stage_candidate(
            &actual.custody,
            &actual.custody_anchor,
            history.head()?.state(),
            family,
            &owner,
        )?;
        if staged.consensus_key().verifying_key().as_bytes() != entry.intent().consensus_key()
            || staged.transport_key().verifying_key().as_bytes() != entry.intent().transport_key()
            || consensus
                .as_ref()
                .is_some_and(|key| key.as_bytes() != staged.consensus_key().as_bytes())
            || transport
                .as_ref()
                .is_some_and(|key| key.as_bytes() != staged.transport_key().as_bytes())
        {
            return Err("candidate source or custody differs from finalized intent".into());
        }
        let next = history
            .head()?
            .state()
            .height()
            .checked_add(1)
            .ok_or("candidate height overflow")?;
        let journal = StateHandoffJournal::open(
            &actual.handoff,
            &actual.handoff_anchor,
            genesis.clone(),
            next,
            actual.maximum_round,
            &history,
        )?;
        drop(journal);
        remove_source(consensus_path, 2, staged.consensus_key())?;
        remove_source(transport_path, 3, staged.transport_key())?;
        println!(
            "{}",
            json!({"status":"candidate_provisioned","resumed":true,"config":root.join("node.json"),"genesis":files::hex(genesis.id().as_bytes()),"height":manifest.height,"family":files::hex(family.as_bytes()),"intent_receipt":files::hex(entry.receipt().operation.as_bytes()),"active_voting_rights":false})
        );
        return Ok(());
    }
    let consensus = consensus.ok_or("candidate consensus source key missing")?;
    let transport = transport.ok_or("candidate transport source key missing")?;
    files::create(&config.genesis, &genesis.encode(), false)?;
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
        files::directory(directory)?;
    }
    let mut history = StateHistory::create(
        &config.history,
        &config.history_anchor,
        genesis.clone(),
        config.maximum_round,
    )?;
    let maximum = genesis.profile().limits().transport_frame_bytes as usize;
    for height in 1..=manifest.height {
        let bytes = files::read(
            &export.join(format!("{height:08}.finality")),
            maximum,
            false,
        )?;
        history.append_finality(&bytes)?;
    }
    if history.head()?.commitment() != replayed.branch.commitment() {
        return Err("candidate observer replay differs from verified export".into());
    }
    StatePeriodCustody::import_candidate(
        &config.custody,
        &config.custody_anchor,
        &genesis,
        family,
        &owner,
        &consensus,
        &transport,
    )?;
    let staged = StatePeriodCustody::stage_candidate(
        &config.custody,
        &config.custody_anchor,
        history.head()?.state(),
        family,
        &owner,
    )?;
    if staged.candidate_offer().is_none() {
        return Err("candidate offer was not staged".into());
    }
    drop(staged);
    let next = history
        .head()?
        .state()
        .height()
        .checked_add(1)
        .ok_or("candidate height overflow")?;
    let journal = StateHandoffJournal::create(
        &config.handoff,
        &config.handoff_anchor,
        genesis.clone(),
        next,
        config.maximum_round,
    )?;
    drop(journal);
    drop(history);
    files::create(
        &config.agenda_profile,
        b"Prioritize precise, checker-expressible foundational mathematics. Approve small reusable helper results and questions that develop a reusable formal library. Reject unclear or unrelated targets.\n",
        true,
    )?;
    files::create(
        &root.join("node.json"),
        &serde_json::to_vec_pretty(&config)?,
        true,
    )?;

    // No source key is removed until its exact pair is durably imported and the
    // independent observer and configuration are fully provisioned.
    remove_source(consensus_path, 2, &consensus)?;
    remove_source(transport_path, 3, &transport)?;
    println!(
        "{}",
        json!({"status":"candidate_provisioned","config":root.join("node.json"),"genesis":files::hex(genesis.id().as_bytes()),"height":manifest.height,"family":files::hex(family.as_bytes()),"intent_receipt":files::hex(entry.receipt().operation.as_bytes()),"active_voting_rights":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use naome_consensus::state::StateBranch;
    use naome_ledger::{
        LedgerState,
        profile::{Genesis, Profile, STATE_CHECKER_PROFILE, ValidatorRegistration},
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "naome-candidate-setup-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            files::directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn endpoint_requires_canonical_literal_address() {
        assert!(endpoint("127.0.0.1:42000").is_ok());
        for invalid in [
            "0.0.0.0:42000",
            "127.0.0.1:0",
            "localhost:42000",
            "[::ffff:127.0.0.1]:42000",
        ] {
            assert!(endpoint(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn source_cleanup_requires_exact_key_and_accepts_crash_after_first_removal() {
        let directory = Directory::new();
        let path = directory.0.join("candidate.key");
        let key = files::write_key(&path, 2).unwrap();
        let other = SigningKey::from_bytes(&[81; 32]);
        assert!(remove_source(&path, 2, &other).is_err());
        assert!(path.exists());
        remove_source(&path, 2, &key).unwrap();
        remove_source(&path, 2, &key).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn absent_finalized_intent_preserves_keys_and_creates_no_candidate_directory() {
        let directory = Directory::new();
        let owner_path = directory.0.join("owner.key");
        let consensus_path = directory.0.join("consensus.key");
        let transport_path = directory.0.join("transport.key");
        let owner = files::write_key(&owner_path, 1).unwrap();
        files::write_key(&consensus_path, 2).unwrap();
        files::write_key(&transport_path, 3).unwrap();
        let account = |i: u8| SigningKey::from_bytes(&[i + 1; 32]);
        let registrations: Vec<_> = (0..4)
            .map(|i| ValidatorRegistration {
                owner: AccountId::for_key(account(i).verifying_key().as_bytes()),
                consensus_key: SigningKey::from_bytes(&[i + 101; 32])
                    .verifying_key()
                    .to_bytes(),
                transport_key: SigningKey::from_bytes(&[i + 201; 32])
                    .verifying_key()
                    .to_bytes(),
                endpoint: format!("127.0.0.1:{}", 42000 + u16::from(i)),
            })
            .collect();
        let genesis = Genesis::new(
            Profile::short_test(),
            "naome:zfc".into(),
            STATE_CHECKER_PROFILE.into(),
            naome_ledger::profile::STATE_PROTOCOL_VERSION,
            100,
            [9; 32],
            (0..5)
                .map(|i| account(i).verifying_key().to_bytes())
                .chain(std::iter::once(owner.verifying_key().to_bytes()))
                .collect(),
            registrations.clone(),
            registrations
                .iter()
                .map(ValidatorRegistration::id)
                .collect(),
        )
        .unwrap();
        let export = directory.0.join("export");
        files::directory(&export).unwrap();
        let genesis_path = directory.0.join("genesis.bin");
        files::create(&genesis_path, &genesis.encode(), false).unwrap();
        let branch = StateBranch::from_genesis(LedgerState::new(genesis.clone())).unwrap();
        let manifest = Manifest {
            version: 1,
            genesis: files::hex(genesis.id().as_bytes()),
            head: files::hex(branch.state().head().as_bytes()),
            state: files::hex(branch.state().commitment().as_bytes()),
            height: 0,
            maximum_round: genesis.profile().limits().consensus_rounds,
        };
        files::create(
            &export.join("manifest.json"),
            &serde_json::to_vec(&manifest).unwrap(),
            false,
        )
        .unwrap();
        let recovery = directory.0.join("recovery.json");
        files::create(&recovery, br#"["127.0.0.1:42000"]"#, false).unwrap();
        let requested = directory.0.join("candidate");
        let args = vec![
            requested.to_string_lossy().into_owned(),
            genesis_path.to_string_lossy().into_owned(),
            export.to_string_lossy().into_owned(),
            owner_path.to_string_lossy().into_owned(),
            files::hex(&[91; 32]),
            consensus_path.to_string_lossy().into_owned(),
            transport_path.to_string_lossy().into_owned(),
            "127.0.0.1:43000".into(),
            "127.0.0.1:43004".into(),
            recovery.to_string_lossy().into_owned(),
        ];
        assert!(run(&args).is_err());
        assert!(!requested.exists());
        assert!(owner_path.exists());
        assert!(consensus_path.exists());
        assert!(transport_path.exists());
    }
}
