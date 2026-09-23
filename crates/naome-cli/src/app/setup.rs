use super::{Result, files};
use naome_ledger::{
    AccountId,
    profile::{Genesis, Limits, Profile, STATE_CHECKER_PROFILE, TimingKind, ValidatorRegistration},
};
use serde::{Deserialize, Serialize};

pub(super) mod candidate;
#[cfg(test)]
mod tests;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub version: u16,
    pub genesis: PathBuf,
    pub history: PathBuf,
    pub history_anchor: PathBuf,
    pub signer: PathBuf,
    pub signer_anchor: PathBuf,
    pub custody: PathBuf,
    pub custody_anchor: PathBuf,
    pub handoff: PathBuf,
    pub handoff_anchor: PathBuf,
    pub consensus_key: PathBuf,
    pub transport_key: PathBuf,
    pub account_key: PathBuf,
    pub agenda_profile: PathBuf,
    pub control_socket: PathBuf,
    pub maximum_round: u64,
    pub simulation: bool,
    pub primary_endpoint: String,
    pub candidate_family: Option<String>,
    pub recovery_endpoints: Vec<String>,
    /// Local bind override for an explicitly provisioned proxy or NAT endpoint.
    #[serde(default)]
    pub listen_address: Option<std::net::SocketAddr>,
    pub handoff_endpoint: String,
    #[serde(default)]
    pub handoff_listen_address: Option<std::net::SocketAddr>,
}
impl NodeConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let mut config: Self = serde_json::from_slice(&files::read(path, 16384, true)?)?;
        if config.version != 5 || config.maximum_round == 0 {
            return Err("unsupported node configuration".into());
        }
        // Portable bundles resolve paths beside their configuration, never
        // against the operator's working directory. Existing absolute paths
        // retain their meaning; this does not initialize or copy custody.
        let parent = path.parent().unwrap_or(Path::new("."));
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let parent = parent.canonicalize()?;
        for field in [
            &mut config.genesis,
            &mut config.history,
            &mut config.history_anchor,
            &mut config.signer,
            &mut config.signer_anchor,
            &mut config.custody,
            &mut config.custody_anchor,
            &mut config.handoff,
            &mut config.handoff_anchor,
            &mut config.consensus_key,
            &mut config.transport_key,
            &mut config.account_key,
            &mut config.agenda_profile,
            &mut config.control_socket,
        ] {
            if field.is_relative() {
                *field = parent.join(&*field);
            }
        }
        Ok(config)
    }
    pub fn genesis(&self) -> Result<Genesis> {
        Ok(Genesis::decode(&files::read(&self.genesis, 16384, false)?)?)
    }
}
fn parameters(args: &[String]) -> Result<(Profile, [String; 4], [usize; 4])> {
    if !(args.len() == 5
        || ((6..=8).contains(&args.len()) && matches!(args[5].as_str(), "compact" | "standard")))
    {
        return Err(
            "usage: setup DIRECTORY lab|research|short-test|ci-test RUN_RECORDS BASE_PORT RETIREMENT_ORDER_JSON [standard|compact [ENDPOINTS_JSON [HANDOFF_ENDPOINTS_JSON]]]".into(),
        );
    }
    // The plan names generated node indices, not the canonical validator list.
    // Refuse to create keys or a run directory until all four are specified.
    let retirement_order: [usize; 4] =
        serde_json::from_slice(&files::read(Path::new(&args[4]), 4096, false)?)?;
    if retirement_order.iter().any(|&index| index >= 4)
        || retirement_order
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 4
    {
        return Err("retirement order must contain each node index 0, 1, 2, 3 exactly once".into());
    }
    let timing = match args[1].as_str() {
        "lab" => TimingKind::Lab,
        "research" => TimingKind::Research,
        "short-test" => TimingKind::ShortTest,
        "ci-test" => TimingKind::CiTest,
        _ => return Err("choose lab, research, short-test, or ci-test".into()),
    };
    let mut limits = Limits {
        run_records: args[2].parse()?,
        ..Limits::default()
    };
    if args.get(5).is_some_and(|mode| mode == "compact") {
        limits.record_bytes = 128 * 1024;
        limits.package_bytes = 64 * 1024;
        limits.transport_frame_bytes = 192 * 1024;
        limits.consensus_rounds = 8;
    }
    let profile = Profile::with_limits(timing, limits)?;
    let base: u16 = args[3].parse()?;
    if !(1024..=65528).contains(&base) {
        return Err("base port must be 1024 through 65528".into());
    }
    let endpoints: [String; 4] = if args.len() >= 7 {
        let values: [String; 4] =
            serde_json::from_slice(&files::read(Path::new(&args[6]), 4096, false)?)?;
        let parsed = values
            .iter()
            .map(|value| {
                let address: std::net::SocketAddr = value.parse()?;
                if value.len() > 128
                    || address.port() == 0
                    || address.ip().is_unspecified()
                    || address.ip().is_multicast()
                    || matches!(address, std::net::SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
                    || matches!(address.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
                    || address.to_string() != *value
                {
                    return Err("canonical literal peer endpoint required".into());
                }
                Ok(address)
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        if parsed.len() != 4 {
            return Err("four distinct literal peer endpoints are required".into());
        }
        values
    } else {
        std::array::from_fn(|index| format!("127.0.0.1:{}", base + index as u16))
    };
    configured_handoff_endpoints(args, &endpoints)?;
    Ok((profile, endpoints, retirement_order))
}

fn handoff_endpoints(endpoints: &[String; 4]) -> Result<[String; 4]> {
    let mut all: std::collections::BTreeSet<_> = endpoints.iter().cloned().collect();
    let mut next = std::array::from_fn(|_| String::new());
    for (index, value) in endpoints.iter().enumerate() {
        let mut address: std::net::SocketAddr = value.parse()?;
        address.set_port(
            address
                .port()
                .checked_add(4)
                .ok_or("peer endpoint leaves no handoff port")?,
        );
        next[index] = address.to_string();
        if !all.insert(next[index].clone()) {
            return Err("handoff endpoints overlap configured endpoints".into());
        }
    }
    Ok(next)
}

fn configured_handoff_endpoints(args: &[String], primary: &[String; 4]) -> Result<[String; 4]> {
    let Some(path) = args.get(7) else {
        return handoff_endpoints(primary);
    };
    let values: [String; 4] = serde_json::from_slice(&files::read(Path::new(path), 4096, false)?)?;
    let mut seen: std::collections::BTreeSet<_> = primary.iter().cloned().collect();
    for value in &values {
        let address: std::net::SocketAddr = value.parse()?;
        if value.len() > 128
            || address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || address.to_string() != *value
            || matches!(address, std::net::SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
            || matches!(address.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
            || !seen.insert(value.clone())
        {
            return Err("distinct canonical literal handoff endpoints required".into());
        }
    }
    Ok(values)
}

pub fn run(args: &[String]) -> Result<()> {
    let (profile, endpoints, retirement_indices) = parameters(args)?;
    let handoff_endpoints = configured_handoff_endpoints(args, &endpoints)?;
    let maximum_round = profile.limits().consensus_rounds;
    let requested = Path::new(&args[0]);
    files::directory(requested)?;
    let root = requested.canonicalize()?;
    let required = profile
        .required_storage_bytes()?
        .checked_mul(4)
        .ok_or("storage estimate overflow")?;
    if files::available(&root)? < required {
        return Err(format!("four nodes require at least {required} free bytes; use a separate pre-genesis run profile or more storage").into());
    }
    let keys = root.join("accounts");
    files::directory(&keys)?;
    let accounts = (0..6)
        .map(|i| files::write_key(&keys.join(format!("account-{i}.key")), 1))
        .collect::<Result<Vec<_>>>()?;
    let mut registrations = Vec::new();
    let mut configs = Vec::new();
    for (index, account) in accounts.iter().enumerate().take(4) {
        let dir = root.join(format!("node-{index}"));
        files::directory(&dir)?;
        let consensus_key = dir.join("consensus.key");
        let transport_key = dir.join("transport.key");
        let consensus = files::write_key(&consensus_key, 2)?;
        let transport = files::write_key(&transport_key, 3)?;
        registrations.push(ValidatorRegistration {
            owner: AccountId::for_key(account.verifying_key().as_bytes()),
            consensus_key: consensus.verifying_key().to_bytes(),
            transport_key: transport.verifying_key().to_bytes(),
            endpoint: endpoints[index].clone(),
        });
        let agenda_profile = dir.join("agenda-profile.txt");
        files::create(&agenda_profile,b"Prioritize precise, checker-expressible foundational mathematics. Approve small reusable helper results and questions that develop a reusable formal library. Reject unclear or unrelated targets.\n",true)?;
        configs.push(NodeConfig {
            version: 5,
            genesis: root.join("genesis.bin"),
            history: dir.join("history"),
            history_anchor: root.join(format!("anchor-history-{index}")),
            signer: dir.join("signer"),
            signer_anchor: root.join(format!("anchor-signer-{index}")),
            custody: dir.join("custody"),
            custody_anchor: root.join(format!("anchor-custody-{index}")),
            handoff: dir.join("handoff"),
            handoff_anchor: root.join(format!("anchor-handoff-{index}")),
            consensus_key,
            transport_key,
            account_key: keys.join(format!("account-{index}.key")),
            agenda_profile,
            control_socket: dir.join("control.sock"),
            maximum_round,
            simulation: true,
            primary_endpoint: endpoints[index].clone(),
            candidate_family: None,
            recovery_endpoints: endpoints
                .iter()
                .chain(handoff_endpoints.iter())
                .cloned()
                .collect(),
            listen_address: None,
            handoff_endpoint: handoff_endpoints[index].clone(),
            handoff_listen_address: None,
        });
    }
    let retirement_order = retirement_indices
        .map(|index| registrations[index].id())
        .to_vec();
    let genesis = Genesis::new(
        profile,
        "naome:zfc".into(),
        STATE_CHECKER_PROFILE.into(),
        naome_ledger::profile::STATE_PROTOCOL_VERSION,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        *files::random()?,
        accounts
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect(),
        registrations,
        retirement_order,
    )?;
    files::create(&root.join("genesis.bin"), &genesis.encode(), false)?;
    for (index, config) in configs.iter().enumerate() {
        // Initialization is available only while generating a fresh genesis and
        // fresh keys in a new directory. A validator start can only reopen.
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
        let history = naome_storage::state::StateHistory::create(
            &config.history,
            &config.history_anchor,
            genesis.clone(),
            maximum_round,
        )?;
        let signer = naome_storage::state::StateSigner::create(
            &config.signer,
            &config.signer_anchor,
            genesis.clone(),
            files::key(&config.consensus_key, 2)?,
            maximum_round,
        )?;
        let owner = files::key(&config.account_key, 1)?;
        let parent = history.head()?;
        let unit = parent
            .authority()
            .owner(AccountId::for_key(owner.verifying_key().as_bytes()))
            .ok_or("configured owner has no authority slot")?;
        let staged = naome_storage::state::StatePeriodCustody::stage_offer(
            &config.custody,
            &config.custody_anchor,
            parent.state(),
            unit.id(),
            &owner,
            config.handoff_endpoint.clone(),
        )?;
        let handoff = naome_storage::state::StateHandoffJournal::create(
            &config.handoff,
            &config.handoff_anchor,
            genesis.clone(),
            1,
            maximum_round,
        )?;
        drop(handoff);
        drop(staged);
        drop(signer);
        drop(history);
        files::create(
            &root.join(format!("node-{index}/node.json")),
            &serde_json::to_vec_pretty(config)?,
            true,
        )?;
    }
    println!(
        "{}",
        serde_json::json!({"status":"configured","genesis":files::hex(genesis.id().as_bytes()),"profile":files::hex(genesis.profile().id().as_bytes()),"retirement_order":genesis.retirement_order().iter().map(|id| files::hex(id.as_bytes())).collect::<Vec<_>>(),"timing":args[1],"run_records":genesis.profile().limits().run_records,"required_storage_bytes":required,"directory":root,"validators_started":false})
    );
    Ok(())
}

pub fn profile_info(path: &Path) -> Result<()> {
    let genesis = Genesis::decode(&files::read(path, 16384, false)?)?;
    let profile = genesis.profile();
    let timing = profile.timing();
    let rewards = profile.rewards();
    println!(
        "{}",
        serde_json::json!({"genesis":files::hex(genesis.id().as_bytes()),"profile":files::hex(profile.id().as_bytes()),"retirement_order":genesis.retirement_order().iter().map(|id| files::hex(id.as_bytes())).collect::<Vec<_>>(),"kind":format!("{:?}",profile.kind()),"limits":profile.limits().named_values().collect::<std::collections::BTreeMap<_,_>>(),"timing":{"voting_seconds":timing.voting_seconds,"commitment_seconds":timing.commitment_seconds,"reveal_seconds":timing.reveal_seconds,"queue_seconds":timing.queue_seconds,"clock_error_seconds":timing.clock_error_seconds,"agent_call_seconds":timing.agent_call_seconds},"rewards":{"issuance_atoms":rewards.issuance_atoms.to_string(),"author_without_citations_atoms":rewards.author_without_citations_atoms.to_string(),"author_with_citations_atoms":rewards.author_with_citations_atoms.to_string(),"citation_pool_atoms":rewards.citation_pool_atoms.to_string(),"validator_atoms_each":rewards.validator_atoms_each.to_string(),"reserve_atoms":rewards.reserve_atoms.to_string()},"required_storage_bytes_per_node":profile.required_storage_bytes()?,"canonical_profile":files::hex(&profile.encode())})
    );
    Ok(())
}
