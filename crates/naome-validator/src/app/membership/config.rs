use super::super::{Result, config::hex32, files};
use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState};
use naome_consensus::verified_membership::{Member, MembershipBranch, MembershipSnapshot};
use naome_network::{Keypair, StaticPeer, verified_membership::MembershipNetwork};
use naome_node::verified_membership::MembershipNode;
use naome_runtime::verified_membership::{MembershipRuntime, MembershipRuntimeTiming};
use naome_storage::verified_membership::{MembershipJournal, MembershipJournalLimits};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    profile: String,
    mode: Mode,
    deployment_discriminator: String,
    pub organization: String,
    pub consensus_seed_file: Option<PathBuf>,
    pub approval_seed_file: Option<PathBuf>,
    pub network_seed_file: PathBuf,
    journal_directory: PathBuf,
    anchor_directory: PathBuf,
    pub inbox_directory: PathBuf,
    listen: String,
    bootstraps: Vec<Peer>,
    genesis_members: Vec<Organization>,
    limits: Limits,
    timing: Timing,
    pub bootstrap_history_directory: Option<PathBuf>,
    pub bootstrap_history_count: Option<u64>,
    pub stop_height: Option<u64>,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Create,
    Open,
    Recover,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Organization {
    organization: String,
    consensus_key: String,
    approval_key: String,
    network_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    peer_id: String,
    address: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    maximum_round: u64,
    maximum_records: u64,
    maximum_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Timing {
    phase_base_millis: u64,
    round_increment_millis: u64,
    tick_millis: u64,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = files::bytes(path, 262_144)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "membership_config_utf8")?;
        let config: Self = toml::from_str(text).map_err(|_| "membership_config_decode")?;
        if config.profile != "verified_membership" {
            return Err("membership_profile");
        }
        hex32(&config.organization)?;
        if config.bootstrap_history_count.unwrap_or(0) > 1_000_000
            || config.bootstrap_history_directory.is_some()
                != config.bootstrap_history_count.is_some()
        {
            return Err("membership_bootstrap_config");
        }
        if config.timing.phase_base_millis == 0
            || config.timing.phase_base_millis > 3_600_000
            || config.timing.round_increment_millis > 3_600_000
            || config.timing.tick_millis == 0
            || config.timing.tick_millis > 60_000
        {
            return Err("membership_timing");
        }
        Ok(config)
    }
    pub fn open(&self, base: &Path) -> Result<(MembershipNode, MembershipNetwork)> {
        let definition = ArtifactChainDefinition::new(hex32(&self.deployment_discriminator)?);
        let mut members = self
            .genesis_members
            .iter()
            .map(|member| {
                Ok(Member {
                    organization: hex32(&member.organization)?,
                    consensus_key: hex32(&member.consensus_key)?,
                    approval_key: hex32(&member.approval_key)?,
                    network_key: hex32(&member.network_key)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        members.sort_by_key(|member| member.organization);
        let genesis = MembershipBranch::genesis(
            ArtifactChainState::new(definition).branch_snapshot(),
            members,
        )
        .map_err(|_| "membership_genesis")?;
        let key = self
            .consensus_seed_file
            .as_ref()
            .map(|path| files::seed(&base.join(path)).map(|seed| SigningKey::from_bytes(&seed)))
            .transpose()?;
        let mut identity_seed = files::seed(&base.join(&self.network_seed_file))?;
        let identity_key = SigningKey::from_bytes(&identity_seed);
        if key
            .as_ref()
            .is_some_and(|key| key.verifying_key() == identity_key.verifying_key())
        {
            return Err("membership_key_reuse");
        }
        if let Some(path) = &self.approval_seed_file {
            let approval = SigningKey::from_bytes(&*files::seed(&base.join(path))?);
            if approval.verifying_key() == identity_key.verifying_key()
                || key
                    .as_ref()
                    .is_some_and(|key| key.verifying_key() == approval.verifying_key())
            {
                return Err("membership_key_reuse");
            }
        }
        let identity =
            Keypair::ed25519_from_bytes(&mut *identity_seed).map_err(|_| "membership_identity")?;
        let peers = self
            .bootstraps
            .iter()
            .map(|peer| {
                Ok(StaticPeer::new(
                    peer.peer_id.parse().map_err(|_| "membership_peer")?,
                    peer.address
                        .parse()
                        .map_err(|_| "membership_peer_address")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut network = MembershipNetwork::new(
            identity,
            peers,
            genesis.next_snapshot().map_err(|_| "membership_snapshot")?,
        )
        .map_err(|_| "membership_network")?;
        network
            .listen_on(
                self.listen
                    .parse()
                    .map_err(|_| "membership_listen_address")?,
            )
            .map_err(|_| "membership_listen")?;
        if matches!(self.mode, Mode::Create) {
            self.validate_binding(
                base,
                genesis.next_snapshot().map_err(|_| "membership_snapshot")?,
                key.as_ref().map(|key| key.verifying_key().to_bytes()),
                &network,
            )?;
        }
        let limits = MembershipJournalLimits {
            maximum_round: self.limits.maximum_round,
            maximum_records: self.limits.maximum_records,
            maximum_bytes: self.limits.maximum_bytes,
        };
        let journal_directory = base.join(&self.journal_directory);
        let anchor_directory = base.join(&self.anchor_directory);
        let journal = match self.mode {
            Mode::Create => MembershipJournal::create(
                &journal_directory,
                &anchor_directory,
                genesis,
                key,
                limits,
            ),
            Mode::Open => {
                MembershipJournal::open(&journal_directory, &anchor_directory, genesis, key, limits)
            }
            Mode::Recover => MembershipJournal::recover_pair(
                &journal_directory,
                &anchor_directory,
                genesis,
                key,
                limits,
            ),
        }
        .map_err(|_| "membership_journal_startup")?;
        let mut node = MembershipNode::new(journal).map_err(|_| "membership_node_startup")?;
        self.validate_local_binding(base, &node, &network)?;
        if matches!(self.mode, Mode::Recover) {
            node.resume_prepared()
                .map_err(|_| "membership_prepared_recovery")?;
        }
        if node.journal().has_pending_signature() {
            return Err("membership_pending_signature");
        }
        network
            .update_membership(node.snapshot().map_err(|_| "membership_snapshot")?)
            .map_err(|_| "membership_network")?;
        Ok((node, network))
    }
    pub fn validate_local_binding(
        &self,
        base: &Path,
        node: &MembershipNode,
        network: &MembershipNetwork,
    ) -> Result<()> {
        let signer = node.machine().map_err(|_| "membership_state")?.signer();
        self.validate_binding(
            base,
            node.snapshot().map_err(|_| "membership_snapshot")?,
            signer,
            network,
        )
    }
    fn validate_binding(
        &self,
        base: &Path,
        snapshot: &MembershipSnapshot,
        signer: Option<[u8; 32]>,
        network: &MembershipNetwork,
    ) -> Result<()> {
        if let Some(member) = snapshot
            .members()
            .iter()
            .find(|member| Some(member.consensus_key) == signer)
        {
            if member.organization != hex32(&self.organization)?
                || !network.is_local_key(&member.network_key)
            {
                return Err("membership_identity_binding");
            }
            if let Some(path) = &self.approval_seed_file
                && SigningKey::from_bytes(&*files::seed(&base.join(path))?)
                    .verifying_key()
                    .to_bytes()
                    != member.approval_key
            {
                return Err("membership_approval_identity_binding");
            }
        }
        Ok(())
    }
    pub fn runtime(
        &self,
        node: MembershipNode,
        network: MembershipNetwork,
    ) -> Result<MembershipRuntime> {
        let mut runtime = MembershipRuntime::new(
            node,
            network,
            MembershipRuntimeTiming {
                phase_base: Duration::from_millis(self.timing.phase_base_millis),
                round_increment: Duration::from_millis(self.timing.round_increment_millis),
                tick: Duration::from_millis(self.timing.tick_millis),
            },
        )
        .map_err(|_| "membership_runtime")?;
        runtime
            .bind_organization(hex32(&self.organization)?)
            .map_err(|_| "membership_identity_binding")?;
        Ok(runtime)
    }
}
