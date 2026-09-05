use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusProtocolVersion, ConsensusRound, FixedConsensusBranchV0, FixedValidatorLockPhaseV0,
};
use naome_network::{
    Keypair, MAX_STATIC_PEERS, Multiaddr, PeerId, StaticArtifactNetwork, StaticPeer,
};
use naome_node::*;
use naome_runtime::{FixedValidatorPhaseDurationV0, FixedValidatorRuntimeTimeoutsV0};
use naome_storage::*;
use serde::Deserialize;

use super::{Result, files};

pub(super) const CONFIG_MAX_BYTES: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    version: u32,
    pub mode: Mode,
    deployment_discriminator: String,
    genesis_id: String,
    protocol_version: u32,
    signing_seed_file: PathBuf,
    validators: Vec<Validator>,
    directories: Directories,
    network: Network,
    limits: Limits,
    timeouts: Timeouts,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Mode {
    Create,
    Open,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Validator {
    consensus_key: String,
    weight: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Directories {
    finality_journal: PathBuf,
    finality_anchor: PathBuf,
    vote_journal: PathBuf,
    vote_anchor: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    identity_seed_file: PathBuf,
    listen: String,
    peers: Vec<Peer>,
    publication_targets: Vec<String>,
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
    finality_max_round: String,
    vote_preparations: String,
    proposal_preparations: String,
    recovery_max_round: String,
    catch_up_heights: String,
    driver_max_round: String,
    higher: Inbox,
    current: Inbox,
    finality: Inbox,
    nil_precommit: Inbox,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inbox {
    entries: String,
    bytes: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Timeouts {
    proposal: Phase,
    prevote: Phase,
    precommit: Phase,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Phase {
    base_millis: String,
    round_increment_millis: String,
}

pub(super) struct Prepared {
    pub base: PathBuf,
    pub mode: Mode,
    pub definition: ArtifactChainDefinition,
    pub context: ConsensusContextV0,
    pub entries: Vec<ActiveAgreementEntry>,
    directories: Directories,
    pub signing_key: Option<SigningKey>,
    pub network: StaticArtifactNetwork,
    pub listen: Multiaddr,
    pub targets: Vec<PeerId>,
    pub timeouts: FixedValidatorRuntimeTimeoutsV0,
    pub driver_max_round: ConsensusRound,
    pub higher: FixedValidatorNodeHigherRoundInboxLimitsV0,
    pub current: FixedValidatorNodeCurrentRoundInboxLimitsV0,
    pub finality: FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
    pub nil_precommit: FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
    finality_limit: FixedValidatorFinalityReplayLimitV0,
    vote_limit: FixedValidatorVoteSafetyReplayLimitV0,
    proposal_limit: FixedValidatorProposalReplayLimitV0,
    recovery_limit: FixedValidatorSignerRecoveryRoundLimitV0,
    catch_up_limit: FixedValidatorSignerCatchUpHeightLimitV0,
}

impl Prepared {
    pub fn provision(&self) -> FixedValidatorNodeProvisionV0<'_> {
        let dirs = &self.directories;
        FixedValidatorNodeProvisionV0::new(
            self.definition,
            self.context,
            &self.entries,
            FixedValidatorNodeDirectoriesV0::new(
                &dirs.finality_journal,
                &dirs.finality_anchor,
                &dirs.vote_journal,
                &dirs.vote_anchor,
            ),
            self.finality_limit,
            self.vote_limit,
            self.proposal_limit,
            self.recovery_limit,
            self.catch_up_limit,
        )
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Prepared> {
        let bytes = files::bytes(path, CONFIG_MAX_BYTES)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "config_utf8")?;
        let config: Self = toml::from_str(text).map_err(|_| "config_schema")?;
        if config.version != 0 {
            return Err("config_version");
        }
        let base = path.parent().ok_or("config_path")?.to_path_buf();
        config.prepare(base)
    }

    fn prepare(self, base: PathBuf) -> Result<Prepared> {
        let definition = ArtifactChainDefinition::new(hex32(&self.deployment_discriminator)?);
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes(hex32(&self.genesis_id)?),
            ConsensusProtocolVersion::new(self.protocol_version),
        );
        let entries = self
            .validators
            .iter()
            .map(|entry| {
                Ok(ActiveAgreementEntry::new(
                    ConsensusKey::from_bytes(hex32(&entry.consensus_key)?),
                    AgreementWeight::new(decimal(&entry.weight)?),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let _ = FixedConsensusBranchV0::try_from_virtual_genesis(
            context,
            &entries,
            ArtifactChainState::new(definition).branch_snapshot(),
        )
        .map_err(|_| "fixed_set")?;
        let signing_seed = files::seed(&base.join(self.signing_seed_file))?;
        let identity_seed = files::seed(&base.join(self.network.identity_seed_file))?;
        if signing_seed == identity_seed {
            return Err("seed_identity_reuse");
        }
        let signing_key = SigningKey::from_bytes(&signing_seed);
        if !entries
            .iter()
            .any(|entry| entry.consensus_key().as_bytes() == signing_key.verifying_key().as_bytes())
        {
            return Err("signer_not_in_fixed_set");
        }
        let mut identity_seed = identity_seed;
        let identity =
            Keypair::ed25519_from_bytes(&mut *identity_seed).map_err(|_| "identity_seed")?;
        let self_id = identity.public().to_peer_id();
        if self.network.peers.len() > MAX_STATIC_PEERS {
            return Err("peers_limit");
        }
        let peers = self
            .network
            .peers
            .iter()
            .map(|peer| {
                let id: PeerId = peer.peer_id.parse().map_err(|_| "peer_id")?;
                if id == self_id {
                    return Err("peer_is_local");
                }
                Ok(StaticPeer::new(id, tcp_address(&peer.address, false)?))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut targets = Vec::new();
        for target in self.network.publication_targets {
            let target: PeerId = target.parse().map_err(|_| "target_id")?;
            if targets.contains(&target) || !peers.iter().any(|p| p.peer_id() == target) {
                return Err("publication_target");
            }
            targets.push(target);
        }
        let network = StaticArtifactNetwork::new(identity, peers).map_err(|_| "network_config")?;
        let listen = tcp_address(&self.network.listen, true)?;
        let limits = self.limits;
        let driver_max_round = ConsensusRound::new(decimal(&limits.driver_max_round)?);
        let timeouts = FixedValidatorRuntimeTimeoutsV0::new(
            self.timeouts.proposal.checked()?,
            self.timeouts.prevote.checked()?,
            self.timeouts.precommit.checked()?,
        );
        for phase in [
            FixedValidatorLockPhaseV0::Proposal,
            FixedValidatorLockPhaseV0::Prevote,
            FixedValidatorLockPhaseV0::Precommit,
        ] {
            let duration = timeouts
                .duration(phase, driver_max_round)
                .map_err(|_| "timeout_overflow")?;
            tokio::time::Instant::now()
                .checked_add(duration)
                .ok_or("deadline_overflow")?;
        }
        let directories = Directories {
            finality_journal: base.join(self.directories.finality_journal),
            finality_anchor: base.join(self.directories.finality_anchor),
            vote_journal: base.join(self.directories.vote_journal),
            vote_anchor: base.join(self.directories.vote_anchor),
        };
        for dir in [
            &directories.finality_journal,
            &directories.finality_anchor,
            &directories.vote_journal,
            &directories.vote_anchor,
        ] {
            if !dir.is_dir() {
                return Err("authority_directory");
            }
        }
        Ok(Prepared {
            base,
            mode: self.mode,
            definition,
            context,
            entries,
            directories,
            signing_key: Some(signing_key),
            network,
            listen,
            targets,
            timeouts,
            driver_max_round,
            higher: FixedValidatorNodeHigherRoundInboxLimitsV0::new(
                decimal(&limits.higher.entries)?,
                decimal(&limits.higher.bytes)?,
            )
            .map_err(|_| "higher_limits")?,
            current: FixedValidatorNodeCurrentRoundInboxLimitsV0::new(
                decimal(&limits.current.entries)?,
                decimal(&limits.current.bytes)?,
            )
            .map_err(|_| "current_limits")?,
            finality: FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(
                decimal(&limits.finality.entries)?,
                decimal(&limits.finality.bytes)?,
            )
            .map_err(|_| "finality_limits")?,
            nil_precommit: FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(
                decimal(&limits.nil_precommit.entries)?,
                decimal(&limits.nil_precommit.bytes)?,
            )
            .map_err(|_| "nil_precommit_limits")?,
            finality_limit: FixedValidatorFinalityReplayLimitV0::new(decimal(
                &limits.finality_max_round,
            )?)
            .map_err(|_| "finality_replay_limit")?,
            vote_limit: FixedValidatorVoteSafetyReplayLimitV0::new(decimal(
                &limits.vote_preparations,
            )?)
            .map_err(|_| "vote_replay_limit")?,
            proposal_limit: FixedValidatorProposalReplayLimitV0::new(decimal(
                &limits.proposal_preparations,
            )?)
            .map_err(|_| "proposal_replay_limit")?,
            recovery_limit: FixedValidatorSignerRecoveryRoundLimitV0::new(decimal(
                &limits.recovery_max_round,
            )?),
            catch_up_limit: FixedValidatorSignerCatchUpHeightLimitV0::new(decimal(
                &limits.catch_up_heights,
            )?),
        })
    }
}

impl Phase {
    fn checked(self) -> Result<FixedValidatorPhaseDurationV0> {
        FixedValidatorPhaseDurationV0::new(
            Duration::from_millis(decimal(&self.base_millis)?),
            Duration::from_millis(decimal(&self.round_increment_millis)?),
        )
        .map_err(|_| "timeout_zero")
    }
}

fn decimal<T: std::str::FromStr>(value: &str) -> Result<T> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("config_decimal");
    }
    value.parse().map_err(|_| "config_decimal_range")
}

fn tcp_address(value: &str, listener: bool) -> Result<Multiaddr> {
    // V0 exposes literal IP/TCP endpoints only; no implicit DNS or transport
    // choice. Parsing alone would also accept unsupported UDP endpoints.
    let fields = value.split('/').collect::<Vec<_>>();
    if fields.len() != 5
        || !fields[0].is_empty()
        || !matches!(fields[1], "ip4" | "ip6")
        || fields[3] != "tcp"
    {
        return Err("tcp_address");
    }
    let port: u16 = fields[4].parse().map_err(|_| "tcp_port")?;
    if !listener && port == 0 {
        return Err("tcp_peer_port_zero");
    }
    value.parse().map_err(|_| "tcp_address")
}

pub(super) fn hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("config_hex32");
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| "config_hex32")?;
    }
    Ok(bytes)
}
