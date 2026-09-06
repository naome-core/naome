use std::path::{Path, PathBuf};

use naome_chain::{ArtifactChainDefinition, ArtifactChainState};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusProtocolVersion, FixedConsensusBranchV0,
};
use naome_storage::{FixedValidatorAnchoredFinalityJournalV0, FixedValidatorFinalityReplayLimitV0};
use serde::Deserialize;

use super::{Result, archive, files};

const CONFIG_MAX_BYTES: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    mode: Mode,
    deployment_discriminator: String,
    genesis_id: String,
    protocol_version: u32,
    validators: Vec<Validator>,
    directories: Directories,
    finality_max_round: String,
    network: Option<archive::Config>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
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
}

pub(super) struct Prepared {
    pub base: PathBuf,
    pub network: Option<archive::Prepared>,
    mode: Mode,
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    entries: Vec<ActiveAgreementEntry>,
    directories: Directories,
    replay_limit: FixedValidatorFinalityReplayLimitV0,
}

impl Prepared {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = files::bytes(path, CONFIG_MAX_BYTES)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "config_utf8")?;
        let config: Config = toml::from_str(text).map_err(|_| "config_schema")?;
        if config.version != 0 {
            return Err("config_version");
        }
        let base = path.parent().ok_or("config_path")?.to_path_buf();
        let definition = ArtifactChainDefinition::new(hex32(&config.deployment_discriminator)?);
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes(hex32(&config.genesis_id)?),
            ConsensusProtocolVersion::new(config.protocol_version),
        );
        let entries = config
            .validators
            .iter()
            .map(|entry| {
                Ok(ActiveAgreementEntry::new(
                    ConsensusKey::from_bytes(hex32(&entry.consensus_key)?),
                    AgreementWeight::new(decimal(&entry.weight)?),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
            context,
            &entries,
            ArtifactChainState::new(definition).branch_snapshot(),
        )
        .map_err(|_| "fixed_set")?;
        // Unlike validator startup, no local signing-key membership check
        // incidentally rejects an empty set. Require a usable public snapshot.
        let _ = branch.begin_round_zero().map_err(|_| "fixed_set")?;
        let replay_limit =
            FixedValidatorFinalityReplayLimitV0::new(decimal(&config.finality_max_round)?)
                .map_err(|_| "finality_replay_limit")?;
        let directories = Directories {
            finality_journal: base.join(config.directories.finality_journal),
            finality_anchor: base.join(config.directories.finality_anchor),
        };
        for directory in [&directories.finality_journal, &directories.finality_anchor] {
            if !directory.is_dir() {
                return Err("authority_directory");
            }
        }
        let network = config
            .network
            .map(|network| network.prepare(&base, &entries))
            .transpose()?;
        Ok(Self {
            base,
            network,
            mode: config.mode,
            definition,
            context,
            entries,
            directories,
            replay_limit,
        })
    }

    pub fn provision(&self) -> Result<FixedValidatorAnchoredFinalityJournalV0> {
        let journal = &self.directories.finality_journal;
        let anchor = &self.directories.finality_anchor;
        match self.mode {
            Mode::Create => FixedValidatorAnchoredFinalityJournalV0::create(
                journal,
                anchor,
                self.definition,
                self.context,
                &self.entries,
                self.replay_limit,
            )
            .map_err(|_| "startup_create"),
            Mode::Open => FixedValidatorAnchoredFinalityJournalV0::open(
                journal,
                anchor,
                self.definition,
                self.context,
                &self.entries,
                self.replay_limit,
            )
            .map_err(|_| "startup_open"),
        }
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

fn hex32(value: &str) -> Result<[u8; 32]> {
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
