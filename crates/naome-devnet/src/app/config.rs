use super::{MAX_HEIGHTS, Result, files, hex, unhex};
use ed25519_dalek::SigningKey;
use naome_chain::ArtifactChainDefinition;
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId, ConsensusKey,
    ConsensusProtocolVersion,
};
use naome_network::{Keypair, Multiaddr};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashSet, path::Path};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    heights: usize,
    validator_addresses: [String; 4],
    publisher_addresses: [String; 2],
    validator_listen_addresses: Option<[String; 4]>,
    publisher_listen_addresses: Option<[String; 2]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Deployment {
    pub version: u32,
    pub heights: usize,
    pub deployment: String,
    pub genesis: String,
    pub validators: Vec<Validator>,
    pub roles: Vec<Role>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Validator {
    key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Role {
    pub name: String,
    pub publisher: bool,
    pub address: String,
    pub listen: String,
    pub peer_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleConfig {
    pub name: String,
    pub publisher: bool,
    pub deployment: Deployment,
}

impl RoleConfig {
    pub fn load(root: &Path) -> Result<Self> {
        let result: Self = serde_json::from_slice(&files::read(&root.join("role.json"), 65_536)?)?;
        result.deployment.validate()?;
        if !result
            .deployment
            .roles
            .iter()
            .any(|r| r.name == result.name && r.publisher == result.publisher)
        {
            return Err("role does not belong to deployment".into());
        }
        Ok(result)
    }
}

impl Deployment {
    fn validate(&self) -> Result<()> {
        if self.version != 0
            || !(4..=MAX_HEIGHTS).contains(&self.heights)
            || self.validators.len() != 4
            || self.roles.len() != 6
        {
            return Err("devnet bounds".into());
        }
        let mut peers = HashSet::new();
        let mut addresses = HashSet::new();
        for (i, role) in self.roles.iter().enumerate() {
            let _ = address(&role.listen)?;
            let expected = if i < 4 {
                format!("validator-{i}")
            } else {
                format!("publisher-{}", i - 4)
            };
            if role.name != expected
                || role.publisher != (i >= 4)
                || !peers.insert(role.peer_id.parse::<naome_network::PeerId>()?)
                || !addresses.insert(address(&role.address)?)
            {
                return Err("devnet role binding".into());
            }
        }
        let _ = self.definition()?;
        let _ = self.context()?;
        let entries = self.entries()?;
        if entries
            .windows(2)
            .any(|w| w[0].consensus_key().as_bytes() >= w[1].consensus_key().as_bytes())
        {
            return Err("devnet validator order".into());
        }
        Ok(())
    }
    pub fn definition(&self) -> Result<ArtifactChainDefinition> {
        Ok(ArtifactChainDefinition::new(unhex(&self.deployment)?))
    }
    pub fn context(&self) -> Result<ConsensusContextV0> {
        Ok(ConsensusContextV0::new(
            self.definition()?.id(),
            ConsensusGenesisId::from_bytes(unhex(&self.genesis)?),
            ConsensusProtocolVersion::new(0),
        ))
    }
    pub fn entries(&self) -> Result<Vec<ActiveAgreementEntry>> {
        self.validators
            .iter()
            .map(|v| {
                Ok(ActiveAgreementEntry::new(
                    ConsensusKey::from_bytes(unhex(&v.key)?),
                    AgreementWeight::new(1),
                ))
            })
            .collect()
    }
}

fn address(text: &str) -> Result<String> {
    let fields: Vec<_> = text.split('/').collect();
    if fields.len() != 5
        || !fields[0].is_empty()
        || !matches!(fields[1], "ip4" | "ip6")
        || fields[3] != "tcp"
        || fields[4].parse::<u16>()? == 0
    {
        return Err("literal nonzero IP/TCP address required".into());
    }
    let address: Multiaddr = text.parse()?;
    if address.to_string() != text {
        return Err("canonical address required".into());
    }
    Ok(text.to_owned())
}

fn random() -> Result<Zeroizing<[u8; 32]>> {
    let mut bytes = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| "operating system randomness unavailable")?;
    Ok(bytes)
}

pub(super) fn init(plan: &Path, root: &Path) -> Result<Value> {
    let plan: Plan = serde_json::from_slice(&files::read(plan, 16_384)?)?;
    if plan.version != 0 || !(4..=MAX_HEIGHTS).contains(&plan.heights) {
        return Err("version must be zero and heights must be 4..128".into());
    }
    let listeners = plan
        .validator_listen_addresses
        .unwrap_or_else(|| plan.validator_addresses.clone())
        .into_iter()
        .chain(
            plan.publisher_listen_addresses
                .unwrap_or_else(|| plan.publisher_addresses.clone()),
        )
        .map(|a| address(&a))
        .collect::<Result<Vec<_>>>()?;
    let addresses = plan
        .validator_addresses
        .into_iter()
        .chain(plan.publisher_addresses)
        .map(|a| address(&a))
        .collect::<Result<Vec<_>>>()?;
    if addresses.iter().collect::<HashSet<_>>().len() != 6 {
        return Err("six distinct advertised endpoints required".into());
    }
    let mut signing = (0..4)
        .map(|_| Ok(SigningKey::from_bytes(&*random()?)))
        .collect::<Result<Vec<_>>>()?;
    signing.sort_by_key(|key| key.verifying_key().to_bytes());
    let seeds = (0..6).map(|_| random()).collect::<Result<Vec<_>>>()?;
    let deployment = Deployment {
        version: 0,
        heights: plan.heights,
        deployment: hex(&*random()?),
        genesis: hex(&*random()?),
        validators: signing
            .iter()
            .map(|key| Validator {
                key: hex(&key.verifying_key().to_bytes()),
            })
            .collect(),
        roles: addresses
            .into_iter()
            .enumerate()
            .map(|(i, address)| {
                let mut seed = Zeroizing::new(*seeds[i]);
                let key = Keypair::ed25519_from_bytes(&mut *seed)?;
                Ok(Role {
                    name: if i < 4 {
                        format!("validator-{i}")
                    } else {
                        format!("publisher-{}", i - 4)
                    },
                    publisher: i >= 4,
                    address,
                    listen: listeners[i].clone(),
                    peer_id: key.public().to_peer_id().to_string(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    deployment.validate()?;
    // Refuse existing output before exposing any new private identity.
    files::directory(root)?;
    for (i, role) in deployment.roles.iter().enumerate() {
        let directory = root.join(&role.name);
        files::directory(&directory)?;
        for name in if role.publisher {
            vec!["journal", "candidates", "payloads", "producer", "logs"]
        } else {
            vec![
                "finality-journal",
                "finality-anchor",
                "vote-journal",
                "vote-anchor",
                "candidates",
                "payloads",
                "evidence",
                "logs",
            ]
        } {
            files::directory(&directory.join(name))?;
        }
        files::create(&directory.join("noise.seed"), &*seeds[i])?;
        if !role.publisher {
            files::create(&directory.join("signing.seed"), &signing[i].to_bytes())?;
        }
        let text = if role.publisher {
            publisher(&deployment, role)
        } else {
            validator(&deployment, role)
        };
        files::create(&directory.join("create.toml"), text.as_bytes())?;
        files::create(
            &directory.join("open.toml"),
            text.replace("mode = \"create\"", "mode = \"open\"")
                .as_bytes(),
        )?;
        files::create(
            &directory.join("role.json"),
            &serde_json::to_vec(
                &json!({"name":role.name,"publisher":role.publisher,"deployment":deployment}),
            )?,
        )?;
    }
    files::create(
        &root.join("deployment.json"),
        &serde_json::to_vec_pretty(&deployment)?,
    )?;
    Ok(
        json!({"event":"devnet_initialized","directory":root,"heights":plan.heights,"validators":4,"publishers":2}),
    )
}

fn publisher(d: &Deployment, role: &Role) -> String {
    let peers = d
        .roles
        .iter()
        .filter(|r| !r.publisher)
        .map(|r| {
            format!(
                "[[peers]]\npeer_id = {:?}\naddress = {:?}\n",
                r.peer_id, r.address
            )
        })
        .collect::<String>();
    format!(
        "version = 0\nmode = \"create\"\ndeployment_discriminator = {:?}\nidentity_seed_file = \"noise.seed\"\nlisten = {:?}\njournal_directory = \"journal\"\noffer_file = \"offer.json\"\n{peers}\n{}",
        d.deployment,
        role.listen,
        sources()
    )
}

fn sources() -> &'static str {
    "[sources]\nmode = \"create\"\ncandidate_directory = \"candidates\"\npayload_directory = \"payloads\"\ncandidate_entries = \"256\"\npayload_entries = \"256\"\npayload_bytes = \"8388608\"\n"
}

fn validator(d: &Deployment, role: &Role) -> String {
    let validators = d
        .validators
        .iter()
        .map(|v| {
            format!(
                "[[validators]]\nconsensus_key = {:?}\nweight = \"1\"\n",
                v.key
            )
        })
        .collect::<String>();
    let others: Vec<_> = d.roles.iter().filter(|r| r.name != role.name).collect();
    let peers = others
        .iter()
        .map(|r| format!("{{peer_id = {:?}, address = {:?}}}", r.peer_id, r.address))
        .collect::<Vec<_>>()
        .join(",");
    let targets = others
        .iter()
        .filter(|r| !r.publisher)
        .map(|r| format!("{:?}", r.peer_id))
        .collect::<Vec<_>>()
        .join(",");
    let publishers = others
        .iter()
        .filter(|r| r.publisher)
        .map(|r| format!("{:?}", r.peer_id))
        .collect::<Vec<_>>()
        .join(",");
    let source_peers = others
        .iter()
        .rev()
        .map(|r| format!("{:?}", r.peer_id))
        .collect::<Vec<_>>()
        .join(",");
    let inboxes = ["higher", "current", "finality", "nil_precommit"]
        .iter()
        .map(|name| format!("[limits.{name}]\nentries = \"8192\"\nbytes = \"8388608\"\n"))
        .collect::<String>();
    let timeouts = ["proposal", "prevote", "precommit"]
        .iter()
        .map(|name| {
            format!(
                "[timeouts.{name}]\nbase_millis = \"10000\"\nround_increment_millis = \"250\"\n"
            )
        })
        .collect::<String>();
    format!(
        r#"version = 0
mode = "create"
deployment_discriminator = "{deployment}"
genesis_id = "{genesis}"
protocol_version = 0
signing_seed_file = "signing.seed"
{validators}
[directories]
finality_journal = "finality-journal"
finality_anchor = "finality-anchor"
vote_journal = "vote-journal"
vote_anchor = "vote-anchor"
[network]
identity_seed_file = "noise.seed"
listen = "{listen}"
peers = [{peers}]
publication_targets = [{targets}]
publication_retry_millis = "250"
serve_finality_proofs = true
serve_artifact_sources = true
[limits]
finality_max_round = "64"
vote_preparations = "8192"
proposal_preparations = "2048"
recovery_max_round = "64"
catch_up_heights = "128"
driver_max_round = "64"
{inboxes}
{timeouts}
{sources}
[evidence]
mode = "create"
directory = "evidence"
[supervisor]
candidate_publishers = [{publishers}]
peers = [{source_peers}]
interval_millis = "1250"
acquisition_blocks = "128"
"#,
        deployment = d.deployment,
        genesis = d.genesis,
        listen = role.listen,
        sources = sources()
    )
}
