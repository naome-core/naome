//! Opt-in local scheduling intent. Journal state remains the sole position authority.
use std::{fs::File, io::Write, os::unix::fs::OpenOptionsExt, path::Path, time::Duration};

use naome_chain::ArtifactBlockId;
use naome_network::{MAX_STATIC_PEERS, PeerId};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use super::{Result, acquisition, config, files};

mod inbox;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_inbox: Option<std::path::PathBuf>,
    pub peers: Vec<String>,
    pub interval_millis: String,
    pub acquisition_blocks: String,
}

pub(super) struct Supervisor {
    pub targets: Vec<ArtifactBlockId>,
    pub peers: Vec<String>,
    pub interval: Duration,
    pub acquisition_blocks: u64,
    pub due: Instant,
    pub peer_index: [usize; 3],
    pub height: Option<u64>,
    pub fresh_stopped: bool,
    pub stopped_target: Option<ArtifactBlockId>,
    pub acquire_payloads: bool,
    pub next_is_sync: bool,
    pub inbox: Option<inbox::Inbox>,
    binding: Vec<u8>,
}

impl Config {
    pub fn prepare(self, configured: &[PeerId], base: &Path) -> Result<Supervisor> {
        if (self.targets.is_empty() == self.candidate_inbox.is_none()) || self.targets.len() > 256 {
            return Err("supervisor_targets_limit");
        }
        if self
            .candidate_inbox
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err("supervisor_inbox_path");
        }
        let targets = self
            .targets
            .iter()
            .map(|s| acquisition::block(s))
            .collect::<Result<Vec<_>>>()?;
        if self.peers.is_empty() || self.peers.len() > MAX_STATIC_PEERS {
            return Err("supervisor_peers_limit");
        }
        let mut seen = Vec::new();
        for text in &self.peers {
            let peer: PeerId = text.parse().map_err(|_| "supervisor_peer")?;
            if !configured.contains(&peer) || seen.contains(&peer) {
                return Err("supervisor_peer");
            }
            seen.push(peer);
        }
        let millis = config::decimal::<u64>(&self.interval_millis)?;
        let blocks = config::decimal::<u64>(&self.acquisition_blocks)?;
        if millis == 0 || !(1..=256).contains(&blocks) {
            return Err("supervisor_limits");
        }
        let interval = Duration::from_millis(millis);
        let due = Instant::now()
            .checked_add(interval)
            .ok_or("supervisor_deadline")?;
        let binding = serde_json::to_vec(&self).map_err(|_| "supervisor_encoding")?;
        Ok(Supervisor {
            targets,
            peers: self.peers,
            interval,
            acquisition_blocks: blocks,
            due,
            peer_index: [0; 3],
            height: None,
            fresh_stopped: false,
            stopped_target: None,
            acquire_payloads: false,
            next_is_sync: true,
            inbox: self
                .candidate_inbox
                .map(|path| inbox::Inbox::new(base.join(path))),
            binding,
        })
    }
}

impl Supervisor {
    /// Written under the existing exclusive signer owner before any runtime poll.
    /// This is immutable scheduling policy, never an acknowledgement or cursor.
    pub fn bind(&mut self, directory: &Path, create: bool) -> Result<()> {
        let path = directory.join("supervisor-policy-v0.json");
        if create {
            let mut file = File::options()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|_| "supervisor_policy_create")?;
            file.write_all(&self.binding)
                .and_then(|_| file.sync_all())
                .map_err(|_| "supervisor_policy_write")?;
        } else if !files::match_and_sync(&path, &self.binding)? {
            return Err("supervisor_policy_mismatch");
        }
        File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| "supervisor_policy_sync")?;
        if let Some(inbox) = &mut self.inbox {
            inbox.bind(directory, create)?;
        }
        Ok(())
    }

    pub fn postpone(&mut self) -> Result<()> {
        self.due = Instant::now()
            .checked_add(self.interval)
            .ok_or("supervisor_deadline")?;
        Ok(())
    }

    pub fn peer(&mut self, class: usize) -> String {
        let peer = self.peers[self.peer_index[class]].clone();
        self.peer_index[class] = (self.peer_index[class] + 1) % self.peers.len();
        peer
    }
}
