//! One replaceable durable offer per immutable configured publisher.
use super::super::{Result, acquisition, files, report};
use naome_chain::{ArtifactBlockId, ArtifactChainId};
use naome_network::{CandidateOffer, PeerId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const MAX_BYTES: usize = 20_000;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    chain: String,
    publishers: Vec<Publisher>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Publisher {
    peer: String,
    candidates: Vec<String>,
}

pub(super) struct Offers {
    publishers: Vec<PeerId>,
    offers: Vec<CandidateOffer>,
    path: PathBuf,
    publisher_cursor: usize,
    hint_cursors: Vec<usize>,
    active_publisher: Option<usize>,
    attempts: usize,
}
impl Offers {
    pub fn new(publishers: Vec<PeerId>) -> Self {
        let hint_cursors = vec![0; publishers.len()];
        Self {
            publishers,
            offers: Vec::new(),
            path: PathBuf::new(),
            publisher_cursor: 0,
            hint_cursors,
            active_publisher: None,
            attempts: 0,
        }
    }
    pub fn bind(&mut self, directory: &Path, create: bool, chain: ArtifactChainId) -> Result<()> {
        self.path = directory.join("candidate-offers-v0.json");
        self.offers = vec![
            CandidateOffer::new(chain, vec![]).map_err(|_| "offer_empty")?;
            self.publishers.len()
        ];
        if create {
            let bytes = self.encode(&self.offers)?;
            write_new(&self.path, &bytes)?;
        } else {
            let bytes = files::bytes(&self.path, MAX_BYTES)?;
            let end = bytes.len().checked_sub(65).ok_or("offer_encoding")?;
            let snapshot: Snapshot =
                serde_json::from_slice(&bytes[..end]).map_err(|_| "offer_encoding")?;
            if snapshot.chain != report::hex(chain.as_bytes())
                || snapshot.publishers.len() != self.publishers.len()
            {
                return Err("offer_binding");
            }
            let mut offers = Vec::new();
            for (entry, peer) in snapshot.publishers.iter().zip(&self.publishers) {
                if entry.peer != peer.to_string() {
                    return Err("offer_publisher_binding");
                }
                let ids = entry
                    .candidates
                    .iter()
                    .map(|s| acquisition::block(s))
                    .collect::<Result<Vec<_>>>()?;
                offers.push(CandidateOffer::new(chain, ids).map_err(|_| "offer_candidates")?);
            }
            if self.encode(&offers)? != bytes || !files::match_and_sync(&self.path, &bytes)? {
                return Err("offer_integrity");
            }
            self.offers = offers;
        }
        sync(directory)
    }
    pub fn accept(&mut self, peer: PeerId, offer: &CandidateOffer) -> Result<bool> {
        let Some(index) = self.publishers.iter().position(|p| *p == peer) else {
            return Ok(false);
        };
        let previous = self.offers.get(index).ok_or("offer_unbound")?;
        if offer.chain_id() != previous.chain_id() {
            return Ok(false);
        }
        // The intake snapshot is fail-closed state, not an overwriteable cache.
        // Check it even when the incoming offer differs from the current one.
        let current = self.encode(&self.offers)?;
        if !files::match_and_sync(&self.path, &current)? {
            return Err("offer_integrity");
        }
        sync(self.path.parent().ok_or("offer_path")?)?;
        if previous == offer {
            return Ok(true);
        }
        let mut offers = self.offers.clone();
        offers[index] = offer.clone();
        let bytes = self.encode(&offers)?;
        let directory = self.path.parent().ok_or("offer_path")?;
        let temporary = directory.join("candidate-offers-v0.pending");
        // Under the existing signer owner, remove only a non-authoritative name.
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("offer_temporary"),
        }
        write_new(&temporary, &bytes)?;
        fs::rename(&temporary, &self.path).map_err(|_| "offer_replace")?;
        sync(directory)?;
        self.offers = offers;
        Ok(true)
    }
    pub fn candidates(&self) -> Vec<ArtifactBlockId> {
        let mut ids = self
            .offers
            .iter()
            .flat_map(|offer| offer.candidates().iter().copied())
            .collect::<Vec<_>>();
        ids.sort_unstable_by_key(|id| *id.as_bytes());
        ids.dedup();
        ids
    }
    /// Publisher turns are independent of other publishers' replaceable sets.
    /// Keep each turn for a complete source-peer cycle before advancing its hint.
    pub fn missing(
        &mut self,
        missing: &[(ArtifactBlockId, bool)],
    ) -> Option<(ArtifactBlockId, bool)> {
        for offset in 0..self.publishers.len() {
            let publisher = (self.publisher_cursor + offset) % self.publishers.len();
            let hints = self.offers[publisher]
                .candidates()
                .iter()
                .filter_map(|id| {
                    missing
                        .iter()
                        .find(|(missing_id, _)| missing_id == id)
                        .copied()
                })
                .collect::<Vec<_>>();
            if hints.is_empty() {
                continue;
            }
            if self.active_publisher != Some(publisher) {
                self.active_publisher = Some(publisher);
                self.attempts = 0;
            }
            self.publisher_cursor = publisher;
            return Some(hints[self.hint_cursors[publisher] % hints.len()]);
        }
        None
    }

    pub fn acquired(&mut self, peers: usize) {
        let Some(publisher) = self.active_publisher else {
            return;
        };
        self.attempts += 1;
        if self.attempts == peers {
            self.hint_cursors[publisher] =
                (self.hint_cursors[publisher] + 1) % naome_network::CANDIDATE_OFFER_MAX_IDS;
            self.publisher_cursor = (publisher + 1) % self.publishers.len();
            self.active_publisher = None;
            self.attempts = 0;
        }
    }

    fn encode(&self, offers: &[CandidateOffer]) -> Result<Vec<u8>> {
        let snapshot = Snapshot {
            chain: report::hex(
                offers
                    .first()
                    .ok_or("offer_publishers_empty")?
                    .chain_id()
                    .as_bytes(),
            ),
            publishers: self
                .publishers
                .iter()
                .zip(offers)
                .map(|(peer, offer)| Publisher {
                    peer: peer.to_string(),
                    candidates: offer
                        .candidates()
                        .iter()
                        .map(|id| report::hex(id.as_bytes()))
                        .collect(),
                })
                .collect(),
        };
        let mut bytes = serde_json::to_vec(&snapshot).map_err(|_| "offer_encoding")?;
        let digest = report::hex(&Sha256::digest(&bytes));
        bytes.push(b'\n');
        bytes.extend_from_slice(digest.as_bytes());
        if bytes.len() > MAX_BYTES {
            return Err("offer_snapshot_limit");
        }
        Ok(bytes)
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "offer_create")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "offer_write")
}
fn sync(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|_| "offer_directory_sync")
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "naome-offers-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn peers() -> Vec<PeerId> {
        (0..8)
            .map(|i| {
                naome_network::Keypair::ed25519_from_bytes(&mut [i; 32])
                    .unwrap()
                    .public()
                    .to_peer_id()
            })
            .collect()
    }
    fn offer(chain: ArtifactChainId, publisher: u8) -> CandidateOffer {
        CandidateOffer::new(
            chain,
            (0..32)
                .map(|i| {
                    let mut id = [publisher; 32];
                    id[31] = i;
                    ArtifactBlockId::from_bytes(id)
                })
                .collect(),
        )
        .unwrap()
    }
    #[test]
    fn full_per_publisher_capacity_replacement_withdrawal_and_exact_reopen() {
        let dir = Directory::new();
        let peers = peers();
        let chain = ArtifactChainId::from_bytes([42; 32]);
        let mut store = Offers::new(peers.clone());
        store.bind(&dir.0, true, chain).unwrap();
        assert!(store.candidates().is_empty());
        for (i, peer) in peers.iter().enumerate() {
            assert!(store.accept(*peer, &offer(chain, i as u8)).unwrap());
        }
        assert_eq!(store.candidates().len(), 256);
        let saved = fs::read(&store.path).unwrap();
        assert!(store.accept(peers[0], &offer(chain, 0)).unwrap());
        assert_eq!(saved, fs::read(&store.path).unwrap());
        let wrong = offer(ArtifactChainId::from_bytes([43; 32]), 0);
        assert!(!store.accept(peers[0], &wrong).unwrap());
        let unknown = naome_network::Keypair::ed25519_from_bytes(&mut [90; 32])
            .unwrap()
            .public()
            .to_peer_id();
        assert!(!store.accept(unknown, &offer(chain, 0)).unwrap());
        assert_eq!(saved, fs::read(&store.path).unwrap());
        assert!(store.accept(peers[0], &offer(chain, 8)).unwrap());
        assert_eq!(store.candidates().len(), 256);
        assert!(
            store
                .accept(peers[0], &CandidateOffer::new(chain, vec![]).unwrap())
                .unwrap()
        );
        assert_eq!(store.candidates().len(), 224);
        // A torn pending replacement is never selected on strict reopen.
        fs::write(dir.0.join("candidate-offers-v0.pending"), b"torn").unwrap();
        let mut reopened = Offers::new(peers.clone());
        reopened.bind(&dir.0, false, chain).unwrap();
        assert_eq!(reopened.candidates(), store.candidates());
        assert!(reopened.accept(peers[0], &offer(chain, 0)).unwrap());
        assert_eq!(reopened.candidates().len(), 256);
    }
    #[test]
    fn strict_missing_corrupt_binding_and_failed_replacement_never_become_empty_success() {
        let dir = Directory::new();
        let peers = peers();
        let chain = ArtifactChainId::from_bytes([42; 32]);
        assert!(
            Offers::new(peers.clone())
                .bind(&dir.0, false, chain)
                .is_err()
        );
        let mut store = Offers::new(peers.clone());
        store.bind(&dir.0, true, chain).unwrap();
        store.accept(peers[0], &offer(chain, 0)).unwrap();
        let saved = fs::read(&store.path).unwrap();
        let mut changed = peers.clone();
        changed.swap(0, 1);
        assert!(Offers::new(changed).bind(&dir.0, false, chain).is_err());
        assert!(
            Offers::new(peers.clone())
                .bind(&dir.0, false, ArtifactChainId::from_bytes([43; 32]))
                .is_err()
        );
        fs::create_dir(dir.0.join("candidate-offers-v0.pending")).unwrap();
        assert!(store.accept(peers[0], &offer(chain, 1)).is_err());
        assert_eq!(store.candidates(), offer(chain, 0).candidates());
        assert_eq!(saved, fs::read(&store.path).unwrap());
        for cut in [0, 1, 64, saved.len() - 1] {
            fs::write(&store.path, &saved[..cut]).unwrap();
            assert!(
                Offers::new(peers.clone())
                    .bind(&dir.0, false, chain)
                    .is_err()
            );
        }
        let mut damaged = saved;
        damaged[0] ^= 1;
        fs::write(&store.path, damaged).unwrap();
        assert!(store.accept(peers[0], &offer(chain, 0)).is_err());
        assert!(store.accept(peers[0], &offer(chain, 1)).is_err());
        assert!(
            Offers::new(peers.clone())
                .bind(&dir.0, false, chain)
                .is_err()
        );
        fs::remove_file(&store.path).unwrap();
        assert!(store.accept(peers[0], &offer(chain, 1)).is_err());
        assert!(!store.path.exists());
    }
    #[test]
    fn moving_noise_across_a_stable_hint_cannot_displace_its_source_peer_cycles() {
        let directory = Directory::new();
        let peers = peers()[..2].to_vec();
        let chain = ArtifactChainId::from_bytes([42; 32]);
        let honest_id = ArtifactBlockId::from_bytes([128; 32]);
        let honest = CandidateOffer::new(chain, vec![honest_id]).unwrap();
        let mut store = Offers::new(peers.clone());
        store.bind(&directory.0, true, chain).unwrap();
        store.accept(peers[1], &honest).unwrap();
        for attempt in 0..18 {
            // This alternating L<H / H<R layout defeats a shared union index.
            let noisy_id =
                ArtifactBlockId::from_bytes([if attempt % 2 == 0 { 1 } else { 254 }; 32]);
            store
                .accept(
                    peers[0],
                    &CandidateOffer::new(chain, vec![noisy_id]).unwrap(),
                )
                .unwrap();
            let missing = store
                .candidates()
                .into_iter()
                .map(|id| (id, false))
                .collect::<Vec<_>>();
            let selected = store.missing(&missing).unwrap().0;
            assert_eq!(selected == honest_id, (attempt / 3) % 2 == 1);
            store.acquired(3);
        }
        // Withdrawing midway through a noisy turn does not shorten the next
        // publisher's complete three-peer fallback cycle.
        for _ in 0..2 {
            let missing = store
                .candidates()
                .into_iter()
                .map(|id| (id, false))
                .collect::<Vec<_>>();
            assert_ne!(store.missing(&missing).unwrap().0, honest_id);
            store.acquired(3);
        }
        store
            .accept(peers[0], &CandidateOffer::new(chain, vec![]).unwrap())
            .unwrap();
        for _ in 0..3 {
            assert_eq!(
                store.missing(&[(honest_id, false)]),
                Some((honest_id, false))
            );
            store.acquired(3);
        }
        // The intake state is durable, while scheduling cursors restart locally.
        let mut reopened = Offers::new(peers);
        reopened.bind(&directory.0, false, chain).unwrap();
        assert_eq!(
            reopened.missing(&[(honest_id, false)]),
            Some((honest_id, false))
        );
    }
}
