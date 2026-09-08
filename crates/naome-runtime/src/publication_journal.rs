//! Separate durable delivery progress. Signed bytes remain in the anchored
//! signer history; loss of a receipt can only cause duplicate delivery.

use std::{
    collections::TryReserveError,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use naome_network::{MAX_STATIC_PEERS, PeerId};
use naome_storage::{
    FixedValidatorCompletedPublicationV0 as Completed,
    FixedValidatorPublicationHistoryV0 as History, FixedValidatorVoteSafetyJournalErrorV0,
    FixedValidatorVoteSafetyJournalStateIdV0 as StateId,
};
use sha2::{Digest, Sha256};

const HEADER: &[u8] = b"naome:fixed-validator-publication-deliveries:v0\0";
const CHECKSUM_DOMAIN: &[u8] = b"naome:fixed-validator-publication-deliveries-checksum:v0\0";
const RECORD_BYTES: usize = 32 + 8 * MAX_STATIC_PEERS + 1;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests;
#[cfg(all(test, unix))]
mod faults {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Stage {
        Create,
        Write,
        FileSync,
        Rename,
        DirectorySync,
    }
    thread_local! { pub(super) static FAIL: std::cell::Cell<Option<Stage>> = const { std::cell::Cell::new(None) }; }
    pub(super) fn check(stage: Stage) -> std::io::Result<()> {
        FAIL.with(|failure| {
            if failure.get() == Some(stage) {
                failure.set(None);
                Err(std::io::Error::other(
                    "injected publication snapshot failure",
                ))
            } else {
                Ok(())
            }
        })
    }
}

#[derive(Debug)]
pub enum FixedValidatorPublicationJournalErrorV0 {
    Io(io::Error),
    Allocation(TryReserveError),
    Source(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    Recovery(Box<naome_node::FixedValidatorNodePublicationRecoveryErrorV0>),
    Locked,
    Invalid,
    MissingProposalPayload,
    Poisoned,
    UnsupportedPlatform,
    AlreadyEnabled,
    RetryRequiresJournal,
    Timing(crate::FixedValidatorRuntimeTimingErrorV0),
}

impl fmt::Display for FixedValidatorPublicationJournalErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "publication delivery journal requires strict restart: {self:?}"
        )
    }
}
impl Error for FixedValidatorPublicationJournalErrorV0 {}
impl From<io::Error> for FixedValidatorPublicationJournalErrorV0 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<TryReserveError> for FixedValidatorPublicationJournalErrorV0 {
    fn from(error: TryReserveError) -> Self {
        Self::Allocation(error)
    }
}
impl From<Box<FixedValidatorVoteSafetyJournalErrorV0>> for FixedValidatorPublicationJournalErrorV0 {
    fn from(error: Box<FixedValidatorVoteSafetyJournalErrorV0>) -> Self {
        Self::Source(error)
    }
}
type Result<T> = std::result::Result<T, FixedValidatorPublicationJournalErrorV0>;

struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Delivery {
    state_id: StateId,
    attempts: [u64; MAX_STATIC_PEERS],
    received: u8,
}

pub(crate) struct PublicationJournal {
    directory: PathBuf,
    file_name: String,
    binding: Vec<u8>,
    deliveries: Vec<Delivery>,
    peer_count: usize,
    poisoned: bool,
    _lock: Lock,
}

impl PublicationJournal {
    pub(crate) fn open(
        directory: &Path,
        create: bool,
        history: &History<'_>,
        peers: &[PeerId],
    ) -> Result<Self> {
        if !cfg!(unix) {
            return Err(FixedValidatorPublicationJournalErrorV0::UnsupportedPlatform);
        }
        let mut binding = Vec::new();
        binding.try_reserve_exact(HEADER.len() + 32 * 4 + 4 + 1 + peers.len() * 66)?;
        binding.extend_from_slice(HEADER);
        binding.extend_from_slice(history.context().chain_id().as_bytes());
        binding.extend_from_slice(history.context().genesis_id().as_bytes());
        binding.extend_from_slice(&history.context().protocol_version().value().to_be_bytes());
        binding.extend_from_slice(history.fixed_set_id().as_bytes());
        binding.extend_from_slice(history.signer().as_bytes());
        binding.push(
            u8::try_from(peers.len())
                .map_err(|_| FixedValidatorPublicationJournalErrorV0::Invalid)?,
        );
        for peer in peers {
            let bytes = peer.to_bytes();
            binding.extend_from_slice(
                &u16::try_from(bytes.len())
                    .map_err(|_| FixedValidatorPublicationJournalErrorV0::Invalid)?
                    .to_be_bytes(),
            );
            binding.extend_from_slice(&bytes);
        }
        let mut ids = Vec::new();
        for entry in history.entries() {
            if matches!(entry, Completed::Proposal(proposal) if proposal.canonical_artifact_bytes().is_none())
            {
                return Err(FixedValidatorPublicationJournalErrorV0::MissingProposalPayload);
            }
            ids.try_reserve(1)?;
            ids.push(entry.state_id());
        }
        ids.sort_unstable();
        if create && !ids.is_empty() {
            return Err(FixedValidatorPublicationJournalErrorV0::Invalid);
        }
        let signer = history
            .signer()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let file_name = format!("fixed-validator-publication-{signer}.deliveries");
        let lock_file = regular_options(true, true)
            .create(true)
            .truncate(false)
            .open(directory.join(format!("{file_name}.lock")))?;
        if !lock_file.metadata()?.is_file() {
            return Err(FixedValidatorPublicationJournalErrorV0::Invalid);
        }
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(FixedValidatorPublicationJournalErrorV0::Locked);
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        let mut journal = Self {
            directory: directory.to_path_buf(),
            file_name,
            binding,
            deliveries: Vec::new(),
            peer_count: peers.len(),
            poisoned: false,
            _lock: Lock(lock_file),
        };
        if create {
            journal.save(true)?;
        } else {
            let maximum = journal
                .binding
                .len()
                .checked_add(8 + 32)
                .and_then(|base| {
                    ids.len()
                        .checked_mul(RECORD_BYTES)
                        .and_then(|records| base.checked_add(records))
                })
                .ok_or(FixedValidatorPublicationJournalErrorV0::Invalid)?;
            let mut file = regular_options(true, false).open(directory.join(&journal.file_name))?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > maximum as u64 {
                return Err(FixedValidatorPublicationJournalErrorV0::Invalid);
            }
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(metadata.len() as usize)?;
            (&mut file)
                .take(maximum as u64 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > maximum {
                return Err(FixedValidatorPublicationJournalErrorV0::Invalid);
            }
            journal.decode(&bytes, &ids)?;
        }
        // A signed completion may predate the delivery entry when the process
        // died between signing and runtime transfer. Its source is immutable.
        let mut changed = false;
        for state_id in ids {
            changed |= journal.insert(state_id)?;
        }
        if changed {
            journal.save(false)?;
        }
        Ok(journal)
    }

    fn decode(&mut self, bytes: &[u8], source_ids: &[StateId]) -> Result<()> {
        let invalid = || FixedValidatorPublicationJournalErrorV0::Invalid;
        let minimum = self.binding.len() + 8 + 32;
        if bytes.len() < minimum || !bytes.starts_with(&self.binding) {
            return Err(invalid());
        }
        let split = bytes.len() - 32;
        if checksum(&bytes[..split]).as_slice() != &bytes[split..] {
            return Err(invalid());
        }
        let count = u64::from_be_bytes(
            bytes[self.binding.len()..self.binding.len() + 8]
                .try_into()
                .unwrap(),
        );
        if count > source_ids.len() as u64 || bytes.len() != minimum + count as usize * RECORD_BYTES
        {
            return Err(invalid());
        }
        self.deliveries.try_reserve_exact(count as usize)?;
        let allowed = if self.peer_count == 8 {
            u8::MAX
        } else {
            (1_u8 << self.peer_count) - 1
        };
        for record in bytes[self.binding.len() + 8..split].chunks_exact(RECORD_BYTES) {
            let state_id = StateId::from_bytes(record[..32].try_into().unwrap());
            if source_ids.binary_search(&state_id).is_err()
                || self
                    .deliveries
                    .last()
                    .is_some_and(|last| last.state_id >= state_id)
            {
                return Err(invalid());
            }
            let attempts = std::array::from_fn(|index| {
                u64::from_be_bytes(record[32 + index * 8..40 + index * 8].try_into().unwrap())
            });
            let received = record[RECORD_BYTES - 1];
            if received & !allowed != 0
                || attempts[self.peer_count..].iter().any(|count| *count != 0)
                || (0..self.peer_count)
                    .any(|index| received & (1 << index) != 0 && attempts[index] == 0)
            {
                return Err(invalid());
            }
            self.deliveries.push(Delivery {
                state_id,
                attempts,
                received,
            });
        }
        Ok(())
    }

    fn insert(&mut self, state_id: StateId) -> Result<bool> {
        if self.poisoned {
            return Err(FixedValidatorPublicationJournalErrorV0::Poisoned);
        }
        match self
            .deliveries
            .binary_search_by_key(&state_id, |entry| entry.state_id)
        {
            Ok(_) => Ok(false),
            Err(index) => {
                self.deliveries.try_reserve(1)?;
                self.deliveries.insert(
                    index,
                    Delivery {
                        state_id,
                        attempts: [0; MAX_STATIC_PEERS],
                        received: 0,
                    },
                );
                Ok(true)
            }
        }
    }

    pub(crate) fn register(&mut self, state_id: StateId) -> Result<()> {
        if self.insert(state_id)? {
            self.save(false)?;
        }
        Ok(())
    }

    pub(crate) fn received(&self, state_id: StateId, peer: usize) -> bool {
        self.deliveries
            .binary_search_by_key(&state_id, |entry| entry.state_id)
            .ok()
            .is_some_and(|index| self.deliveries[index].received & (1 << peer) != 0)
    }

    pub(crate) fn attempt(&mut self, state_id: StateId, peer: usize) -> Result<()> {
        let index = self
            .deliveries
            .binary_search_by_key(&state_id, |entry| entry.state_id)
            .map_err(|_| FixedValidatorPublicationJournalErrorV0::Invalid)?;
        self.deliveries[index].attempts[peer] = self.deliveries[index].attempts[peer]
            .checked_add(1)
            .ok_or(FixedValidatorPublicationJournalErrorV0::Invalid)?;
        self.save(false)
    }

    // Private to the runtime: a peer/size receipt alone is not sufficient.
    // The caller must have completed the exact owned in-flight ticket first.
    pub(crate) fn acknowledge(&mut self, state_id: StateId, peer: usize) -> Result<()> {
        let index = self
            .deliveries
            .binary_search_by_key(&state_id, |entry| entry.state_id)
            .map_err(|_| FixedValidatorPublicationJournalErrorV0::Invalid)?;
        if self.deliveries[index].attempts[peer] == 0 {
            return Err(FixedValidatorPublicationJournalErrorV0::Invalid);
        }
        self.deliveries[index].received |= 1 << peer;
        self.save(false)
    }

    fn save(&mut self, create: bool) -> Result<()> {
        if self.poisoned {
            return Err(FixedValidatorPublicationJournalErrorV0::Poisoned);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(
            self.binding.len() + 8 + self.deliveries.len() * RECORD_BYTES + 32,
        )?;
        bytes.extend_from_slice(&self.binding);
        bytes.extend_from_slice(&(self.deliveries.len() as u64).to_be_bytes());
        for delivery in &self.deliveries {
            bytes.extend_from_slice(delivery.state_id.as_bytes());
            for count in delivery.attempts {
                bytes.extend_from_slice(&count.to_be_bytes());
            }
            bytes.push(delivery.received);
        }
        let digest = checksum(&bytes);
        bytes.extend_from_slice(&digest);
        // Poison before an ambiguous write. Only a strict open may classify the
        // installed snapshot; an older complete snapshot merely causes repeats.
        self.poisoned = true;
        let target = self.directory.join(&self.file_name);
        #[cfg(all(test, unix))]
        faults::check(faults::Stage::Create)?;
        if create {
            let mut file = regular_options(false, true).create_new(true).open(target)?;
            #[cfg(all(test, unix))]
            faults::check(faults::Stage::Write)?;
            file.write_all(&bytes)?;
            #[cfg(all(test, unix))]
            faults::check(faults::Stage::FileSync)?;
            file.sync_all()?;
        } else {
            let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temporary = self.directory.join(format!(
                "{}.tmp-{}-{sequence}",
                self.file_name,
                std::process::id()
            ));
            let mut file = regular_options(false, true)
                .create_new(true)
                .open(&temporary)?;
            #[cfg(all(test, unix))]
            faults::check(faults::Stage::Write)?;
            file.write_all(&bytes)?;
            #[cfg(all(test, unix))]
            faults::check(faults::Stage::FileSync)?;
            file.sync_all()?;
            #[cfg(all(test, unix))]
            faults::check(faults::Stage::Rename)?;
            fs::rename(temporary, target)?;
        }
        #[cfg(all(test, unix))]
        faults::check(faults::Stage::DirectorySync)?;
        sync_directory(&self.directory)?;
        self.poisoned = false;
        Ok(())
    }
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(crate) fn regular_options(read: bool, write: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(read).write(write);
    #[cfg(unix)]
    {
        use rustix::fs::OFlags;
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32);
    }
    options
}

pub(crate) fn sync_directory(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(directory)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Err(io::ErrorKind::Unsupported.into())
    }
}
