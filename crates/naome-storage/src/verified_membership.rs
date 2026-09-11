//! One anchored event journal owns verified-membership finality, membership and signing lineage.
//!
//! Key use follows the synchronized intent record and independent anchor. An
//! incomplete preparation is readable after restart but requires explicit exact
//! intent recovery before new events. Neither file alone authorizes rollback.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use ed25519_dalek::SigningKey;
use naome_consensus::verified_membership::*;
use sha2::{Digest, Sha256};

use crate::store_io::{ExclusiveLock, lock_open_file};

mod records;
#[cfg(all(test, unix))]
mod tests;
#[cfg(all(test, not(unix)))]
#[path = "verified_membership/unsupported_tests.rs"]
mod unsupported_tests;

const HEADER: &[u8] = b"naome/verified-membership/v0/journal\0";
const ANCHOR_HEADER: &[u8] = b"naome/verified-membership/v0/anchor\0";
const JOURNAL_NAME: &str = "verified-membership.journal";
const ANCHOR_NAME: &str = "verified-membership.anchor";
const MAX_BODY_BYTES: usize = 128 + 4 * MembershipMachineEvent::MAX_BYTES;
const MAX_OUTBOX_ITEMS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipJournalLimits {
    pub maximum_round: u64,
    pub maximum_records: u64,
    pub maximum_bytes: u64,
}

#[derive(Debug)]
pub enum MembershipJournalError {
    UnsupportedDurableDirectorySync,
    Io(io::Error),
    InvalidPath,
    Locked,
    Encoding,
    Binding,
    Integrity,
    Anchor,
    Limit,
    PendingSignature,
    Key,
    Poisoned,
    ConflictingFinality,
    Consensus(MembershipConsensusError),
    Membership(MembershipError),
}
impl fmt::Display for MembershipJournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "membership journal: {self:?}")
    }
}
impl Error for MembershipJournalError {}
impl From<io::Error> for MembershipJournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<MembershipError> for MembershipJournalError {
    fn from(error: MembershipError) -> Self {
        Self::Membership(error)
    }
}
impl From<MembershipConsensusError> for MembershipJournalError {
    fn from(error: MembershipConsensusError) -> Self {
        Self::Consensus(error)
    }
}

/// Selected state is private to a single locked journal/anchor pair.
/// Durable membership ownership requires Unix directory synchronization. Other
/// platforms refuse creation, opening and recovery before touching owner files.
pub struct MembershipJournal {
    genesis: MembershipBranch,
    snapshots: BTreeMap<u64, MembershipSnapshot>,
    halted: bool,
    file: File,
    anchor: File,
    machine: MembershipMachine,
    key: Option<SigningKey>,
    limits: MembershipJournalLimits,
    sequence: u64,
    state_id: [u8; 32],
    end: u64,
    pending: Vec<MembershipSigningIntent>,
    outbox: BTreeMap<[u8; 32], MembershipPublication>,
    proofs: BTreeMap<u64, (u64, usize, [u8; 32])>,
    poisoned: bool,
    _journal_lock: ExclusiveLock,
    _anchor_lock: ExclusiveLock,
}

impl MembershipJournal {
    pub fn create(
        journal_directory: &Path,
        anchor_directory: &Path,
        genesis: MembershipBranch,
        key: Option<SigningKey>,
        limits: MembershipJournalLimits,
    ) -> Result<Self, MembershipJournalError> {
        require_platform()?;
        validate_limits(limits)?;
        if genesis.height() != 0 {
            return Err(MembershipJournalError::Binding);
        }
        let (journal_directory, anchor_directory) =
            directories(journal_directory, anchor_directory)?;
        let journal_lock = lock(&journal_directory)?;
        let anchor_lock = lock(&anchor_directory)?;
        let header = header(&genesis, key.as_ref(), limits);
        let machine = MembershipMachine::new(
            genesis.clone(),
            key.as_ref().map(|key| key.verifying_key().to_bytes()),
            limits.maximum_round,
        )?;
        let mut file = new_file(&journal_directory.join(JOURNAL_NAME))?;
        file.write_all(&header)?;
        file.sync_all()?;
        sync_directory(&journal_directory)?;
        let state_id = hash(
            b"naome/verified-membership/v0/journal-genesis\0",
            &[&header],
        );
        let mut anchor = new_file(&anchor_directory.join(ANCHOR_NAME))?;
        anchor.write_all(ANCHOR_HEADER)?;
        anchor.write_all(&hash(
            b"naome/verified-membership/v0/anchor-binding\0",
            &[&header],
        ))?;
        write_anchor(&mut anchor, 0, state_id)?;
        sync_directory(&anchor_directory)?;
        Ok(Self {
            snapshots: BTreeMap::from([(1, genesis.next_snapshot()?.clone())]),
            genesis,
            halted: false,
            file,
            anchor,
            machine,
            key,
            limits,
            sequence: 0,
            state_id,
            end: header.len() as u64,
            pending: Vec::new(),
            outbox: BTreeMap::new(),
            proofs: BTreeMap::new(),
            poisoned: false,
            _journal_lock: journal_lock,
            _anchor_lock: anchor_lock,
        })
    }

    pub fn open(
        journal_directory: &Path,
        anchor_directory: &Path,
        genesis: MembershipBranch,
        key: Option<SigningKey>,
        limits: MembershipJournalLimits,
    ) -> Result<Self, MembershipJournalError> {
        Self::open_impl(
            journal_directory,
            anchor_directory,
            genesis.clone(),
            key,
            limits,
            false,
        )
    }

    /// Explicitly repair only a journal-ahead crash gap after complete replay.
    /// Never discard a complete journal entry or move an anchor backward.
    pub fn recover_pair(
        journal_directory: &Path,
        anchor_directory: &Path,
        genesis: MembershipBranch,
        key: Option<SigningKey>,
        limits: MembershipJournalLimits,
    ) -> Result<Self, MembershipJournalError> {
        Self::open_impl(
            journal_directory,
            anchor_directory,
            genesis,
            key,
            limits,
            true,
        )
    }

    fn open_impl(
        journal_directory: &Path,
        anchor_directory: &Path,
        genesis: MembershipBranch,
        key: Option<SigningKey>,
        limits: MembershipJournalLimits,
        recover: bool,
    ) -> Result<Self, MembershipJournalError> {
        require_platform()?;
        validate_limits(limits)?;
        if genesis.height() != 0 {
            return Err(MembershipJournalError::Binding);
        }
        let (journal_directory, anchor_directory) =
            directories(journal_directory, anchor_directory)?;
        let journal_lock = lock(&journal_directory)?;
        let anchor_lock = lock(&anchor_directory)?;
        let header = header(&genesis, key.as_ref(), limits);
        let mut file = existing_file(&journal_directory.join(JOURNAL_NAME))?;
        let file_length = file.metadata()?.len();
        if file_length > limits.maximum_bytes {
            return Err(MembershipJournalError::Limit);
        }
        let mut actual = vec![0; header.len()];
        file.read_exact(&mut actual)?;
        if actual != header {
            return Err(MembershipJournalError::Binding);
        }
        let mut anchor = existing_file(&anchor_directory.join(ANCHOR_NAME))?;
        let (anchors, anchor_end) =
            read_anchors(&mut anchor, &header, limits.maximum_records, recover)?;
        let state_id = hash(
            b"naome/verified-membership/v0/journal-genesis\0",
            &[&header],
        );
        if anchors.first() != Some(&(0, state_id)) {
            return Err(MembershipJournalError::Anchor);
        }
        let machine = MembershipMachine::new(
            genesis.clone(),
            key.as_ref().map(|key| key.verifying_key().to_bytes()),
            limits.maximum_round,
        )?;
        let mut journal = Self {
            snapshots: BTreeMap::from([(1, genesis.next_snapshot()?.clone())]),
            genesis,
            halted: false,
            file,
            anchor,
            machine,
            key,
            limits,
            sequence: 0,
            state_id,
            end: header.len() as u64,
            pending: Vec::new(),
            outbox: BTreeMap::new(),
            proofs: BTreeMap::new(),
            poisoned: false,
            _journal_lock: journal_lock,
            _anchor_lock: anchor_lock,
        };
        let mut missing_anchors = Vec::new();
        while journal.end < file_length {
            if journal.sequence >= limits.maximum_records {
                return Err(MembershipJournalError::Limit);
            }
            let start = journal.end;
            if file_length - start < 4 {
                break;
            }
            let mut length = [0; 4];
            journal.file.read_exact(&mut length)?;
            let length_value = u32::from_be_bytes(length) as usize;
            if length_value == 0 || length_value > MAX_BODY_BYTES {
                return Err(MembershipJournalError::Limit);
            }
            let next_end = start
                .checked_add(4 + length_value as u64 + 32)
                .ok_or(MembershipJournalError::Limit)?;
            if next_end > file_length {
                break;
            }
            let mut body = vec![0; length_value];
            journal.file.read_exact(&mut body)?;
            let mut actual = [0; 32];
            journal.file.read_exact(&mut actual)?;
            let expected = hash(
                b"naome/verified-membership/v0/journal-step\0",
                &[&journal.state_id, &length, &body],
            );
            if actual != expected {
                return Err(MembershipJournalError::Integrity);
            }
            journal.apply_body(&body, start + 4)?;
            journal.sequence += 1;
            journal.state_id = expected;
            journal.end = next_end;
            journal.file.seek(SeekFrom::Start(next_end))?;
            if let Some(anchored) = anchors.get(journal.sequence as usize) {
                if *anchored != (journal.sequence, journal.state_id) {
                    return Err(MembershipJournalError::Anchor);
                }
            } else {
                missing_anchors.push((journal.sequence, journal.state_id));
            }
        }
        let anchored_sequence = anchors.last().ok_or(MembershipJournalError::Anchor)?.0;
        if anchored_sequence > journal.sequence {
            return Err(MembershipJournalError::Anchor);
        }
        // A complete journal record ahead of its anchor is never silently
        // discarded. Require explicit paired recovery instead of rolling back.
        if anchored_sequence != journal.sequence && !recover {
            return Err(MembershipJournalError::Anchor);
        }
        if recover {
            journal.anchor.set_len(anchor_end)?;
            journal.anchor.seek(SeekFrom::Start(anchor_end))?;
            for (sequence, state_id) in missing_anchors {
                write_anchor(&mut journal.anchor, sequence, state_id)?;
            }
            journal.anchor.sync_all()?;
        }
        if journal.end != file_length {
            journal.file.set_len(journal.end)?;
            journal.file.sync_all()?;
        }
        journal.file.seek(SeekFrom::Start(journal.end))?;
        Ok(journal)
    }

    pub fn machine(&self) -> Result<&MembershipMachine, MembershipJournalError> {
        self.healthy()?;
        Ok(&self.machine)
    }
    pub fn has_pending_signature(&self) -> bool {
        !self.pending.is_empty()
    }
    pub fn state_id(&self) -> Result<[u8; 32], MembershipJournalError> {
        self.healthy()?;
        Ok(self.state_id)
    }
    pub fn publications(&self) -> Result<Vec<MembershipPublication>, MembershipJournalError> {
        self.healthy()?;
        Ok(self.outbox.values().cloned().collect())
    }

    /// Append and independently anchor the whole unsigned transition before key
    /// use. Its finality and signing lineage therefore share one durable order.
    pub fn process(
        &mut self,
        event: MembershipMachineEvent,
    ) -> Result<Vec<MembershipPublication>, MembershipJournalError> {
        self.healthy()?;
        if !self.pending.is_empty() {
            return Err(MembershipJournalError::PendingSignature);
        }
        let transition = self.machine.prepare(event.clone())?;
        if transition.next().state_id() == self.machine.state_id()
            && transition.intents().is_empty()
            && transition.publications().is_empty()
        {
            return Ok(Vec::new());
        }
        let unsigned = transition.publications().to_vec();
        let body = records::event_body(&event, transition.finalized());
        self.append(&body)?;
        let mut publications = unsigned;
        publications.extend(self.complete_prepared()?);
        Ok(publications)
    }

    /// Explicit recovery repeats only the exact durable intent, then stores and
    /// anchors its strictly verified signature before releasing any bytes.
    pub fn resume_prepared(
        &mut self,
    ) -> Result<Vec<MembershipPublication>, MembershipJournalError> {
        self.healthy()?;
        self.complete_prepared()
    }

    fn complete_prepared(&mut self) -> Result<Vec<MembershipPublication>, MembershipJournalError> {
        if self.pending.is_empty() {
            return Ok(Vec::new());
        }
        let key = self.key.as_ref().ok_or(MembershipJournalError::Key)?;
        let publications = self
            .pending
            .iter()
            .map(|intent| intent.complete(key))
            .collect::<Result<Vec<_>, _>>()?;
        let body = records::completion_body(&publications);
        self.append(&body)?;
        Ok(publications)
    }

    /// Serve only an exact proof reconstructed and checked during journal replay.
    pub fn finalized_proof(
        &mut self,
        height: u64,
    ) -> Result<Option<MembershipFinalityProof>, MembershipJournalError> {
        self.healthy()?;
        self.read_proof(height)
    }
    fn read_proof(
        &mut self,
        height: u64,
    ) -> Result<Option<MembershipFinalityProof>, MembershipJournalError> {
        let Some((offset, length, expected)) = self.proofs.get(&height).copied() else {
            return Ok(None);
        };
        self.file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; length];
        let result = self.file.read_exact(&mut bytes);
        self.file.seek(SeekFrom::Start(self.end))?;
        result?;
        if hash(b"naome/verified-membership/v0/proof-record\0", &[&bytes]) != expected {
            self.poisoned = true;
            return Err(MembershipJournalError::Integrity);
        }
        Ok(Some(MembershipFinalityProof::from_bytes(&bytes)?))
    }

    fn healthy(&self) -> Result<(), MembershipJournalError> {
        if self.halted {
            Err(MembershipJournalError::ConflictingFinality)
        } else if self.poisoned {
            Err(MembershipJournalError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// A fully verified conflicting historical decision irreversibly stops this
    /// journal. Unauthenticated accusations cannot alter the signing lineage.
    pub fn observe_historical_finality(
        &mut self,
        proof: MembershipFinalityProof,
    ) -> Result<(), MembershipJournalError> {
        self.healthy()?;
        if !self.verify_historical_conflict(&proof)? {
            return Ok(());
        }
        let mut body = vec![2];
        body.extend_from_slice(&proof.to_bytes());
        // Even a failed attempt to anchor evidence must stop this process.
        if let Err(error) = self.append(&body) {
            self.poisoned = true;
            return Err(error);
        }
        Err(MembershipJournalError::ConflictingFinality)
    }

    fn verify_historical_conflict(
        &mut self,
        proof: &MembershipFinalityProof,
    ) -> Result<bool, MembershipJournalError> {
        let height = proof.proposal.value.height();
        let retained = self
            .read_proof(height)?
            .ok_or(MembershipJournalError::Encoding)?;
        if retained.proposal.value == proof.proposal.value {
            return Ok(false);
        }
        let coordinate = proof.certificate.coordinate();
        let snapshot = self
            .snapshots
            .range(..=height)
            .next_back()
            .ok_or(MembershipJournalError::Integrity)?
            .1;
        if coordinate.context != self.genesis.context().0
            || coordinate.height != height
            || coordinate.parent != retained.proposal.value.parent()
            || coordinate.snapshot != snapshot.id()
            || coordinate.round > self.limits.maximum_round
            || coordinate.round != proof.proposal.round
            || coordinate.role != MembershipVoteRole::Precommit
            || coordinate.target != Some(proof.proposal.value.root())
        {
            return Err(MembershipJournalError::Encoding);
        }
        // Quorum authentication precedes the potentially long historical replay.
        proof.certificate.verify(snapshot)?;
        let mut parent = self.genesis.clone();
        for previous in 1..height {
            let proof = self
                .read_proof(previous)?
                .ok_or(MembershipJournalError::Integrity)?;
            parent = parent
                .verify_finality(
                    proof.proposal,
                    proof.payload,
                    proof.certificate,
                    self.limits.maximum_round,
                )?
                .into_branch();
        }
        parent.verify_finality(
            proof.proposal.clone(),
            proof.payload.clone(),
            proof.certificate.clone(),
            self.limits.maximum_round,
        )?;
        Ok(true)
    }

    fn append(&mut self, body: &[u8]) -> Result<(), MembershipJournalError> {
        self.healthy()?;
        if body.is_empty()
            || body.len() > MAX_BODY_BYTES
            || self.sequence >= self.limits.maximum_records
        {
            return Err(MembershipJournalError::Limit);
        }
        let end = self
            .end
            .checked_add(4 + body.len() as u64 + 32)
            .ok_or(MembershipJournalError::Limit)?;
        if end > self.limits.maximum_bytes {
            return Err(MembershipJournalError::Limit);
        }
        let length = (body.len() as u32).to_be_bytes();
        let state_id = hash(
            b"naome/verified-membership/v0/journal-step\0",
            &[&self.state_id, &length, body],
        );
        self.poisoned = true;
        self.file.seek(SeekFrom::Start(self.end))?;
        self.file.write_all(&length)?;
        self.file.write_all(body)?;
        self.file.sync_all()?;
        self.file.write_all(&state_id)?;
        self.file.sync_all()?;
        write_anchor(&mut self.anchor, self.sequence + 1, state_id)?;
        self.apply_body(body, self.end + 4)?;
        self.sequence += 1;
        self.state_id = state_id;
        self.end = end;
        self.poisoned = false;
        Ok(())
    }
}

fn header(
    genesis: &MembershipBranch,
    key: Option<&SigningKey>,
    limits: MembershipJournalLimits,
) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    bytes.extend_from_slice(&genesis.context().0);
    match key {
        None => bytes.push(0),
        Some(key) => {
            bytes.push(1);
            bytes.extend_from_slice(&key.verifying_key().to_bytes());
        }
    }
    bytes.extend_from_slice(&limits.maximum_round.to_be_bytes());
    bytes.extend_from_slice(&limits.maximum_records.to_be_bytes());
    bytes.extend_from_slice(&limits.maximum_bytes.to_be_bytes());
    bytes
}
fn validate_limits(limits: MembershipJournalLimits) -> Result<(), MembershipJournalError> {
    if limits.maximum_records == 0
        || limits.maximum_records > 100_000_000
        || limits.maximum_bytes < 1024
        || limits.maximum_round > 1_000_000
    {
        return Err(MembershipJournalError::Limit);
    }
    Ok(())
}
fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}
fn directories(
    journal: &Path,
    anchor: &Path,
) -> Result<(PathBuf, PathBuf), MembershipJournalError> {
    for directory in [journal, anchor] {
        if !fs::symlink_metadata(directory)?.is_dir() {
            return Err(MembershipJournalError::InvalidPath);
        }
    }
    let journal = journal.canonicalize()?;
    let anchor = anchor.canonicalize()?;
    if journal.starts_with(&anchor) || anchor.starts_with(&journal) {
        return Err(MembershipJournalError::InvalidPath);
    }
    Ok((journal, anchor))
}
fn lock(directory: &Path) -> Result<ExclusiveLock, MembershipJournalError> {
    let path = directory.join("verified-membership.lock");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_file() => return Err(MembershipJournalError::InvalidPath),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = safe_options();
    options.create(true).truncate(false);
    let file = options.open(path)?;
    validate_file(&file)?;
    lock_open_file(file).map_err(|_| MembershipJournalError::Locked)
}
fn new_file(path: &Path) -> Result<File, MembershipJournalError> {
    let file = safe_options().create_new(true).open(path)?;
    validate_file(&file)?;
    Ok(file)
}
fn existing_file(path: &Path) -> Result<File, MembershipJournalError> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(MembershipJournalError::InvalidPath);
    }
    let file = safe_options().open(path)?;
    validate_file(&file)?;
    Ok(file)
}
fn safe_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    options
}
fn validate_file(file: &File) -> Result<(), MembershipJournalError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(MembershipJournalError::InvalidPath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(MembershipJournalError::InvalidPath);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(MembershipJournalError::InvalidPath);
        }
    }
    Ok(())
}
fn require_platform() -> Result<(), MembershipJournalError> {
    if cfg!(unix) {
        Ok(())
    } else {
        Err(MembershipJournalError::UnsupportedDurableDirectorySync)
    }
}
fn sync_directory(path: &Path) -> Result<(), MembershipJournalError> {
    crate::fixed_validator_anchor::sync_directory(path).map_err(|_| MembershipJournalError::Anchor)
}
fn write_anchor(
    file: &mut File,
    sequence: u64,
    state_id: [u8; 32],
) -> Result<(), MembershipJournalError> {
    let sequence = sequence.to_be_bytes();
    let checksum = hash(
        b"naome/verified-membership/v0/anchor-position\0",
        &[&sequence, &state_id],
    );
    file.write_all(&sequence)?;
    file.write_all(&state_id)?;
    file.write_all(&checksum)?;
    file.sync_all()?;
    Ok(())
}
type AnchorEntries = Vec<(u64, [u8; 32])>;

fn read_anchors(
    file: &mut File,
    header: &[u8],
    maximum_records: u64,
    recover: bool,
) -> Result<(AnchorEntries, u64), MembershipJournalError> {
    let length = file.metadata()?.len();
    let prefix_length = ANCHOR_HEADER.len() + 32;
    if length < prefix_length as u64 + 72
        || (!recover && !(length - prefix_length as u64).is_multiple_of(72))
    {
        return Err(MembershipJournalError::Anchor);
    }
    let count = (length - prefix_length as u64) / 72;
    if count > maximum_records + 1 {
        return Err(MembershipJournalError::Limit);
    }
    let mut prefix = vec![0; prefix_length];
    file.read_exact(&mut prefix)?;
    if prefix[..ANCHOR_HEADER.len()] != *ANCHOR_HEADER
        || prefix[ANCHOR_HEADER.len()..]
            != hash(b"naome/verified-membership/v0/anchor-binding\0", &[header])
    {
        return Err(MembershipJournalError::Binding);
    }
    let mut anchors = Vec::new();
    for index in 0..count {
        let mut position = [0; 72];
        file.read_exact(&mut position)?;
        let sequence = u64::from_be_bytes(
            position[..8]
                .try_into()
                .map_err(|_| MembershipJournalError::Encoding)?,
        );
        let state_id: [u8; 32] = position[8..40]
            .try_into()
            .map_err(|_| MembershipJournalError::Encoding)?;
        if sequence != index
            || position[40..]
                != hash(
                    b"naome/verified-membership/v0/anchor-position\0",
                    &[&position[..8], &state_id],
                )
        {
            return Err(MembershipJournalError::Anchor);
        }
        anchors.push((sequence, state_id));
    }
    Ok((anchors, prefix_length as u64 + count * 72))
}
