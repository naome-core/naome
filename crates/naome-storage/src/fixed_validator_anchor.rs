//! Crash-safe independent anchors for fixed-validator V0 journals.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use naome_consensus::{ConsensusContextV0, ConsensusKey, FixedAgreementSetId};
use sha2::{Digest, Sha256};

use super::{ExclusiveLockError, open_exclusive_lock};

#[cfg(all(test, unix))]
pub(crate) mod faults;

const FINALITY_HEADER: &[u8] = b"naome:fixed-validator-finality-anchor:v0\0";
const FINALITY_CHECKSUM_DOMAIN: &[u8] = b"naome:fixed-validator-finality-anchor-checksum:v0\0";
const VOTE_HEADER: &[u8] = b"naome:fixed-validator-vote-safety-anchor:v0\0";
const VOTE_CHECKSUM_DOMAIN: &[u8] = b"naome:fixed-validator-vote-safety-anchor-checksum:v0\0";

const FINALITY_FILE_NAME: &str = "fixed-validator-finality.anchor";
const FINALITY_TEMP_STEM: &str = "fixed-validator-finality.anchor.tmp";
const VOTE_FILE_STEM: &str = "fixed-validator-vote-safety-";
const VOTE_FILE_SUFFIX: &str = ".anchor";

const ID_BYTES: usize = 32;
const PROTOCOL_VERSION_BYTES: usize = 4;
const LIMIT_BYTES: usize = 8;
const SEQUENCE_BYTES: usize = 8;
const CHECKSUM_BYTES: usize = 32;

pub(crate) const FINALITY_ANCHOR_BYTES: usize = FINALITY_HEADER.len()
    + ID_BYTES
    + ID_BYTES
    + PROTOCOL_VERSION_BYTES
    + FixedAgreementSetId::BYTE_LENGTH
    + LIMIT_BYTES
    + SEQUENCE_BYTES
    + ID_BYTES
    + CHECKSUM_BYTES;
pub(crate) const VOTE_ANCHOR_BYTES: usize = VOTE_HEADER.len()
    + ID_BYTES
    + ID_BYTES
    + PROTOCOL_VERSION_BYTES
    + FixedAgreementSetId::BYTE_LENGTH
    + ID_BYTES
    + LIMIT_BYTES
    + SEQUENCE_BYTES
    + ID_BYTES
    + CHECKSUM_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AnchorPositionV0 {
    pub(crate) sequence: u64,
    pub(crate) state_id: [u8; ID_BYTES],
}

#[derive(Debug)]
pub(crate) struct JournalAnchorTransitionV0 {
    pairing_seal: Arc<()>,
    prior: AnchorPositionV0,
    next: AnchorPositionV0,
}

impl JournalAnchorTransitionV0 {
    pub(crate) fn new(
        pairing_seal: &Arc<()>,
        prior: AnchorPositionV0,
        next_state_id: [u8; ID_BYTES],
    ) -> Result<Self, FixedValidatorAnchorErrorV0> {
        let next_sequence = prior
            .sequence
            .checked_add(1)
            .ok_or(FixedValidatorAnchorErrorV0::SequenceExhausted)?;
        Ok(Self {
            pairing_seal: Arc::clone(pairing_seal),
            prior,
            next: AnchorPositionV0 {
                sequence: next_sequence,
                state_id: next_state_id,
            },
        })
    }

    pub(crate) const fn next(&self) -> AnchorPositionV0 {
        self.next
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnchorKindV0 {
    Finality,
    Vote { signer: ConsensusKey },
}

#[derive(Debug)]
pub(crate) struct FixedValidatorAnchorFileV0 {
    _lock: File,
    directory: PathBuf,
    file_name: String,
    temporary_stem: String,
    context: ConsensusContextV0,
    fixed_set_id: FixedAgreementSetId,
    replay_limit: u64,
    kind: AnchorKindV0,
    position: AnchorPositionV0,
    pairing_seal: Arc<()>,
    poisoned: bool,
}

impl FixedValidatorAnchorFileV0 {
    pub(crate) fn create_finality(
        directory: &Path,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        replay_limit: u64,
        state_id: [u8; ID_BYTES],
    ) -> Result<Self, FixedValidatorAnchorErrorV0> {
        Self::create(
            directory,
            FINALITY_FILE_NAME.to_owned(),
            FINALITY_TEMP_STEM.to_owned(),
            context,
            fixed_set_id,
            replay_limit,
            AnchorKindV0::Finality,
            state_id,
        )
    }

    pub(crate) fn open_finality(
        directory: &Path,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        replay_limit: u64,
    ) -> Result<Self, FixedValidatorAnchorErrorV0> {
        Self::open(
            directory,
            FINALITY_FILE_NAME.to_owned(),
            FINALITY_TEMP_STEM.to_owned(),
            context,
            fixed_set_id,
            replay_limit,
            AnchorKindV0::Finality,
        )
    }

    pub(crate) fn create_vote(
        directory: &Path,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signer: ConsensusKey,
        replay_limit: u64,
        state_id: [u8; ID_BYTES],
    ) -> Result<Self, FixedValidatorAnchorErrorV0> {
        let (file_name, temporary_stem) = vote_file_names(signer)?;
        Self::create(
            directory,
            file_name,
            temporary_stem,
            context,
            fixed_set_id,
            replay_limit,
            AnchorKindV0::Vote { signer },
            state_id,
        )
    }

    pub(crate) fn open_vote(
        directory: &Path,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        signer: ConsensusKey,
        replay_limit: u64,
    ) -> Result<Self, FixedValidatorAnchorErrorV0> {
        let (file_name, temporary_stem) = vote_file_names(signer)?;
        Self::open(
            directory,
            file_name,
            temporary_stem,
            context,
            fixed_set_id,
            replay_limit,
            AnchorKindV0::Vote { signer },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        directory: &Path,
        file_name: String,
        temporary_stem: String,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        replay_limit: u64,
        kind: AnchorKindV0,
        state_id: [u8; ID_BYTES],
    ) -> Result<Self, FixedValidatorAnchorErrorV0> {
        require_durable_directory_sync()?;
        let lock = open_anchor_lock(directory, &file_name)?;
        let position = AnchorPositionV0 {
            sequence: 0,
            state_id,
        };
        let bytes = canonical_bytes(context, fixed_set_id, replay_limit, kind, position);
        create_synced(directory, &file_name, &bytes)?;
        Ok(Self {
            _lock: lock,
            directory: directory.to_path_buf(),
            file_name,
            temporary_stem,
            context,
            fixed_set_id,
            replay_limit,
            kind,
            position,
            pairing_seal: Arc::new(()),
            poisoned: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn open(
        directory: &Path,
        file_name: String,
        temporary_stem: String,
        context: ConsensusContextV0,
        fixed_set_id: FixedAgreementSetId,
        replay_limit: u64,
        kind: AnchorKindV0,
    ) -> Result<Self, FixedValidatorAnchorErrorV0> {
        require_durable_directory_sync()?;
        let path = directory.join(&file_name);
        let lock = open_anchor_lock(directory, &file_name)?;
        let expected_length = encoded_length(kind);
        let mut file = File::open(&path).map_err(|source| match source.kind() {
            io::ErrorKind::NotFound => FixedValidatorAnchorErrorV0::Missing { path: path.clone() },
            _ => FixedValidatorAnchorErrorV0::Open { source },
        })?;
        let actual_length = usize::try_from(
            file.metadata()
                .map_err(|source| FixedValidatorAnchorErrorV0::Read { source })?
                .len(),
        )
        .unwrap_or(usize::MAX);
        if actual_length != expected_length {
            return Err(FixedValidatorAnchorErrorV0::InvalidLength {
                expected: expected_length,
                actual: actual_length,
            });
        }
        let mut bytes = vec![0_u8; expected_length];
        file.read_exact(&mut bytes)
            .map_err(|source| FixedValidatorAnchorErrorV0::Read { source })?;
        let position = decode_bytes(&bytes, context, fixed_set_id, replay_limit, kind)?;
        Ok(Self {
            _lock: lock,
            directory: directory.to_path_buf(),
            file_name,
            temporary_stem,
            context,
            fixed_set_id,
            replay_limit,
            kind,
            position,
            pairing_seal: Arc::new(()),
            poisoned: false,
        })
    }

    pub(crate) const fn position(&self) -> AnchorPositionV0 {
        self.position
    }

    pub(crate) fn pairing_seal(&self) -> &Arc<()> {
        &self.pairing_seal
    }

    pub(crate) fn stabilize(&self) -> Result<(), FixedValidatorAnchorErrorV0> {
        let path = self.directory.join(&self.file_name);
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .and_then(|file| {
                #[cfg(all(test, unix))]
                faults::check(&path, faults::Operation::StabilizeFile)?;
                file.sync_all()
            })
            .and_then(|()| {
                #[cfg(all(test, unix))]
                faults::check(&path, faults::Operation::StabilizeDirectory)?;
                sync_directory_platform(&self.directory)
            })
            .map_err(|source| FixedValidatorAnchorErrorV0::Stabilize { source })
    }

    pub(crate) fn advance(
        &mut self,
        transition: JournalAnchorTransitionV0,
    ) -> Result<(), FixedValidatorAnchorErrorV0> {
        if self.poisoned {
            return Err(FixedValidatorAnchorErrorV0::Poisoned);
        }
        if !Arc::ptr_eq(&self.pairing_seal, &transition.pairing_seal) {
            return Err(FixedValidatorAnchorErrorV0::ForeignTransition);
        }
        if transition.prior != self.position {
            return Err(FixedValidatorAnchorErrorV0::TransitionMismatch {
                anchored_sequence: self.position.sequence,
                transition_sequence: transition.prior.sequence,
            });
        }
        let bytes = canonical_bytes(
            self.context,
            self.fixed_set_id,
            self.replay_limit,
            self.kind,
            transition.next,
        );
        let result = replace_synced(
            &self.directory,
            &temporary_name(&self.temporary_stem, transition.next.sequence),
            &self.file_name,
            &bytes,
        );
        if let Err(error) = result {
            self.poisoned = true;
            return Err(error);
        }
        self.position = transition.next;
        Ok(())
    }
}

fn encoded_length(kind: AnchorKindV0) -> usize {
    match kind {
        AnchorKindV0::Finality => FINALITY_ANCHOR_BYTES,
        AnchorKindV0::Vote { .. } => VOTE_ANCHOR_BYTES,
    }
}

fn canonical_bytes(
    context: ConsensusContextV0,
    fixed_set_id: FixedAgreementSetId,
    replay_limit: u64,
    kind: AnchorKindV0,
    position: AnchorPositionV0,
) -> Vec<u8> {
    let (header, checksum_domain) = match kind {
        AnchorKindV0::Finality => (FINALITY_HEADER, FINALITY_CHECKSUM_DOMAIN),
        AnchorKindV0::Vote { .. } => (VOTE_HEADER, VOTE_CHECKSUM_DOMAIN),
    };
    let mut bytes = Vec::with_capacity(encoded_length(kind));
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(context.chain_id().as_bytes());
    bytes.extend_from_slice(context.genesis_id().as_bytes());
    bytes.extend_from_slice(&context.protocol_version().value().to_be_bytes());
    bytes.extend_from_slice(fixed_set_id.as_bytes());
    if let AnchorKindV0::Vote { signer } = kind {
        bytes.extend_from_slice(signer.as_bytes());
    }
    bytes.extend_from_slice(&replay_limit.to_be_bytes());
    bytes.extend_from_slice(&position.sequence.to_be_bytes());
    bytes.extend_from_slice(&position.state_id);
    let mut hasher = Sha256::new();
    hasher.update(checksum_domain);
    hasher.update(&bytes);
    bytes.extend_from_slice(&hasher.finalize());
    debug_assert_eq!(bytes.len(), encoded_length(kind));
    bytes
}

fn decode_bytes(
    bytes: &[u8],
    expected_context: ConsensusContextV0,
    expected_fixed_set_id: FixedAgreementSetId,
    expected_replay_limit: u64,
    expected_kind: AnchorKindV0,
) -> Result<AnchorPositionV0, FixedValidatorAnchorErrorV0> {
    let expected_length = encoded_length(expected_kind);
    if bytes.len() != expected_length {
        return Err(FixedValidatorAnchorErrorV0::InvalidLength {
            expected: expected_length,
            actual: bytes.len(),
        });
    }
    let checksum_start = bytes.len() - CHECKSUM_BYTES;
    let (header, checksum_domain) = match expected_kind {
        AnchorKindV0::Finality => (FINALITY_HEADER, FINALITY_CHECKSUM_DOMAIN),
        AnchorKindV0::Vote { .. } => (VOTE_HEADER, VOTE_CHECKSUM_DOMAIN),
    };
    let mut hasher = Sha256::new();
    hasher.update(checksum_domain);
    hasher.update(&bytes[..checksum_start]);
    if hasher.finalize().as_slice() != &bytes[checksum_start..] {
        return Err(FixedValidatorAnchorErrorV0::ChecksumMismatch);
    }
    let mut offset = 0;
    if take(bytes, &mut offset, header.len()) != header {
        return Err(FixedValidatorAnchorErrorV0::HeaderMismatch);
    }
    if take(bytes, &mut offset, ID_BYTES) != expected_context.chain_id().as_bytes()
        || take(bytes, &mut offset, ID_BYTES) != expected_context.genesis_id().as_bytes()
        || take(bytes, &mut offset, PROTOCOL_VERSION_BYTES)
            != expected_context.protocol_version().value().to_be_bytes()
        || take(bytes, &mut offset, FixedAgreementSetId::BYTE_LENGTH)
            != expected_fixed_set_id.as_bytes()
    {
        return Err(FixedValidatorAnchorErrorV0::BindingMismatch);
    }
    if let AnchorKindV0::Vote { signer } = expected_kind
        && take(bytes, &mut offset, ID_BYTES) != signer.as_bytes()
    {
        return Err(FixedValidatorAnchorErrorV0::BindingMismatch);
    }
    let replay_limit = u64::from_be_bytes(
        take(bytes, &mut offset, LIMIT_BYTES)
            .try_into()
            .expect("the fixed anchor limit has exact width"),
    );
    if replay_limit == 0 || replay_limit != expected_replay_limit {
        return Err(FixedValidatorAnchorErrorV0::BindingMismatch);
    }
    let sequence = u64::from_be_bytes(
        take(bytes, &mut offset, SEQUENCE_BYTES)
            .try_into()
            .expect("the fixed anchor sequence has exact width"),
    );
    let state_id = take(bytes, &mut offset, ID_BYTES)
        .try_into()
        .expect("the fixed anchor state identity has exact width");
    debug_assert_eq!(offset, checksum_start);
    Ok(AnchorPositionV0 { sequence, state_id })
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> &'a [u8] {
    let end = *offset + length;
    let value = &bytes[*offset..end];
    *offset = end;
    value
}

fn vote_file_names(signer: ConsensusKey) -> Result<(String, String), FixedValidatorAnchorErrorV0> {
    let mut stem = String::new();
    stem.try_reserve_exact(VOTE_FILE_STEM.len() + ID_BYTES * 2)
        .map_err(|_| FixedValidatorAnchorErrorV0::PathAllocation)?;
    stem.push_str(VOTE_FILE_STEM);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in signer.as_bytes() {
        stem.push(HEX[usize::from(byte >> 4)] as char);
        stem.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    let mut file_name = stem.clone();
    file_name.push_str(VOTE_FILE_SUFFIX);
    let mut temporary_stem = file_name.clone();
    temporary_stem.push_str(".tmp");
    Ok((file_name, temporary_stem))
}

fn temporary_name(stem: &str, sequence: u64) -> String {
    format!("{stem}-{sequence:016x}")
}

fn open_anchor_lock(
    directory: &Path,
    file_name: &str,
) -> Result<File, FixedValidatorAnchorErrorV0> {
    let mut lock_file_name = String::new();
    lock_file_name
        .try_reserve_exact(file_name.len() + ".lock".len())
        .map_err(|_| FixedValidatorAnchorErrorV0::PathAllocation)?;
    lock_file_name.push_str(file_name);
    lock_file_name.push_str(".lock");
    let path = directory.join(&lock_file_name);
    open_exclusive_lock(directory, &lock_file_name).map_err(|error| match error {
        ExclusiveLockError::LockFile(source) => {
            FixedValidatorAnchorErrorV0::LockFile { path, source }
        }
        ExclusiveLockError::Locked => FixedValidatorAnchorErrorV0::Locked { path },
        ExclusiveLockError::Lock(source) => FixedValidatorAnchorErrorV0::Lock { path, source },
    })
}

fn create_synced(
    directory: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<(), FixedValidatorAnchorErrorV0> {
    require_durable_directory_sync()?;
    let path = directory.join(file_name);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|source| match source.kind() {
            io::ErrorKind::AlreadyExists => {
                FixedValidatorAnchorErrorV0::AlreadyExists { path: path.clone() }
            }
            _ => FixedValidatorAnchorErrorV0::Write { source },
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })?;
    sync_directory_platform(directory)
        .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })
}

fn replace_synced(
    directory: &Path,
    temporary_file_name: &str,
    file_name: &str,
    bytes: &[u8],
) -> Result<(), FixedValidatorAnchorErrorV0> {
    require_durable_directory_sync()?;
    let temporary_path = directory.join(temporary_file_name);
    #[cfg(all(test, unix))]
    faults::check(
        &directory.join(file_name),
        faults::Operation::CreateTemporary,
    )
    .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })?;
    let mut temporary = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary_path)
        .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })?;
    #[cfg(all(test, unix))]
    faults::check(
        &directory.join(file_name),
        faults::Operation::WriteTemporary,
    )
    .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })?;
    temporary
        .write_all(bytes)
        .and_then(|()| {
            #[cfg(all(test, unix))]
            faults::check(&directory.join(file_name), faults::Operation::SyncTemporary)?;
            temporary.sync_all()
        })
        .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })?;
    #[cfg(all(test, unix))]
    faults::check(&directory.join(file_name), faults::Operation::Rename)
        .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })?;
    fs::rename(&temporary_path, directory.join(file_name))
        .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })?;
    #[cfg(all(test, unix))]
    faults::check(
        &directory.join(file_name),
        faults::Operation::SyncReplacementDirectory,
    )
    .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })?;
    sync_directory_platform(directory)
        .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })
}

pub(crate) fn sync_directory(directory: &Path) -> Result<(), FixedValidatorAnchorErrorV0> {
    require_durable_directory_sync()?;
    sync_directory_platform(directory)
        .map_err(|source| FixedValidatorAnchorErrorV0::Write { source })
}

#[cfg(unix)]
fn sync_directory_platform(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory_platform(_directory: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable parent-directory synchronization is unavailable on this platform",
    ))
}

fn require_durable_directory_sync() -> Result<(), FixedValidatorAnchorErrorV0> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(FixedValidatorAnchorErrorV0::UnsupportedDurableDirectorySync)
    }
}

/// Failure to load or durably advance one independent fixed-validator anchor.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorAnchorErrorV0 {
    UnsupportedDurableDirectorySync,
    PathAllocation,
    LockFile {
        path: PathBuf,
        source: io::Error,
    },
    Locked {
        path: PathBuf,
    },
    Lock {
        path: PathBuf,
        source: io::Error,
    },
    AlreadyExists {
        path: PathBuf,
    },
    Missing {
        path: PathBuf,
    },
    Open {
        source: io::Error,
    },
    Read {
        source: io::Error,
    },
    InvalidLength {
        expected: usize,
        actual: usize,
    },
    HeaderMismatch,
    BindingMismatch,
    ChecksumMismatch,
    SequenceExhausted,
    ForeignTransition,
    TransitionMismatch {
        anchored_sequence: u64,
        transition_sequence: u64,
    },
    Write {
        source: io::Error,
    },
    Stabilize {
        source: io::Error,
    },
    Poisoned,
}

impl fmt::Display for FixedValidatorAnchorErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDurableDirectorySync => formatter.write_str(
                "this platform cannot provide the required durable parent-directory synchronization",
            ),
            Self::PathAllocation => formatter.write_str("anchor path allocation failed"),
            Self::LockFile { path, source } => write!(
                formatter,
                "cannot open fixed-validator anchor lock {}: {source}",
                path.display()
            ),
            Self::Locked { path } => write!(
                formatter,
                "fixed-validator anchor is already exclusively open through {}",
                path.display()
            ),
            Self::Lock { path, source } => write!(
                formatter,
                "cannot acquire fixed-validator anchor lock {}: {source}",
                path.display()
            ),
            Self::AlreadyExists { path } => write!(
                formatter,
                "fixed-validator anchor already exists at {}",
                path.display()
            ),
            Self::Missing { path } => write!(
                formatter,
                "fixed-validator anchor is missing at {}",
                path.display()
            ),
            Self::Open { source } => write!(formatter, "anchor opening failed: {source}"),
            Self::Read { source } => write!(formatter, "anchor read failed: {source}"),
            Self::InvalidLength { expected, actual } => write!(
                formatter,
                "anchor has {actual} bytes, expected exactly {expected}"
            ),
            Self::HeaderMismatch => formatter.write_str("anchor kind or version header mismatch"),
            Self::BindingMismatch => formatter.write_str(
                "anchor does not match the exact context, fixed set, signer, or replay limit",
            ),
            Self::ChecksumMismatch => formatter.write_str("anchor checksum mismatch"),
            Self::SequenceExhausted => formatter.write_str("anchor journal sequence is exhausted"),
            Self::ForeignTransition => {
                formatter.write_str("anchor transition belongs to another live journal pairing")
            }
            Self::TransitionMismatch {
                anchored_sequence,
                transition_sequence,
            } => write!(
                formatter,
                "anchor is at journal sequence {anchored_sequence}, but the transition starts at {transition_sequence}"
            ),
            Self::Write { source } => {
                write!(formatter, "anchor replacement has unknown durability: {source}")
            }
            Self::Stabilize { source } => {
                write!(formatter, "anchor stabilization failed: {source}")
            }
            Self::Poisoned => formatter.write_str(
                "anchor is poisoned after ambiguous replacement; drop and strictly reopen the paired journal",
            ),
        }
    }
}

impl Error for FixedValidatorAnchorErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LockFile { source, .. }
            | Self::Lock { source, .. }
            | Self::Open { source }
            | Self::Read { source }
            | Self::Write { source }
            | Self::Stabilize { source } => Some(source),
            _ => None,
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
