//! Artifact-journal typed failures.

use super::*;

#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactChainJournalError {
    /// The sidecar lock file could not be opened.
    LockFile { source: io::Error },
    /// Another process or handle already owns the journal lock.
    Locked,
    /// The operating-system file lock could not be acquired.
    Lock { source: io::Error },
    /// A new journal file could not be created or initialized.
    Create { source: io::Error },
    /// An existing journal file could not be opened.
    Open { source: io::Error },
    /// Existing journal bytes could not be read.
    Read { offset: u64, source: io::Error },
    /// The journal header or chain identifier is incomplete or unsupported.
    InvalidHeader,
    /// The file is bound to a different artifact-chain context.
    ChainIdMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// A complete entry declares an impossible body length.
    InvalidEntryLength {
        entry: u64,
        offset: u64,
        actual: u32,
        minimum: u32,
        maximum: u32,
    },
    /// An entry boundary cannot be represented safely.
    EntryOffsetOverflow { entry: u64, offset: u64 },
    /// Allocating one bounded artifact payload failed.
    Allocation { entry: u64, bytes: usize },
    /// Reserving the selected-block index for one journal entry failed.
    BlockIndexAllocation { entry: u64 },
    /// The commit footer does not repeat the decoded canonical block identity.
    BlockIdMismatch {
        entry: u64,
        offset: u64,
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// Strict block replay rejected one complete committed entry.
    Replay {
        entry: u64,
        offset: u64,
        source: Box<ArtifactBlockApplyError>,
    },
    /// An incomplete final entry could not be removed durably.
    Recovery { offset: u64, source: io::Error },
    /// A fully replayed visible journal image could not be stabilized.
    Stabilize { source: io::Error },
    /// Strict replay produced a different block ancestry than expected.
    HeadBlockIdMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// Read-only block preparation rejected its artifact identity.
    Preparation { source: ArtifactBlockPrepareError },
    /// The supplied block failed before journal I/O.
    BlockAdmission { source: ArtifactBlockApplyError },
    /// Commit durability is unknown and the handle is now poisoned.
    Commit {
        block_id: ArtifactBlockId,
        source: io::Error,
    },
    /// Memory may be ahead of durable storage after an ambiguous commit.
    Poisoned,
}

impl fmt::Display for ArtifactChainJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockFile { source } => write!(formatter, "journal lock file failed: {source}"),
            Self::Locked => {
                formatter.write_str("artifact chain journal is already exclusively open")
            }
            Self::Lock { source } => write!(formatter, "journal locking failed: {source}"),
            Self::Create { source } => write!(formatter, "journal creation failed: {source}"),
            Self::Open { source } => write!(formatter, "journal opening failed: {source}"),
            Self::Read { offset, source } => {
                write!(formatter, "journal read failed at byte {offset}: {source}")
            }
            Self::InvalidHeader => formatter.write_str("invalid artifact chain journal header"),
            Self::ChainIdMismatch { expected, actual } => write!(
                formatter,
                "artifact chain identifier mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::InvalidEntryLength {
                entry,
                offset,
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} has body length {actual}, expected {minimum}..={maximum}"
            ),
            Self::EntryOffsetOverflow { entry, offset } => write!(
                formatter,
                "journal entry {entry} at byte {offset} exceeds the offset range"
            ),
            Self::Allocation { entry, bytes } => write!(
                formatter,
                "journal entry {entry} artifact payload could not allocate {bytes} bytes"
            ),
            Self::BlockIndexAllocation { entry } => {
                write!(
                    formatter,
                    "journal entry {entry} could not reserve its block index slot"
                )
            }
            Self::BlockIdMismatch {
                entry,
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} commits block {actual:?}, expected decoded block {expected:?}"
            ),
            Self::Replay {
                entry,
                offset,
                source,
            } => write!(
                formatter,
                "journal entry {entry} at byte {offset} failed strict block replay: {source}"
            ),
            Self::Recovery { offset, source } => write!(
                formatter,
                "incomplete journal tail at byte {offset} could not be recovered: {source}"
            ),
            Self::Stabilize { source } => {
                write!(formatter, "replayed journal stabilization failed: {source}")
            }
            Self::HeadBlockIdMismatch { expected, actual } => write!(
                formatter,
                "artifact-chain head mismatch: expected {expected:?}, replayed {actual:?}"
            ),
            Self::Preparation { source } => write!(formatter, "block preparation failed: {source}"),
            Self::BlockAdmission { source } => {
                write!(formatter, "block admission failed: {source}")
            }
            Self::Commit { block_id, source } => write!(
                formatter,
                "journal commit of block {block_id:?} has unknown durability: {source}"
            ),
            Self::Poisoned => formatter
                .write_str("journal is poisoned after an ambiguous commit; drop and reopen it"),
        }
    }
}

impl Error for ArtifactChainJournalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LockFile { source }
            | Self::Lock { source }
            | Self::Create { source }
            | Self::Open { source }
            | Self::Read { source, .. }
            | Self::Recovery { source, .. }
            | Self::Stabilize { source }
            | Self::Commit { source, .. } => Some(source),
            Self::Replay { source, .. } => Some(source.as_ref()),
            Self::Preparation { source } => Some(source),
            Self::BlockAdmission { source } => Some(source),
            Self::Locked
            | Self::InvalidHeader
            | Self::ChainIdMismatch { .. }
            | Self::InvalidEntryLength { .. }
            | Self::EntryOffsetOverflow { .. }
            | Self::Allocation { .. }
            | Self::BlockIndexAllocation { .. }
            | Self::BlockIdMismatch { .. }
            | Self::HeadBlockIdMismatch { .. }
            | Self::Poisoned => None,
        }
    }
}
