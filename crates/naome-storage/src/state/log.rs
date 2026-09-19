//! Shared private append/anchor mechanics. This module grants no consensus
//! authority: callers must replay every complete payload before obtaining an
//! operational history or signer.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::ResearchStorageError as Error;
use crate::platform::{durable_open_options, require_finality_platform, sync_finality_file};
use crate::store_io::{
    ExclusiveLock, ExclusiveLockError, StoreIo, append_body_and_commit, open_exclusive_lock,
};

const ANCHOR_MAGIC: &[u8; 8] = b"NAOSANC1";
const ANCHOR_BYTES: usize = 8 + 32 + 8 + 32 + 32;
const FRAME_OVERHEAD: u64 = 4 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Position {
    pub sequence: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub payload_bytes: u32,
    pub frames: u64,
    /// Includes the immutable prefix and all body/footer bytes.
    pub file_bytes: u64,
}
impl Limits {
    fn validate(self, prefix_bytes: usize) -> Result<(), Error> {
        if self.payload_bytes == 0 || self.frames == 0 || self.file_bytes < prefix_bytes as u64 {
            return Err(Error::Invalid("journal limits"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Index {
    offset: u64,
    length: u32,
    prior: [u8; 32],
    digest: [u8; 32],
}

pub(super) trait Anchor {
    fn position(&self) -> Position;
    /// Must synchronize the replacement and its directory binding before success.
    fn advance(&mut self, prior: Position, next: Position) -> Result<(), Error>;
}

pub(super) struct Log<F, A> {
    file: F,
    anchor: A,
    limits: Limits,
    index: Vec<Index>,
    position: Position,
    end: u64,
    poisoned: bool,
}

impl<F: StoreIo, A: Anchor> Log<F, A> {
    pub(super) fn replay(
        mut file: F,
        anchor: A,
        prefix: &[u8],
        limits: Limits,
        mut accept: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        let scan = scan(&mut file, prefix, limits, anchor.position(), &mut accept)?;
        // No truncation or sync occurs until the entire complete history and
        // exact independent anchor have been verified successfully.
        if scan.tail {
            file.set_len(scan.end)?;
        }
        file.sync_all()?;
        Ok(Self {
            file,
            anchor,
            limits,
            index: scan.index,
            position: scan.position,
            end: scan.end,
            poisoned: false,
        })
    }
    pub(super) fn empty(file: F, anchor: A, prefix: &[u8], limits: Limits) -> Result<Self, Error> {
        limits.validate(prefix.len())?;
        let position = genesis_position(prefix);
        if anchor.position() != position {
            return Err(Error::Invalid("initial journal anchor"));
        }
        Ok(Self {
            file,
            anchor,
            limits,
            index: Vec::new(),
            position,
            end: prefix.len() as u64,
            poisoned: false,
        })
    }
    pub(super) fn ensure(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    pub(super) fn position(&self) -> Result<Position, Error> {
        self.ensure()?;
        Ok(self.position)
    }
    pub(super) fn remaining_capacity(&self) -> Result<(u64, u64), Error> {
        self.ensure()?;
        Ok((
            self.limits.file_bytes - self.end,
            self.limits.frames - self.position.sequence,
        ))
    }
    #[cfg(all(test, unix))]
    pub(super) fn exhaust_capacity(&mut self, bytes: bool) {
        if bytes {
            self.limits.file_bytes = self.end;
        } else {
            self.limits.frames = self.position.sequence;
        }
    }
    /// Reserves allocation and checks room for a compound operation before its
    /// first durable intent. The signer serializes all work while pending, so
    /// no intervening operation can consume this completion capacity.
    pub(super) fn reserve_batch(&mut self, lengths: &[usize]) -> Result<(), Error> {
        self.ensure()?;
        let frames = self
            .position
            .sequence
            .checked_add(lengths.len() as u64)
            .ok_or(Error::Limit("journal frames"))?;
        if frames > self.limits.frames {
            return Err(Error::Limit("journal frames"));
        }
        let mut end = self.end;
        for length in lengths {
            if *length == 0 || *length > self.limits.payload_bytes as usize {
                return Err(Error::Limit("frame payload"));
            }
            end = end
                .checked_add(FRAME_OVERHEAD)
                .and_then(|v| v.checked_add(*length as u64))
                .ok_or(Error::Limit("journal bytes"))?;
        }
        if end > self.limits.file_bytes {
            return Err(Error::Limit("journal bytes"));
        }
        self.index
            .try_reserve(lengths.len())
            .map_err(|_| Error::Limit("journal index allocation"))?;
        Ok(())
    }
    pub(super) fn append(&mut self, body: &[u8]) -> Result<Position, Error> {
        self.ensure()?;
        let length = u32::try_from(body.len()).map_err(|_| Error::Limit("frame payload"))?;
        if length == 0 || length > self.limits.payload_bytes {
            return Err(Error::Limit("frame payload"));
        }
        if self.position.sequence >= self.limits.frames {
            return Err(Error::Limit("journal frames"));
        }
        let end = self
            .end
            .checked_add(FRAME_OVERHEAD)
            .and_then(|v| v.checked_add(u64::from(length)))
            .ok_or(Error::Limit("journal length"))?;
        if end > self.limits.file_bytes {
            return Err(Error::Limit("journal bytes"));
        }
        self.index
            .try_reserve(1)
            .map_err(|_| Error::Limit("journal index allocation"))?;
        let next = Position {
            sequence: self
                .position
                .sequence
                .checked_add(1)
                .ok_or(Error::Limit("journal sequence"))?,
            digest: step_digest(self.position.digest, length, body),
        };
        let write = (|| {
            self.file.seek(SeekFrom::Start(self.end))?;
            append_body_and_commit(&mut self.file, &[&length.to_be_bytes(), body], &next.digest)?;
            self.anchor.advance(self.position, next)
        })();
        if let Err(error) = write {
            self.poisoned = true;
            return Err(error);
        }
        self.index.push(Index {
            offset: self.end,
            length,
            prior: self.position.digest,
            digest: next.digest,
        });
        self.position = next;
        self.end = end;
        Ok(next)
    }
    pub(super) fn payload(&mut self, index: usize) -> Result<Vec<u8>, Error> {
        self.ensure()?;
        let index = *self
            .index
            .get(index)
            .ok_or(Error::Invalid("journal frame index"))?;
        let result = read_indexed(&mut self.file, index);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

/// Holds both the independently locked anchor and the caller-selected owner
/// lock. For finality that owner lock is the existing artifact-chain lock.
pub(super) struct FileLog {
    pub core: Log<File, FileAnchor>,
    _anchor_lock: ExclusiveLock,
    _owner_lock: ExclusiveLock,
}
impl FileLog {
    pub(super) fn create(
        directory: &Path,
        anchor_directory: &Path,
        file_name: &str,
        owner_lock_name: &str,
        anchor_name: &str,
        prefix: &[u8],
        limits: Limits,
    ) -> Result<Self, Error> {
        require_finality_platform(directory)?;
        require_finality_platform(anchor_directory)?;
        limits.validate(prefix.len())?;
        let owner_lock = lock(directory, owner_lock_name)?;
        let anchor_lock = lock(anchor_directory, &format!("{anchor_name}.lock"))?;
        // Both paths must be absent before either is initialized. Partial
        // provisioning is never inferred to be a safe new genesis on reopen.
        if directory.join(file_name).exists() || anchor_directory.join(anchor_name).exists() {
            return Err(Error::Invalid("journal or anchor already exists"));
        }
        let mut file = durable_open_options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.join(file_name))?;
        file.write_all(prefix)?;
        file.sync_all()?;
        sync_finality_file(directory, file_name)?;
        let position = genesis_position(prefix);
        let anchor = FileAnchor::create(anchor_directory, anchor_name, prefix, position)?;
        Ok(Self {
            core: Log::empty(file, anchor, prefix, limits)?,
            _anchor_lock: anchor_lock,
            _owner_lock: owner_lock,
        })
    }
    // Same explicit custody/configuration fields as create, plus the replay
    // verifier. Keeping the visitor separate makes validation mandatory here.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn open(
        directory: &Path,
        anchor_directory: &Path,
        file_name: &str,
        owner_lock_name: &str,
        anchor_name: &str,
        prefix: &[u8],
        limits: Limits,
        accept: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        require_finality_platform(directory)?;
        require_finality_platform(anchor_directory)?;
        let owner_lock = lock(directory, owner_lock_name)?;
        let anchor_lock = lock(anchor_directory, &format!("{anchor_name}.lock"))?;
        let anchor = FileAnchor::open(anchor_directory, anchor_name, prefix)?;
        let file = durable_open_options()
            .read(true)
            .write(true)
            .open(directory.join(file_name))?;
        let core = Log::replay(file, anchor, prefix, limits, accept)?;
        sync_finality_file(anchor_directory, anchor_name)?;
        Ok(Self {
            core,
            _anchor_lock: anchor_lock,
            _owner_lock: owner_lock,
        })
    }
}

/// Read-only verified point-in-time prefix. No lock, creation, truncation, sync,
/// key ownership, or selected-history mutation is performed by an observer.
pub(super) fn observe(
    directory: &Path,
    anchor_directory: &Path,
    file_name: &str,
    anchor_name: &str,
    prefix: &[u8],
    limits: Limits,
    accept: impl FnMut(&[u8]) -> Result<(), Error>,
) -> Result<Position, Error> {
    let anchor = FileAnchor::open(anchor_directory, anchor_name, prefix)?;
    let mut file = File::open(directory.join(file_name))?;
    let result = scan(&mut file, prefix, limits, anchor.position(), accept)?;
    // If a writer advanced its independent anchor while scanning, the observer
    // retries rather than presenting a mixed snapshot as current selected state.
    if FileAnchor::open(anchor_directory, anchor_name, prefix)?.position() != result.position {
        return Err(Error::Invalid("anchor changed during observation"));
    }
    Ok(result.position)
}

struct Scan {
    index: Vec<Index>,
    position: Position,
    end: u64,
    tail: bool,
}
fn scan<F: Read + Seek>(
    file: &mut F,
    prefix: &[u8],
    limits: Limits,
    anchored: Position,
    mut accept: impl FnMut(&[u8]) -> Result<(), Error>,
) -> Result<Scan, Error> {
    limits.validate(prefix.len())?;
    let length = file.seek(SeekFrom::End(0))?;
    if length > limits.file_bytes {
        return Err(Error::Limit("journal bytes"));
    }
    if length < prefix.len() as u64 {
        return Err(Error::Invalid("incomplete journal header"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut actual = vec![0; prefix.len()];
    file.read_exact(&mut actual)?;
    if actual != prefix {
        return Err(Error::Invalid("journal context/header"));
    }
    let mut position = genesis_position(prefix);
    let mut end = prefix.len() as u64;
    let mut index = Vec::new();
    let mut tail = false;
    while end < length {
        if length - end < 4 {
            tail = true;
            break;
        }
        file.seek(SeekFrom::Start(end))?;
        let mut size = [0; 4];
        file.read_exact(&mut size)?;
        let size = u32::from_be_bytes(size);
        if size == 0 || size > limits.payload_bytes {
            return Err(Error::Invalid("frame length"));
        }
        let frame_end = end
            .checked_add(FRAME_OVERHEAD)
            .and_then(|v| v.checked_add(u64::from(size)))
            .ok_or(Error::Invalid("frame offset overflow"))?;
        if frame_end > length {
            tail = true;
            break;
        }
        if position.sequence >= limits.frames {
            return Err(Error::Limit("journal frames"));
        }
        let mut body = bounded_buffer(size as usize)?;
        file.read_exact(&mut body)?;
        let mut digest = [0; 32];
        file.read_exact(&mut digest)?;
        if digest != step_digest(position.digest, size, &body) {
            return Err(Error::Invalid("complete frame checksum"));
        }
        accept(&body)?;
        index
            .try_reserve(1)
            .map_err(|_| Error::Limit("journal index allocation"))?;
        index.push(Index {
            offset: end,
            length: size,
            prior: position.digest,
            digest,
        });
        position = Position {
            sequence: position
                .sequence
                .checked_add(1)
                .ok_or(Error::Limit("journal sequence"))?,
            digest,
        };
        end = frame_end;
    }
    if position != anchored {
        return Err(Error::Invalid("journal/anchor mismatch"));
    }
    Ok(Scan {
        index,
        position,
        end,
        tail,
    })
}

fn read_indexed(file: &mut (impl Read + Seek), index: Index) -> Result<Vec<u8>, Error> {
    file.seek(SeekFrom::Start(index.offset))?;
    let mut length = [0; 4];
    file.read_exact(&mut length)?;
    if u32::from_be_bytes(length) != index.length {
        return Err(Error::Invalid("changed journal length"));
    }
    let mut body = bounded_buffer(index.length as usize)?;
    file.read_exact(&mut body)?;
    let mut digest = [0; 32];
    file.read_exact(&mut digest)?;
    if digest != index.digest || step_digest(index.prior, index.length, &body) != digest {
        return Err(Error::Invalid("changed journal content"));
    }
    Ok(body)
}
fn bounded_buffer(length: usize) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| Error::Limit("frame allocation"))?;
    buffer.resize(length, 0);
    Ok(buffer)
}
fn lock(directory: &Path, name: &str) -> Result<ExclusiveLock, Error> {
    open_exclusive_lock(directory, name).map_err(|e| match e {
        ExclusiveLockError::Locked => Error::Locked,
        ExclusiveLockError::LockFile(e) | ExclusiveLockError::Lock(e) => Error::Io(e),
    })
}
pub(super) fn hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for field in fields {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field);
    }
    h.finalize().into()
}
fn genesis_position(prefix: &[u8]) -> Position {
    Position {
        sequence: 0,
        digest: hash(b"naome:state:journal:genesis:v1\0", &[prefix]),
    }
}
fn step_digest(prior: [u8; 32], length: u32, body: &[u8]) -> [u8; 32] {
    hash(
        b"naome:state:journal:step:v1\0",
        &[&prior, &length.to_be_bytes(), body],
    )
}

pub(super) struct FileAnchor {
    directory: PathBuf,
    name: String,
    context: [u8; 32],
    position: Position,
}
impl FileAnchor {
    fn create(
        directory: &Path,
        name: &str,
        prefix: &[u8],
        position: Position,
    ) -> Result<Self, Error> {
        let result = Self {
            directory: directory.to_owned(),
            name: name.to_owned(),
            context: hash(b"naome:state:anchor:context:v1\0", &[prefix]),
            position,
        };
        let mut file = durable_open_options()
            .write(true)
            .create_new(true)
            .open(directory.join(name))?;
        file.write_all(&result.encode(position))?;
        file.sync_all()?;
        sync_finality_file(directory, name)?;
        Ok(result)
    }
    fn open(directory: &Path, name: &str, prefix: &[u8]) -> Result<Self, Error> {
        let context = hash(b"naome:state:anchor:context:v1\0", &[prefix]);
        let mut file = File::open(directory.join(name))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((ANCHOR_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() != ANCHOR_BYTES || &bytes[..8] != ANCHOR_MAGIC || bytes[8..40] != context {
            return Err(Error::Invalid("anchor encoding or context"));
        }
        if bytes[80..] != hash(b"naome:state:anchor:checksum:v1\0", &[&bytes[..80]]) {
            return Err(Error::Invalid("anchor checksum"));
        }
        let sequence = u64::from_be_bytes(bytes[40..48].try_into().expect("fixed slice"));
        let digest = bytes[48..80].try_into().expect("fixed slice");
        Ok(Self {
            directory: directory.to_owned(),
            name: name.to_owned(),
            context,
            position: Position { sequence, digest },
        })
    }
    fn encode(&self, position: Position) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ANCHOR_BYTES);
        bytes.extend_from_slice(ANCHOR_MAGIC);
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&position.sequence.to_be_bytes());
        bytes.extend_from_slice(&position.digest);
        bytes.extend_from_slice(&hash(b"naome:state:anchor:checksum:v1\0", &[&bytes]));
        bytes
    }
}
impl Anchor for FileAnchor {
    fn position(&self) -> Position {
        self.position
    }
    fn advance(&mut self, prior: Position, next: Position) -> Result<(), Error> {
        if self.position != prior
            || next.sequence
                != prior
                    .sequence
                    .checked_add(1)
                    .ok_or(Error::Limit("anchor sequence"))?
        {
            return Err(Error::Invalid("anchor advance"));
        }
        let temporary_name = format!(
            "{}.next-{}-{}",
            self.name,
            next.sequence,
            std::process::id()
        );
        let temporary_path = self.directory.join(&temporary_name);
        #[cfg(test)]
        super::faults::check(
            &self.directory.join(&self.name),
            super::faults::Point::Create,
        )?;
        let mut temporary = durable_open_options()
            .write(true)
            .create_new(true)
            .open(&temporary_path)?;
        #[cfg(test)]
        super::faults::check(
            &self.directory.join(&self.name),
            super::faults::Point::Write,
        )?;
        temporary.write_all(&self.encode(next))?;
        #[cfg(test)]
        super::faults::check(&self.directory.join(&self.name), super::faults::Point::Sync)?;
        temporary.sync_all()?;
        #[cfg(test)]
        super::faults::check(
            &self.directory.join(&self.name),
            super::faults::Point::Rename,
        )?;
        #[cfg(windows)]
        atomicwrites::replace_atomic(&temporary_path, &self.directory.join(&self.name))?;
        #[cfg(not(windows))]
        std::fs::rename(&temporary_path, self.directory.join(&self.name))?;
        #[cfg(test)]
        super::faults::check(
            &self.directory.join(&self.name),
            super::faults::Point::DirectorySync,
        )?;
        sync_finality_file(&self.directory, &self.name)?;
        self.position = next;
        Ok(())
    }
}

#[cfg(test)]
#[path = "log_tests.rs"]
mod tests;

/// Replays an exact previously indexed prefix, preserving bounded reads even
/// when more complete frames follow it. The supplied digest must come from the
/// already verified selected log, never from an external checkpoint.
pub(super) fn prefix_replay(
    directory: &Path,
    name: &str,
    prefix: &[u8],
    limits: Limits,
    end: u64,
    position: Position,
    accept: impl FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let file = File::open(directory.join(name))?;
    let mut bounded = BoundedReader { file, end };
    let scan = scan(&mut bounded, prefix, limits, position, accept)?;
    if scan.tail || scan.end != end {
        return Err(Error::Invalid("selected prefix extent"));
    }
    Ok(())
}
struct BoundedReader {
    file: File,
    end: u64,
}
impl Read for BoundedReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let position = self.file.stream_position()?;
        let remaining = self.end.saturating_sub(position).min(bytes.len() as u64) as usize;
        self.file.read(&mut bytes[..remaining])
    }
}
impl Seek for BoundedReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        match position {
            SeekFrom::End(delta) => {
                let end = i128::from(self.end) + i128::from(delta);
                if end < 0 || end > i128::from(u64::MAX) {
                    return Err(std::io::Error::other("invalid bounded seek"));
                }
                self.file.seek(SeekFrom::Start(end as u64))
            }
            other => self.file.seek(other),
        }
    }
}
pub(super) fn prefix_position(prefix: &[u8]) -> Position {
    genesis_position(prefix)
}
pub(super) fn extend_position(
    prior: Position,
    end: u64,
    body: &[u8],
) -> Result<(Position, u64), Error> {
    let length = u32::try_from(body.len()).map_err(|_| Error::Limit("frame payload"))?;
    Ok((
        Position {
            sequence: prior
                .sequence
                .checked_add(1)
                .ok_or(Error::Limit("journal sequence"))?,
            digest: step_digest(prior.digest, length, body),
        },
        end.checked_add(FRAME_OVERHEAD)
            .and_then(|v| v.checked_add(u64::from(length)))
            .ok_or(Error::Limit("journal bytes"))?,
    ))
}
