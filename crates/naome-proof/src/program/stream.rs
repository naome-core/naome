//! Canonical program bytes and authenticated stream transitions. These rules
//! establish input integrity only, never mathematical validity or admission.
use super::{
    CHUNK_BYTES, CHUNK_RECORDS, Chunk, Command, Manifest, RECORD_BYTES, command_hash, stream_hash,
};
use serde::{Deserialize, Serialize};

pub const MANIFEST_BYTES: usize = 2048;

pub fn encode_command(command: &Command) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(command).map_err(|error| error.to_string())?;
    if bytes.len() > RECORD_BYTES {
        return Err("program command byte capacity".into());
    }
    Ok(bytes)
}

pub fn decode_command(bytes: &[u8]) -> Result<Command, String> {
    if bytes.len() > RECORD_BYTES {
        return Err("program command byte capacity".into());
    }
    let command = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if encode_command(&command)? != bytes {
        return Err("noncanonical program command".into());
    }
    Ok(command)
}

impl Manifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.commands == 0 || self.input_bytes == 0 {
            return Err("invalid program manifest".into());
        }
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MANIFEST_BYTES {
            return Err("program manifest byte capacity".into());
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MANIFEST_BYTES {
            return Err("program manifest byte capacity".into());
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if manifest.canonical_bytes()? != bytes {
            return Err("noncanonical program manifest".into());
        }
        Ok(manifest)
    }
}

/// Forward commitment to a sequence of canonical input records. The caller
/// obtains record bytes from encode_command/decode_command before appending.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Prefix {
    pub commands: u64,
    pub input_bytes: u64,
    pub hash: [u8; 32],
}
impl Prefix {
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > RECORD_BYTES {
            return Err("program command byte capacity".into());
        }
        let commands = self
            .commands
            .checked_add(1)
            .ok_or("program address exhausted")?;
        let input_bytes = self
            .input_bytes
            .checked_add(bytes.len() as u64)
            .ok_or("program byte width")?;
        *self = Self {
            commands,
            input_bytes,
            hash: command_hash(self.hash, bytes),
        };
        Ok(())
    }
}

/// Bounded chunk reconstruction shared by canonical storage and the evaluator.
/// Storage supplies rows; this owner checks their order, canonical bytes and hash.
pub struct ChunkReader {
    chunk: Chunk,
    records: usize,
    maximum: usize,
    bytes: usize,
    hash: [u8; 32],
}
impl ChunkReader {
    pub fn new(
        start: u64,
        previous: [u8; 32],
        records: usize,
        maximum: usize,
    ) -> Result<Self, String> {
        if records == 0 || records > CHUNK_RECORDS || maximum == 0 || maximum > CHUNK_BYTES {
            return Err("program chunk request capacity".into());
        }
        Ok(Self {
            chunk: Chunk {
                start,
                previous,
                next: [0; 32],
                records: Vec::new(),
            },
            records,
            maximum,
            bytes: 0,
            hash: previous,
        })
    }
    pub fn end(&self) -> u64 {
        self.chunk.start + self.chunk.records.len() as u64
    }
    /// False means this row belongs to the next chunk. No partial record is kept.
    pub fn push(&mut self, position: u64, bytes: &[u8], stored: [u8; 32]) -> Result<bool, String> {
        if position != self.end() || bytes.len() > RECORD_BYTES {
            return Err("program record order or width differs".into());
        }
        if self.chunk.records.len() == self.records
            || bytes.len() > self.maximum.saturating_sub(self.bytes)
        {
            if self.chunk.records.is_empty() {
                return Err("program record exceeds chunk budget".into());
            }
            return Ok(false);
        }
        let command = decode_command(bytes)?;
        let hash = command_hash(self.hash, bytes);
        if stored != hash {
            return Err("program input hash mismatch".into());
        }
        position.checked_add(1).ok_or("program address exhausted")?;
        self.bytes += bytes.len();
        self.hash = hash;
        self.chunk.records.push(command);
        Ok(true)
    }
    pub fn finish(mut self, available: u64, next: [u8; 32]) -> Result<Chunk, String> {
        if self.chunk.start > available
            || self.end() > available
            || (self.chunk.start < available && self.chunk.records.is_empty())
        {
            return Err("program input prefix missing".into());
        }
        self.chunk.next = next;
        Ok(self.chunk)
    }
}

/// Received prefix bound to both the forward hash and the manifest's reverse
/// commitment. It carries no checked-state flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub commands: u64,
    pub input_bytes: u64,
    pub hash: [u8; 32],
    pub remaining: [u8; 32],
}
pub struct PreparedRecord {
    pub position: u64,
    pub bytes: Vec<u8>,
    pub hash: [u8; 32],
    pub suffix: [u8; 32],
}
impl Progress {
    pub fn require_complete(&self, manifest: &Manifest) -> Result<(), String> {
        if self.commands != manifest.commands
            || self.input_bytes != manifest.input_bytes
            || self.hash != manifest.program_hash
            || self.remaining != [0; 32]
        {
            return Err("program input is incomplete or differs from manifest".into());
        }
        Ok(())
    }
    /// Prepare the complete authenticated transition before the storage owner
    /// writes a row. Failure leaves this progress and all storage unchanged.
    pub fn prepare_append(
        &self,
        manifest: &Manifest,
        chunk: &Chunk,
    ) -> Result<(Self, Vec<PreparedRecord>), String> {
        if chunk.records.is_empty() || chunk.records.len() > CHUNK_RECORDS {
            return Err("program chunk record capacity".into());
        }
        let mut total = 0usize;
        let mut records = Vec::with_capacity(chunk.records.len());
        for command in &chunk.records {
            let bytes = encode_command(command)?;
            total = total
                .checked_add(bytes.len())
                .ok_or("program chunk width")?;
            if total > CHUNK_BYTES {
                return Err("program chunk byte capacity".into());
            }
            records.push(PreparedRecord {
                position: 0,
                bytes,
                hash: [0; 32],
                suffix: [0; 32],
            });
        }
        let mut suffix = chunk.next;
        for record in records.iter_mut().rev() {
            suffix = stream_hash(&record.bytes, suffix);
            record.suffix = suffix;
        }
        if self.commands != chunk.start || self.hash != chunk.previous || self.remaining != suffix {
            return Err("program chunk authentication or prefix mismatch".into());
        }
        let end = self
            .commands
            .checked_add(records.len() as u64)
            .ok_or("program chunk cursor width")?;
        if end > manifest.commands || (end == manifest.commands && chunk.next != [0; 32]) {
            return Err("program chunk end mismatch".into());
        }
        let mut prefix = Prefix {
            commands: self.commands,
            input_bytes: self.input_bytes,
            hash: self.hash,
        };
        for (command, record) in chunk.records.iter().zip(&mut records) {
            if matches!(command, Command::Seal { .. }) && prefix.commands + 1 != manifest.commands {
                return Err("program seal precedes declared end".into());
            }
            record.position = prefix.commands;
            prefix.append(&record.bytes)?;
            record.hash = prefix.hash;
        }
        let progress = Self {
            commands: prefix.commands,
            input_bytes: prefix.input_bytes,
            hash: prefix.hash,
            remaining: chunk.next,
        };
        if progress.commands > manifest.commands || progress.input_bytes > manifest.input_bytes {
            return Err("program prefix exceeds manifest".into());
        }
        if progress.commands == manifest.commands {
            progress.require_complete(manifest)?;
        }
        Ok((progress, records))
    }
}

#[cfg(test)]
mod tests;
