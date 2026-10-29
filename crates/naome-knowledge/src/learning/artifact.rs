//! Typed local binary checkpoints. The job journal remains their sole owner.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ops::Range;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Blob {
    pub sha256: String,
    pub bytes: usize,
}
impl Blob {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            sha256: crate::hex(&Sha256::digest(bytes)),
            bytes: bytes.len(),
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        crate::object::id_bytes(&self.sha256)?;
        if self.bytes == 0 || self.bytes > crate::resources::limits().native_model_blob_bytes {
            return Err("native model blob capacity".into());
        }
        Ok(())
    }
    pub fn chunks(&self) -> usize {
        self.bytes
            .div_ceil(crate::resources::limits().native_model_chunk_bytes)
    }
    pub fn chunk_len(&self, index: usize) -> Result<usize, String> {
        self.validate()?;
        if index >= self.chunks() {
            return Err("native model chunk index".into());
        }
        Ok(
            (self.bytes - index * crate::resources::limits().native_model_chunk_bytes)
                .min(crate::resources::limits().native_model_chunk_bytes),
        )
    }
    pub fn key(&self, index: usize) -> String {
        format!("{}:{index:06}", self.sha256)
    }
    /// At most two existing chunks share one durable IO acknowledgement. The
    /// chunk identities, individual lengths and lifetime charges stay exact.
    pub fn ranges(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        (0..self.chunks())
            .step_by(2)
            .map(|start| start..(start + 2).min(self.chunks()))
    }
    pub fn range_len(&self, range: &Range<usize>) -> Result<usize, String> {
        self.validate()?;
        if range.start >= range.end || range.end - range.start > 2 || range.end > self.chunks() {
            return Err("native model chunk range".into());
        }
        range.clone().map(|index| self.chunk_len(index)).sum()
    }
}
pub(crate) trait ArtifactIo {
    /// Only a separate source-owner process adds CPU beyond this worker's meter.
    fn external_history_cpu(&self) -> bool {
        false
    }

    fn history(
        &mut self,
        _request: &super::history::Request,
    ) -> Result<super::history::Receipt, String> {
        Err("artifact owner cannot provide admitted history".into())
    }
    fn read(&mut self, blob: &Blob, range: Range<usize>) -> Result<Vec<u8>, String>;
    fn write(&mut self, blob: &Blob, range: Range<usize>, bytes: Vec<u8>) -> Result<(), String>;
}
pub(crate) fn load<I: ArtifactIo + ?Sized>(io: &mut I, blob: &Blob) -> Result<Vec<u8>, String> {
    blob.validate()?;
    let mut bytes = Vec::with_capacity(blob.bytes);
    for range in blob.ranges() {
        let length = blob.range_len(&range)?;
        let chunk = io.read(blob, range)?;
        if chunk.len() != length {
            return Err("native model chunk length differs".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if Blob::of(&bytes) != *blob {
        return Err("native model checkpoint hash differs".into());
    }
    Ok(bytes)
}
pub(crate) fn save<I: ArtifactIo + ?Sized>(io: &mut I, bytes: &[u8]) -> Result<Blob, String> {
    let blob = Blob::of(bytes);
    blob.validate()?;
    let chunk = crate::resources::limits().native_model_chunk_bytes;
    for range in blob.ranges() {
        let data = bytes[range.start * chunk..(range.end * chunk).min(bytes.len())].to_vec();
        io.write(&blob, range, data)?;
    }
    Ok(blob)
}
