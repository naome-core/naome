//! Typed local binary checkpoints. The job journal remains their sole owner.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ops::Range;

pub(crate) const CHUNKS_PER_TRANSFER: usize = 3;
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
    pub fn validate(&self) -> Result<(), crate::Error> {
        crate::object::id_bytes(&self.sha256)?;
        if self.bytes == 0 || self.bytes > crate::resources::limits().native_model_blob_bytes {
            return Err(crate::ResearchFailure::ModelBlobCapacity.into());
        }
        Ok(())
    }
    pub fn chunks(&self) -> usize {
        self.bytes
            .div_ceil(crate::resources::limits().native_model_chunk_bytes)
    }
    pub fn chunk_len(&self, index: usize) -> Result<usize, crate::Error> {
        self.validate()?;
        if index >= self.chunks() {
            return Err(crate::ResearchFailure::ModelChunkIndex.into());
        }
        Ok(
            (self.bytes - index * crate::resources::limits().native_model_chunk_bytes)
                .min(crate::resources::limits().native_model_chunk_bytes),
        )
    }
    pub fn key(&self, index: usize) -> String {
        format!("{}:{index:06}", self.sha256)
    }
    /// Group durable IO acknowledgements within the existing wire bound.
    /// Chunks retain their individual identities, lengths and lifetime charges.
    pub fn ranges(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        (0..self.chunks())
            .step_by(CHUNKS_PER_TRANSFER)
            .map(|start| start..(start + CHUNKS_PER_TRANSFER).min(self.chunks()))
    }
    pub fn range_len(&self, range: &Range<usize>) -> Result<usize, crate::Error> {
        self.validate()?;
        if range.start >= range.end
            || range.end - range.start > CHUNKS_PER_TRANSFER
            || range.end > self.chunks()
        {
            return Err(crate::ResearchFailure::ModelChunkRange.into());
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
    ) -> Result<super::history::Receipt, crate::Error> {
        Err(crate::WorkerFailure::HistoryUnsupported.into())
    }
    fn read(&mut self, blob: &Blob, range: Range<usize>) -> Result<Vec<u8>, crate::Error>;
    fn write(
        &mut self,
        blob: &Blob,
        range: Range<usize>,
        bytes: Vec<u8>,
    ) -> Result<(), crate::Error>;
}
pub(crate) fn load<I: ArtifactIo + ?Sized>(
    io: &mut I,
    blob: &Blob,
) -> Result<Vec<u8>, crate::Error> {
    load_with(blob, |blob, range| io.read(blob, range))
}

pub(super) fn load_with(
    blob: &Blob,
    mut read: impl FnMut(&Blob, Range<usize>) -> Result<Vec<u8>, crate::Error>,
) -> Result<Vec<u8>, crate::Error> {
    blob.validate()?;
    let mut bytes = Vec::with_capacity(blob.bytes);
    for range in blob.ranges() {
        let length = blob.range_len(&range)?;
        let chunk = read(blob, range)?;
        if chunk.len() != length {
            return Err(crate::ResearchFailure::NativeModelChunkLengthDiffers.into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if Blob::of(&bytes) != *blob {
        return Err(crate::ResearchFailure::NativeModelHashMismatch.into());
    }
    Ok(bytes)
}
pub(crate) fn save<I: ArtifactIo + ?Sized>(io: &mut I, bytes: &[u8]) -> Result<Blob, crate::Error> {
    let blob = Blob::of(bytes);
    blob.validate()?;
    let chunk = crate::resources::limits().native_model_chunk_bytes;
    for range in blob.ranges() {
        let data = bytes[range.start * chunk..(range.end * chunk).min(bytes.len())].to_vec();
        io.write(&blob, range, data)?;
    }
    Ok(blob)
}
