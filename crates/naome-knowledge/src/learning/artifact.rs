//! Typed local binary checkpoints. The job journal remains their sole owner.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
}
pub(crate) trait ArtifactIo {
    fn read(&mut self, blob: &Blob, index: usize) -> Result<Vec<u8>, String>;
    fn write(&mut self, blob: &Blob, index: usize, bytes: Vec<u8>) -> Result<(), String>;
}
pub(crate) fn load<I: ArtifactIo + ?Sized>(io: &mut I, blob: &Blob) -> Result<Vec<u8>, String> {
    blob.validate()?;
    let mut bytes = Vec::with_capacity(blob.bytes);
    for i in 0..blob.chunks() {
        let chunk = io.read(blob, i)?;
        if chunk.len() != blob.chunk_len(i)? {
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
    for (index, chunk) in bytes
        .chunks(crate::resources::limits().native_model_chunk_bytes)
        .enumerate()
    {
        io.write(&blob, index, chunk.to_vec())?;
    }
    Ok(blob)
}
