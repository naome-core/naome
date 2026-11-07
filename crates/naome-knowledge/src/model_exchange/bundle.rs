use super::{Blob, Registration};
use crate::{learning::ArtifactIo, resources::MemoryLease};
use std::{ops::Range, sync::Arc};

/// A bounded in-memory snapshot. Partial downloads cannot become a bundle.
pub(crate) struct Bundle {
    pub(crate) registration: Registration,
    parts: Vec<Vec<u8>>,
    _memory: Arc<MemoryLease>,
}

impl Bundle {
    pub(crate) fn reserve(registration: &Registration) -> Result<Arc<MemoryLease>, String> {
        registration.validate()?;
        let bytes = registration.model.blobs().map(|b| b.bytes).sum::<usize>();
        MemoryLease::acquire(bytes).map_err(|e| e.to_string())
    }

    pub(crate) fn new(
        registration: Registration,
        parts: Vec<Vec<u8>>,
        memory: Arc<MemoryLease>,
    ) -> Result<Self, String> {
        if registration.model.blobs().count() != parts.len()
            || registration
                .model
                .blobs()
                .zip(&parts)
                .any(|(blob, bytes)| Blob::of(bytes) != *blob)
        {
            return Err("model transfer hash or length differs".into());
        }
        Ok(Self {
            registration,
            parts,
            _memory: memory,
        })
    }

    pub(crate) fn part(&self, blob: &Blob) -> Option<&[u8]> {
        self.registration
            .model
            .blobs()
            .zip(&self.parts)
            .find_map(|(expected, bytes)| (expected == blob).then_some(bytes.as_slice()))
    }

    pub(super) fn parts(&self) -> impl Iterator<Item = &[u8]> {
        self.parts.iter().map(Vec::as_slice)
    }
}

pub(super) struct Artifacts<'a>(pub(super) &'a Bundle, pub(super) &'a Bundle);

impl ArtifactIo for Artifacts<'_> {
    fn read(&mut self, blob: &Blob, range: Range<usize>) -> Result<Vec<u8>, String> {
        let length = blob.range_len(&range)?;
        let offset = range.start * crate::resources::limits().native_model_chunk_bytes;
        self.0
            .part(blob)
            .or_else(|| self.1.part(blob))
            .and_then(|bytes| bytes.get(offset..offset + length))
            .map(<[u8]>::to_vec)
            .ok_or("reference artifact range missing".into())
    }

    fn write(&mut self, _: &Blob, _: Range<usize>, _: Vec<u8>) -> Result<(), String> {
        Err("reference evaluator cannot write a checkpoint".into())
    }
}
