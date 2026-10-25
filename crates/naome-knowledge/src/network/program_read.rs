//! The immutable portion admitted by one outgoing program read. Calibration
//! affects the next request, never the interpretation of an in-flight reply.
use super::*;

pub(super) struct ProgramRead {
    pub(super) root: ProofId,
    pub(super) id: ProofId,
    pub(super) start: u64,
    pub(super) limit: usize,
}

impl ProgramRead {
    pub(super) fn body(&self) -> Body {
        Body::ProgramGet {
            root: *self.root.as_bytes(),
            id: *self.id.as_bytes(),
            start: self.start,
            limit: self.limit,
        }
    }

    /// Routing and admission only. The store still authenticates the chunk
    /// chain and canonical commands before accepting any payload bytes.
    pub(super) fn matches_reply(
        &self,
        root: [u8; 32],
        id: [u8; 32],
        chunk: &naome_proof::program::Chunk,
    ) -> bool {
        root == *self.root.as_bytes()
            && id == *self.id.as_bytes()
            && chunk.start == self.start
            && !chunk.records.is_empty()
            && chunk.records.len() <= self.limit
    }
}

#[cfg(test)]
mod tests;
