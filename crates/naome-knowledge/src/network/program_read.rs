//! The immutable portion admitted by one outgoing program read. Calibration
//! affects the next request, never the interpretation of an in-flight reply.
use super::*;

pub(super) struct ProgramRead {
    pub(super) root: ArtifactId,
    pub(super) id: ArtifactId,
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
    pub(super) fn check_reply(
        &self,
        root: [u8; 32],
        id: [u8; 32],
        chunk: &naome_proof::program::Chunk,
    ) -> Result<(), crate::InputFault> {
        if root != *self.root.as_bytes() {
            return Err(crate::InputFault::ProgramReplyRoot);
        }
        if id != *self.id.as_bytes() {
            return Err(crate::InputFault::ProgramReplyId);
        }
        if chunk.start != self.start {
            return Err(crate::InputFault::ProgramReplyStart);
        }
        if chunk.records.is_empty() {
            return Err(crate::InputFault::ProgramReplyEmpty);
        }
        if chunk.records.len() > self.limit {
            return Err(crate::InputFault::ProgramReplyLimit);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
