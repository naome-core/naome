//! Key-only Patricia fingerprints. Storage summaries are not checked contexts.
use crate::ContextError;
use naome_proof::ProofId;
use sha2::{Digest, Sha256};

pub(crate) fn leaf(key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naome:checked-map:leaf:v1\0");
    hash.update(key);
    hash.finalize().into()
}
pub(crate) fn branch(bit: u8, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naome:checked-map:branch:v1\0");
    hash.update([bit]);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

/// Streaming, order-checked reconstruction using at most 256 pending branches.
/// The digest says nothing about mathematical validity or proof admission.
#[derive(Default, Clone)]
pub struct ProofSetFingerprint {
    previous: Option<[u8; 32]>,
    pending: Vec<(u8, [u8; 32])>,
    current: [u8; 32],
}
impl ProofSetFingerprint {
    pub fn push(&mut self, id: ProofId) -> Result<(), ContextError> {
        let key = *id.as_bytes();
        if let Some(previous) = self.previous {
            if previous >= key {
                return Err(ContextError::Corrupt);
            }
            let bit = previous
                .iter()
                .zip(key)
                .enumerate()
                .find_map(|(i, (left, right))| {
                    let difference = left ^ right;
                    (difference != 0).then(|| (i * 8 + difference.leading_zeros() as usize) as u8)
                })
                .ok_or(ContextError::Corrupt)?;
            while self.pending.last().is_some_and(|(level, _)| *level >= bit) {
                let (level, left) = self.pending.pop().expect("pending branch");
                self.current = branch(level, left, self.current);
            }
            self.pending.push((bit, self.current));
        }
        self.current = leaf(&key);
        self.previous = Some(key);
        Ok(())
    }
    pub fn finish(mut self) -> [u8; 32] {
        while let Some((bit, left)) = self.pending.pop() {
            self.current = branch(bit, left, self.current);
        }
        self.current
    }
}

#[cfg(test)]
mod tests;
