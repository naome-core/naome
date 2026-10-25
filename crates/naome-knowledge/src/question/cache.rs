//! Byte-bounded LRU of complete, read-only decisions. No admission authority.
use super::*;
use std::collections::VecDeque;

#[derive(Default)]
pub(super) struct DecisionCache {
    entries: VecDeque<Box<Entry>>,
    bytes: usize,
}

struct Entry {
    decision: PrefilterDecision,
    bytes: usize,
}

impl DecisionCache {
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    pub(super) fn trim(&mut self, maximum: usize) {
        while self.bytes > maximum {
            let entry = self.entries.pop_front().expect("charged cache entry");
            self.bytes -= entry.bytes;
        }
        // The per-entry allowance covers at most four pointer slots. Release
        // excess capacity after eviction without reallocating on ordinary hits
        // or replacing one entry in an otherwise full cache.
        if self.entries.capacity() > self.entries.len().saturating_mul(4) {
            self.entries.shrink_to_fit();
        }
    }

    pub(super) fn get(
        &mut self,
        request: &AssessmentQuestion<'_>,
        snapshot: &KnowledgeSnapshot<'_>,
        policy: &PrefilterPolicy,
    ) -> Option<PrefilterDecision> {
        let position = self.entries.iter().position(|entry| {
            entry.decision.input == request.input_id()
                && entry.decision.matches_inputs(request, snapshot, policy)
        })?;
        let entry = self.entries.remove(position).expect("located cache entry");
        let decision = entry.decision.clone();
        self.entries.push_back(entry);
        Some(decision)
    }

    pub(super) fn insert(&mut self, decision: &PrefilterDecision, maximum: usize) {
        // Retaining a previous local world has no useful hit and wastes memory.
        self.entries.retain(|entry| {
            let retained = entry.decision.snapshot == decision.snapshot
                && entry.decision.policy == decision.policy
                && entry.decision.input != decision.input;
            if !retained {
                self.bytes -= entry.bytes;
            }
            retained
        });
        if decision.inconclusive() {
            self.trim(maximum);
            return;
        }
        // The fixed allowance covers allocator rounding and at most four
        // deque pointer slots per entry, including its first allocation.
        let bytes = std::mem::size_of::<Entry>()
            + 64
            + decision
                .deduction
                .as_ref()
                .map_or(0, retained_witness_bytes)
            + decision.equivalence.as_ref().map_or(0, |directions| {
                directions.iter().map(retained_witness_bytes).sum()
            });
        if bytes > maximum {
            self.trim(maximum);
            return;
        }
        self.trim(maximum - bytes);
        self.entries.push_back(Box::new(Entry {
            decision: decision.clone(),
            bytes,
        }));
        self.bytes += bytes;
    }
}

fn retained_witness_bytes(witness: &naome_checker::question::DeductionWitness) -> usize {
    witness.canonical_certificate().len() + std::mem::size_of_val(witness.original_proofs()) + 32
}

#[cfg(test)]
mod tests;
