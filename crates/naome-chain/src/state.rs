//! Canonical complete application records and exact-parent deterministic replay.
//!
//! Ledger owns execution rules. This module owns the record encoding, identity,
//! and the comparison of claimed effects with a freshly executed successor.
//! Neither provisional preparation nor decoding grants finality.

use naome_ledger::{
    ResearchError, ResearchState, authentication::SignedOperation, time::TimeCertificate,
};
use sha2::{Digest, Sha256};
mod codec;
mod finalized;
mod record;
pub use finalized::FinalizedStateRecord;
pub use record::StateRecord;

fn hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

/// Chain preparation/replay for a complete ledger state. Implemented here so
/// the ledger cannot independently create an authoritative history encoding.
pub trait StateRecordExecution {
    fn prepare_record(
        &self,
        time: TimeCertificate,
        operations: Vec<SignedOperation>,
    ) -> Result<StateTransition, ResearchError>;
    fn validate_record(&self, record: &StateRecord) -> Result<StateTransition, ResearchError>;
}
impl StateRecordExecution for ResearchState {
    fn prepare_record(
        &self,
        time: TimeCertificate,
        operations: Vec<SignedOperation>,
    ) -> Result<StateTransition, ResearchError> {
        let execution = self.execute(time, operations)?;
        let record = StateRecord::new(
            self,
            execution.state(),
            execution.time_certificate().clone(),
            execution.operations().to_vec(),
            execution.effects().to_vec(),
        )?;
        let next = execution.bind_record(record.id());
        Ok(StateTransition { record, next })
    }

    fn validate_record(&self, record: &StateRecord) -> Result<StateTransition, ResearchError> {
        if record.parent() != self.head()
            || record.height()
                != self
                    .height()
                    .checked_add(1)
                    .ok_or(ResearchError::Overflow)?
            || record.previous_state() != self.commitment()
        {
            return Err(ResearchError::Invalid("state record parent"));
        }
        let transition = self.prepare_record(
            record.time_certificate().clone(),
            record.operations().to_vec(),
        )?;
        if transition.record.encode()? != record.encode()? {
            return Err(ResearchError::Invalid("state record effects or successor"));
        }
        Ok(transition)
    }
}

/// A checked canonical record and its provisional successor. Consensus evidence
/// and durable installation are still required before external publication.
pub struct StateTransition {
    record: StateRecord,
    next: ResearchState,
}
impl StateTransition {
    pub fn record(&self) -> &StateRecord {
        &self.record
    }
    pub fn state(&self) -> &ResearchState {
        &self.next
    }
    pub fn into_state(self) -> ResearchState {
        self.next
    }
    pub fn into_parts(self) -> (StateRecord, ResearchState) {
        (self.record, self.next)
    }
}

#[cfg(test)]
mod receipt_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
