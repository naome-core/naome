use naome_foundation::Formula;
use naome_proof::StatementId;
use sha2::{Digest, Sha256};

use crate::{state::persistent_map::PersistentMap, statement_id};

use super::{AssessmentLimits, Identity, RegisteredQuestion, RejectionReason};

/// The receiver's entire local registry with incremental canonical indexes.
/// Every record is checked at insertion; snapshots borrow the complete index
/// and its cached content fingerprint without scanning or copying records.
#[derive(Clone, Default)]
pub struct QuestionRegistry {
    records: PersistentMap<Identity, Formula>,
    statements: PersistentMap<StatementId, PersistentMap<Identity, ()>>,
    contents: PersistentMap<Identity, ()>,
    length: usize,
}

impl QuestionRegistry {
    pub const fn new() -> Self {
        Self {
            records: PersistentMap::new(),
            statements: PersistentMap::new(),
            contents: PersistentMap::new(),
            length: 0,
        }
    }

    /// Inserts a whole bounded record without replacing existing knowledge.
    /// Different records may bind the same formula; self-exemption never hides
    /// another record. There is no total registry cardinality/byte ceiling.
    pub fn insert(&mut self, entry: RegisteredQuestion<'_>) -> Result<(), RejectionReason> {
        let bytes = entry
            .formula
            .encode_canonical_with_node_limit(AssessmentLimits::MAXIMUM.formula_nodes)
            .map_err(|_| RejectionReason::InputLimit)?
            .0;
        if !entry.formula.is_closed() || self.records.contains_key(&entry.record) {
            return Err(RejectionReason::InvalidRegistry);
        }
        let length = self
            .length
            .checked_add(1)
            .ok_or(RejectionReason::ExecutionLimit)?;
        let statement = statement_id(&bytes);
        let mut bucket = self.statements.get(&statement).cloned().unwrap_or_default();
        if let Some((record, ())) = bucket.entries().next()
            && self.records.get(record) != Some(entry.formula)
        {
            return Err(RejectionReason::InvalidRegistry);
        }
        let mut hash = Sha256::new();
        hash.update(b"naome:local-question-record:v2\0");
        hash.update(entry.record);
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
        self.contents.insert(hash.finalize().into(), ());
        self.records.insert(entry.record, entry.formula.clone());
        bucket.insert(entry.record, ());
        self.statements.set(statement, bucket);
        self.length = length;
        Ok(())
    }

    pub const fn len(&self) -> usize {
        self.length
    }
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Binds every record identity and complete canonical formula, independent
    /// of arrival order. A clone's later insertion leaves the old root intact.
    pub fn identity(&self) -> Identity {
        let mut hash = Sha256::new();
        hash.update(b"naome:local-question-registry:v2\0");
        hash.update((self.length as u64).to_le_bytes());
        hash.update(self.contents.fingerprint());
        hash.finalize().into()
    }

    pub(super) fn get(&self, record: &Identity) -> Option<&Formula> {
        self.records.get(record)
    }

    pub(super) fn records_for(
        &self,
        statement: StatementId,
    ) -> impl Iterator<Item = Identity> + '_ {
        self.statements
            .get(&statement)
            .into_iter()
            .flat_map(PersistentMap::entries)
            .map(|(record, ())| *record)
    }

    /// Looks up canonical equality against the entire indexed registry.
    pub fn contains(&self, formula: &Formula) -> bool {
        let Ok((bytes, _)) =
            formula.encode_canonical_with_node_limit(AssessmentLimits::MAXIMUM.formula_nodes)
        else {
            return false;
        };
        self.records_for(statement_id(&bytes))
            .next()
            .is_some_and(|record| self.get(&record) == Some(formula))
    }
}
