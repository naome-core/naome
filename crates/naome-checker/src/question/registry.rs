use naome_foundation::Formula;
use naome_proof::StatementId;
use sha2::{Digest, Sha256};

use crate::{state::persistent_map::PersistentMap, statement_id};

use super::{AssessmentLimits, Identity, RegisteredQuestion, RejectionReason};
use crate::{ContextError, ContextStorage};
use std::{borrow::Cow, sync::Arc};
mod cold;

/// The receiver's entire local registry with incremental canonical indexes.
/// Every record is checked at insertion; snapshots borrow the complete index
/// and its cached content fingerprint without scanning or copying records.
#[derive(Clone, Default)]
pub struct QuestionRegistry {
    records: PersistentMap<Identity, Formula>,
    statements: PersistentMap<StatementId, PersistentMap<Identity, ()>>,
    contents: PersistentMap<Identity, ()>,
    length: usize,
    cold: Option<cold::DiskRegistry>,
}

impl QuestionRegistry {
    pub const fn new() -> Self {
        Self {
            records: PersistentMap::new(),
            statements: PersistentMap::new(),
            contents: PersistentMap::new(),
            length: 0,
            cold: None,
        }
    }

    /// Rebuild a complete checked registry on disposable authenticated storage.
    /// The caller must replay every canonical source; persisted roots grant no validity.
    pub fn with_storage(storage: Arc<dyn ContextStorage>) -> Self {
        Self {
            cold: Some(cold::DiskRegistry::new(storage)),
            ..Self::new()
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
        let duplicate = match &self.cold {
            Some(cold) => cold
                .has_record(&entry.record)
                .map_err(|_| RejectionReason::InvalidRegistry)?,
            None => self.records.contains_key(&entry.record),
        };
        if !entry.formula.is_closed() || duplicate {
            return Err(RejectionReason::InvalidRegistry);
        }
        let length = self
            .length
            .checked_add(1)
            .ok_or(RejectionReason::ExecutionLimit)?;
        let mut hash = Sha256::new();
        hash.update(b"naome:local-question-record:v2\0");
        hash.update(entry.record);
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(&bytes);
        let content: Identity = hash.finalize().into();
        if let Some(cold) = &mut self.cold {
            cold.insert(entry, &bytes, content)
                .map_err(|_| RejectionReason::InvalidRegistry)?;
            self.length = length;
            return Ok(());
        }
        let statement = statement_id(&bytes);
        let mut bucket = self.statements.get(&statement).cloned().unwrap_or_default();
        if let Some((record, ())) = bucket.entries().next()
            && self.records.get(record) != Some(entry.formula)
        {
            return Err(RejectionReason::InvalidRegistry);
        }
        self.contents.insert(content, ());
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
        hash.update(self.cold.as_ref().map_or_else(
            || self.contents.fingerprint(),
            |cold| cold.contents.fingerprint(),
        ));
        hash.finalize().into()
    }

    pub(super) fn get(&self, record: &Identity) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        match &self.cold {
            Some(cold) => cold.get(record),
            None => Ok(self.records.get(record).map(Cow::Borrowed)),
        }
    }

    pub(super) fn records_for(
        &self,
        statement: StatementId,
    ) -> Result<Box<dyn Iterator<Item = Result<Identity, ContextError>> + '_>, ContextError> {
        match &self.cold {
            Some(cold) => cold.records_for(statement),
            None => Ok(Box::new(
                self.statements
                    .get(&statement)
                    .into_iter()
                    .flat_map(PersistentMap::entries)
                    .map(|(record, ())| Ok(*record)),
            )),
        }
    }

    /// Exact canonical equality against the entire registry; errors are never absence.
    pub fn contains(&self, formula: &Formula) -> Result<bool, ContextError> {
        let bytes = formula
            .encode_canonical_with_node_limit(AssessmentLimits::MAXIMUM.formula_nodes)
            .map_err(|_| ContextError::Limit)?
            .0;
        let mut records = self.records_for(statement_id(&bytes))?;
        match records.next() {
            Some(record) => Ok(self.get(&record?)?.as_deref() == Some(formula)),
            None => Ok(false),
        }
    }
}
