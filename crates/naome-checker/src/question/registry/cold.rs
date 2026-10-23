//! Complete authenticated registry indexes with bounded traversal state.
//! Roots are created only by checked insertion, never loaded from persistence.
use super::*;
use crate::{
    ContextError, ContextStorage,
    state::disk_map::{DiskMap, Root},
};
use std::{borrow::Cow, sync::Arc};

#[derive(Clone)]
pub(super) struct DiskRegistry {
    pub(super) records: DiskMap,
    statements: DiskMap,
    pub(super) contents: DiskMap,
}
impl DiskRegistry {
    pub(super) fn new(storage: Arc<dyn ContextStorage>) -> Self {
        Self {
            records: DiskMap::new(storage.clone()),
            statements: DiskMap::new(storage.clone()),
            contents: DiskMap::new(storage),
        }
    }
    fn report<T>(&self, result: Result<T, ContextError>) -> Result<T, ContextError> {
        if let Err(error) = &result {
            self.records.storage().record_failure(error);
        }
        result
    }
    pub(super) fn has_record(&self, record: &Identity) -> Result<bool, ContextError> {
        self.report(self.records.contains_key(record))
    }
    pub(super) fn get(&self, record: &Identity) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        self.report((|| {
            let Some(metadata) = self.records.get(record)? else {
                return Ok(None);
            };
            if metadata.len() != 72 {
                return Err(ContextError::Corrupt);
            }
            let statement = StatementId::from_bytes(
                metadata[..32]
                    .try_into()
                    .map_err(|_| ContextError::Corrupt)?,
            );
            let address = metadata[32..64]
                .try_into()
                .map_err(|_| ContextError::Corrupt)?;
            let length = usize::try_from(u64::from_be_bytes(
                metadata[64..]
                    .try_into()
                    .map_err(|_| ContextError::Corrupt)?,
            ))
            .map_err(|_| ContextError::Corrupt)?;
            if length > naome_foundation::FORMULA_MAX_BYTES {
                return Err(ContextError::Corrupt);
            }
            let bytes = self.records.storage().read(address, length)?;
            if bytes.len() != length
                || formula_address(&bytes) != address
                || statement_id(&bytes) != statement
            {
                return Err(ContextError::Corrupt);
            }
            let formula = Formula::decode_canonical_with_node_limit(
                &bytes,
                AssessmentLimits::MAXIMUM.formula_nodes,
            )
            .map_err(|_| ContextError::Corrupt)?
            .0;
            if !formula.is_closed() {
                return Err(ContextError::Corrupt);
            }
            Ok(Some(Cow::Owned(formula)))
        })())
    }
    fn bucket(&self, statement: StatementId) -> Result<DiskMap, ContextError> {
        let value = self.statements.get(statement.as_bytes())?;
        let root = match value.as_deref() {
            None => None,
            Some(bytes) if bytes.len() == 64 => Some(Root {
                address: bytes[..32].try_into().map_err(|_| ContextError::Corrupt)?,
                fingerprint: bytes[32..].try_into().map_err(|_| ContextError::Corrupt)?,
            }),
            _ => return Err(ContextError::Corrupt),
        };
        Ok(DiskMap::from_root(self.records.storage(), root))
    }
    pub(super) fn records_for(
        &self,
        statement: StatementId,
    ) -> Result<Box<dyn Iterator<Item = Result<Identity, ContextError>>>, ContextError> {
        let bucket = self.report(self.bucket(statement))?;
        let storage = self.records.storage();
        Ok(Box::new(bucket.entries().map(move |entry| {
            let result = entry.and_then(|(key, value)| {
                if value.is_empty() {
                    Ok(key)
                } else {
                    Err(ContextError::Corrupt)
                }
            });
            if let Err(error) = &result {
                storage.record_failure(error)
            }
            result
        })))
    }
    pub(super) fn insert(
        &mut self,
        entry: RegisteredQuestion<'_>,
        bytes: &[u8],
        content: Identity,
    ) -> Result<(), ContextError> {
        let result = (|| {
            if self.records.contains_key(&entry.record)? {
                return Err(ContextError::Corrupt);
            }
            let statement = statement_id(bytes);
            let mut bucket = self.bucket(statement)?;
            if let Some(first) = bucket.entries().next() {
                let (record, _) = first?;
                if self.get(&record)?.as_deref() != Some(entry.formula) {
                    return Err(ContextError::Corrupt);
                }
            }
            let address = formula_address(bytes);
            self.records.storage().write(address, bytes)?;
            let mut metadata = Vec::with_capacity(72);
            metadata.extend_from_slice(statement.as_bytes());
            metadata.extend_from_slice(&address);
            metadata.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            let mut next = self.clone();
            next.records.insert(entry.record, &metadata)?;
            bucket.insert(entry.record, &[])?;
            let root = bucket.root().ok_or(ContextError::Corrupt)?;
            let mut encoded = Vec::with_capacity(64);
            encoded.extend_from_slice(&root.address);
            encoded.extend_from_slice(&root.fingerprint);
            next.statements.set(*statement.as_bytes(), &encoded)?;
            next.contents.insert(content, &[])?;
            Ok(next)
        })();
        *self = self.report(result)?;
        Ok(())
    }
}
fn formula_address(bytes: &[u8]) -> Identity {
    let mut hash = Sha256::new();
    hash.update(b"naome:registered-question-formula:v1\0");
    hash.update(bytes);
    hash.finalize().into()
}
