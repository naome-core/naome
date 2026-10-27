//! Bounded, operation-local authenticated reads; residency grants no validity.
use super::*;
use naome_proof::{DefinitionResolution, DefinitionResolver};
use std::{
    cell::{Cell, OnceCell, RefCell},
    collections::BTreeMap,
};

pub(crate) struct ReadContext<'a> {
    source: &'a dyn ContextView,
    proofs: RefCell<BTreeMap<ProofId, Option<ProofHeader>>>,
    statements: RefCell<BTreeMap<StatementId, Option<StatementHeader>>>,
    parsed: Vec<OnceCell<Parsed>>,
    limits: ReadCacheLimits,
    parsed_bytes: Cell<usize>,
}
enum Parsed {
    Formula(StatementId, usize, Formula),
    Definition(DefinitionId, DefinitionCertificate),
}
impl<'a> ReadContext<'a> {
    pub(crate) fn new(source: &'a dyn ContextView) -> Self {
        Self {
            source,
            proofs: RefCell::new(BTreeMap::new()),
            statements: RefCell::new(BTreeMap::new()),
            parsed: (0..source.read_cache_limits().entries)
                .map(|_| OnceCell::new())
                .collect(),
            limits: source.read_cache_limits(),
            parsed_bytes: Cell::new(source.read_cache_limits().entries * 512),
        }
    }
}
impl sealed::Sealed for ReadContext<'_> {}
impl DefinitionResolver for ReadContext<'_> {
    fn resolve_definition(
        &self,
        id: DefinitionId,
    ) -> Result<Option<DefinitionResolution<'_>>, naome_proof::DefinitionAccessError> {
        Ok(self
            .definition_certificate(id)
            .map_err(naome_proof::DefinitionAccessError::from)?
            .map(|definition| match definition {
                Cow::Borrowed(definition) => {
                    DefinitionResolution::new(definition.relation_arity(), definition.body())
                }
                Cow::Owned(definition) => definition.resolution(),
            }))
    }
}
impl ContextView for ReadContext<'_> {
    fn read_cache_limits(&self) -> ReadCacheLimits {
        self.limits
    }
    fn snapshot_id(&self) -> [u8; 32] {
        self.source.snapshot_id()
    }
    fn contains_artifact(&self, id: ArtifactId) -> Result<bool, ContextError> {
        self.source.contains_artifact(id)
    }
    fn program_source(&self, id: ProofId) -> Result<Option<ProgramSource>, ContextError> {
        self.source.program_source(id)
    }
    fn proof_header(&self, id: ProofId) -> Result<Option<ProofHeader>, ContextError> {
        if let Some(header) = self.proofs.borrow().get(&id) {
            return Ok(*header);
        }
        let header = self.source.proof_header(id)?;
        let mut cache = self.proofs.borrow_mut();
        if cache.len() == self.limits.entries {
            cache.clear();
        }
        if self.limits.entries > 0 {
            cache.insert(id, header);
        }
        Ok(header)
    }
    fn statement_header(&self, id: StatementId) -> Result<Option<StatementHeader>, ContextError> {
        if let Some(header) = self.statements.borrow().get(&id) {
            return Ok(*header);
        }
        let header = self.source.statement_header(id)?;
        let mut cache = self.statements.borrow_mut();
        if cache.len() == self.limits.entries {
            cache.clear();
        }
        if self.limits.entries > 0 {
            cache.insert(id, header);
        }
        Ok(header)
    }
    fn statement_formula(
        &self,
        id: StatementId,
        maximum: usize,
    ) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        if let Some((length, formula)) = self.cached(id) {
            if *length > maximum {
                return Err(ContextError::Limit);
            }
            return Ok(Some(Cow::Borrowed(formula)));
        }
        let header = self.statements.borrow().get(&id).copied().flatten();
        let formula = match header {
            Some(header) => self
                .source
                .statement_formula_from_header(id, header, maximum)?,
            None => self.source.statement_formula(id, maximum)?,
        };
        let length = match (&formula, header) {
            (_, Some(header)) => header.length,
            (Some(formula), _) => formula
                .encode_canonical()
                .map_err(|_| ContextError::Corrupt)?
                .len(),
            _ => return Ok(None),
        };
        self.remember(id, length, formula)
    }
    fn proof_formula(
        &self,
        header: ProofHeader,
        maximum: usize,
    ) -> Result<Option<Cow<'_, Formula>>, ContextError> {
        if self.cached(header.statement).is_some() {
            return self.statement_formula(header.statement, maximum);
        }
        let formula = self.source.proof_formula(header, maximum)?;
        self.remember(header.statement, header.length, formula)
    }
    fn bucket(
        &self,
        kind: BucketKind,
        target: StatementId,
    ) -> Result<StatementCursor<'_>, ContextError> {
        self.source.bucket(kind, target)
    }
    fn definition_certificate(
        &self,
        id: DefinitionId,
    ) -> Result<Option<Cow<'_, DefinitionCertificate>>, ContextError> {
        for parsed in self.parsed.iter().filter_map(OnceCell::get) {
            if let Parsed::Definition(cached, definition) = parsed
                && *cached == id
            {
                return Ok(Some(Cow::Borrowed(definition)));
            }
        }
        let Some(definition) = self.source.definition_certificate(id)? else {
            return Ok(None);
        };
        if matches!(&definition, Cow::Borrowed(_)) {
            return Ok(Some(definition));
        }
        let charge = definition
            .canonical_bytes()
            .len()
            .checked_mul(64)
            .and_then(|n| n.checked_add(512))
            .ok_or(ContextError::Limit)?;
        if let Some(slot) = self.available_slot(charge) {
            let parsed = slot.get_or_init(|| Parsed::Definition(id, definition.into_owned()));
            self.parsed_bytes.set(self.parsed_bytes.get() + charge);
            let Parsed::Definition(_, definition) = parsed else {
                unreachable!()
            };
            return Ok(Some(Cow::Borrowed(definition)));
        }
        Ok(Some(definition))
    }
}
impl ReadContext<'_> {
    fn cached(&self, id: StatementId) -> Option<(&usize, &Formula)> {
        self.parsed
            .iter()
            .filter_map(OnceCell::get)
            .find_map(|parsed| match parsed {
                Parsed::Formula(cached, length, formula) if *cached == id => {
                    Some((length, formula))
                }
                _ => None,
            })
    }
    fn available_slot(&self, charge: usize) -> Option<&OnceCell<Parsed>> {
        if self
            .parsed_bytes
            .get()
            .checked_add(charge)
            .is_some_and(|n| n <= self.limits.bytes)
        {
            self.parsed.iter().find(|slot| slot.get().is_none())
        } else {
            None
        }
    }
    fn remember<'s>(
        &'s self,
        id: StatementId,
        length: usize,
        formula: Option<Cow<'s, Formula>>,
    ) -> Result<Option<Cow<'s, Formula>>, ContextError> {
        let Some(formula) = formula else {
            return Ok(None);
        };
        if matches!(&formula, Cow::Borrowed(_)) {
            return Ok(Some(formula));
        }
        let charge = length
            .checked_mul(64)
            .and_then(|n| n.checked_add(512))
            .ok_or(ContextError::Limit)?;
        if let Some(slot) = self.available_slot(charge) {
            // OnceCell slots never move or evict within this operation, so warm
            // consumers borrow the decoded tree without another deep clone.
            let Parsed::Formula(_, _, formula) =
                slot.get_or_init(|| Parsed::Formula(id, length, formula.into_owned()))
            else {
                unreachable!()
            };
            self.parsed_bytes.set(self.parsed_bytes.get() + charge);
            return Ok(Some(Cow::Borrowed(formula)));
        }
        Ok(Some(Cow::Owned(formula.into_owned())))
    }
}
