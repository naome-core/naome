//! Cited conclusions retain checker authority and are imported in disk-backed
//! quanta. Persisted results and imported-node caches grant no restart trust.
use super::*;
use crate::context::{ProgramNodes, ProgramRepresentation};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramDependency {
    pub(crate) proof: ProofId,
    pub(crate) statement: StatementId,
    pub(crate) derivation: DerivationId,
}
impl ProgramDependency {
    pub const fn proof_id(self) -> ProofId {
        self.proof
    }
}

impl CheckedProgram {
    pub fn definition_dependencies_after(
        &self,
        after: Option<naome_proof::DefinitionId>,
        limit: usize,
    ) -> Result<Vec<naome_proof::DefinitionId>, Error> {
        self.engine.live()?;
        if limit == 0 || limit > 4096 {
            return Err("program dependency page capacity".into());
        }
        let mut query = sql(self
            .engine
            .connection
            .prepare_cached("SELECT id FROM checked_definition WHERE id>?1 ORDER BY id LIMIT ?2"))?;
        let mut rows = sql(query.query(params![
            after.map(|id| id.as_bytes().to_vec()).unwrap_or_default(),
            limit as i64
        ]))?;
        let mut result = Vec::with_capacity(limit);
        while let Some(row) = sql(rows.next())? {
            let id: Vec<u8> = sql(row.get(0))?;
            result.push(naome_proof::DefinitionId::from_bytes(
                id.try_into().map_err(|_| crate::ContextError::Corrupt)?,
            ));
        }
        Ok(result)
    }
    pub fn references_definition(&self, id: naome_proof::DefinitionId) -> Result<bool, Error> {
        self.engine.live()?;
        sql(self.engine.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM checked_definition WHERE id=?1)",
            [id.as_bytes().as_slice()],
            |row| row.get(0),
        ))
    }

    /// Complete ascending dependency pages from this evaluator's actual checks.
    /// A page bound limits residency, never total program dependency count.
    pub fn dependencies_after(
        &self,
        after: Option<ProofId>,
        limit: usize,
    ) -> Result<Vec<ProgramDependency>, Error> {
        self.engine.live()?;
        if limit == 0 || limit > 4096 {
            return Err("program dependency page capacity".into());
        }
        let mut query = sql(self.engine.connection.prepare_cached(
            "SELECT proof,statement,derivation FROM checked_reference WHERE proof>?1 ORDER BY proof LIMIT ?2",
        ))?;
        let mut rows = sql(query.query(params![
            after.map(|id| id.as_bytes().to_vec()).unwrap_or_default(),
            limit as i64
        ]))?;
        let mut result = Vec::with_capacity(limit);
        while let Some(row) = sql(rows.next())? {
            let key = |index| -> Result<[u8; 32], Error> {
                let bytes: Vec<u8> = sql(row.get(index))?;
                bytes
                    .try_into()
                    .map_err(|_| "checked dependency width".into())
            };
            result.push(ProgramDependency {
                proof: ProofId::from_bytes(key(0)?),
                statement: StatementId::from_bytes(key(1)?),
                derivation: DerivationId::from_bytes(key(2)?),
            });
        }
        Ok(result)
    }

    pub fn references_proof(&self, proof: ProofId) -> Result<bool, Error> {
        self.engine.live()?;
        sql(self.engine.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM checked_reference WHERE proof=?1)",
            [proof.as_bytes().as_slice()],
            |row| row.get(0),
        ))
    }
}

impl Engine {
    pub(super) fn observe_reference_context(&mut self, context: &dyn ContextView) {
        let snapshot = context.snapshot_id();
        if self
            .reference_snapshot
            .is_some_and(|previous| previous != snapshot)
        {
            self.context_consistent = false;
        }
        self.reference_snapshot = Some(snapshot);
    }

    pub(super) fn import_reference(
        &mut self,
        evaluation: &mut Evaluation,
        context: &dyn ContextView,
        proof: ProofId,
        query: Option<&crate::diagnostics::FormulaQuery>,
    ) -> Result<Option<u64>, Error> {
        if evaluation.reference.is_none() {
            self.observe_reference_context(context);
            evaluation.reference = match context.program_source(proof)? {
                Some(source) => Some(source),
                None => {
                    return Err(Error::Check(Box::new(self.proof_diagnostic(
                        &Command::ProofReference {
                            proof_id: *proof.as_bytes(),
                        },
                        crate::diagnostics::Failure::MissingProof {
                            proof_id: crate::diagnostics::Digest(*proof.as_bytes()),
                        },
                        context,
                        query,
                    )?)));
                }
            };
        }
        let source = evaluation
            .reference
            .as_ref()
            .expect("checked reference source");
        if source.proof != proof {
            return Err(crate::ContextError::Corrupt.into());
        }
        let node = match &source.representation {
            ProgramRepresentation::Formula(formula) => {
                // This representation obeys the existing bounded certificate
                // codec. Unbounded graph sources take the incremental path.
                Some(checker::Context::fixed(self, formula)?)
            }
            ProgramRepresentation::Graph { root, nodes } => {
                self.import_node(*root, nodes.as_ref(), &mut evaluation.reference_depth)?
            }
        };
        if let Some(node) = node {
            if !self.load(node)?.2.closed() {
                return Err(crate::ContextError::Corrupt.into());
            }
            sql(self.connection.execute(
                "INSERT OR IGNORE INTO checked_reference VALUES(?1,?2,?3)",
                params![
                    proof.as_bytes().as_slice(),
                    source.statement.as_bytes().as_slice(),
                    source.derivation.as_bytes().as_slice()
                ],
            ))?;
            let (statement, derivation): (Vec<u8>, Vec<u8>) = sql(self.connection.query_row(
                "SELECT statement,derivation FROM checked_reference WHERE proof=?1",
                [proof.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ))?;
            if statement != source.statement.as_bytes()
                || derivation != source.derivation.as_bytes()
            {
                return Err(crate::ContextError::Corrupt.into());
            }
        }
        Ok(node)
    }

    fn imported(&self, address: [u8; 32]) -> Result<Option<u64>, Error> {
        let id = sql(self
            .connection
            .query_row(
                "SELECT id FROM node WHERE hash=?1",
                [address.as_slice()],
                |row| unsigned(row, 0),
            )
            .optional())?;
        let Some(id) = id else {
            return Ok(None);
        };
        // The canonical hash index is reusable only after this evaluator has
        // authenticated the node. Persisted nodes alone never restore trust.
        if self.authenticated(id)?.is_none() {
            return Ok(None);
        }
        if self.load(id)?.1 != address {
            return Err(crate::ContextError::Corrupt.into());
        }
        Ok(Some(id))
    }

    fn import_node(
        &mut self,
        root: [u8; 32],
        nodes: &dyn ProgramNodes,
        depth: &mut u64,
    ) -> Result<Option<u64>, Error> {
        if let Some(id) = self.imported(root)? {
            return Ok(Some(id));
        }
        // Reuse disk slots beneath a live, volatile stack cursor. Popping never
        // frees temp pages; stale slots above this cursor carry no authority.
        let push = |connection: &Connection, position: u64, address: [u8; 32]| {
            sql(connection.execute(
                "INSERT INTO reference_pending VALUES(?1,?2) ON CONFLICT(sequence) DO UPDATE SET address=excluded.address",
                params![number(position)?, address.as_slice()],
            )).map(|_| ())
        };
        if *depth == 0 {
            push(&self.connection, 1, root)?;
            *depth = 1;
            return Ok(None);
        }
        let bytes: Vec<u8> = sql(self.connection.query_row(
            "SELECT address FROM reference_pending WHERE sequence=?1",
            [number(*depth)?],
            |row| row.get(0),
        ))?;
        let address: [u8; 32] = bytes.try_into().map_err(|_| "reference node width")?;
        if self.imported(address)?.is_some() {
            *depth -= 1;
            return Ok(None);
        }
        let (node, properties) = nodes.read(address)?;
        let mut children = [None, None];
        for (i, child) in node.children().into_iter().enumerate() {
            if let Some(child) = child {
                let Some(id) = self.imported(child)? else {
                    let next = depth
                        .checked_add(1)
                        .ok_or("reference stack address exhausted")?;
                    push(&self.connection, next, child)?;
                    *depth = next;
                    return Ok(None);
                };
                children[i] = Some(id);
            }
        }
        let mut at = 0;
        let local = node.map(|_| {
            let id = children[at].expect("imported child");
            at += 1;
            id
        });
        let id = self.intern(local)?;
        if self.load(id)? != (local, address, properties) {
            return Err(crate::ContextError::Corrupt.into());
        }
        *depth -= 1;
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
