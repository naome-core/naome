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
    pub(super) fn import_reference(
        &mut self,
        evaluation: &mut Evaluation,
        context: &dyn ContextView,
        proof: ProofId,
    ) -> Result<Option<u64>, Error> {
        if evaluation.reference.is_none() {
            evaluation.reference = Some(
                context
                    .program_source(proof)?
                    .ok_or("program references an unknown checked proof")?,
            );
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
                self.import_node(*root, nodes.as_ref())?
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
                "SELECT node FROM reference_imported WHERE address=?1",
                [address.as_slice()],
                |row| unsigned(row, 0),
            )
            .optional())?;
        if let Some(id) = id
            && self.load(id)?.1 != address
        {
            return Err(crate::ContextError::Corrupt.into());
        }
        Ok(id)
    }

    fn import_node(
        &mut self,
        root: [u8; 32],
        nodes: &dyn ProgramNodes,
    ) -> Result<Option<u64>, Error> {
        if let Some(id) = self.imported(root)? {
            return Ok(Some(id));
        }
        let top: Option<(i64, Vec<u8>)> = sql(self
            .connection
            .query_row(
                "SELECT sequence,address FROM reference_pending ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional())?;
        let Some((sequence, address)) = top else {
            sql(self.connection.execute(
                "INSERT INTO reference_pending(address) VALUES(?1)",
                [root.as_slice()],
            ))?;
            return Ok(None);
        };
        let address: [u8; 32] = address.try_into().map_err(|_| "reference node width")?;
        if self.imported(address)?.is_some() {
            sql(self.connection.execute(
                "DELETE FROM reference_pending WHERE sequence=?1",
                [sequence],
            ))?;
            return Ok(None);
        }
        let (node, properties) = nodes.read(address)?;
        let mut children = [None, None];
        for (i, child) in node.children().into_iter().enumerate() {
            if let Some(child) = child {
                let Some(id) = self.imported(child)? else {
                    sql(self.connection.execute(
                        "INSERT INTO reference_pending(address) VALUES(?1)",
                        [child.as_slice()],
                    ))?;
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
        sql(self.connection.execute(
            "INSERT INTO reference_imported VALUES(?1,?2)",
            params![address.as_slice(), number(id)?],
        ))?;
        sql(self.connection.execute(
            "DELETE FROM reference_pending WHERE sequence=?1",
            [sequence],
        ))?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
