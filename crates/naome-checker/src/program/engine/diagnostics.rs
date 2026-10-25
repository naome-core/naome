use super::*;
use crate::diagnostics::{
    Digest, FORMULA_FRAGMENT_NODES, Failure, FormulaFragment, FormulaQuery, InputBinding,
    InputFormat, InspectionError, Operand, OperandRole as R, ProofDiagnostic, Rule,
    formula::{GraphRead, graph_difference, graph_fragment, graph_query},
};

impl GraphRead for Engine {
    type Handle = u64;
    type Error = Error;
    fn read(&self, handle: u64) -> Result<(Node<u64>, Digest, Properties), Error> {
        self.load(handle)
            .map(|(node, hash, p)| (node, Digest(hash), p))
    }
}

/// Rule metadata describes the executed command; it contains no validity rule.
type CommandMetadata = (Rule, Vec<(R, u64)>, Vec<(R, u32)>);
fn metadata(command: &Command) -> CommandMetadata {
    let (rule, references, variables) = match *command {
        Command::Equal { left, right } => (
            Rule::Equal,
            vec![],
            vec![(R::First, left), (R::Second, right)],
        ),
        Command::Member { element, set } => (
            Rule::Member,
            vec![],
            vec![(R::Element, element), (R::Source, set)],
        ),
        Command::Not { formula } => (Rule::Not, vec![(R::Formula, formula)], vec![]),
        Command::Implies {
            antecedent,
            consequent,
        } => (
            Rule::Implies,
            vec![(R::Antecedent, antecedent), (R::Consequent, consequent)],
            vec![],
        ),
        Command::ForAll { variable, body } => (
            Rule::ForAll,
            vec![(R::Body, body)],
            vec![(R::Variable, variable)],
        ),
        Command::Substitute { from, to, body } => (
            Rule::Substitute,
            vec![(R::Body, body)],
            vec![(R::From, from), (R::To, to)],
        ),
        Command::Simplification {
            antecedent,
            consequent,
        } => (
            Rule::Simplification,
            vec![(R::Antecedent, antecedent), (R::Consequent, consequent)],
            vec![],
        ),
        Command::Frege {
            first,
            second,
            third,
        } => (
            Rule::Frege,
            vec![(R::First, first), (R::Second, second), (R::Third, third)],
            vec![],
        ),
        Command::Contraposition {
            antecedent,
            consequent,
        } => (
            Rule::Contraposition,
            vec![(R::Antecedent, antecedent), (R::Consequent, consequent)],
            vec![],
        ),
        Command::Distribution {
            variable,
            antecedent,
            consequent,
        } => (
            Rule::Distribution,
            vec![(R::Antecedent, antecedent), (R::Consequent, consequent)],
            vec![(R::Variable, variable)],
        ),
        Command::Vacuous { formula } => (Rule::Vacuous, vec![(R::Formula, formula)], vec![]),
        Command::Instantiation {
            variable,
            replacement,
            body,
        } => (
            Rule::Instantiation,
            vec![(R::Body, body)],
            vec![(R::Variable, variable), (R::To, replacement)],
        ),
        Command::Reflexivity { variable } => {
            (Rule::Reflexivity, vec![], vec![(R::Variable, variable)])
        }
        Command::Substitution { from, to, body } => (
            Rule::Substitution,
            vec![(R::Body, body)],
            vec![(R::From, from), (R::To, to)],
        ),
        Command::Axiom { .. } => (Rule::Axiom, vec![], vec![]),
        Command::ProofReference { .. } => (Rule::ProofReference, vec![], vec![]),
        Command::Separation {
            predicate,
            element,
            source,
            result,
        } => (
            Rule::Separation,
            vec![(R::Predicate, predicate)],
            vec![
                (R::Element, element),
                (R::Source, source),
                (R::Result, result),
            ],
        ),
        Command::Replacement {
            predicate,
            input,
            output,
            witness,
            source,
            result,
        } => (
            Rule::Replacement,
            vec![(R::Predicate, predicate)],
            vec![
                (R::Input, input),
                (R::Output, output),
                (R::Witness, witness),
                (R::Source, source),
                (R::Result, result),
            ],
        ),
        Command::ModusPonens {
            premise,
            implication,
        } => (
            Rule::ModusPonens,
            vec![(R::Premise, premise), (R::Implication, implication)],
            vec![],
        ),
        Command::Generalization { premise, variable } => (
            Rule::Generalization,
            vec![(R::Premise, premise)],
            vec![(R::Variable, variable)],
        ),
        Command::Alias { input } => (Rule::Alias, vec![(R::Input, input)], vec![]),
        Command::Seal { proof } => (Rule::Seal, vec![(R::Conclusion, proof)], vec![]),
    };
    (rule, references, variables)
}

impl Engine {
    fn query_formula(
        &self,
        anchor: u64,
        query: &FormulaQuery,
    ) -> Result<Result<FormulaFragment, InspectionError>, Error> {
        let root = if let Some(start) = query.start {
            let id: Option<u64> = sql(self
                .connection
                .query_row(
                    "SELECT id FROM node WHERE hash=?1",
                    [start.0.as_slice()],
                    |row| unsigned(row, 0),
                )
                .optional())?;
            let Some(id) = id else {
                return Ok(Err(InspectionError::UnknownFormula));
            };
            if self.authenticated(id)?.is_none() {
                return Ok(Err(InspectionError::ReplayRequired {
                    checked_before: self.cursor,
                    required_before: self.cursor.saturating_add(1),
                }));
            }
            id
        } else {
            anchor
        };
        graph_query(self, root, query)
    }

    fn diagnostic_binding(&self) -> Result<InputBinding, Error> {
        let (commands, hash): (u64, Vec<u8>) = sql(self.connection.query_row(
            "SELECT commands,substr(hash,1,33) FROM state WHERE id=1",
            [],
            |row| Ok((unsigned(row, 0)?, row.get(1)?)),
        ))?;
        Ok(InputBinding {
            format: InputFormat::Program,
            digest: Digest(hash.try_into().map_err(|_| crate::ContextError::Corrupt)?),
            commands,
            source_digest: None,
        })
    }
    pub(super) fn current_command(&self) -> Result<Command, Error> {
        let bytes: Vec<u8> = sql(self.connection.query_row(
            "SELECT substr(command,1,4097) FROM input WHERE position=?1",
            [number(self.cursor)?],
            |r| r.get(0),
        ))?;
        decode_command(&bytes).map_err(Into::into)
    }
    pub(super) fn proof_diagnostic(
        &self,
        command: &Command,
        failure: Failure,
        context: &dyn ContextView,
        query: Option<&FormulaQuery>,
    ) -> Result<ProofDiagnostic, Error> {
        let (rule, references, variables) = metadata(command);
        let mut diagnostic = ProofDiagnostic::new(
            self.diagnostic_binding()?,
            context.snapshot_id(),
            self.cursor,
            rule,
            failure,
        );
        diagnostic.context_consistent = self.context_consistent
            && self
                .reference_snapshot
                .is_none_or(|snapshot| snapshot == context.snapshot_id());
        let mut premise = None;
        let mut implication = None;
        for (role, reference) in references {
            let mut operand = Operand::new(role);
            operand.reference = Some(reference);
            if reference < self.cursor {
                let value = checker::Context::previous(self, reference)?;
                operand.proved = Some(value.proved);
                let fragment = graph_fragment(self, value.formula, FORMULA_FRAGMENT_NODES, 0)?;
                if let Some(query) = query
                    && query.operand == role
                    && fragment.root == query.root
                {
                    diagnostic.inspection = self.query_formula(value.formula, query)?.ok();
                }
                operand.formula = Some(fragment);
                if role == R::Premise {
                    premise = Some(value.formula);
                }
                if role == R::Implication {
                    implication = Some(value.formula);
                }
            }
            diagnostic.operands.push(operand);
        }
        if let Some(implication) = implication
            && let Some((antecedent, _)) = checker::Context::implication(self, implication)?
        {
            let mut operand = Operand::new(R::Antecedent);
            let fragment = graph_fragment(self, antecedent, FORMULA_FRAGMENT_NODES, 0)?;
            if let Some(query) = query
                && query.operand == R::Antecedent
                && fragment.root == query.root
            {
                diagnostic.inspection = self.query_formula(antecedent, query)?.ok();
            }
            operand.formula = Some(fragment);
            diagnostic.operands.push(operand);
            if let Some(premise) = premise
                && premise != antecedent
            {
                diagnostic.difference = Some(graph_difference(self, antecedent, premise)?);
            }
        }
        for (role, variable) in variables {
            let mut operand = Operand::new(role);
            operand.variable = Some(variable);
            diagnostic.operands.push(operand);
        }
        Ok(diagnostic)
    }

    /// Inspects only formulas named by this exact input/context-bound failure.
    /// A rolled-back batch or a reopened engine may need ordinary prefix replay
    /// first. `ReplayRequired` is explicit; persisted records never restore trust.
    /// Alternatively use `advance_with_inspection` to capture the fragment at
    /// the failure before rollback. All queries have fixed node/path bounds.
    pub fn inspect_formula(
        &self,
        diagnostic: &ProofDiagnostic,
        query: &FormulaQuery,
        context: &dyn ContextView,
    ) -> Result<FormulaFragment, Error> {
        self.live()?;
        diagnostic.validate_schema().map_err(Error::Inspection)?;
        query.validate().map_err(Error::Inspection)?;
        if self.diagnostic_binding()? != diagnostic.input {
            return Err(Error::Inspection(InspectionError::InputChanged));
        }
        if Digest(context.snapshot_id()) != diagnostic.context_snapshot {
            return Err(Error::Inspection(InspectionError::ContextChanged));
        }
        if !diagnostic.context_consistent
            || !self.context_consistent
            || self
                .reference_snapshot
                .is_some_and(|snapshot| Digest(snapshot) != diagnostic.context_snapshot)
        {
            return Err(Error::Inspection(InspectionError::ContextChanged));
        }
        if !diagnostic.matches_query(query) {
            return Err(Error::Inspection(InspectionError::UnknownFormula));
        }
        if self.cursor < diagnostic.checked_before {
            return Err(Error::Inspection(InspectionError::ReplayRequired {
                checked_before: self.cursor,
                required_before: diagnostic.checked_before,
            }));
        }
        let id: Option<u64> = sql(self
            .connection
            .query_row(
                "SELECT id FROM node WHERE hash=?1",
                [query.root.0.as_slice()],
                |row| unsigned(row, 0),
            )
            .optional())?;
        let Some(id) = id else {
            return Err(Error::Inspection(InspectionError::UnknownFormula));
        };
        if self.authenticated(id)?.is_none() {
            return Err(Error::Inspection(InspectionError::ReplayRequired {
                checked_before: self.cursor,
                required_before: diagnostic.checked_before,
            }));
        }
        self.query_formula(id, query)?.map_err(Error::Inspection)
    }
}

impl CheckedProgram {
    /// Inspects the live sealed result named by a target/manifest failure.
    /// Expected target values remain caller-owned; inspect them with
    /// `diagnostics::inspect_formula_value` when their tree is available.
    pub fn inspect_formula(
        &self,
        diagnostic: &ProofDiagnostic,
        query: &FormulaQuery,
    ) -> Result<FormulaFragment, Error> {
        self.engine.live()?;
        diagnostic.validate_schema().map_err(Error::Inspection)?;
        query.validate().map_err(Error::Inspection)?;
        if diagnostic.input != self.engine.diagnostic_binding()? {
            return Err(Error::Inspection(InspectionError::InputChanged));
        }
        if self.engine.context_snapshot.map(Digest) != Some(diagnostic.context_snapshot)
            || !diagnostic.context_consistent
        {
            return Err(Error::Inspection(InspectionError::ContextChanged));
        }
        if !diagnostic.matches_query(query) {
            return Err(Error::Inspection(InspectionError::UnknownFormula));
        }
        if query.operand != R::Conclusion {
            return Err(Error::Inspection(InspectionError::TargetRequired));
        }
        if query.root.0 != self.manifest.conclusion {
            return Err(Error::Inspection(InspectionError::UnknownFormula));
        }
        self.engine
            .query_formula(
                self.engine.accepted.ok_or(crate::ContextError::Corrupt)?,
                query,
            )?
            .map_err(Error::Inspection)
    }
    /// Compares every immutable manifest claim with this independently checked
    /// result. Input commitments remain separate from mathematical target errors.
    pub fn check_manifest(&self, expected: &Manifest) -> Result<(), Error> {
        use crate::diagnostics::{ClaimField as F, ClaimValue as V};
        let actual = &self.manifest;
        let fields = [
            (
                F::Commands,
                V::Count(expected.commands),
                V::Count(actual.commands),
            ),
            (
                F::InputBytes,
                V::Count(expected.input_bytes),
                V::Count(actual.input_bytes),
            ),
            (
                F::ProgramHash,
                V::Digest(Digest(expected.program_hash)),
                V::Digest(Digest(actual.program_hash)),
            ),
            (
                F::StreamRoot,
                V::Digest(Digest(expected.stream_root)),
                V::Digest(Digest(actual.stream_root)),
            ),
            (
                F::Statement,
                V::Digest(Digest(expected.statement)),
                V::Digest(Digest(actual.statement)),
            ),
        ];
        // Check the claimed conclusion before its derived statement identity.
        for (field, expected, actual) in fields.into_iter().take(4) {
            if expected != actual {
                let mut diagnostic = self.target_report(Failure::ManifestMismatch {
                    field,
                    expected,
                    actual,
                })?;
                diagnostic.rule = Rule::Seal;
                return Err(Error::Check(Box::new(diagnostic)));
            }
        }
        self.check_target_root(Digest(expected.conclusion))?;
        let (field, expected, actual) = fields[4];
        if expected != actual {
            let mut diagnostic = self.target_report(Failure::ManifestMismatch {
                field,
                expected,
                actual,
            })?;
            diagnostic.rule = Rule::Seal;
            return Err(Error::Check(Box::new(diagnostic)));
        }
        Ok(())
    }
    /// Requires an immutable target root without materializing either DAG.
    /// The expected root is an obligation, not an admitted mathematical fact.
    pub fn check_target_root(&self, target: Digest) -> Result<(), Error> {
        self.engine.live()?;
        if target.0 == self.manifest.conclusion {
            return Ok(());
        }
        let mut diagnostic = self.target_report(Failure::TargetMismatch)?;
        diagnostic.target_root = Some(target);
        Err(Error::Check(Box::new(diagnostic)))
    }
    /// Requires the original bounded target. Larger targets can use
    /// `check_target_root`; neither operation materializes the proved DAG.
    pub fn check_target(&self, target: &Formula) -> Result<(), Error> {
        if let Err(error) = target.encode_canonical() {
            return Err(Error::Check(Box::new(
                self.target_report(crate::diagnostics::formula_failure(&error))?,
            )));
        }
        match self.check_target_root(Digest(format::formula_hash(target))) {
            Err(Error::Check(mut diagnostic)) => {
                diagnostic
                    .bind_target(target)
                    .expect("target was codec-validated");
                Err(Error::Check(diagnostic))
            }
            other => other,
        }
    }
    fn target_report(&self, failure: Failure) -> Result<ProofDiagnostic, Error> {
        self.engine.live()?;
        let snapshot = self
            .engine
            .context_snapshot
            .ok_or(crate::ContextError::Corrupt)?;
        let mut diagnostic = ProofDiagnostic::new(
            self.engine.diagnostic_binding()?,
            snapshot,
            self.manifest.commands - 1,
            Rule::Target,
            failure,
        );
        diagnostic.context_consistent = self.engine.context_consistent
            && self
                .engine
                .reference_snapshot
                .is_none_or(|reference| reference == snapshot);
        diagnostic.checked_before = self.manifest.commands;
        let root = self.engine.accepted.ok_or(crate::ContextError::Corrupt)?;
        let mut operand = Operand::new(R::Conclusion);
        operand.proved = Some(true);
        operand.reference = Some(self.manifest.commands - 1);
        operand.formula = Some(graph_fragment(
            &self.engine,
            root,
            FORMULA_FRAGMENT_NODES,
            0,
        )?);
        diagnostic.operands.push(operand);
        Ok(diagnostic)
    }
}
