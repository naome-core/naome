use super::formula::{tree_fragment, tree_query};
use super::*;
use crate::{
    CheckError, CheckErrorKind, CheckedStep, ContextError, ContextView, IdentityMode,
    check_with_diagnostic_query,
};
use naome_foundation::{Formula, FormulaMismatch, FormulaView, LogicError, SchemaError};
use naome_proof::{ProofCertificate, ProofFormula, ProofStep};

/// Rechecks the exact certificate against the exact immutable context, then
/// inspects a bounded fragment at the same failure. Successful checks and stale
/// bindings cannot be used as an inspection of a previous error. This performs
/// ordinary bounded certificate checking; it creates no new proof authority.
pub fn inspect_certificate(
    certificate: &ProofCertificate,
    context: &dyn ContextView,
    diagnostic: &ProofDiagnostic,
    query: &FormulaQuery,
) -> Result<FormulaFragment, InspectionError> {
    diagnostic.validate_schema()?;
    query.validate()?;
    if diagnostic.input.format != InputFormat::Certificate
        || diagnostic.input.digest != Digest::of(&certificate.to_canonical_bytes())
    {
        return Err(InspectionError::InputChanged);
    }
    if diagnostic.context_snapshot != Digest(context.snapshot_id())
        || !diagnostic.context_consistent
    {
        return Err(InspectionError::ContextChanged);
    }
    if !diagnostic.matches_query(query) {
        return Err(InspectionError::UnknownFormula);
    }
    let error = match check_with_diagnostic_query(
        certificate,
        context,
        IdentityMode::OmitDerivation,
        Some(query),
    ) {
        Err(error) => error,
        Ok((conclusion, _, _)) if matches!(diagnostic.failure, Failure::TargetMismatch) => {
            if query.operand != OperandRole::Conclusion {
                return Err(InspectionError::TargetRequired);
            }
            let mut fragment = super::inspect_formula_value(&conclusion, query)?;
            fragment.variable_namespace = VariableNamespace::Input;
            return Ok(fragment);
        }
        Ok(_) => return Err(InspectionError::InputChanged),
    };
    if error.diagnostic().location.step != diagnostic.location.step
        || error.diagnostic().failure != diagnostic.failure
    {
        return Err(InspectionError::InputChanged);
    }
    error
        .diagnostic
        .inspection
        .clone()
        .ok_or(InspectionError::InvalidPath)
}

pub(crate) fn rule(step: &ProofStep) -> Rule {
    match step {
        ProofStep::Simplification { .. } => Rule::Simplification,
        ProofStep::Frege { .. } => Rule::Frege,
        ProofStep::ClassicalContraposition { .. } => Rule::Contraposition,
        ProofStep::UniversalDistribution { .. } => Rule::Distribution,
        ProofStep::VacuousUniversal { .. } => Rule::Vacuous,
        ProofStep::UniversalInstantiation { .. } => Rule::Instantiation,
        ProofStep::EqualityReflexivity { .. } => Rule::Reflexivity,
        ProofStep::EqualitySubstitution { .. } => Rule::Substitution,
        ProofStep::ZfcAxiom(_) => Rule::Axiom,
        ProofStep::Separation(_) => Rule::Separation,
        ProofStep::Replacement(_) => Rule::Replacement,
        ProofStep::ProofReference { .. } => Rule::ProofReference,
        ProofStep::ModusPonens { .. } => Rule::ModusPonens,
        ProofStep::Generalization { .. } => Rule::Generalization,
    }
}

pub(crate) fn schema_roles(step: &ProofStep) -> Vec<(OperandRole, u32)> {
    use OperandRole as R;
    match step {
        ProofStep::Separation(s) => vec![
            (R::Element, s.element.identifier()),
            (R::Source, s.source.identifier()),
            (R::Result, s.result.identifier()),
        ],
        ProofStep::Replacement(s) => vec![
            (R::Input, s.input.identifier()),
            (R::Output, s.output.identifier()),
            (R::Witness, s.uniqueness_witness.identifier()),
            (R::Source, s.source.identifier()),
            (R::Result, s.result.identifier()),
        ],
        _ => Vec::new(),
    }
}

pub(crate) fn error(
    kind: CheckErrorKind,
    certificate: &ProofCertificate,
    context: &dyn ContextView,
    results: &[Option<CheckedStep>],
    derived: Option<&Formula>,
    query: Option<&FormulaQuery>,
) -> CheckError {
    let step = &certificate.steps()[kind.step() as usize];
    let mut roles = schema_roles(step);
    use OperandRole as Role;
    match step {
        ProofStep::Generalization { variable, .. }
        | ProofStep::UniversalDistribution { variable, .. }
        | ProofStep::EqualityReflexivity { variable } => {
            roles.push((Role::Variable, variable.identifier()))
        }
        ProofStep::UniversalInstantiation {
            variable,
            replacement,
            ..
        } => roles.extend([
            (Role::Variable, variable.identifier()),
            (Role::To, replacement.identifier()),
        ]),
        ProofStep::EqualitySubstitution { from, to, .. } => {
            roles.extend([(Role::From, from.identifier()), (Role::To, to.identifier())])
        }
        _ => {}
    }
    let parameters = match step {
        ProofStep::Separation(s) => s.parameters.as_slice(),
        ProofStep::Replacement(s) => s.parameters.as_slice(),
        _ => &[],
    };
    let failure = match &kind {
        CheckErrorKind::ContextAccess { source, .. } => match source {
            ContextError::Limit => Failure::ContextLimit,
            ContextError::Corrupt => Failure::ContextCorrupt,
            ContextError::Storage(_) => Failure::ContextStorage,
        },
        CheckErrorKind::UnknownProofReference { proof_id, .. } => Failure::MissingProof {
            proof_id: Digest(*proof_id.as_bytes()),
        },
        CheckErrorKind::DefinitionExpansion { source, .. } => Failure::Expansion {
            reason: source.into(),
        },
        CheckErrorKind::Logic { source, .. } => match source {
            LogicError::ExpectedImplication => Failure::ExpectedImplication {
                operand: OperandRole::Implication,
            },
            LogicError::AntecedentMismatch => Failure::AntecedentMismatch,
        },
        CheckErrorKind::Schema { source, .. } => {
            let role = |v: u32| {
                roles
                    .iter()
                    .find(|(_, value)| *value == v)
                    .map(|(role, _)| *role)
                    .expect("schema collision names a role")
            };
            let position = |v| {
                parameters
                    .iter()
                    .position(|value| *value == v)
                    .expect("schema error names a declared parameter") as u32
            };
            match source {
                SchemaError::RoleVariableCollision(v) => Failure::RoleCollision {
                    variable: v.identifier(),
                    roles: roles
                        .iter()
                        .filter(|(_, value)| *value == v.identifier())
                        .map(|(role, _)| *role)
                        .collect(),
                },
                SchemaError::ParameterCollidesWithRole(v) => Failure::ParameterRoleCollision {
                    variable: v.identifier(),
                    role: role(v.identifier()),
                    parameter: position(*v),
                },
                SchemaError::DuplicateParameter(v) => {
                    let first = position(*v);
                    let second = parameters
                        .iter()
                        .enumerate()
                        .find(|(i, value)| *i > first as usize && **value == *v)
                        .expect("duplicate parameter")
                        .0 as u32;
                    Failure::DuplicateParameter {
                        variable: v.identifier(),
                        first,
                        second,
                    }
                }
                SchemaError::ForbiddenPredicateVariable(v) => Failure::ForbiddenPredicateVariable {
                    variable: v.identifier(),
                    role: role(v.identifier()),
                },
                SchemaError::UndeclaredPredicateVariable(v) => {
                    Failure::UndeclaredPredicateVariable {
                        variable: v.identifier(),
                    }
                }
            }
        }
        CheckErrorKind::DerivedFormula { source, .. } => formula_failure(source),
        CheckErrorKind::FormulaWorkLimitExceeded {
            actual, maximum, ..
        } => Failure::FormulaWorkLimit {
            actual: *actual,
            maximum: *maximum,
        },
        CheckErrorKind::OpenConclusion { .. } => Failure::OpenConclusion,
    };
    let mut diagnostic = ProofDiagnostic::new(
        InputBinding {
            format: InputFormat::Certificate,
            digest: Digest::of(&certificate.to_canonical_bytes()),
            commands: certificate.steps().len() as u64,
            source_digest: None,
        },
        context.snapshot_id(),
        u64::from(kind.step()),
        rule(step),
        failure,
    );
    if matches!(kind, CheckErrorKind::OpenConclusion { .. }) {
        diagnostic.checked_before = certificate.steps().len() as u64;
    }
    let mut formula_operand = |role, reference: Option<u32>, formula: Option<&Formula>, proved| {
        let mut operand = Operand::new(role);
        operand.reference = reference.map(u64::from);
        operand.proved = proved;
        if formula.is_none() {
            diagnostic.operands_complete = false;
        }
        if let Some(formula) = formula {
            operand.formula = Some(tree_fragment(formula.view(), FORMULA_FRAGMENT_NODES, 0));
            if let Some(query) = query
                && query.operand == role
                && operand
                    .formula
                    .as_ref()
                    .is_some_and(|f| f.root == query.root)
            {
                diagnostic.inspection = tree_query(formula.view(), query).ok();
            }
        }
        diagnostic.operands.push(operand);
    };
    match step {
        ProofStep::ModusPonens {
            premise,
            implication,
        } => {
            let result = |r: u32| {
                results
                    .get(r as usize)
                    .and_then(Option::as_ref)
                    .map(|r| &r.formula)
            };
            formula_operand(
                OperandRole::Premise,
                Some(*premise),
                result(*premise),
                Some(true),
            );
            formula_operand(
                OperandRole::Implication,
                Some(*implication),
                result(*implication),
                Some(true),
            );
            if let Some(implication) = result(*implication)
                && let Some((antecedent, _)) = implication.view().implication_parts()
            {
                let antecedent = antecedent.to_owned();
                formula_operand(OperandRole::Antecedent, None, Some(&antecedent), None);
                if let Some(premise) = result(*premise)
                    && let Some(comparison) = FormulaMismatch::between(&antecedent, premise)
                {
                    diagnostic.difference =
                        Some(tree_difference(&antecedent, premise, &comparison));
                }
            }
        }
        ProofStep::Generalization { premise, .. } => {
            formula_operand(
                OperandRole::Premise,
                Some(*premise),
                results
                    .get(*premise as usize)
                    .and_then(Option::as_ref)
                    .map(|r| &r.formula),
                Some(true),
            );
        }
        _ => {}
    }
    // Input formula fields have no proofhood claim. A failed expansion leaves
    // its typed dependency/limit cause, never an invented primitive formula.
    let mut add_raw = |role, raw: &ProofFormula| {
        if let Ok(formula) = crate::primitive_formula(kind.step(), raw, context) {
            let fragment = tree_fragment(formula.view(), FORMULA_FRAGMENT_NODES, 0);
            if let Some(query) = query
                && query.operand == role
                && fragment.root == query.root
            {
                diagnostic.inspection = tree_query(formula.view(), query).ok();
            }
            let mut operand = Operand::new(role);
            operand.formula = Some(fragment);
            diagnostic.operands.push(operand);
        } else {
            diagnostic.operands_complete = false;
            diagnostic.operands.push(Operand::new(role));
        }
    };
    use OperandRole as R;
    match step {
        ProofStep::Simplification {
            antecedent,
            consequent,
        }
        | ProofStep::ClassicalContraposition {
            antecedent,
            consequent,
        }
        | ProofStep::UniversalDistribution {
            antecedent,
            consequent,
            ..
        } => {
            add_raw(R::Antecedent, antecedent);
            add_raw(R::Consequent, consequent);
        }
        ProofStep::Frege {
            first,
            second,
            third,
        } => {
            add_raw(R::First, first);
            add_raw(R::Second, second);
            add_raw(R::Third, third);
        }
        ProofStep::VacuousUniversal { formula } => add_raw(R::Formula, formula),
        ProofStep::UniversalInstantiation { body, .. }
        | ProofStep::EqualitySubstitution { body, .. } => add_raw(R::Body, body),
        ProofStep::Separation(s) => add_raw(R::Predicate, &s.predicate),
        ProofStep::Replacement(s) => add_raw(R::Predicate, &s.predicate),
        _ => {}
    }
    for (role, variable) in roles {
        let mut operand = Operand::new(role);
        operand.variable = Some(variable);
        diagnostic.operands.push(operand);
    }
    diagnostic.operands_complete &= parameters.len() <= 32;
    for (index, variable) in parameters.iter().enumerate().take(32) {
        let mut operand = Operand::new(R::Parameter);
        operand.index = Some(index as u32);
        operand.variable = Some(variable.identifier());
        diagnostic.operands.push(operand);
    }
    // Always retain the exact offending parameter even beyond the small prefix.
    if let Failure::DuplicateParameter { first, second, .. } = diagnostic.failure {
        for index in [first, second] {
            if !diagnostic
                .operands
                .iter()
                .any(|o| o.role == R::Parameter && o.index == Some(index))
            {
                let mut operand = Operand::new(R::Parameter);
                operand.index = Some(index);
                operand.variable = Some(parameters[index as usize].identifier());
                diagnostic.operands.push(operand);
            }
        }
    }
    if let Some(formula) = derived {
        let mut operand = Operand::new(R::Conclusion);
        operand.proved = (!matches!(kind, CheckErrorKind::DerivedFormula { .. })).then_some(true);
        operand.formula = Some(tree_fragment(formula.view(), FORMULA_FRAGMENT_NODES, 0));
        if let Some(query) = query
            && query.operand == R::Conclusion
            && operand
                .formula
                .as_ref()
                .is_some_and(|f| f.root == query.root)
        {
            diagnostic.inspection = tree_query(formula.view(), query).ok();
        }
        diagnostic.operands.push(operand);
    }
    CheckError {
        kind,
        diagnostic: std::sync::Arc::new(diagnostic),
    }
}

pub(crate) fn tree_difference(
    expected: &Formula,
    actual: &Formula,
    comparison: &FormulaMismatch,
) -> Difference {
    let path = comparison
        .path()
        .iter()
        .copied()
        .map(PathSegment::from)
        .collect::<Vec<_>>();
    let node = |view: FormulaView<'_>| {
        let query = FormulaQuery {
            start: None,
            operand: OperandRole::Formula,
            root: Digest([0; 32]),
            path: path.clone(),
            maximum_nodes: 1,
        };
        tree_query(view, &query)
            .expect("comparison path follows its formula")
            .root_node()
            .expect("generated fragment includes its root")
            .clone()
    };
    Difference {
        path: path.clone(),
        expected: node(expected.view()),
        actual: node(actual.view()),
        complete: true,
    }
}

/// Builds the same contract for a checked proof which proves another target.
/// The target is retained as an obligation, never rewritten to the conclusion.
pub fn target_mismatch(
    certificate: &ProofCertificate,
    context: &dyn ContextView,
    expected: &Formula,
    actual: &Formula,
) -> Result<ProofDiagnostic, FormulaFailure> {
    target_mismatch_at_snapshot(certificate, context.snapshot_id(), expected, actual)
}

/// Target comparison using a context identity retained by a sealed checked proof.
pub fn target_mismatch_at_snapshot(
    certificate: &ProofCertificate,
    snapshot: [u8; 32],
    expected: &Formula,
    actual: &Formula,
) -> Result<ProofDiagnostic, FormulaFailure> {
    actual
        .encode_canonical()
        .map_err(|error| FormulaFailure::from(&error))?;
    let mut diagnostic = ProofDiagnostic::new(
        InputBinding {
            format: InputFormat::Certificate,
            digest: Digest::of(&certificate.to_canonical_bytes()),
            commands: certificate.steps().len() as u64,
            source_digest: None,
        },
        snapshot,
        certificate.steps().len() as u64 - 1,
        Rule::Target,
        Failure::TargetMismatch,
    );
    diagnostic.checked_before = certificate.steps().len() as u64;
    diagnostic.bind_target(expected)?;
    let mut operand = Operand::new(OperandRole::Conclusion);
    operand.proved = Some(true);
    operand.formula = Some(tree_fragment(actual.view(), FORMULA_FRAGMENT_NODES, 0));
    diagnostic.operands.push(operand);
    diagnostic.difference = FormulaMismatch::between(expected, actual)
        .map(|comparison| tree_difference(expected, actual, &comparison));
    Ok(diagnostic)
}
