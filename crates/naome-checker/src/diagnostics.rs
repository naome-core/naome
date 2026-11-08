//! Deterministic evidence for failed proof checks, shared by both proof formats.
//!
//! Diagnostics explain a failed condition; they never establish proofhood or
//! select a repair. Only the ordinary checker can accept a replacement proof.
//! Formula fragments use the existing authenticated DAG vocabulary, including
//! exact free-variable identifiers and De Bruijn indices. They are bounded
//! projections, not truncated formula serializations. Inspect omitted children
//! using [`inspect_certificate`] or [`crate::program::Engine::inspect_formula`].
//! Inputs and context snapshots must match before an inspection is reused.
//!
//! # Consumer contract
//!
//! Serialize the public check error directly; `failure.code` and its typed
//! fields carry the condition, while display messages and formula previews are
//! presentation only. `input`, `context_snapshot`, the original target, and
//! checker identity/version bind the evidence. The version is a package release,
//! not a source-commit attestation.
//!
//! `checked_before` describes locally checked derivations before the first
//! failure. Global closure and target requirements can still fail. Constructed
//! formulas have no proof authority; only `Operand::proved` reports whether the
//! ordinary kernel had checked that input as a derivation. Later commands have
//! not been checked. Inspecting structure never admits a proof or selects a fix.
//!
//! Check every completeness flag before interpreting absence. Formula nodes use
//! exact free identifiers and De Bruijn indices in the named variable namespace.
//! A query can follow a bounded `path`, then continue using a returned child hash
//! as `FormulaQuery::start`, keeping the original operand `root`. Program reads
//! authenticate nodes in the replayed prefix; they do not establish that an
//! arbitrary address is reachable from that operand. Consumers follow the
//! returned child links and carry binder depth themselves across address-based
//! segments (`scope_depth` is then unknown). Restart and rolled-back batches
//! require ordinary replay; persisted node records do not restore trust.
//!
//! ```
//! use naome_checker::{check, diagnostics::{Failure, OperandRole}};
//! use naome_foundation::FreeVariable;
//! use naome_proof::{ProofCertificate, ProofStep};
//! let proof = ProofCertificate::new(vec![
//!     ProofStep::EqualityReflexivity { variable: FreeVariable::new(0) },
//!     ProofStep::ModusPonens { premise: 0, implication: 0 },
//! ]).unwrap();
//! let error = check(&proof).unwrap_err();
//! assert_eq!(error.diagnostic().failure,
//!     Failure::ExpectedImplication { operand: OperandRole::Implication });
//! assert_eq!(error.diagnostic().checked_before, 1);
//! ```

use naome_foundation::{FOUNDATION_ID, FormulaCodecError};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::fmt;

pub(crate) mod certificate;
pub(crate) mod formula;
mod reasons;
pub use certificate::inspect_certificate;
pub use certificate::{target_mismatch, target_mismatch_at_snapshot};
pub use formula::inspect_formula_value;
pub use formula::{
    Difference, FormulaFragment, FormulaNode, FormulaQuery, NodeKind, NodeRecord, PathSegment,
    Variable, VariableNamespace,
};
pub use reasons::{
    ClaimField, ClaimValue, DIAGNOSTIC_FAILURE_CODES, EXPANSION_FAILURE_CODES, ExpansionFailure,
    FORMULA_FAILURE_CODES, Failure, FormulaFailure,
};

/// The mathematical checker identity; presentation changes do not change it.
pub const CHECKER_ID: &str = "naome:zfc-checker";
pub const CHECKER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SCHEMA_VERSION: u32 = 1;
/// Default nodes per operand. The number of operands of one rule is bounded.
pub const FORMULA_FRAGMENT_NODES: usize = 16;
/// Hard per-query node and path bound, independent of total program size.
pub const MAX_INSPECTION_NODES: usize = 256;
pub const MAX_INSPECTION_PATH: usize = 256;
pub const MAX_SOURCE_ORIGINS: usize = 16;

/// A content digest. It binds data, not mathematical validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub [u8; 32]);
impl Digest {
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputFormat {
    Certificate,
    Program,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InputBinding {
    pub format: InputFormat,
    /// SHA-256 of canonical certificate bytes, or the existing program hash.
    pub digest: Digest,
    pub commands: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Invalid,
    MissingDependency,
    LimitExceeded,
    ContextFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    DefinedRelation,
    Equal,
    Member,
    Not,
    Implies,
    ForAll,
    Substitute,
    Simplification,
    Frege,
    Contraposition,
    Distribution,
    Vacuous,
    Instantiation,
    Deduction,
    Reflexivity,
    Substitution,
    Axiom,
    ProofReference,
    Separation,
    Replacement,
    ModusPonens,
    Generalization,
    Alias,
    Seal,
    Target,
}

/// Operand names belong to the mathematical rule, not source argument order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperandRole {
    Premise,
    Implication,
    Antecedent,
    Consequent,
    First,
    Second,
    Third,
    Formula,
    Body,
    Predicate,
    Variable,
    From,
    To,
    Element,
    Source,
    Result,
    Input,
    Output,
    Witness,
    Parameter,
    Proof,
    Conclusion,
    Target,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Location {
    /// Zero-based certificate step or program command, bound to `input`.
    pub step: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Operand {
    pub role: OperandRole,
    pub index: Option<u32>,
    pub reference: Option<u64>,
    /// `Some(true)` only for an input actually proved in this check's prefix.
    pub proved: Option<bool>,
    pub formula: Option<FormulaFragment>,
    pub variable: Option<u32>,
}
impl Operand {
    pub(crate) fn new(role: OperandRole) -> Self {
        Self {
            role,
            index: None,
            reference: None,
            proved: None,
            formula: None,
            variable: None,
        }
    }
}

/// A small, input-bound explanation. No field authorizes admission or editing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProofDiagnostic {
    pub schema_version: u32,
    pub checker: &'static str,
    pub checker_version: &'static str,
    pub foundation: &'static str,
    pub input: InputBinding,
    pub context_snapshot: Digest,
    /// False if an incremental run used more than one context snapshot. Such
    /// a report requires replay against one frozen context before reuse.
    pub context_consistent: bool,
    /// The immutable requested target, when supplied by the caller.
    pub target: Option<FormulaFragment>,
    /// Also supports an immutable target whose DAG cannot be materialized.
    pub target_root: Option<Digest>,
    pub question_record: Option<Digest>,
    pub alternative_targets: Vec<FormulaFragment>,
    pub outcome: Outcome,
    pub location: Location,
    pub rule: Rule,
    pub failure: Failure,
    pub operands: Vec<Operand>,
    pub operands_complete: bool,
    pub difference: Option<Difference>,
    /// The first failing step is not a checked fact. Dependent steps were not
    /// checked; this boundary is in the input format's execution order.
    pub checked_before: u64,
    /// Returned only by an explicit bounded inspection request.
    pub inspection: Option<FormulaFragment>,
}
impl ProofDiagnostic {
    pub fn validate_schema(&self) -> Result<(), InspectionError> {
        if self.schema_version != SCHEMA_VERSION
            || self.checker != CHECKER_ID
            || self.checker_version != CHECKER_VERSION
            || self.foundation != FOUNDATION_ID
        {
            return Err(InspectionError::UnsupportedDiagnostic);
        }
        Ok(())
    }
    /// Attaches the caller's fixed target. This obligation is data, not a proof.
    pub fn bind_target(
        &mut self,
        target: &naome_foundation::Formula,
    ) -> Result<(), FormulaFailure> {
        target
            .encode_canonical()
            .map_err(|error| FormulaFailure::from(&error))?;
        let mut fragment = formula::tree_fragment(target.view(), FORMULA_FRAGMENT_NODES, 0);
        fragment.variable_namespace = VariableNamespace::Supplied;
        self.target_root = Some(fragment.root);
        self.target = Some(fragment);
        Ok(())
    }
    pub fn code(&self) -> u32 {
        self.failure.code()
    }
    pub fn operand(&self, role: OperandRole) -> Option<&Operand> {
        self.operands.iter().find(|operand| operand.role == role)
    }
    pub(crate) fn new(
        input: InputBinding,
        context_snapshot: [u8; 32],
        step: u64,
        rule: Rule,
        failure: Failure,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            checker: CHECKER_ID,
            checker_version: CHECKER_VERSION,
            foundation: FOUNDATION_ID,
            input,
            context_snapshot: Digest(context_snapshot),
            context_consistent: true,
            target: None,
            target_root: None,
            question_record: None,
            alternative_targets: Vec::new(),
            outcome: failure.outcome(),
            location: Location { step },
            rule,
            failure,
            operands: Vec::new(),
            operands_complete: true,
            difference: None,
            checked_before: step,
            inspection: None,
        }
    }
    /// Tests membership in this report; it does not authenticate external data.
    pub fn matches_query(&self, query: &FormulaQuery) -> bool {
        if query.operand == OperandRole::Target {
            self.target.as_ref().is_some_and(|f| f.root == query.root)
                || self
                    .alternative_targets
                    .iter()
                    .any(|f| f.root == query.root)
        } else {
            self.operand(query.operand)
                .and_then(|o| o.formula.as_ref())
                .is_some_and(|f| f.root == query.root)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum InspectionError {
    InputChanged,
    ContextChanged,
    InvalidQuery,
    UnknownFormula,
    InvalidPath,
    ReplayRequired {
        checked_before: u64,
        required_before: u64,
    },
    ContextUnavailable,
    FormulaOutsideLimits {
        reason: FormulaFailure,
    },
    UnsupportedDiagnostic,
    TargetRequired,
}
impl fmt::Display for InspectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proof diagnostic inspection: {self:?}")
    }
}
impl std::error::Error for InspectionError {}

pub(crate) fn formula_failure(error: &FormulaCodecError) -> Failure {
    Failure::Formula {
        reason: FormulaFailure::from(error),
    }
}

#[cfg(test)]
mod tests;
