//! Bounded, exact proof-group admission against an immutable selected library.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use naome_checker::{ArtifactState, CheckedProof};
use naome_foundation::Formula;
use naome_proof::{ProofCertificate, ProofId, ProofStep, StatementId};

use crate::codec::{Reader, Writer};
use crate::identity::hash;
use crate::profile::Profile;
use crate::question::CompiledQuestion;
use crate::{AccountId, PackageHash, ResearchError};

mod package;
mod verification;
pub use package::ProofPackage;
use verification::{bounded_certificate, dependencies};

/// Finalized operation position; raw proof identity breaks simultaneous ties.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdmissionCoordinate {
    pub height: u64,
    pub operation_index: u32,
}

/// Exact orientation of the checked root relative to the approved question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofOutcome {
    Proved,
    Refuted,
}

/// Measured deterministic work, to be accumulated across a complete record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerificationWork {
    pub checker_calls: u64,
    pub checker_input_bytes: u64,
    pub dag_steps: u64,
    pub normalization_steps: u64,
}

/// Verified certificate content with the package's bound prospective author.
/// Authentication belongs to the enclosing signed-operation layer. This value
/// alone establishes neither publication nor an admission coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProof {
    proof_id: ProofId,
    statement_id: StatementId,
    conclusion: Formula,
    bytes: Vec<u8>,
    dependencies: Vec<ProofId>,
    author: AccountId,
}

impl VerifiedProof {
    pub fn proof_id(&self) -> ProofId {
        self.proof_id
    }
    pub fn statement_id(&self) -> StatementId {
        self.statement_id
    }
    pub fn conclusion(&self) -> &Formula {
        &self.conclusion
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn dependencies(&self) -> &[ProofId] {
        &self.dependencies
    }
    pub fn author(&self) -> AccountId {
        self.author
    }
    pub fn recipient(&self) -> AccountId {
        self.author
    }
}

/// An immutable selected proof with actual original publication provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryProof {
    proof: VerifiedProof,
    coordinate: AdmissionCoordinate,
}

impl LibraryProof {
    pub fn coordinate(&self) -> AdmissionCoordinate {
        self.coordinate
    }
}

impl std::ops::Deref for LibraryProof {
    type Target = VerifiedProof;
    fn deref(&self) -> &Self::Target {
        &self.proof
    }
}

type StatementIndex = BTreeMap<Vec<u8>, BTreeSet<(AdmissionCoordinate, ProofId)>>;

/// A verified result that cannot be constructed by supplying unchecked fields.
#[derive(Clone)]
pub struct NormalizedPackage {
    author: AccountId,
    root: ProofId,
    outcome: ProofOutcome,
    original_hash: PackageHash,
    parent_library_root: [u8; 32],
    proofs: Vec<VerifiedProof>,
    substitutions: BTreeMap<ProofId, ProofId>,
    citations: Vec<ProofId>,
    final_bytes: Vec<u8>,
    work: VerificationWork,
    publication_dag: crate::ArtifactDag,
}

impl NormalizedPackage {
    pub fn author(&self) -> AccountId {
        self.author
    }
    pub fn root(&self) -> ProofId {
        self.root
    }
    pub fn outcome(&self) -> ProofOutcome {
        self.outcome
    }
    pub fn original_hash(&self) -> PackageHash {
        self.original_hash
    }
    pub fn parent_library_root(&self) -> [u8; 32] {
        self.parent_library_root
    }
    pub fn new_proofs(&self) -> &[VerifiedProof] {
        &self.proofs
    }
    pub fn substitutions(&self) -> &BTreeMap<ProofId, ProofId> {
        &self.substitutions
    }
    pub fn citations(&self) -> &[ProofId] {
        &self.citations
    }
    pub fn final_bytes(&self) -> &[u8] {
        &self.final_bytes
    }
    pub fn work(&self) -> VerificationWork {
        self.work
    }
}

/// Selected research proofs. Only an entire verified package can be published.
#[derive(Clone, Default)]
pub struct ProofLibrary {
    dag: crate::ArtifactDag,
    records: Arc<BTreeMap<ProofId, Arc<LibraryProof>>>,
    cached_root: OnceLock<[u8; 32]>,
    statements: Arc<StatementIndex>,
}

impl ProofLibrary {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn lookup(&self, id: ProofId) -> Option<&LibraryProof> {
        self.records.get(&id).map(AsRef::as_ref)
    }
    pub fn proofs(&self) -> impl Iterator<Item = &LibraryProof> {
        self.records.values().map(AsRef::as_ref)
    }

    /// The immutable checked artifact component. Its set is exactly the proofs
    /// encoded by this library; the complete state commitment additionally binds
    /// publication provenance, accounts, questions, rewards, and claims.
    pub fn artifact_dag(&self) -> &crate::ArtifactDag {
        &self.dag
    }

    /// Selects the earliest exact conclusion, never an equivalent or opposite one.
    pub fn exact_target(&self, conclusion: &Formula) -> Option<&LibraryProof> {
        let bytes = conclusion.encode_canonical().ok()?;
        let (_, id) = self.statements.get(&bytes)?.first()?;
        self.lookup(*id)
    }

    pub fn known_target(&self, question: &CompiledQuestion) -> Option<&LibraryProof> {
        [
            self.exact_target(question.proved_target()),
            self.exact_target(question.refuted_target()),
        ]
        .into_iter()
        .flatten()
        .min_by_key(|proof| (proof.coordinate, proof.proof_id))
    }

    /// Canonical complete proof-library state; finality must additionally bind all
    /// research, account, phase, and monetary state outside this component.
    pub fn encode(&self) -> Result<Vec<u8>, ResearchError> {
        let mut w = Writer::new();
        self.encode_into(&mut w)?;
        Ok(w.finish())
    }

    fn encode_into(&self, w: &mut Writer) -> Result<(), ResearchError> {
        w.u16(1);
        w.u64(self.records.len() as u64);
        for proof in self.records.values() {
            w.fixed(proof.proof_id.as_bytes());
            w.fixed(proof.statement_id.as_bytes());
            w.bytes(&proof.conclusion.encode_canonical().map_err(math)?)?;
            w.bytes(&proof.bytes)?;
            w.fixed(proof.author.as_bytes());
            w.u64(proof.coordinate.height);
            w.u32(proof.coordinate.operation_index);
            w.u32(proof.dependencies.len() as u32);
            for id in &proof.dependencies {
                w.fixed(id.as_bytes());
            }
        }
        Ok(())
    }

    pub fn root(&self) -> [u8; 32] {
        if let Some(root) = self.cached_root.get() {
            return *root;
        }
        let mut count = Writer::counting();
        self.encode_into(&mut count)
            .expect("verified library fields fit canonical encoding");
        let mut digest = Writer::hashing(b"naome:state:proof-library:v1\0", count.len());
        self.encode_into(&mut digest)
            .expect("verified library fields fit canonical encoding");
        let root = digest.finish_hash();
        let _ = self.cached_root.set(root);
        root
    }

    /// Publication uses temporary state and is all-or-nothing. The enclosing
    /// state machine must atomically commit this alongside outcome and rewards.
    pub fn publish(
        &mut self,
        package: &NormalizedPackage,
        coordinate: AdmissionCoordinate,
    ) -> Result<(), ResearchError> {
        if self.root() != package.parent_library_root {
            return Err(ResearchError::Invalid("normalization parent changed"));
        }
        let mut staged = self.clone();
        for proof in &package.proofs {
            if staged.records.contains_key(&proof.proof_id)
                || staged.exact_target(&proof.conclusion).is_some()
            {
                return Err(ResearchError::Invalid("proof already selected"));
            }
            let published = LibraryProof {
                proof: proof.clone(),
                coordinate,
            };
            Arc::make_mut(&mut staged.statements)
                .entry(published.conclusion.encode_canonical().map_err(math)?)
                .or_default()
                .insert((coordinate, published.proof_id));
            Arc::make_mut(&mut staged.records).insert(published.proof_id, Arc::new(published));
        }
        staged.dag = package.publication_dag.clone();
        staged.cached_root = OnceLock::new();
        *self = staged;
        Ok(())
    }

    pub fn normalize(
        &self,
        package: &ProofPackage,
        question: &CompiledQuestion,
        profile: &Profile,
    ) -> Result<NormalizedPackage, ResearchError> {
        verification::normalize(
            self,
            package,
            question,
            profile,
            &mut VerificationWork::default(),
        )
    }

    /// Shares one record budget across every original and normalized package,
    /// charging before each checker call rather than after a whole reveal.
    /// Checks and normalizes against this immutable library while charging a
    /// caller-owned cumulative record budget. This grants no publication authority.
    pub fn normalize_with_work(
        &self,
        package: &ProofPackage,
        question: &CompiledQuestion,
        profile: &Profile,
        work: &mut VerificationWork,
    ) -> Result<NormalizedPackage, ResearchError> {
        verification::normalize(self, package, question, profile, work)
    }
}

fn math(error: impl std::fmt::Display) -> ResearchError {
    ResearchError::Mathematical(error.to_string())
}

fn record(checked: &CheckedProof, author: AccountId) -> VerifiedProof {
    VerifiedProof {
        proof_id: checked.proof_id(),
        statement_id: checked.statement_id(),
        conclusion: checked.conclusion().clone(),
        bytes: checked.normal_form().canonical_bytes().to_vec(),
        dependencies: dependencies(checked.normal_form().certificate()),
        author,
    }
}

#[cfg(test)]
mod tests;

impl std::fmt::Debug for NormalizedPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NormalizedPackage")
            .field("root", &self.root)
            .field("outcome", &self.outcome)
            .field("proofs", &self.proofs)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ProofLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofLibrary")
            .field("proof_count", &self.len())
            .field("cached_root", &self.cached_root.get())
            .finish_non_exhaustive()
    }
}
