//! Existing-system inputs for the local experiment. No chain or reward writes.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use naome_checker::{
    ArtifactState, ArtifactStateError, CheckedProof, normalize_and_check_with_state,
};
use naome_foundation::Formula;
use naome_ledger::{RecordId, state::LedgerState};
use naome_proof::{ProofCertificate, ProofStep};
use naome_research::state::ResearchState;

use crate::{
    Applied, Candidate, Citation, CitationId, Config, Event, EventId, Input, InputError,
    Orchestrator, ParticipantId, ProofId, QuestionId, ResultId, Verdict, VerificationReceipt,
};

#[derive(Debug, PartialEq, Eq)]
pub enum AdapterError {
    UnknownQuestion,
    UnknownParticipant,
    Certificate(String),
    Checking(String),
    TargetMismatch,
    IdentityMismatch,
    Registration(String),
    Input(InputError),
}

/// A fixed confirmed local research snapshot, not a finalized blockchain view.
/// Legacy answered questions are excluded rather than awarded retroactive rewards.
/// Later research confirmations require a new explicit import; this is not a feed.
pub struct ResearchImport {
    pub core: Orchestrator,
    pub verifier: ProofAdapter,
    pub research_head: [u8; 32],
    /// First unused local event ID after the imported registrations and approvals.
    pub next_event: EventId,
}

impl ResearchImport {
    pub fn new(source: &ResearchState, config: Config) -> Result<Self, String> {
        let mut core = Orchestrator::new(config);
        let mut targets = BTreeMap::new();
        let participants: BTreeSet<_> = source
            .genesis()
            .genesis
            .participants
            .iter()
            .map(ParticipantId::for_key)
            .collect();
        let mut next = 1;
        for (id, question) in source.questions() {
            if source.solved(*id) {
                continue;
            }
            let question_id = QuestionId(*id);
            targets.insert(question_id, question.formula()?);
            core.apply(Event {
                id: EventId(next),
                input: Input::RegisterQuestion(question_id),
            })
            .map_err(|error| format!("snapshot registration: {error:?}"))?;
            next += 1;
            for key in &source.genesis().genesis.participants {
                if source.vote(*key, *id) == Some(true) {
                    core.apply(Event {
                        id: EventId(next),
                        input: Input::Approval {
                            question: question_id,
                            participant: ParticipantId::for_key(key),
                            approved: true,
                        },
                    })
                    .map_err(|error| format!("snapshot approval: {error:?}"))?;
                    next += 1;
                }
            }
        }
        Ok(Self {
            core,
            verifier: ProofAdapter {
                artifacts: source.artifacts().clone(),
                targets,
                participants,
                proof_questions: BTreeMap::new(),
            },
            research_head: source.head(),
            next_event: EventId(next),
        })
    }
}

/// Validity, native identities and the normalized step metric stay coupled.
/// The request's solver must still be authenticated by the caller.
#[derive(Debug)]
pub struct VerifiedSubmission {
    receipt: VerificationReceipt,
    checked: CheckedProof,
}

impl VerifiedSubmission {
    /// Inspect the receipt. Real adapter admissions must use `apply_verified` to
    /// keep artifact registration and selection coupled.
    pub fn receipt(&self) -> VerificationReceipt {
        self.receipt
    }
}

/// A checked citing derivation and its distinct direct references. Its exact proof
/// may already be selected; different packages of an admitted derivation fail.
/// Caller authentication and ordered citation admission remain external duties.
#[derive(Debug)]
pub struct VerifiedCitation {
    checked: CheckedProof,
    citations: Vec<Citation>,
}

impl VerifiedCitation {
    pub fn proof_id(&self) -> ProofId {
        self.checked.proof_id()
    }
    pub fn verified_steps(&self) -> NonZeroU64 {
        step_count(&self.checked)
    }
    pub fn citations(&self) -> &[Citation] {
        &self.citations
    }
}

/// Owns checked artifacts in an explicitly experimental local context. Selected
/// improvements retain prior artifacts so references to old proofs still resolve.
/// This context and its question bindings are not persisted or written to a ledger.
pub struct ProofAdapter {
    artifacts: ArtifactState,
    targets: BTreeMap<QuestionId, Formula>,
    participants: BTreeSet<ParticipantId>,
    proof_questions: BTreeMap<ProofId, (QuestionId, ResultId)>,
}

impl ProofAdapter {
    fn check(&self, bytes: &[u8]) -> Result<CheckedProof, AdapterError> {
        let certificate = ProofCertificate::from_canonical_bytes(bytes)
            .map_err(|error| AdapterError::Certificate(error.to_string()))?;
        normalize_and_check_with_state(certificate, &self.artifacts)
            .map_err(|error| AdapterError::Checking(error.to_string()))
    }

    fn check_new(&self, bytes: &[u8]) -> Result<CheckedProof, AdapterError> {
        let checked = self.check(bytes)?;
        // Mathematical validity alone permits aliases. Normal registration makes
        // derivation identity transparent to inline/reference packaging shortcuts.
        self.artifacts
            .validate_proof_registration(&checked)
            .map_err(|error| AdapterError::Registration(error.to_string()))?;
        Ok(checked)
    }

    pub fn verify(
        &self,
        request: Candidate,
        bytes: &[u8],
    ) -> Result<VerifiedSubmission, AdapterError> {
        let target = self
            .targets
            .get(&request.question)
            .ok_or(AdapterError::UnknownQuestion)?;
        if !self.participants.contains(&request.solver) {
            return Err(AdapterError::UnknownParticipant);
        }
        let checked = self.check_new(bytes)?;
        if checked.conclusion() != target
            && checked.conclusion() != &Formula::negate(target.clone())
        {
            return Err(AdapterError::TargetMismatch);
        }
        if checked.proof_id() != request.proof || checked.statement_id() != request.result {
            return Err(AdapterError::IdentityMismatch);
        }
        Ok(VerifiedSubmission {
            receipt: VerificationReceipt {
                request,
                verdict: Verdict::Valid {
                    verified_steps: step_count(&checked),
                },
            },
            checked,
        })
    }

    /// Revalidate and stage artifact registration before changing the selection.
    /// On registration or input failure, neither context nor core is changed.
    /// This acceptance supports mock publication; it establishes no block inclusion.
    pub fn apply_verified(
        &mut self,
        core: &mut Orchestrator,
        event: EventId,
        verified: VerifiedSubmission,
    ) -> Result<Applied, AdapterError> {
        let receipt = verified.receipt;
        // Another admission may have changed the context since verification.
        // Stage all fallible registration work before the core can enqueue effects.
        let mut staged = self.artifacts.clone();
        staged
            .register_proof(verified.checked)
            .map_err(|error| AdapterError::Registration(error.to_string()))?;
        let applied = core
            .apply(Event {
                id: event,
                input: Input::Verified(receipt),
            })
            .map_err(AdapterError::Input)?;
        if applied == Applied::Selected {
            self.artifacts = staged;
            self.proof_questions.insert(
                receipt.request.proof,
                (receipt.request.question, receipt.request.result),
            );
        }
        Ok(applied)
    }

    /// Extract direct citations from a new proof or the exact proof already
    /// admitted by `apply_verified`. Mathematical checking still runs on retries.
    pub fn verify_citation(&self, bytes: &[u8]) -> Result<VerifiedCitation, AdapterError> {
        let checked = self.check(bytes)?;
        match self.artifacts.validate_proof_registration(&checked) {
            Ok(()) | Err(ArtifactStateError::DuplicateProof { .. }) => {}
            Err(error) => return Err(AdapterError::Registration(error.to_string())),
        }
        let mut cited = BTreeMap::new();
        for step in checked.normal_form().certificate().steps() {
            if let ProofStep::ProofReference { proof_id } = step
                && let Some((question, result)) = self.proof_questions.get(proof_id)
            {
                cited.insert(*question, *result);
            }
        }
        let citations = cited
            .into_iter()
            .map(|(question, result)| Citation {
                citation: CitationId {
                    citing_proof: checked.proof_id(),
                    question,
                },
                question,
                result,
            })
            .collect();
        Ok(VerifiedCitation { checked, citations })
    }

    /// Admit a checked citing proof, or reuse its exact existing admission, and
    /// return citation inputs. Select a solving proof with `apply_verified` first.
    /// Repeated citation inputs carry the same IDs and are deduplicated by the core;
    /// actual publication and input order remain controlled by the caller.
    pub fn admit_citation(
        &mut self,
        verified: VerifiedCitation,
    ) -> Result<Vec<Citation>, AdapterError> {
        match self.artifacts.register_proof(verified.checked) {
            Ok(_) | Err(ArtifactStateError::DuplicateProof { .. }) => {}
            Err(error) => return Err(AdapterError::Registration(error.to_string())),
        }
        Ok(verified.citations)
    }
}

fn step_count(checked: &CheckedProof) -> NonZeroU64 {
    // Counts canonical root-reachable certificate steps. Each ProofReference is
    // one step; no transitive expansion and no unused authoring padding is counted.
    NonZeroU64::new(checked.normal_form().certificate().steps().len() as u64)
        .expect("checked certificates contain a root step")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceObservation {
    pub ledger_head: RecordId,
    pub account: ParticipantId,
    /// Exact ledger atoms, never the experiment's whole-NAO mock amounts.
    pub balance_atoms: u128,
}

/// Read the supplied ledger snapshot. Its authoritative history must be established
/// by the caller; this observation neither credits accounts nor proves finality.
pub fn observe_balance(source: &LedgerState, account: ParticipantId) -> Option<BalanceObservation> {
    source
        .balances()
        .account(account)
        .map(|balance_atoms| BalanceObservation {
            ledger_head: source.head(),
            account,
            balance_atoms,
        })
}
