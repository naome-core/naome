//! Complete deterministic research state. Provisional execution grants no finality.

use crate::{
    AccountId, CommitmentId, LedgerError, OperationId, QuestionId, RecordId, ResolutionId,
    SolutionRoundId, StateCommitment,
    accounting::{Balances, CitationRecipient, RewardPlan},
    authentication::SignedOperation,
    capacity::Capacity,
    codec::Writer,
    identity::hash,
    library::{
        AdmissionCoordinate, NormalizedPackage, ProofLibrary, ProofOutcome, VerificationWork,
    },
    operations::{JoinIntent, OperationBody, SignedOriginal},
    profile::Genesis,
    question::{CompiledQuestion, QuestionContext, checker_profile_id, solution_round_id},
    time::TimeCertificate,
};
use naome_proof::ProofId;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

mod encoding;
#[cfg(test)]
mod tests;
mod transition;

/// An attempt phase advances only through a validated finalized record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Voting,
    ApprovedWait,
    Commit,
    CommitClosedWait,
    Reveal,
    SettlementPending,
}

/// Visible lifecycle of a particular submitted question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuestionStatus {
    Queued,
    Active,
    NotApproved,
    Unresolved,
    KnownUnpaid,
    Completed,
    Expired,
    CapacityEnd,
}

/// Immutable input and current status of a finalized question submission.
#[derive(Clone, Debug)]
pub struct QuestionEntry {
    submission: OperationId,
    author: AccountId,
    purpose: String,
    question: CompiledQuestion,
    admitted: AdmissionCoordinate,
    expires: u64,
    status: QuestionStatus,
    opened_question: Option<QuestionId>,
}
impl QuestionEntry {
    pub const fn submission(&self) -> OperationId {
        self.submission
    }
    pub const fn author(&self) -> AccountId {
        self.author
    }
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
    pub fn question(&self) -> &CompiledQuestion {
        &self.question
    }
    pub const fn admitted(&self) -> AdmissionCoordinate {
        self.admitted
    }
    pub const fn expires(&self) -> u64 {
        self.expires
    }
    pub const fn status(&self) -> QuestionStatus {
        self.status
    }
    pub const fn opened_question(&self) -> Option<QuestionId> {
        self.opened_question
    }
}

/// Idempotent successful action receipt. Its record identity is recovered from
/// history, avoiding a record/successor-state self-hash cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub operation: OperationId,
    pub author: AccountId,
    pub nonce: u64,
    pub coordinate: AdmissionCoordinate,
}

#[derive(Clone)]
struct CommitmentEntry {
    id: CommitmentId,
    receipt: Receipt,
    reserved_bytes: u64,
    reveal: Option<AcceptedReveal>,
}
#[derive(Clone)]
struct AcceptedReveal {
    receipt: Receipt,
    original: Arc<SignedOriginal>,
}

#[derive(Clone)]
struct Attempt {
    submission: OperationId,
    question_id: QuestionId,
    family: ResolutionId,
    number: u64,
    phase: Phase,
    deadline: Option<u64>,
    round: Option<SolutionRoundId>,
    votes: BTreeMap<AccountId, bool>,
    commitments: BTreeMap<AccountId, CommitmentEntry>,
}

/// A read-only view suitable for scheduling and CLI status.
#[derive(Clone, Debug)]
pub struct ActiveAttempt {
    pub submission: OperationId,
    pub question: QuestionId,
    pub family: ResolutionId,
    pub number: u64,
    pub phase: Phase,
    pub deadline: Option<u64>,
    pub solution_round: Option<SolutionRoundId>,
    pub votes: BTreeMap<AccountId, bool>,
    pub commitments: usize,
    pub reveals: usize,
}

/// A permanently consumed family; unpaid known proofs create no issuance.
#[derive(Clone, Debug)]
pub enum FamilyResult {
    KnownUnpaid {
        proof: ProofId,
    },
    Completed {
        proof: ProofId,
        author: AccountId,
        outcome: ProofOutcome,
        ordinal: u64,
        normalization_receipt: Arc<[u8]>,
    },
}

/// A one-time nontransferable record, with no active voting rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EligibilityClaim {
    pub family: ResolutionId,
    pub author: AccountId,
    pub completion_ordinal: u64,
}

/// The current finalized candidate consent for a later handoff. The author may
/// supersede it before activation; no intent consumes the claim or grants weight.
#[derive(Clone)]
pub struct JoinIntentEntry {
    intent: JoinIntent,
    receipt: Receipt,
    signed_operation: Arc<[u8]>,
}
impl JoinIntentEntry {
    pub fn intent(&self) -> &JoinIntent {
        &self.intent
    }
    pub const fn receipt(&self) -> Receipt {
        self.receipt
    }
    /// Exact authenticated bytes committed to state, including possession proofs.
    pub fn signed_operation(&self) -> &[u8] {
        &self.signed_operation
    }
}

/// All application state required by deterministic replay. The selected journal
/// and consensus layer, not this in-memory type, determine what is finalized.
#[derive(Clone)]
pub struct LedgerState {
    genesis: Arc<Genesis>,
    height: u64,
    head: RecordId,
    time: u64,
    library: ProofLibrary,
    accounts: BTreeMap<AccountId, [u8; 32]>,
    balances: Balances,
    next_nonce: BTreeMap<AccountId, u64>,
    receipts: BTreeMap<OperationId, Receipt>,
    nonce_receipts: BTreeMap<(AccountId, u64), OperationId>,
    questions: BTreeMap<OperationId, Arc<QuestionEntry>>,
    queue: VecDeque<OperationId>,
    attempt_numbers: BTreeMap<ResolutionId, u64>,
    active: Option<Attempt>,
    families: BTreeMap<ResolutionId, FamilyResult>,
    claims: BTreeMap<ResolutionId, EligibilityClaim>,
    join_intents: BTreeMap<ResolutionId, JoinIntentEntry>,
    capacity: Capacity,
    terminated: bool,
}

impl LedgerState {
    /// Constructs the empty adopted test genesis. All balances and proof sets are zero.
    pub fn new(genesis: Genesis) -> Self {
        let head = RecordId::from_bytes(hash(
            b"naome:state:genesis-record:v1\0",
            &[genesis.id().as_bytes()],
        ));
        let time = genesis.start_utc();
        let balances = Balances::new(&genesis);
        let capacity = Capacity::new(genesis.profile());
        let next_nonce = genesis.accounts().iter().map(|a| (a.id(), 1)).collect();
        let accounts = genesis
            .accounts()
            .iter()
            .map(|a| (a.id(), *a.key()))
            .collect();
        Self {
            genesis: Arc::new(genesis),
            height: 0,
            head,
            time,
            library: ProofLibrary::new(),
            accounts,
            balances,
            next_nonce,
            receipts: BTreeMap::new(),
            nonce_receipts: BTreeMap::new(),
            questions: BTreeMap::new(),
            queue: VecDeque::new(),
            attempt_numbers: BTreeMap::new(),
            active: None,
            families: BTreeMap::new(),
            claims: BTreeMap::new(),
            join_intents: BTreeMap::new(),
            capacity,
            terminated: false,
        }
    }
    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn head(&self) -> RecordId {
        self.head
    }
    pub const fn time(&self) -> u64 {
        self.time
    }
    pub const fn terminated(&self) -> bool {
        self.terminated
    }
    pub fn library(&self) -> &ProofLibrary {
        &self.library
    }
    pub fn balances(&self) -> &Balances {
        &self.balances
    }
    /// Canonically admitted research keys, including the initial genesis accounts.
    /// Membership grants no validator or consensus authority.
    pub fn accounts(&self) -> &BTreeMap<AccountId, [u8; 32]> {
        &self.accounts
    }
    pub fn account_key(&self, account: AccountId) -> Option<&[u8; 32]> {
        self.accounts.get(&account)
    }
    /// Capacity availability only; finalized admission also checks the record's
    /// automatic transitions, key roles and exact next nonce.
    pub fn registration_available(&self) -> bool {
        !self.terminated
            && (self.accounts.len() as u64) < self.genesis.profile().limits().registered_accounts
            && self.capacity.remaining() > self.capacity.reserved() + 1
            && (self.active.is_some() || self.capacity.can_open(self.genesis.profile()))
    }
    pub fn receipt(&self, id: OperationId) -> Option<&Receipt> {
        self.receipts.get(&id)
    }
    pub fn next_nonce(&self, author: AccountId) -> Option<u64> {
        self.next_nonce.get(&author).copied()
    }
    pub fn question(&self, id: OperationId) -> Option<&QuestionEntry> {
        self.questions.get(&id).map(Arc::as_ref)
    }
    pub fn questions(&self) -> impl Iterator<Item = &QuestionEntry> {
        self.questions.values().map(Arc::as_ref)
    }
    pub fn queued(&self) -> impl Iterator<Item = &QuestionEntry> {
        self.queue
            .iter()
            .filter_map(|id| self.questions.get(id).map(Arc::as_ref))
    }
    pub fn families(&self) -> &BTreeMap<ResolutionId, FamilyResult> {
        &self.families
    }
    pub fn claims(&self) -> &BTreeMap<ResolutionId, EligibilityClaim> {
        &self.claims
    }
    /// Current finalized join preparation per claim, never the active set.
    pub fn join_intents(&self) -> &BTreeMap<ResolutionId, JoinIntentEntry> {
        &self.join_intents
    }
    pub fn join_intent(&self, family: ResolutionId) -> Option<&JoinIntentEntry> {
        self.join_intents.get(&family)
    }
    /// Cheap local intake preview. Final admission also verifies candidate keys,
    /// endpoint uniqueness, nonce, automatic transitions, and ordinary capacity.
    pub fn can_submit_join_intent(
        &self,
        author: AccountId,
        family: ResolutionId,
        ordinal: u64,
    ) -> bool {
        !self.terminated
            && self.capacity.remaining() > self.capacity.reserved() + 1
            && (self.active.is_some() || self.capacity.can_open(self.genesis.profile()))
            && self
                .claims
                .get(&family)
                .is_some_and(|claim| claim.author == author && claim.completion_ordinal == ordinal)
            && matches!(
                self.families.get(&family),
                Some(FamilyResult::Completed {
                    author: completed_author,
                    ordinal: completed_ordinal,
                    ..
                }) if *completed_author == author && *completed_ordinal == ordinal
            )
    }
    pub fn remaining_records(&self) -> u64 {
        self.capacity.remaining()
    }
    pub fn reserved_records(&self) -> u64 {
        self.capacity.reserved()
    }
    pub fn remaining_bytes(&self) -> u64 {
        self.capacity.remaining_bytes()
    }
    pub fn reserved_bytes(&self) -> u64 {
        self.capacity.reserved_bytes()
    }
    pub fn active(&self) -> Option<ActiveAttempt> {
        self.active.as_ref().map(|a| ActiveAttempt {
            submission: a.submission,
            question: a.question_id,
            family: a.family,
            number: a.number,
            phase: a.phase,
            deadline: a.deadline,
            solution_round: a.round,
            votes: a.votes.clone(),
            commitments: a.commitments.len(),
            reveals: a
                .commitments
                .values()
                .filter(|c| c.reveal.is_some())
                .count(),
        })
    }
    pub fn active_question(&self) -> Option<&QuestionEntry> {
        self.active
            .as_ref()
            .and_then(|a| self.questions.get(&a.submission).map(Arc::as_ref))
    }
    /// Whether this author already occupies a commitment slot in the active attempt.
    pub fn has_active_commitment(&self, author: AccountId) -> bool {
        self.active
            .as_ref()
            .is_some_and(|attempt| attempt.commitments.contains_key(&author))
    }
    /// Checks an outstanding finalized reveal reservation for local queue priority.
    /// The reveal still requires signature, deadline and mathematical validation.
    pub fn awaiting_reveal(&self, author: AccountId, commitment: CommitmentId) -> bool {
        self.active.as_ref().is_some_and(|attempt| {
            attempt.phase == Phase::Reveal
                && attempt
                    .commitments
                    .get(&author)
                    .is_some_and(|entry| entry.id == commitment && entry.reveal.is_none())
        })
    }
    /// A complete state commitment includes content roots for immutable bytes,
    /// every account/receipt/question/phase/family/claim and both resource budgets.
    pub fn commitment(&self) -> StateCommitment {
        let mut count = Writer::counting();
        self.write_state(&mut count);
        let mut digest = Writer::hashing(b"naome:state:state:v4\0", count.len());
        self.write_state(&mut digest);
        StateCommitment::from_bytes(digest.finish_hash())
    }
    /// Materializes the canonical application state for independent inspection.
    /// Ordinary commitment calculation streams these bytes without allocating them.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.write_state(&mut writer);
        writer.finish()
    }

    /// Executes operations provisionally against this exact parent. This does
    /// not construct a chain record, select history, or grant finality.
    pub fn execute(
        &self,
        time: TimeCertificate,
        operations: Vec<SignedOperation>,
    ) -> Result<LedgerExecution, LedgerError> {
        self.prepare(time, operations)
    }
}

/// Deterministically checked ledger effects awaiting a canonical chain record.
/// The provisional successor retains its parent's record identity until bound
/// by the chain layer. Consensus must still verify and finalize that record.
pub struct LedgerExecution {
    next: LedgerState,
    time: TimeCertificate,
    operations: Vec<SignedOperation>,
    effects: Vec<u8>,
}
impl LedgerExecution {
    pub fn state(&self) -> &LedgerState {
        &self.next
    }
    pub fn time_certificate(&self) -> &TimeCertificate {
        &self.time
    }
    pub fn operations(&self) -> &[SignedOperation] {
        &self.operations
    }
    pub fn effects(&self) -> &[u8] {
        &self.effects
    }

    /// Binds an externally constructed chain identity to a provisional result.
    /// This supplies no proof that the identifier is a valid record and grants
    /// no selected-history authority; consensus must replay the chain record.
    pub fn bind_record(mut self, record: RecordId) -> LedgerState {
        self.next.head = record;
        self.next
    }
}
