//! Provisioning, strict reopen, and signing-lineage issuance.

use super::*;

/// Four exact caller-owned storage namespaces used by one local signer.
///
/// Directories may be shared when the underlying typed filenames and locks do
/// not collide. This value neither creates directories nor chooses a layout.
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct FixedValidatorNodeDirectoriesV0<'path> {
    finality_journal: &'path Path,
    finality_anchor: &'path Path,
    vote_journal: &'path Path,
    vote_anchor: &'path Path,
}

impl<'path> FixedValidatorNodeDirectoriesV0<'path> {
    /// Binds the exact directories supplied by the caller.
    pub const fn new(
        finality_journal: &'path Path,
        finality_anchor: &'path Path,
        vote_journal: &'path Path,
        vote_anchor: &'path Path,
    ) -> Self {
        Self {
            finality_journal,
            finality_anchor,
            vote_journal,
            vote_anchor,
        }
    }

    /// Returns the finality-journal directory.
    pub const fn finality_journal(self) -> &'path Path {
        self.finality_journal
    }

    /// Returns the finality-anchor directory.
    pub const fn finality_anchor(self) -> &'path Path {
        self.finality_anchor
    }

    /// Returns the per-key vote-journal directory.
    pub const fn vote_journal(self) -> &'path Path {
        self.vote_journal
    }

    /// Returns the per-key vote-anchor directory.
    pub const fn vote_anchor(self) -> &'path Path {
        self.vote_anchor
    }
}

/// Caller-local maximum sequential finality-to-signer height handoffs.
///
/// Zero is valid and permits only a signer already caught up to finality. This
/// local work bound grants no finality, branch-selection, or recovery authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorSignerCatchUpHeightLimitV0(u64);

impl FixedValidatorSignerCatchUpHeightLimitV0 {
    /// Constructs an inclusive height-handoff limit, including zero.
    pub const fn new(maximum: u64) -> Self {
        Self(maximum)
    }

    /// Returns the inclusive maximum number of sequential height handoffs.
    pub const fn maximum(self) -> u64 {
        self.0
    }
}

/// Exact caller-selected inputs for one fixed-validator V0 node startup.
///
/// This is an in-memory typed boundary, not an operator configuration format.
/// It deliberately provides no defaults and owns no signing key.
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct FixedValidatorNodeProvisionV0<'config> {
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    fixed_entries: &'config [ActiveAgreementEntry],
    directories: FixedValidatorNodeDirectoriesV0<'config>,
    finality_replay_limit: FixedValidatorFinalityReplayLimitV0,
    vote_replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
    proposal_replay_limit: FixedValidatorProposalReplayLimitV0,
    signer_recovery_round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
    signer_catch_up_height_limit: FixedValidatorSignerCatchUpHeightLimitV0,
}

impl<'config> FixedValidatorNodeProvisionV0<'config> {
    /// Binds every exact caller-selected startup input.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        definition: ArtifactChainDefinition,
        context: ConsensusContextV0,
        fixed_entries: &'config [ActiveAgreementEntry],
        directories: FixedValidatorNodeDirectoriesV0<'config>,
        finality_replay_limit: FixedValidatorFinalityReplayLimitV0,
        vote_replay_limit: FixedValidatorVoteSafetyReplayLimitV0,
        proposal_replay_limit: FixedValidatorProposalReplayLimitV0,
        signer_recovery_round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
        signer_catch_up_height_limit: FixedValidatorSignerCatchUpHeightLimitV0,
    ) -> Self {
        Self {
            definition,
            context,
            fixed_entries,
            directories,
            finality_replay_limit,
            vote_replay_limit,
            proposal_replay_limit,
            signer_recovery_round_limit,
            signer_catch_up_height_limit,
        }
    }

    /// Creates both anchored pairs and binds the exact initial lineage.
    ///
    /// Configuration is preflighted before file access. Creation is ordered but
    /// not cross-file atomic; a later failure never removes an earlier durable
    /// pair.
    pub fn create(
        self,
        signing_key: SigningKey,
    ) -> Result<FixedValidatorNodeReadyV0, FixedValidatorNodeStartupErrorV0> {
        let preflight_branch = self.preflight(&signing_key)?;
        let fixed_set_id = preflight_branch.fixed_agreement_set_id();
        let finality = FixedValidatorAnchoredFinalityJournalV0::create(
            self.directories.finality_journal,
            self.directories.finality_anchor,
            self.definition,
            self.context,
            self.fixed_entries,
            self.finality_replay_limit,
        )
        .map_err(FixedValidatorNodeStartupErrorV0::finality_pair)?;
        let mut vote = FixedValidatorAnchoredVoteSafetyJournalV0::create(
            self.directories.vote_journal,
            self.directories.vote_anchor,
            self.context,
            fixed_set_id,
            signing_key,
            self.vote_replay_limit,
        )
        .map_err(FixedValidatorNodeStartupErrorV0::vote_pair)?;
        let _ = vote
            .activate_proposal_authoring(self.proposal_replay_limit)
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
        let branch = finality
            .head()
            .map_err(FixedValidatorNodeStartupErrorV0::finality)?
            .clone();
        debug_assert_eq!(branch.coordinate(), preflight_branch.coordinate());
        let round = branch
            .begin_round_zero()
            .map_err(FixedValidatorNodeStartupErrorV0::Consensus)?;
        let _ = vote
            .bind_signing_lineage(&round)
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
        drop(round);
        Ok(FixedValidatorNodeReadyV0 {
            finality,
            vote,
            session_plan: FixedValidatorNodeSessionPlanV0::Initial(branch),
            signer_recovery_round_limit: self.signer_recovery_round_limit,
            signer_catch_up_height_limit: self.signer_catch_up_height_limit,
        })
    }

    /// Strictly opens both anchored pairs and classifies the restart state.
    ///
    /// An anchored finality conflict is monotonically routed into the signer
    /// before any recovery capability can be issued.
    pub fn open(
        self,
        signing_key: SigningKey,
    ) -> Result<FixedValidatorNodeStartupV0, FixedValidatorNodeStartupErrorV0> {
        let preflight_branch = self.preflight(&signing_key)?;
        let fixed_set_id = preflight_branch.fixed_agreement_set_id();
        let finality = FixedValidatorAnchoredFinalityJournalV0::open(
            self.directories.finality_journal,
            self.directories.finality_anchor,
            self.definition,
            self.context,
            self.fixed_entries,
            self.finality_replay_limit,
        )
        .map_err(FixedValidatorNodeStartupErrorV0::finality_pair)?;
        let mut vote = FixedValidatorAnchoredVoteSafetyJournalV0::open(
            self.directories.vote_journal,
            self.directories.vote_anchor,
            self.context,
            fixed_set_id,
            signing_key,
            self.vote_replay_limit,
        )
        .map_err(FixedValidatorNodeStartupErrorV0::vote_pair)?;

        if let Some(finality_halt) = finality
            .halt()
            .map_err(FixedValidatorNodeStartupErrorV0::finality)?
        {
            let stop = finality
                .acknowledge_signer_stop()
                .map_err(FixedValidatorNodeStartupErrorV0::finality)?;
            let outcome = vote
                .stop_after_durable_finality_conflict(stop)
                .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
            let signer_stop = match outcome {
                FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stop)
                | FixedValidatorFinalityConflictSignerStopOutcomeV0::AlreadyStopped(stop) => stop,
            };
            return Ok(FixedValidatorNodeStartupV0::FinalityStopped(
                FixedValidatorNodeFinalityStoppedV0 {
                    finality_halt,
                    signer_stop,
                },
            ));
        }

        if let Some(halt) = vote
            .halt()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?
        {
            return Ok(FixedValidatorNodeStartupV0::SignerStopped(
                FixedValidatorNodeSignerStopV0::VoteSafety(halt),
            ));
        }
        if let Some(halt) = vote
            .proposal_halt()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?
        {
            return Ok(FixedValidatorNodeStartupV0::SignerStopped(
                FixedValidatorNodeSignerStopV0::ProposalSafety(halt),
            ));
        }
        if let Some(stop) = vote
            .finality_conflict_stop()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?
        {
            return Ok(FixedValidatorNodeStartupV0::SignerStopped(
                FixedValidatorNodeSignerStopV0::FinalityConflict(stop),
            ));
        }
        if let Some(pending) = vote
            .pending_vote()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?
        {
            return Ok(FixedValidatorNodeStartupV0::PendingPreparation(pending));
        }
        if let Some(pending) = vote
            .pending_proposal()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?
        {
            return Ok(FixedValidatorNodeStartupV0::PendingProposal(pending));
        }

        let _ = vote
            .activate_proposal_authoring(self.proposal_replay_limit)
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;

        let recovery = vote
            .acknowledge_signer_recovery()
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
        let recovered = finality
            .recover_anchored_signer_branch(recovery)
            .map_err(FixedValidatorNodeStartupErrorV0::finality)?;
        Ok(FixedValidatorNodeStartupV0::Ready(Box::new(
            FixedValidatorNodeReadyV0 {
                finality,
                vote,
                session_plan: FixedValidatorNodeSessionPlanV0::Recovered(recovered),
                signer_recovery_round_limit: self.signer_recovery_round_limit,
                signer_catch_up_height_limit: self.signer_catch_up_height_limit,
            },
        )))
    }

    fn preflight(
        self,
        signing_key: &SigningKey,
    ) -> Result<FixedConsensusBranchV0, FixedValidatorNodeStartupErrorV0> {
        let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
            self.context,
            self.fixed_entries,
            ArtifactChainState::new(self.definition).branch_snapshot(),
        )
        .map_err(FixedValidatorNodeStartupErrorV0::Genesis)?;
        let signer = ConsensusKey::from_bytes(signing_key.verifying_key().to_bytes());
        if !self
            .fixed_entries
            .iter()
            .any(|entry| entry.consensus_key() == signer)
        {
            return Err(FixedValidatorNodeStartupErrorV0::SignerNotInFixedSet { signer });
        }
        Ok(branch)
    }
}

/// A strictly opened node state that can issue exactly one scoped session.
#[must_use]
pub struct FixedValidatorNodeReadyV0 {
    pub(super) finality: FixedValidatorAnchoredFinalityJournalV0,
    pub(super) vote: FixedValidatorAnchoredVoteSafetyJournalV0,
    pub(super) session_plan: FixedValidatorNodeSessionPlanV0,
    pub(super) signer_recovery_round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
    pub(super) signer_catch_up_height_limit: FixedValidatorSignerCatchUpHeightLimitV0,
}

impl FixedValidatorNodeReadyV0 {
    /// Consumes the owner and runs one closure with its sole signing session.
    ///
    /// The higher-ranked closure result cannot retain a borrow of the scope, so
    /// the session cannot outlive either local journal owner.
    pub fn run_with_signing_session<R>(
        self,
        callback: impl for<'scope> FnOnce(FixedValidatorNodeSigningScopeV0<'scope>) -> R,
    ) -> Result<R, FixedValidatorNodeStartupErrorV0> {
        let Self {
            mut finality,
            mut vote,
            session_plan,
            signer_recovery_round_limit,
            signer_catch_up_height_limit,
        } = self;
        let scope = issue_signing_scope(
            &mut finality,
            &mut vote,
            session_plan,
            signer_recovery_round_limit,
            signer_catch_up_height_limit,
        )?;
        Ok(callback(scope))
    }

    /// Owns both anchored journals while awaiting one non-escaping callback.
    ///
    /// Constructing this future moves the ready owner but does not issue a
    /// session. On its first poll, the same synchronous issuance and bounded
    /// catch-up as [`Self::run_with_signing_session`] finish before the callback
    /// runs. Journal and proof operations remain synchronous, with no internal
    /// suspension or new persistence boundary.
    ///
    /// Dropping the outer future drops its callback and journals; it does not
    /// return callback-owned volatile runtime state or undo durable writes.
    /// Strict anchored reopen alone classifies the surviving durable prefix.
    /// The caller chooses the executor and polling lifetime; this method spawns
    /// no task and requires neither `Send` nor `'static` callback captures.
    ///
    /// The callback result cannot retain the scope:
    ///
    /// ```compile_fail
    /// use naome_node::{FixedValidatorNodeReadyV0, FixedValidatorNodeSigningScopeV0};
    ///
    /// async fn escape(ready: FixedValidatorNodeReadyV0) -> FixedValidatorNodeSigningScopeV0<'static> {
    ///     ready.run_with_signing_session_async(async |scope| scope).await.unwrap()
    /// }
    /// ```
    ///
    /// Nor can it return another future retaining the scope:
    ///
    /// ```compile_fail
    /// use naome_node::FixedValidatorNodeReadyV0;
    ///
    /// async fn escape_future(ready: FixedValidatorNodeReadyV0) {
    ///     let escaped = ready.run_with_signing_session_async(async |scope| {
    ///         async move { drop(scope); }
    ///     }).await.unwrap();
    ///     escaped.await;
    /// }
    /// ```
    pub async fn run_with_signing_session_async<R>(
        self,
        callback: impl for<'scope> AsyncFnOnce(FixedValidatorNodeSigningScopeV0<'scope>) -> R,
    ) -> Result<R, FixedValidatorNodeStartupErrorV0> {
        let Self {
            mut finality,
            mut vote,
            session_plan,
            signer_recovery_round_limit,
            signer_catch_up_height_limit,
        } = self;
        let scope = issue_signing_scope(
            &mut finality,
            &mut vote,
            session_plan,
            signer_recovery_round_limit,
            signer_catch_up_height_limit,
        )?;
        Ok(callback(scope).await)
    }
}

fn issue_signing_scope<'node>(
    finality: &'node mut FixedValidatorAnchoredFinalityJournalV0,
    vote: &'node mut FixedValidatorAnchoredVoteSafetyJournalV0,
    session_plan: FixedValidatorNodeSessionPlanV0,
    signer_recovery_round_limit: FixedValidatorSignerRecoveryRoundLimitV0,
    signer_catch_up_height_limit: FixedValidatorSignerCatchUpHeightLimitV0,
) -> Result<FixedValidatorNodeSigningScopeV0<'node>, FixedValidatorNodeStartupErrorV0> {
    let signer = vote.signer();
    let (branch, signing_session) = match session_plan {
        FixedValidatorNodeSessionPlanV0::Initial(branch) => {
            let round = branch
                .begin_round_zero()
                .map_err(FixedValidatorNodeStartupErrorV0::Consensus)?;
            let signing_session = vote
                .issue_signing_session(&round)
                .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
            drop(round);
            (branch, signing_session)
        }
        FixedValidatorNodeSessionPlanV0::Recovered(recovered) => {
            let recovered = vote
                .issue_recovered_signing_session(recovered, signer_recovery_round_limit)
                .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
            let (branch, mut signing_session) = recovered.into_parts();
            let branch = catch_up_signer_to_finality(
                finality,
                branch,
                &mut signing_session,
                signer_catch_up_height_limit,
            )?;
            (branch, signing_session)
        }
    };
    Ok(FixedValidatorNodeSigningScopeV0 {
        finality,
        branch,
        signing_session: FixedValidatorNodeVotingSessionV0 {
            signer,
            signing_session,
        },
    })
}

pub(super) enum FixedValidatorNodeSessionPlanV0 {
    Initial(FixedConsensusBranchV0),
    Recovered(FixedValidatorRecoveredSignerBranchV0),
}

/// A strict restart result that never hides stopped or pending signer state.
#[must_use]
pub enum FixedValidatorNodeStartupV0 {
    /// Both pairs matched and exact signer-branch recovery is prepared.
    Ready(Box<FixedValidatorNodeReadyV0>),
    /// Finality was conflict-halted and its exact stop reached the signer.
    FinalityStopped(FixedValidatorNodeFinalityStoppedV0),
    /// The signer already carried an independent terminal cause.
    SignerStopped(FixedValidatorNodeSignerStopV0),
    /// One durable vote preparation cannot be resumed or signed after restart.
    PendingPreparation(FixedValidatorPendingVoteV0),
    /// One durable proposal preparation cannot be resumed or signed after restart.
    PendingProposal(FixedValidatorPendingProposalV0),
}

fn catch_up_signer_to_finality(
    finality: &FixedValidatorAnchoredFinalityJournalV0,
    mut branch: FixedConsensusBranchV0,
    signing_session: &mut FixedValidatorAnchoredVoteSafetySigningSessionV0<'_>,
    limit: FixedValidatorSignerCatchUpHeightLimitV0,
) -> Result<FixedConsensusBranchV0, FixedValidatorNodeStartupErrorV0> {
    let finality_next_height = finality
        .head()
        .map_err(FixedValidatorNodeStartupErrorV0::finality)?
        .next_height()
        .map_err(FixedValidatorNodeStartupErrorV0::Consensus)?;
    let signer_next_height = branch
        .next_height()
        .map_err(FixedValidatorNodeStartupErrorV0::Consensus)?;
    let required = finality_next_height
        .value()
        .checked_sub(signer_next_height.value())
        .ok_or(FixedValidatorNodeStartupErrorV0::SignerAheadOfFinality {
            signer_next_height,
            finality_next_height,
        })?;
    if required > limit.maximum() {
        return Err(
            FixedValidatorNodeStartupErrorV0::SignerCatchUpHeightLimitExceeded {
                required,
                maximum: limit.maximum(),
            },
        );
    }
    for _ in 0..required {
        let signer_next_height = branch
            .next_height()
            .map_err(FixedValidatorNodeStartupErrorV0::Consensus)?;
        let durable = finality
            .acknowledge_signer_height_transition(signer_next_height)
            .map_err(FixedValidatorNodeStartupErrorV0::finality)?;
        let prepared = signing_session
            .prepare_height_with_durable_finality(durable)
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
        branch = signing_session
            .acknowledge_prepared_height(prepared)
            .map_err(FixedValidatorNodeStartupErrorV0::vote)?;
    }
    Ok(branch)
}

/// Exact finality halt paired with the local signer stop it authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodeFinalityStoppedV0 {
    pub(super) finality_halt: FixedValidatorFinalityHaltV0,
    pub(super) signer_stop: FixedValidatorFinalityConflictSignerStopV0,
}

impl FixedValidatorNodeFinalityStoppedV0 {
    /// Returns the anchored finality conflict.
    pub const fn finality_halt(self) -> FixedValidatorFinalityHaltV0 {
        self.finality_halt
    }

    /// Returns the corresponding anchored per-key stop.
    pub const fn signer_stop(self) -> FixedValidatorFinalityConflictSignerStopV0 {
        self.signer_stop
    }
}

/// An already terminal signer state found while finality remained operable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum FixedValidatorNodeSignerStopV0 {
    /// A non-identical same-slot vote intent halted the local signer.
    VoteSafety(FixedValidatorVoteSafetyHaltV0),
    /// A non-identical same-slot proposal intent halted the local signer.
    ProposalSafety(FixedValidatorProposalSafetyHaltV0),
    /// An earlier explicitly routed finality conflict stopped the signer.
    FinalityConflict(FixedValidatorFinalityConflictSignerStopV0),
}

/// A fail-closed provisioning, restart, or session-issuance failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeStartupErrorV0 {
    /// The caller's definition, context, or fixed entries cannot form genesis.
    Genesis(FixedConsensusGenesisError),
    /// The supplied signing key is absent from the exact preselected fixed set.
    SignerNotInFixedSet { signer: ConsensusKey },
    /// The paired finality journal or anchor could not create or strictly open.
    FinalityPair(Box<FixedValidatorAnchoredFinalityJournalErrorV0>),
    /// The paired vote journal or anchor could not create or strictly open.
    VotePair(Box<FixedValidatorAnchoredVoteSafetyJournalErrorV0>),
    /// An opened finality journal rejected the requested lifecycle operation.
    Finality(Box<FixedValidatorFinalityJournalErrorV0>),
    /// An opened vote journal rejected the requested lifecycle operation.
    Vote(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// Exact consensus-position derivation failed.
    Consensus(ProposerSelectionError),
    /// The recovered signer lineage is unexpectedly ahead of selected finality.
    SignerAheadOfFinality {
        signer_next_height: ConsensusHeight,
        finality_next_height: ConsensusHeight,
    },
    /// The complete catch-up gap exceeds the caller-local height-work limit.
    SignerCatchUpHeightLimitExceeded { required: u64, maximum: u64 },
}

impl FixedValidatorNodeStartupErrorV0 {
    fn finality_pair(source: FixedValidatorAnchoredFinalityJournalErrorV0) -> Self {
        Self::FinalityPair(Box::new(source))
    }

    fn vote_pair(source: FixedValidatorAnchoredVoteSafetyJournalErrorV0) -> Self {
        Self::VotePair(Box::new(source))
    }

    fn finality(source: FixedValidatorFinalityJournalErrorV0) -> Self {
        Self::Finality(Box::new(source))
    }

    fn vote(source: FixedValidatorVoteSafetyJournalErrorV0) -> Self {
        Self::Vote(Box::new(source))
    }
}

impl fmt::Display for FixedValidatorNodeStartupErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Genesis(source) => {
                write!(formatter, "invalid fixed-validator node genesis: {source}")
            }
            Self::SignerNotInFixedSet { signer } => {
                write!(
                    formatter,
                    "node signing key {signer:?} is absent from the fixed validator set"
                )
            }
            Self::FinalityPair(source) => write!(formatter, "node finality pair failed: {source}"),
            Self::VotePair(source) => write!(formatter, "node vote-safety pair failed: {source}"),
            Self::Finality(source) => write!(formatter, "node finality startup failed: {source}"),
            Self::Vote(source) => write!(formatter, "node signer startup failed: {source}"),
            Self::Consensus(source) => {
                write!(
                    formatter,
                    "node startup consensus derivation failed: {source}"
                )
            }
            Self::SignerAheadOfFinality {
                signer_next_height,
                finality_next_height,
            } => write!(
                formatter,
                "node signer next height {} is ahead of selected finality next height {}",
                signer_next_height.value(),
                finality_next_height.value()
            ),
            Self::SignerCatchUpHeightLimitExceeded { required, maximum } => write!(
                formatter,
                "node signer catch-up requires {required} height handoffs, exceeding caller-local limit {maximum}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeStartupErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Genesis(source) => Some(source),
            Self::FinalityPair(source) => Some(source.as_ref()),
            Self::VotePair(source) => Some(source.as_ref()),
            Self::Finality(source) => Some(source.as_ref()),
            Self::Vote(source) => Some(source.as_ref()),
            Self::Consensus(source) => Some(source),
            Self::SignerNotInFixedSet { .. }
            | Self::SignerAheadOfFinality { .. }
            | Self::SignerCatchUpHeightLimitExceeded { .. } => None,
        }
    }
}
