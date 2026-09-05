//! Independent anchor pairing and acknowledged adapters.

use super::*;

impl FixedValidatorAnchoredFinalityJournalV0 {
    /// Creates a new finality journal and its independent genesis anchor.
    ///
    /// The journal header and its parent-directory entry synchronize before the
    /// anchor is installed. Failure after either write returns no operational
    /// wrapper; callers must inspect and explicitly provision a fresh directory
    /// rather than inferring or repairing authority from either file.
    pub fn create(
        journal_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        definition: ArtifactChainDefinition,
        context: ConsensusContextV0,
        entries: &[ActiveAgreementEntry],
        replay_limit: FixedValidatorFinalityReplayLimitV0,
    ) -> Result<Self, FixedValidatorAnchoredFinalityJournalErrorV0> {
        let journal_directory = journal_directory.as_ref();
        let mut journal = FixedValidatorFinalityJournalV0::create(
            journal_directory,
            definition,
            context,
            entries,
            replay_limit,
        )
        .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        sync_directory(journal_directory)
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Anchor)?;
        let state_id = journal
            .state_id()
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        let anchor = FixedValidatorAnchorFileV0::create_finality(
            anchor_directory.as_ref(),
            context,
            journal.fixed_agreement_set_id(),
            replay_limit.max_round(),
            *state_id.as_bytes(),
        )
        .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Anchor)?;
        journal.core.anchor = Some(anchor);
        Ok(Self { journal })
    }

    /// Strictly opens a journal only from its independent typed anchor.
    ///
    /// Missing, corrupt, context-mismatched, behind, ahead, or divergent anchor
    /// state returns no wrapper and changes neither complete file. One incomplete
    /// final journal frame retains the existing exact-prefix recovery rule.
    pub fn open(
        journal_directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        definition: ArtifactChainDefinition,
        context: ConsensusContextV0,
        entries: &[ActiveAgreementEntry],
        replay_limit: FixedValidatorFinalityReplayLimitV0,
    ) -> Result<Self, FixedValidatorAnchoredFinalityJournalErrorV0> {
        let branch = fixed_genesis(definition, context, entries)
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        let fixed_set_id = branch.fixed_agreement_set_id();
        let expected_prefix = canonical_prefix(context, fixed_set_id, replay_limit)
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        let journal_directory = journal_directory.as_ref();
        let lock = open_shared_lock(journal_directory)
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        let anchor = FixedValidatorAnchorFileV0::open_finality(
            anchor_directory.as_ref(),
            context,
            fixed_set_id,
            replay_limit.max_round(),
        )
        .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Anchor)?;
        let anchored = anchor.position();

        let mut branches = Vec::new();
        branches.try_reserve_exact(1).map_err(|_| {
            FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                FixedValidatorFinalityJournalErrorV0::Allocation {
                    entry: 0,
                    bytes: std::mem::size_of::<FixedConsensusBranchV0>(),
                },
            )
        })?;
        branches.push(branch);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(journal_directory.join(JOURNAL_FILE_NAME))
            .map_err(|source| {
                FixedValidatorAnchoredFinalityJournalErrorV0::Journal(
                    FixedValidatorFinalityJournalErrorV0::Open { source },
                )
            })?;
        let mut core = FixedValidatorFinalityJournalCore::replay(
            file,
            context,
            replay_limit,
            expected_prefix,
            branches,
            FixedValidatorFinalityJournalStateIdV0::from_bytes(anchored.state_id),
            Some(anchored.sequence),
        )
        .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Journal)?;
        anchor
            .stabilize()
            .map_err(FixedValidatorAnchoredFinalityJournalErrorV0::Anchor)?;
        core.anchor = Some(anchor);
        Ok(Self {
            journal: FixedValidatorFinalityJournalV0 { _lock: lock, core },
        })
    }

    /// Returns the exact caller-selected consensus context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.journal.context()
    }

    /// Returns the header-bound local replay-round ceiling.
    pub const fn replay_limit(&self) -> FixedValidatorFinalityReplayLimitV0 {
        self.journal.replay_limit()
    }

    /// Returns the immutable agreement-set identity bound by both files.
    pub fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.journal.fixed_agreement_set_id()
    }

    /// Returns the current healthy journal-state identity.
    pub fn state_id(
        &self,
    ) -> Result<FixedValidatorFinalityJournalStateIdV0, FixedValidatorFinalityJournalErrorV0> {
        self.journal.state_id()
    }

    /// Returns the durable terminal-halt summary, if present.
    pub fn halt(
        &self,
    ) -> Result<Option<FixedValidatorFinalityHaltV0>, FixedValidatorFinalityJournalErrorV0> {
        self.journal.halt()
    }

    /// Returns the exact operable finalized head.
    pub fn head(&self) -> Result<&FixedConsensusBranchV0, FixedValidatorFinalityJournalErrorV0> {
        self.journal.head()
    }

    /// Returns the exact selected artifact-chain identity while operable.
    pub fn artifact_chain_id(
        &self,
    ) -> Result<ArtifactChainId, FixedValidatorFinalityJournalErrorV0> {
        self.journal.artifact_chain_id()
    }

    /// Returns the exact finalized artifact head while operable.
    pub fn artifact_head_block_id(
        &self,
    ) -> Result<ArtifactBlockId, FixedValidatorFinalityJournalErrorV0> {
        self.journal.artifact_head_block_id()
    }

    /// Returns the authenticated finalized artifact-set root while operable.
    pub fn artifact_set_root(
        &self,
    ) -> Result<ArtifactSetRoot, FixedValidatorFinalityJournalErrorV0> {
        self.journal.artifact_set_root()
    }

    /// Returns one retained selected snapshot by exact block identity.
    pub fn artifact_branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, FixedValidatorFinalityJournalErrorV0> {
        self.journal.artifact_branch_snapshot_at(block_id)
    }

    /// Returns the retained selected parent required to verify one height.
    pub fn parent_for_height(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<&FixedConsensusBranchV0>, FixedValidatorFinalityJournalErrorV0> {
        self.journal.parent_for_height(height)
    }

    /// Returns one retained first finality proof by its positive height.
    pub fn finality_record(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<&FixedValidatorFinalityRecordV0>, FixedValidatorFinalityJournalErrorV0> {
        self.journal.finality_record(height)
    }

    /// Returns the number of durably finalized values before terminal halt.
    pub fn finalized_len(&self) -> Result<usize, FixedValidatorFinalityJournalErrorV0> {
        self.journal.finalized_len()
    }

    /// Issues one signer-height transition from the internally anchored state.
    pub fn acknowledge_signer_height_transition(
        &self,
        height: ConsensusHeight,
    ) -> Result<FixedValidatorDurableFinalityTransitionV0<'_>, FixedValidatorFinalityJournalErrorV0>
    {
        let state_id = self.journal.state_id()?;
        self.journal
            .acknowledge_signer_height_transition_is_externally_durable(height, state_id)
    }

    /// Issues signer-stop authority from the internally anchored terminal state.
    pub fn acknowledge_signer_stop(
        &self,
    ) -> Result<FixedValidatorDurableFinalityConflictV0<'_>, FixedValidatorFinalityJournalErrorV0>
    {
        let state_id = self.journal.state_id()?;
        self.journal
            .acknowledge_signer_stop_is_externally_durable(state_id)
    }

    /// Recovers only the retained branch named by an anchored signer capability.
    pub fn recover_anchored_signer_branch(
        &self,
        recovery: FixedValidatorAnchoredSignerRecoveryV0<'_>,
    ) -> Result<FixedValidatorRecoveredSignerBranchV0, FixedValidatorFinalityJournalErrorV0> {
        self.journal.recover_anchored_signer_branch(recovery)
    }

    /// Commits one sealed transition and advances the anchor before publication.
    pub fn commit_verified(
        &mut self,
        transition: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityCommitOutcomeV0, FixedValidatorFinalityJournalErrorV0> {
        self.journal.commit_verified(transition)
    }

    /// Commits two verified unselected direct children as one neutral halt.
    ///
    /// Both transitions must name the same exact next position and selected
    /// parent and must have distinct proposal-signing roots. The journal orders
    /// them canonically, appends one paired frame, advances the external anchor
    /// once, and publishes no selected child.
    pub fn commit_verified_preselection_conflict(
        &mut self,
        first: OwnedVerifiedFixedConsensusTransitionV0,
        second: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityHaltV0, FixedValidatorFinalityJournalErrorV0> {
        self.journal
            .core
            .commit_verified_preselection_conflict(first, second)
    }
}
