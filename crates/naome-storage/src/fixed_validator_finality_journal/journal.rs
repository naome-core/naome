//! Raw journal creation, reopen, and capability issuance.

use super::*;

impl FixedValidatorFinalityJournalV0 {
    /// Creates and exclusively opens one empty joint journal.
    ///
    /// Creation never replaces the artifact-only or joint format already at the
    /// shared path. The returned genesis state ID must be retained through a
    /// separately trusted caller-owned anchor before it can authenticate a later
    /// operational reopen.
    pub fn create(
        directory: impl AsRef<Path>,
        definition: ArtifactChainDefinition,
        context: ConsensusContextV0,
        entries: &[ActiveAgreementEntry],
        replay_limit: FixedValidatorFinalityReplayLimitV0,
    ) -> Result<Self, FixedValidatorFinalityJournalErrorV0> {
        let branch = fixed_genesis(definition, context, entries)?;
        let prefix = canonical_prefix(context, branch.fixed_agreement_set_id(), replay_limit)?;
        let state_id = genesis_state_id(&prefix);
        let mut branches = Vec::new();
        branches.try_reserve_exact(1).map_err(|_| {
            FixedValidatorFinalityJournalErrorV0::Allocation {
                entry: 0,
                bytes: std::mem::size_of::<FixedConsensusBranchV0>(),
            }
        })?;
        branches.push(branch);
        let snapshot_index = genesis_snapshot_index(&branches)?;

        let directory = directory.as_ref();
        let lock = open_shared_lock(directory)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.join(JOURNAL_FILE_NAME))
            .map_err(|source| FixedValidatorFinalityJournalErrorV0::Create { source })?;
        file.append_write_all(AppendPhase::Body, &prefix)
            .and_then(|()| file.append_sync_all(AppendPhase::Body))
            .map_err(|source| FixedValidatorFinalityJournalErrorV0::Create { source })?;

        Ok(Self {
            _lock: lock,
            core: FixedValidatorFinalityJournalCore::empty(
                file,
                context,
                replay_limit,
                branches,
                snapshot_index,
                state_id,
            ),
        })
    }

    /// Exclusively opens and strictly replays one externally anchored journal.
    ///
    /// Replay returns no handle unless the complete verified prefix has exactly
    /// `expected_state_id`. An incomplete final entry is truncated only after
    /// that equality is established. Complete suffix deletion, an unanchored
    /// durable append, corruption, or another expected identity fails closed.
    pub fn open_verified(
        directory: impl AsRef<Path>,
        definition: ArtifactChainDefinition,
        context: ConsensusContextV0,
        entries: &[ActiveAgreementEntry],
        replay_limit: FixedValidatorFinalityReplayLimitV0,
        expected_state_id: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<Self, FixedValidatorFinalityJournalErrorV0> {
        let branch = fixed_genesis(definition, context, entries)?;
        let expected_prefix =
            canonical_prefix(context, branch.fixed_agreement_set_id(), replay_limit)?;
        let mut branches = Vec::new();
        branches.try_reserve_exact(1).map_err(|_| {
            FixedValidatorFinalityJournalErrorV0::Allocation {
                entry: 0,
                bytes: std::mem::size_of::<FixedConsensusBranchV0>(),
            }
        })?;
        branches.push(branch);

        let directory = directory.as_ref();
        let lock = open_shared_lock(directory)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.join(JOURNAL_FILE_NAME))
            .map_err(|source| FixedValidatorFinalityJournalErrorV0::Open { source })?;
        let core = FixedValidatorFinalityJournalCore::replay(
            file,
            context,
            replay_limit,
            expected_prefix,
            branches,
            expected_state_id,
            None,
        )?;
        Ok(Self { _lock: lock, core })
    }

    /// Returns the exact caller-selected consensus context.
    pub const fn context(&self) -> ConsensusContextV0 {
        self.core.context
    }

    /// Returns the header-bound local replay-round ceiling.
    pub const fn replay_limit(&self) -> FixedValidatorFinalityReplayLimitV0 {
        self.core.replay_limit
    }

    /// Returns the immutable agreement-set identity bound by the journal header.
    pub fn fixed_agreement_set_id(&self) -> FixedAgreementSetId {
        self.core
            .branches
            .first()
            .expect("every finality journal retains virtual genesis")
            .fixed_agreement_set_id()
    }

    /// Returns the current unambiguous journal-state identity.
    pub fn state_id(
        &self,
    ) -> Result<FixedValidatorFinalityJournalStateIdV0, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_healthy()?;
        Ok(self.core.state_id)
    }

    /// Returns the durable terminal-halt summary, if present.
    pub fn halt(
        &self,
    ) -> Result<Option<FixedValidatorFinalityHaltV0>, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_healthy()?;
        Ok(self.core.halt)
    }

    /// Returns the exact operable finalized head.
    pub fn head(&self) -> Result<&FixedConsensusBranchV0, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self
            .core
            .branches
            .last()
            .expect("every journal retains its virtual-genesis branch"))
    }

    /// Returns the exact selected artifact-chain identity while operable.
    pub fn artifact_chain_id(
        &self,
    ) -> Result<ArtifactChainId, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self.core.context.chain_id())
    }

    /// Returns the exact finalized artifact head while operable.
    pub fn artifact_head_block_id(
        &self,
    ) -> Result<ArtifactBlockId, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self
            .core
            .branches
            .last()
            .expect("every journal retains its virtual-genesis branch")
            .artifact_snapshot()
            .head_block_id())
    }

    /// Returns the authenticated finalized artifact-set root while operable.
    pub fn artifact_set_root(
        &self,
    ) -> Result<ArtifactSetRoot, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self
            .core
            .branches
            .last()
            .expect("every journal retains its virtual-genesis branch")
            .artifact_snapshot()
            .artifact_set_root())
    }

    /// Returns one owned finalized artifact snapshot by exact selected head.
    ///
    /// Virtual genesis and every replayed or durably committed finality step are
    /// retained. Unknown or non-selected addresses return `None`; terminal halt
    /// and poisoned handles deny the lookup before inspecting history.
    pub fn artifact_branch_snapshot_at(
        &self,
        block_id: ArtifactBlockId,
    ) -> Result<Option<ArtifactChainBranchSnapshot>, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self
            .core
            .snapshot_index
            .get(&block_id)
            .and_then(|index| self.core.branches.get(*index))
            .map(|branch| branch.artifact_snapshot().clone()))
    }

    /// Returns the retained selected parent required to verify one height.
    pub fn parent_for_height(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<&FixedConsensusBranchV0>, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        let Some(parent_index) = height.value().checked_sub(1) else {
            return Ok(None);
        };
        let Ok(parent_index) = usize::try_from(parent_index) else {
            return Ok(None);
        };
        Ok(self.core.branches.get(parent_index))
    }

    /// Returns one retained first finality proof by its positive height.
    pub fn finality_record(
        &self,
        height: ConsensusHeight,
    ) -> Result<Option<&FixedValidatorFinalityRecordV0>, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        let Some(index) = height.value().checked_sub(1) else {
            return Ok(None);
        };
        let Ok(index) = usize::try_from(index) else {
            return Ok(None);
        };
        Ok(self.core.records.get(index))
    }

    /// Returns the number of durably finalized values before any terminal halt.
    pub fn finalized_len(&self) -> Result<usize, FixedValidatorFinalityJournalErrorV0> {
        self.core.ensure_operational()?;
        Ok(self.core.records.len())
    }

    /// Acknowledges and reconstructs one retained signer-height transition.
    ///
    /// The caller must first persist the journal's exact current state identity
    /// in a separately protected monotonic anchor. This method rechecks that
    /// asserted identity before reconstructing the retained first envelope and
    /// artifact payload against the selected parent. The returned capability
    /// immutably borrows this healthy journal until a key-owning vote-safety
    /// session consumes it, preventing an intervening commit or conflict halt.
    pub fn acknowledge_signer_height_transition_is_externally_durable(
        &self,
        height: ConsensusHeight,
        externally_durable_state_id: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<FixedValidatorDurableFinalityTransitionV0<'_>, FixedValidatorFinalityJournalErrorV0>
    {
        self.core.ensure_operational()?;
        if externally_durable_state_id != self.core.state_id {
            return Err(
                FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
                    required: self.core.state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        let transition = self.core.reconstruct_selected_transition(height)?;
        Ok(FixedValidatorDurableFinalityTransitionV0 {
            _journal: self,
            transition,
        })
    }

    /// Issues explicit signer-stop authority for the exact anchored conflict.
    ///
    /// The finality journal must be healthy and terminally halted, and the
    /// caller must first persist its exact current state identity in a
    /// separately protected monotonic anchor. The returned non-clone value
    /// carries only the journal-verified conflict and matching context/set; a
    /// vote-safety journal must explicitly consume it to durably stop one local
    /// signer. No branch is selected, rolled back, or exposed by this handoff.
    pub fn acknowledge_signer_stop_is_externally_durable(
        &self,
        externally_durable_state_id: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<FixedValidatorDurableFinalityConflictV0<'_>, FixedValidatorFinalityJournalErrorV0>
    {
        self.core.ensure_healthy()?;
        let halt = self
            .core
            .halt
            .ok_or(FixedValidatorFinalityJournalErrorV0::SignerStopConflictRequired)?;
        if externally_durable_state_id != self.core.state_id {
            return Err(
                FixedValidatorFinalityJournalErrorV0::ExternalFinalityAnchorMismatch {
                    required: self.core.state_id,
                    acknowledged: externally_durable_state_id,
                },
            );
        }
        debug_assert_eq!(halt.state_id(), self.core.state_id);
        let fixed_set_id = self
            .core
            .branches
            .first()
            .expect("every finality journal retains virtual genesis")
            .fixed_agreement_set_id();
        Ok(FixedValidatorDurableFinalityConflictV0 {
            _journal: self,
            context: self.core.context,
            fixed_set_id,
            halt,
        })
    }

    /// Recovers only the retained branch named by an anchored signer capability.
    ///
    /// Under the caller's point-in-time authorization contract, this narrow read
    /// remains available after a later finality halt when the signer issued the
    /// recovery capability before any explicit conflict stop. The capability
    /// does not establish that ordering. This method rejects poisoned state,
    /// missing history, or any lineage mismatch and exposes no caller-selected
    /// height, sibling, head, or general history API.
    pub fn recover_anchored_signer_branch(
        &self,
        recovery: FixedValidatorAnchoredSignerRecoveryV0<'_>,
    ) -> Result<FixedValidatorRecoveredSignerBranchV0, FixedValidatorFinalityJournalErrorV0> {
        let branch = self.core.recover_anchored_signer_branch(&recovery)?;
        Ok(recovery.into_recovered(branch))
    }

    /// Consumes one sealed verified transition and classifies it against history.
    pub fn commit_verified(
        &mut self,
        transition: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityCommitOutcomeV0, FixedValidatorFinalityJournalErrorV0> {
        self.core.commit_verified(transition)
    }
}
