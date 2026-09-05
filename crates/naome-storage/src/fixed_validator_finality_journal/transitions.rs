//! Live durable signing-safety transitions.

use super::*;

impl<F: StoreIo> FixedValidatorFinalityJournalCore<F> {
    pub(super) fn commit_verified(
        &mut self,
        transition: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityCommitOutcomeV0, FixedValidatorFinalityJournalErrorV0> {
        self.ensure_operational()?;
        let position = transition.position();
        let round = position.round().value();
        if round > self.replay_limit.max_round() {
            return Err(FixedValidatorFinalityJournalErrorV0::RoundLimitExceeded {
                round,
                maximum: self.replay_limit.max_round(),
            });
        }
        let value = transition.value();
        let height = value.height();
        let height_index = height_index(height).map_err(|()| {
            FixedValidatorFinalityJournalErrorV0::CommitHeightIndexOverflow { height }
        })?;
        let parent_index = height_index
            .checked_sub(1)
            .expect("a sealed transition always has positive height");
        let Some(parent) = self.branches.get(parent_index) else {
            return Err(FixedValidatorFinalityJournalErrorV0::UnselectedParent { height });
        };
        if parent.coordinate() != transition.parent_coordinate() {
            return Err(FixedValidatorFinalityJournalErrorV0::UnselectedParent { height });
        }

        if height_index < self.branches.len() {
            let selected = self
                .records
                .get(parent_index)
                .expect("each retained positive-height branch has one finality record");
            if selected.value == value {
                return Ok(FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized {
                    height,
                    ancestry_id: value.ancestry_id(),
                    retained_envelope_id: selected.envelope_id,
                    state_id: self.state_id,
                });
            }
            let selected_ancestry = selected.value.ancestry_id();
            let selected_envelope_id = selected.envelope_id;
            let entry = u64::try_from(self.records.len()).expect("record count fits u64");
            let body = canonical_record_body(CONFLICT_HALT_RECORD, &transition, entry)?;
            let body_length = u32::try_from(body.len())
                .expect("bounded fixed-validator journal record length fits u32");
            let next_state_id = step_state_id(self.state_id, body_length.to_be_bytes(), &body);
            let halt = halt_from_transition(
                selected_ancestry,
                selected_envelope_id,
                &transition,
                next_state_id,
            );
            self.append_record(
                &body,
                next_state_id,
                FinalityAppendEvidenceV0::Single(transition.envelope_id()),
                entry,
            )?;
            self.halt = Some(halt);
            self.state_id = next_state_id;
            return Ok(FixedValidatorFinalityCommitOutcomeV0::Halted(halt));
        }
        if height_index != self.branches.len() {
            return Err(FixedValidatorFinalityJournalErrorV0::UnselectedParent { height });
        }

        let entry = u64::try_from(self.records.len()).expect("record count fits u64");
        self.branches.try_reserve(1).map_err(|_| {
            FixedValidatorFinalityJournalErrorV0::Allocation {
                entry,
                bytes: std::mem::size_of::<FixedConsensusBranchV0>(),
            }
        })?;
        self.records.try_reserve(1).map_err(|_| {
            FixedValidatorFinalityJournalErrorV0::Allocation {
                entry,
                bytes: std::mem::size_of::<FixedValidatorFinalityRecordV0>(),
            }
        })?;
        self.snapshot_index.try_reserve(1).map_err(|_| {
            FixedValidatorFinalityJournalErrorV0::SnapshotIndexAllocation {
                entry,
                retained_snapshots: self.snapshot_index.len(),
            }
        })?;
        let body = canonical_record_body(FINALIZE_RECORD, &transition, entry)?;
        let body_length = u32::try_from(body.len())
            .expect("bounded fixed-validator journal record length fits u32");
        let next_state_id = step_state_id(self.state_id, body_length.to_be_bytes(), &body);
        let record = record_from_transition(&transition, next_state_id, body);
        let ancestry_id = value.ancestry_id();
        let envelope_id = transition.envelope_id();
        self.append_record(
            record.canonical_record_body(),
            next_state_id,
            FinalityAppendEvidenceV0::Single(envelope_id),
            entry,
        )?;
        let branch = transition.into_branch();
        let artifact_head = branch.artifact_snapshot().head_block_id();
        self.records.push(record);
        let branch_index = self.branches.len();
        self.branches.push(branch);
        let replaced = self.snapshot_index.insert(artifact_head, branch_index);
        debug_assert!(replaced.is_none());
        self.state_id = next_state_id;
        Ok(FixedValidatorFinalityCommitOutcomeV0::Finalized {
            position,
            ancestry_id,
            envelope_id,
            state_id: next_state_id,
        })
    }

    pub(super) fn commit_verified_preselection_conflict(
        &mut self,
        first: OwnedVerifiedFixedConsensusTransitionV0,
        second: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorFinalityHaltV0, FixedValidatorFinalityJournalErrorV0> {
        self.ensure_operational()?;
        let first_position = first.position();
        let second_position = second.position();
        if first_position != second_position {
            return Err(
                FixedValidatorFinalityJournalErrorV0::PreselectionConflictPositionMismatch {
                    first: first_position,
                    second: second_position,
                },
            );
        }
        let round = first_position.round().value();
        if round > self.replay_limit.max_round() {
            return Err(FixedValidatorFinalityJournalErrorV0::RoundLimitExceeded {
                round,
                maximum: self.replay_limit.max_round(),
            });
        }
        let height = first_position.height();
        let height_index = height_index(height).map_err(|()| {
            FixedValidatorFinalityJournalErrorV0::CommitHeightIndexOverflow { height }
        })?;
        if height_index != self.branches.len() {
            return Err(FixedValidatorFinalityJournalErrorV0::UnselectedParent { height });
        }
        let parent_index = height_index
            .checked_sub(1)
            .expect("a sealed transition always has positive height");
        let parent = self
            .branches
            .get(parent_index)
            .expect("the next unselected height has one selected parent");
        if first.parent_coordinate() != second.parent_coordinate()
            || first.parent_coordinate() != parent.coordinate()
        {
            return Err(FixedValidatorFinalityJournalErrorV0::UnselectedParent { height });
        }

        let first_root = first.value().proposal_signing_root();
        let second_root = second.value().proposal_signing_root();
        if first.value() == second.value() || first_root == second_root {
            return Err(
                FixedValidatorFinalityJournalErrorV0::PreselectionConflictNotDistinct { height },
            );
        }
        let (first, second) = if first_root < second_root {
            (first, second)
        } else {
            (second, first)
        };
        let entry = u64::try_from(self.records.len()).expect("record count fits u64");
        let body = canonical_preselection_conflict_record_body(&first, &second, entry)?;
        let body_length = u32::try_from(body.len())
            .expect("bounded fixed-validator journal record length fits u32");
        let next_state_id = step_state_id(self.state_id, body_length.to_be_bytes(), &body);
        let halt = halt_from_preselection_pair(&first, &second, next_state_id);
        self.append_record(
            &body,
            next_state_id,
            FinalityAppendEvidenceV0::Pair {
                first: first.envelope_id(),
                second: second.envelope_id(),
            },
            entry,
        )?;
        self.halt = Some(halt);
        self.state_id = next_state_id;
        Ok(halt)
    }
}
