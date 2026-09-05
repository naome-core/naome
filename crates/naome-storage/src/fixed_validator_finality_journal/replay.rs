//! Strict record replay and retained evidence reconstruction.

use super::*;

impl<F: StoreIo> FixedValidatorFinalityJournalCore<F> {
    pub(super) fn replay(
        mut file: F,
        context: ConsensusContextV0,
        replay_limit: FixedValidatorFinalityReplayLimitV0,
        expected_prefix: Vec<u8>,
        branches: Vec<FixedConsensusBranchV0>,
        expected_state_id: FixedValidatorFinalityJournalStateIdV0,
        expected_anchor_sequence: Option<u64>,
    ) -> Result<Self, FixedValidatorFinalityJournalErrorV0> {
        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|source| FixedValidatorFinalityJournalErrorV0::Read { offset: 0, source })?;
        if file_len < JOURNAL_PREFIX_BYTES as u64 {
            return Err(FixedValidatorFinalityJournalErrorV0::InvalidHeader);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|source| FixedValidatorFinalityJournalErrorV0::Read { offset: 0, source })?;
        let mut actual_prefix = Vec::new();
        actual_prefix
            .try_reserve_exact(JOURNAL_PREFIX_BYTES)
            .map_err(|_| FixedValidatorFinalityJournalErrorV0::Allocation {
                entry: 0,
                bytes: JOURNAL_PREFIX_BYTES,
            })?;
        actual_prefix.resize(JOURNAL_PREFIX_BYTES, 0);
        read_exact_at(&mut file, &mut actual_prefix, 0)?;
        if actual_prefix != expected_prefix {
            return Err(FixedValidatorFinalityJournalErrorV0::HeaderMismatch);
        }

        let state_id = genesis_state_id(&actual_prefix);
        let snapshot_index = genesis_snapshot_index(&branches)?;
        let mut core = Self::empty(
            file,
            context,
            replay_limit,
            branches,
            snapshot_index,
            state_id,
        );
        let mut entry_start = JOURNAL_PREFIX_BYTES as u64;
        let mut entry = 0_u64;
        let mut recovery_offset = None;

        while entry_start < file_len {
            let remaining = file_len - entry_start;
            if remaining < RECORD_LENGTH_BYTES {
                recovery_offset = Some(entry_start);
                break;
            }
            core.file
                .seek(SeekFrom::Start(entry_start))
                .map_err(|source| FixedValidatorFinalityJournalErrorV0::Read {
                    offset: entry_start,
                    source,
                })?;
            let mut body_length_bytes = [0_u8; 4];
            read_exact_at(&mut core.file, &mut body_length_bytes, entry_start)?;
            let body_length_u32 = u32::from_be_bytes(body_length_bytes);
            let body_length = usize::try_from(body_length_u32)
                .expect("every u32 record length fits the supported Rust targets");
            if !(MIN_RECORD_BODY_BYTES..=MAX_RECORD_BODY_BYTES).contains(&body_length) {
                return Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordLength {
                    entry,
                    offset: entry_start,
                    actual: body_length_u32,
                    minimum: u32::try_from(MIN_RECORD_BODY_BYTES)
                        .expect("the minimum record length fits u32"),
                    maximum: u32::try_from(MAX_RECORD_BODY_BYTES)
                        .expect("the maximum record length fits u32"),
                });
            }
            let entry_length = ENTRY_FIXED_BYTES
                .checked_add(u64::from(body_length_u32))
                .ok_or(FixedValidatorFinalityJournalErrorV0::EntryOffsetOverflow {
                    entry,
                    offset: entry_start,
                })?;
            let entry_end = entry_start.checked_add(entry_length).ok_or(
                FixedValidatorFinalityJournalErrorV0::EntryOffsetOverflow {
                    entry,
                    offset: entry_start,
                },
            )?;
            if file_len < entry_end {
                recovery_offset = Some(entry_start);
                break;
            }
            if core.halt.is_some() {
                return Err(FixedValidatorFinalityJournalErrorV0::RecordAfterHalt {
                    offset: entry_start,
                });
            }

            let mut body = Vec::new();
            body.try_reserve_exact(body_length).map_err(|_| {
                FixedValidatorFinalityJournalErrorV0::Allocation {
                    entry,
                    bytes: body_length,
                }
            })?;
            body.resize(body_length, 0);
            let body_offset = entry_start + RECORD_LENGTH_BYTES;
            read_exact_at(&mut core.file, &mut body, body_offset)?;
            let footer_offset = body_offset + u64::from(body_length_u32);
            let mut stored_state_id = [0_u8; FixedValidatorFinalityJournalStateIdV0::BYTE_LENGTH];
            read_exact_at(&mut core.file, &mut stored_state_id, footer_offset)?;
            let expected_entry_state_id = step_state_id(core.state_id, body_length_bytes, &body);
            let actual_entry_state_id =
                FixedValidatorFinalityJournalStateIdV0::from_bytes(stored_state_id);
            if actual_entry_state_id != expected_entry_state_id {
                return Err(
                    FixedValidatorFinalityJournalErrorV0::RecordStateIdMismatch {
                        entry,
                        offset: entry_start,
                        expected: expected_entry_state_id,
                        actual: actual_entry_state_id,
                    },
                );
            }

            core.replay_record(entry, entry_start, body, actual_entry_state_id)?;
            core.state_id = actual_entry_state_id;
            core.record_sequence = core
                .record_sequence
                .checked_add(1)
                .ok_or(FixedValidatorFinalityJournalErrorV0::RecordSequenceExhausted)?;
            core.committed_end = entry_end;
            entry_start = entry_end;
            entry += 1;
        }

        if let Some(expected_sequence) = expected_anchor_sequence
            && (core.record_sequence != expected_sequence || core.state_id != expected_state_id)
        {
            return Err(match core.record_sequence.cmp(&expected_sequence) {
                std::cmp::Ordering::Greater => FixedValidatorFinalityJournalErrorV0::AnchorBehind {
                    anchored_sequence: expected_sequence,
                    journal_sequence: core.record_sequence,
                },
                std::cmp::Ordering::Less => FixedValidatorFinalityJournalErrorV0::AnchorAhead {
                    anchored_sequence: expected_sequence,
                    journal_sequence: core.record_sequence,
                },
                std::cmp::Ordering::Equal => {
                    FixedValidatorFinalityJournalErrorV0::AnchorStateMismatch {
                        sequence: expected_sequence,
                    }
                }
            });
        }
        if core.state_id != expected_state_id {
            return Err(
                FixedValidatorFinalityJournalErrorV0::ExpectedStateIdMismatch {
                    expected: expected_state_id,
                    actual: core.state_id,
                },
            );
        }

        if let Some(offset) = recovery_offset {
            core.file
                .set_len(offset)
                .and_then(|()| core.file.sync_all())
                .map_err(|source| FixedValidatorFinalityJournalErrorV0::Recovery {
                    offset,
                    source,
                })?;
        } else {
            core.file
                .sync_all()
                .map_err(|source| FixedValidatorFinalityJournalErrorV0::Stabilize { source })?;
        }
        Ok(core)
    }

    pub(super) fn replay_record(
        &mut self,
        entry: u64,
        offset: u64,
        body: Vec<u8>,
        state_id: FixedValidatorFinalityJournalStateIdV0,
    ) -> Result<(), FixedValidatorFinalityJournalErrorV0> {
        match parse_record(entry, offset, &body, self.replay_limit)? {
            ParsedRecord::Single {
                tag,
                round,
                transition: parsed,
            } => {
                let height = parsed.height;
                let height_index = height_index(height).map_err(|()| {
                    FixedValidatorFinalityJournalErrorV0::HeightIndexOverflow { entry, height }
                })?;
                match tag {
                    FINALIZE_RECORD if height_index != self.branches.len() => {
                        return Err(
                            FixedValidatorFinalityJournalErrorV0::NonconsecutiveFinality {
                                entry,
                                height,
                            },
                        );
                    }
                    CONFLICT_HALT_RECORD if height_index >= self.branches.len() => {
                        return Err(FixedValidatorFinalityJournalErrorV0::InvalidConflictHalt {
                            entry,
                            height,
                        });
                    }
                    FINALIZE_RECORD | CONFLICT_HALT_RECORD => {}
                    _ => unreachable!("record tag is parsed before classification"),
                }
                let parent_index = height_index
                    .checked_sub(1)
                    .expect("strict value decoding rejects height zero");
                let parent = self.branches.get(parent_index).ok_or(
                    FixedValidatorFinalityJournalErrorV0::InvalidSelectedParent { entry, height },
                )?;
                let mut typed_round = parent
                    .begin_round_zero()
                    .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
                for _ in 0..round {
                    typed_round = typed_round
                        .advance_round()
                        .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
                }
                let payload = clone_bytes(parsed.payload, entry)?;
                let transition = typed_round
                    .decode_and_verify(parsed.envelope, payload)
                    .map_err(|source| FixedValidatorFinalityJournalErrorV0::Replay {
                        entry,
                        offset,
                        source: Box::new(source),
                    })?
                    .into_owned();
                match tag {
                    FINALIZE_RECORD => {
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
                        let record = record_from_transition(&transition, state_id, body);
                        let branch = transition.into_branch();
                        let artifact_head = branch.artifact_snapshot().head_block_id();
                        self.records.push(record);
                        let branch_index = self.branches.len();
                        self.branches.push(branch);
                        let replaced = self.snapshot_index.insert(artifact_head, branch_index);
                        debug_assert!(replaced.is_none());
                    }
                    CONFLICT_HALT_RECORD => {
                        let selected = self.records.get(parent_index).ok_or(
                            FixedValidatorFinalityJournalErrorV0::InvalidConflictHalt {
                                entry,
                                height,
                            },
                        )?;
                        if selected.value == transition.value() {
                            return Err(
                                FixedValidatorFinalityJournalErrorV0::InvalidConflictHalt {
                                    entry,
                                    height,
                                },
                            );
                        }
                        self.halt = Some(halt_from_transition(
                            selected.value.ancestry_id(),
                            selected.envelope_id,
                            &transition,
                            state_id,
                        ));
                    }
                    _ => unreachable!("record tag was checked before verification"),
                }
                Ok(())
            }
            ParsedRecord::PreselectionConflict {
                round,
                first: first_parsed,
                second: second_parsed,
            } => {
                let height = first_parsed.height;
                if second_parsed.height != height {
                    return Err(
                        FixedValidatorFinalityJournalErrorV0::InvalidPreselectionConflict {
                            entry,
                            height,
                        },
                    );
                }
                let height_index = height_index(height).map_err(|()| {
                    FixedValidatorFinalityJournalErrorV0::HeightIndexOverflow { entry, height }
                })?;
                if height_index != self.branches.len() {
                    return Err(
                        FixedValidatorFinalityJournalErrorV0::InvalidPreselectionConflict {
                            entry,
                            height,
                        },
                    );
                }
                let parent_index = height_index
                    .checked_sub(1)
                    .expect("strict value decoding rejects height zero");
                let parent = self.branches.get(parent_index).ok_or(
                    FixedValidatorFinalityJournalErrorV0::InvalidSelectedParent { entry, height },
                )?;
                let mut typed_round = parent
                    .begin_round_zero()
                    .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
                for _ in 0..round {
                    typed_round = typed_round
                        .advance_round()
                        .map_err(FixedValidatorFinalityJournalErrorV0::Proposer)?;
                }
                let first_payload = clone_bytes(first_parsed.payload, entry)?;
                let first = typed_round
                    .decode_and_verify(first_parsed.envelope, first_payload)
                    .map_err(|source| FixedValidatorFinalityJournalErrorV0::Replay {
                        entry,
                        offset,
                        source: Box::new(source),
                    })?
                    .into_owned();
                let second_payload = clone_bytes(second_parsed.payload, entry)?;
                let second = typed_round
                    .decode_and_verify(second_parsed.envelope, second_payload)
                    .map_err(|source| FixedValidatorFinalityJournalErrorV0::Replay {
                        entry,
                        offset,
                        source: Box::new(source),
                    })?
                    .into_owned();
                if first.position() != second.position()
                    || first.parent_coordinate() != second.parent_coordinate()
                    || first.value() == second.value()
                    || first.value().proposal_signing_root()
                        >= second.value().proposal_signing_root()
                {
                    return Err(
                        FixedValidatorFinalityJournalErrorV0::InvalidPreselectionConflict {
                            entry,
                            height,
                        },
                    );
                }
                self.halt = Some(halt_from_preselection_pair(&first, &second, state_id));
                Ok(())
            }
        }
    }
}
