//! Ordered journal frames, independent anchoring, and failure publication.

use super::*;

impl<F: StoreIo> FixedValidatorVoteSafetyJournalCore<F> {
    pub(super) fn append_record(
        &mut self,
        body: &[u8],
        entry: u64,
    ) -> Result<FixedValidatorVoteSafetyJournalStateIdV0, FixedValidatorVoteSafetyJournalErrorV0>
    {
        let body_length =
            u32::try_from(body.len()).expect("bounded vote-safety journal record length fits u32");
        let body_length_bytes = body_length.to_be_bytes();
        let next_state_id = step_state_id(self.state_id, body_length_bytes, body);
        let next_sequence = self
            .record_sequence
            .checked_add(1)
            .ok_or(FixedValidatorVoteSafetyJournalErrorV0::RecordSequenceExhausted)?;
        let entry_length = ENTRY_FIXED_BYTES
            .checked_add(u64::from(body_length))
            .ok_or(
                FixedValidatorVoteSafetyJournalErrorV0::EntryOffsetOverflow {
                    entry,
                    offset: self.committed_end,
                },
            )?;
        let next_committed_end = self.committed_end.checked_add(entry_length).ok_or(
            FixedValidatorVoteSafetyJournalErrorV0::EntryOffsetOverflow {
                entry,
                offset: self.committed_end,
            },
        )?;
        let commit_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::Start(self.committed_end))?;
            crate::store_io::append_body_and_commit(
                &mut self.file,
                &[&body_length_bytes, body],
                next_state_id.as_bytes(),
            )?;
            if let Some(anchor) = self.anchor.as_mut() {
                let transition = JournalAnchorTransitionV0::new(
                    anchor.pairing_seal(),
                    AnchorPositionV0 {
                        sequence: self.record_sequence,
                        state_id: *self.state_id.as_bytes(),
                    },
                    *next_state_id.as_bytes(),
                )
                .map_err(io::Error::other)?;
                debug_assert_eq!(transition.next().sequence, next_sequence);
                anchor.advance(transition).map_err(io::Error::other)?;
            }
            Ok(())
        })();
        if let Err(source) = commit_result {
            self.poisoned = true;
            return Err(FixedValidatorVoteSafetyJournalErrorV0::Commit {
                proposed_state_id: next_state_id,
                source,
            });
        }
        self.committed_end = next_committed_end;
        self.record_sequence = next_sequence;
        Ok(next_state_id)
    }
}
