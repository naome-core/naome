use super::*;

impl LedgerState {
    pub(super) fn write_state(&self, w: &mut Writer) {
        w.u16(3);
        w.fixed(self.genesis.id().as_bytes());
        w.u64(self.height);
        w.u64(self.time);
        w.fixed(&self.library.root());
        w.u32(self.accounts.len() as u32);
        for (account, key) in &self.accounts {
            w.fixed(account.as_bytes());
            w.fixed(key);
        }
        self.balances.encode_into(w);
        w.u32(self.next_nonce.len() as u32);
        for (author, nonce) in &self.next_nonce {
            w.fixed(author.as_bytes());
            w.u64(*nonce);
        }
        w.u32(self.receipts.len() as u32);
        for receipt in self.receipts.values() {
            encode_receipt(w, receipt);
        }
        w.u32(self.nonce_receipts.len() as u32);
        for ((author, nonce), id) in &self.nonce_receipts {
            w.fixed(author.as_bytes());
            w.u64(*nonce);
            w.fixed(id.as_bytes());
        }
        w.u32(self.questions.len() as u32);
        for entry in self.questions.values() {
            w.fixed(entry.submission.as_bytes());
            w.fixed(entry.author.as_bytes());
            w.string(&entry.purpose).expect("bounded question purpose");
            w.string(entry.question.source())
                .expect("bounded formal source");
            w.fixed(entry.question.profile_id().as_bytes());
            w.fixed(entry.question.resolution_id().as_bytes());
            w.u64(entry.admitted.height);
            w.u32(entry.admitted.operation_index);
            w.u64(entry.expires);
            w.u8(status_tag(entry.status));
            if let Some(id) = entry.opened_question {
                w.u8(1);
                w.fixed(id.as_bytes());
            } else {
                w.u8(0);
            }
        }
        w.u32(self.queue.len() as u32);
        for id in &self.queue {
            w.fixed(id.as_bytes());
        }
        w.u32(self.attempt_numbers.len() as u32);
        for (family, number) in &self.attempt_numbers {
            w.fixed(family.as_bytes());
            w.u64(*number);
        }
        if let Some(active) = &self.active {
            w.u8(1);
            w.fixed(active.submission.as_bytes());
            w.fixed(active.question_id.as_bytes());
            w.fixed(active.family.as_bytes());
            w.u64(active.number);
            w.u8(phase_tag(active.phase));
            if let Some(deadline) = active.deadline {
                w.u8(1);
                w.u64(deadline);
            } else {
                w.u8(0);
            }
            if let Some(round) = active.round {
                w.u8(1);
                w.fixed(round.as_bytes());
            } else {
                w.u8(0);
            }
            w.u32(active.votes.len() as u32);
            for (author, yes) in &active.votes {
                w.fixed(author.as_bytes());
                w.u8(u8::from(*yes));
            }
            w.u32(active.commitments.len() as u32);
            for (author, commitment) in &active.commitments {
                w.fixed(author.as_bytes());
                w.fixed(commitment.id.as_bytes());
                encode_receipt(w, &commitment.receipt);
                w.u64(commitment.reserved_bytes);
                if let Some(reveal) = &commitment.reveal {
                    w.u8(1);
                    encode_receipt(w, &reveal.receipt);
                    // The canonical action receipt binds the full signed reveal;
                    // this explicit original hash additionally binds retained bytes.
                    w.fixed(reveal.original.original_hash().as_bytes());
                } else {
                    w.u8(0);
                }
            }
        } else {
            w.u8(0);
        }
        w.u32(self.families.len() as u32);
        for (family, result) in &self.families {
            w.fixed(family.as_bytes());
            match result {
                FamilyResult::KnownUnpaid { proof } => {
                    w.u8(0);
                    w.fixed(proof.as_bytes());
                }
                FamilyResult::Completed {
                    proof,
                    author,
                    outcome,
                    ordinal,
                    normalization_receipt,
                } => {
                    w.u8(1);
                    w.fixed(proof.as_bytes());
                    w.fixed(author.as_bytes());
                    w.u8(outcome_tag(*outcome));
                    w.u64(*ordinal);
                    w.fixed(&hash(
                        b"naome:state:normalization-receipt:v1\0",
                        &[normalization_receipt],
                    ));
                }
            }
        }
        w.u32(self.claims.len() as u32);
        for claim in self.claims.values() {
            w.fixed(claim.family.as_bytes());
            w.fixed(claim.author.as_bytes());
            w.u64(claim.completion_ordinal);
        }
        w.u32(self.join_intents.len() as u32);
        for (family, pending) in &self.join_intents {
            w.fixed(family.as_bytes());
            encode_receipt(w, &pending.receipt);
            // Exact authenticated operation bytes include every candidate field
            // and both key-possession proofs, not merely a mutable lookup hint.
            w.bytes(&pending.signed_operation)
                .expect("bounded signed join intent");
        }
        self.capacity.encode_into(w);
        w.u8(u8::from(self.terminated));
    }
}

pub(super) fn encode_receipt(w: &mut Writer, receipt: &Receipt) {
    w.fixed(receipt.operation.as_bytes());
    w.fixed(receipt.author.as_bytes());
    w.u64(receipt.nonce);
    w.u64(receipt.coordinate.height);
    w.u32(receipt.coordinate.operation_index);
}
pub(super) fn phase_tag(phase: Phase) -> u8 {
    match phase {
        Phase::Voting => 0,
        Phase::ApprovedWait => 1,
        Phase::Commit => 2,
        Phase::CommitClosedWait => 3,
        Phase::Reveal => 4,
        Phase::SettlementPending => 5,
    }
}
pub(super) fn outcome_tag(outcome: ProofOutcome) -> u8 {
    match outcome {
        ProofOutcome::Proved => 0,
        ProofOutcome::Refuted => 1,
    }
}
fn status_tag(status: QuestionStatus) -> u8 {
    match status {
        QuestionStatus::Queued => 0,
        QuestionStatus::Active => 1,
        QuestionStatus::NotApproved => 2,
        QuestionStatus::Unresolved => 3,
        QuestionStatus::KnownUnpaid => 4,
        QuestionStatus::Completed => 5,
        QuestionStatus::Expired => 6,
        QuestionStatus::CapacityEnd => 7,
    }
}
