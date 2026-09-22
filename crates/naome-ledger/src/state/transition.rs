use super::encoding::{encode_receipt, outcome_tag};
use super::*;

impl LedgerState {
    pub(super) fn prepare(
        &self,
        time: TimeCertificate,
        operations: Vec<SignedOperation>,
    ) -> Result<LedgerExecution, LedgerError> {
        if self.terminated {
            return Err(LedgerError::Invalid("research run terminated"));
        }
        let limits = self.genesis.profile().limits();
        if operations.len() as u64 > limits.operations_per_record {
            return Err(LedgerError::Limit("operations per record"));
        }
        let operation_bytes = operations.iter().try_fold(0usize, |size, op| {
            size.checked_add(op.encode().len() + 4)
                .ok_or(LedgerError::Overflow)
        })?;
        if operation_bytes as u64 > limits.record_bytes {
            return Err(LedgerError::Limit("record operation bytes"));
        }
        let height = self.height.checked_add(1).ok_or(LedgerError::Overflow)?;
        let certificate =
            TimeCertificate::decode(&time.encode(), &self.genesis, self.head, height, self.time)?;
        let mut next = self.clone();
        next.height = height;
        next.time = certificate.time();
        let mut effects = Vec::new();
        let mut work = VerificationWork::default();
        let mut productive = next.expire_queue(&mut effects)?;
        let mut active_progress = false;
        let mut opened = false;
        let mut registered = false;
        if self.active.is_none() && !self.capacity.can_open(self.genesis.profile()) {
            if !operations.is_empty() {
                return Err(LedgerError::Invalid(
                    "terminal record contains user actions",
                ));
            }
            while let Some(id) = next.queue.pop_front() {
                next.set_question_status(id, QuestionStatus::CapacityEnd)?;
                effect(&mut effects, 13, |w| w.fixed(id.as_bytes()));
            }
            next.capacity.terminate(self.genesis.profile())?;
            next.terminated = true;
            productive = true;
            effect(&mut effects, 12, |_| {});
        } else {
            if self.active.is_none() {
                let (did_open, did_work) = next.open_next(&mut effects)?;
                opened = did_open;
                productive |= did_work;
            } else {
                active_progress = next.advance_phase(self, &mut effects, &mut work)?;
                productive |= active_progress;
            }
            for (index, operation) in operations.iter().enumerate() {
                let coordinate = AdmissionCoordinate {
                    height,
                    operation_index: index as u32,
                };
                let (accepted, active) =
                    next.admit_action(self, operation, coordinate, &mut effects, &mut work)?;
                registered |= accepted
                    && matches!(
                        OperationBody::decode(operation.payload(), &self.genesis)?,
                        OperationBody::Register
                    );
                productive |= accepted;
                active_progress |= active;
            }
            if !productive {
                return Err(LedgerError::Invalid("unproductive research record"));
            }
            // New identities never consume the protected completion reservation,
            // including when bundled with a vote, reveal or automatic transition.
            if registered && (opened || active_progress) {
                return Err(LedgerError::Invalid(
                    "registration requires an ordinary record",
                ));
            }
            if opened {
                next.capacity.open(self.genesis.profile())?;
            } else if active_progress {
                next.capacity.active_record()?;
            } else {
                next.capacity.ordinary_record()?;
            }
            if next.active.is_none() {
                next.capacity.release();
            }
        }
        if !productive {
            return Err(LedgerError::Invalid("unproductive research record"));
        }
        next.balances
            .verify_conservation(&self.genesis, &next.accounts)?;
        if !next.accounts.keys().eq(next.next_nonce.keys()) {
            return Err(LedgerError::Invalid("nonce account set"));
        }
        if next.claims.len() as u64 != next.balances.paid_completions() {
            return Err(LedgerError::Invalid("claim issuance conservation"));
        }
        let mut derived = Writer::new();
        derived.u16(1);
        derived.u32(effects.len() as u32);
        for effect in effects {
            derived.bytes(&effect)?;
        }
        Ok(LedgerExecution {
            next,
            time: certificate,
            operations,
            effects: derived.finish(),
        })
    }

    fn set_question_status(
        &mut self,
        id: OperationId,
        status: QuestionStatus,
    ) -> Result<(), LedgerError> {
        let entry = self
            .questions
            .get_mut(&id)
            .ok_or(LedgerError::Invalid("missing question state"))?;
        Arc::make_mut(entry).status = status;
        Ok(())
    }
    fn expire_queue(&mut self, effects: &mut Vec<Vec<u8>>) -> Result<bool, LedgerError> {
        let mut retained = VecDeque::new();
        let mut changed = false;
        while let Some(id) = self.queue.pop_front() {
            let entry = self
                .questions
                .get(&id)
                .ok_or(LedgerError::Invalid("queued question missing"))?;
            if self.time >= entry.expires {
                self.set_question_status(id, QuestionStatus::Expired)?;
                effect(effects, 1, |w| w.fixed(id.as_bytes()));
                changed = true;
            } else {
                retained.push_back(id);
            }
        }
        self.queue = retained;
        Ok(changed)
    }
    fn open_next(&mut self, effects: &mut Vec<Vec<u8>>) -> Result<(bool, bool), LedgerError> {
        let mut changed = false;
        while let Some(submission) = self.queue.pop_front() {
            let entry = self
                .questions
                .get(&submission)
                .ok_or(LedgerError::Invalid("opening question missing"))?
                .clone();
            let family = entry.question.resolution_id();
            if self.families.contains_key(&family) {
                return Err(LedgerError::Invalid("closed family remained queued"));
            }
            if let Some(proof) = self
                .library
                .known_target(&entry.question)
                .map(|proof| proof.proof_id())
            {
                self.families
                    .insert(family, FamilyResult::KnownUnpaid { proof });
                self.set_question_status(submission, QuestionStatus::KnownUnpaid)?;
                effect(effects, 2, |w| {
                    w.fixed(submission.as_bytes());
                    w.fixed(family.as_bytes());
                    w.fixed(proof.as_bytes());
                });
                changed = true;
                continue;
            }
            let number = self
                .attempt_numbers
                .get(&family)
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(LedgerError::Overflow)?;
            let context = QuestionContext {
                genesis: self.genesis.id(),
                profile: self.genesis.profile().id(),
                checker: checker_profile_id(self.genesis.checker_profile()),
                library_root: self.library.root(),
                author: entry.author,
            };
            let question_id = entry.question.question_id(context, &entry.purpose)?;
            let deadline = self
                .time
                .checked_add(self.genesis.profile().timing().voting_seconds)
                .ok_or(LedgerError::Overflow)?;
            self.attempt_numbers.insert(family, number);
            self.set_question_status(submission, QuestionStatus::Active)?;
            Arc::make_mut(
                self.questions
                    .get_mut(&submission)
                    .ok_or(LedgerError::Invalid("opening question missing"))?,
            )
            .opened_question = Some(question_id);
            self.active = Some(Attempt {
                submission,
                question_id,
                family,
                number,
                phase: Phase::Voting,
                deadline: Some(deadline),
                round: None,
                votes: BTreeMap::new(),
                commitments: BTreeMap::new(),
            });
            effect(effects, 3, |w| {
                w.fixed(submission.as_bytes());
                w.fixed(question_id.as_bytes());
                w.u64(number);
                w.u64(deadline);
            });
            return Ok((true, true));
        }
        Ok((false, changed))
    }

    fn advance_phase(
        &mut self,
        parent: &LedgerState,
        effects: &mut Vec<Vec<u8>>,
        work: &mut VerificationWork,
    ) -> Result<bool, LedgerError> {
        let mut attempt = self
            .active
            .take()
            .ok_or(LedgerError::Invalid("missing active attempt"))?;
        let mut retain = true;
        let mut progressed = true;
        match attempt.phase {
            Phase::Voting
                if self.time
                    >= attempt
                        .deadline
                        .ok_or(LedgerError::Invalid("voting deadline"))? =>
            {
                if attempt.votes.values().filter(|&&yes| yes).count() >= 3 {
                    attempt.phase = Phase::ApprovedWait;
                    attempt.deadline = None;
                    effect(effects, 4, |w| w.fixed(attempt.question_id.as_bytes()));
                } else {
                    self.set_question_status(attempt.submission, QuestionStatus::NotApproved)?;
                    retain = false;
                    effect(effects, 5, |w| w.fixed(attempt.question_id.as_bytes()));
                }
            }
            Phase::ApprovedWait => {
                let round = solution_round_id(
                    self.genesis.id(),
                    attempt.question_id,
                    attempt.number,
                    parent.head,
                )?;
                let deadline = self
                    .time
                    .checked_add(self.genesis.profile().timing().commitment_seconds)
                    .ok_or(LedgerError::Overflow)?;
                attempt.phase = Phase::Commit;
                attempt.round = Some(round);
                attempt.deadline = Some(deadline);
                effect(effects, 6, |w| {
                    w.fixed(round.as_bytes());
                    w.u64(deadline);
                });
            }
            Phase::Commit
                if self.time
                    >= attempt
                        .deadline
                        .ok_or(LedgerError::Invalid("commit deadline"))? =>
            {
                attempt.phase = Phase::CommitClosedWait;
                attempt.deadline = None;
                effect(effects, 7, |w| {
                    w.fixed(attempt.round.expect("commit phase has round").as_bytes())
                });
            }
            Phase::CommitClosedWait => {
                let deadline = self
                    .time
                    .checked_add(self.genesis.profile().timing().reveal_seconds)
                    .ok_or(LedgerError::Overflow)?;
                attempt.phase = Phase::Reveal;
                attempt.deadline = Some(deadline);
                effect(effects, 8, |w| {
                    w.fixed(attempt.round.expect("commit closure has round").as_bytes());
                    w.u64(deadline);
                });
            }
            Phase::Reveal
                if self.time
                    >= attempt
                        .deadline
                        .ok_or(LedgerError::Invalid("reveal deadline"))? =>
            {
                attempt.phase = Phase::SettlementPending;
                attempt.deadline = None;
                effect(effects, 9, |w| {
                    w.fixed(attempt.round.expect("reveal has round").as_bytes())
                });
            }
            Phase::SettlementPending => {
                self.settle(parent, &attempt, effects, work)?;
                retain = false;
            }
            _ => progressed = false,
        }
        if retain {
            self.active = Some(attempt);
        }
        Ok(progressed)
    }

    fn admit_action(
        &mut self,
        parent: &LedgerState,
        operation: &SignedOperation,
        coordinate: AdmissionCoordinate,
        effects: &mut Vec<Vec<u8>>,
        work: &mut VerificationWork,
    ) -> Result<(bool, bool), LedgerError> {
        operation.verify_signature(&self.genesis)?;
        let body = OperationBody::decode(operation.payload(), &self.genesis)?;
        let id = operation.id();
        if let Some(receipt) = self.receipts.get(&id) {
            effect(effects, 15, |w| encode_receipt(w, receipt));
            return Ok((false, false));
        }
        let expected = if matches!(body, OperationBody::Register) {
            if self.accounts.contains_key(&operation.author()) {
                return Err(LedgerError::Invalid("account already registered"));
            }
            if self.accounts.len() as u64 >= self.genesis.profile().limits().registered_accounts {
                return Err(LedgerError::Limit("registered accounts"));
            }
            if self.genesis.validators().iter().any(|validator| {
                &validator.consensus_key == operation.public_key()
                    || &validator.transport_key == operation.public_key()
            }) {
                return Err(LedgerError::Invalid("key roles overlap"));
            }
            1
        } else {
            if self.account_key(operation.author()) != Some(operation.public_key()) {
                return Err(LedgerError::Invalid("unregistered action account"));
            }
            self.next_nonce
                .get(&operation.author())
                .copied()
                .ok_or(LedgerError::Invalid("action account"))?
        };
        if operation.nonce() != expected {
            return Err(LedgerError::Invalid("action is not exact next nonce"));
        }
        if self
            .nonce_receipts
            .contains_key(&(operation.author(), operation.nonce()))
        {
            return Err(LedgerError::Invalid("nonce content conflict"));
        }
        let receipt = Receipt {
            operation: id,
            author: operation.author(),
            nonce: operation.nonce(),
            coordinate,
        };
        let active_progress = match body {
            OperationBody::Register => {
                self.accounts
                    .insert(operation.author(), *operation.public_key());
                self.balances.register(operation.author())?;
                effect(effects, 16, |w| {
                    w.fixed(operation.author().as_bytes());
                    w.fixed(operation.public_key());
                });
                false
            }
            OperationBody::Submit { purpose, question } => {
                let family = question.resolution_id();
                if self.families.contains_key(&family) {
                    return Err(LedgerError::Invalid("family permanently closed"));
                }
                if self.active.as_ref().is_some_and(|a| a.family == family)
                    || self
                        .queue
                        .iter()
                        .any(|id| self.questions[id].question.resolution_id() == family)
                {
                    return Err(LedgerError::Invalid("family already queued or active"));
                }
                if self.queue.len() as u64 >= self.genesis.profile().limits().queued_questions {
                    return Err(LedgerError::Limit("question queue"));
                }
                let expires = self
                    .time
                    .checked_add(self.genesis.profile().timing().queue_seconds)
                    .ok_or(LedgerError::Overflow)?;
                self.questions.insert(
                    id,
                    Arc::new(QuestionEntry {
                        submission: id,
                        author: operation.author(),
                        purpose,
                        question,
                        admitted: coordinate,
                        expires,
                        status: QuestionStatus::Queued,
                        opened_question: None,
                    }),
                );
                self.queue.push_back(id);
                false
            }
            OperationBody::Vote {
                question,
                attempt,
                yes,
            } => {
                self.require_parent_phase(parent, Phase::Voting)?;
                if !self
                    .genesis
                    .validators()
                    .iter()
                    .any(|v| v.owner == operation.author())
                {
                    return Err(LedgerError::Invalid("vote requires validator owner"));
                }
                let active = self
                    .active
                    .as_mut()
                    .ok_or(LedgerError::Invalid("vote without attempt"))?;
                if active.question_id != question || active.number != attempt {
                    return Err(LedgerError::Invalid("ballot attempt"));
                }
                if active.votes.insert(operation.author(), yes).is_some() {
                    return Err(LedgerError::Invalid("owner already voted"));
                }
                true
            }
            OperationBody::Commit { round, commitment } => {
                self.require_parent_phase(parent, Phase::Commit)?;
                let active = self
                    .active
                    .as_mut()
                    .ok_or(LedgerError::Invalid("commit without attempt"))?;
                if active.round != Some(round) {
                    return Err(LedgerError::Invalid("commit solution round"));
                }
                if active.commitments.contains_key(&operation.author()) {
                    return Err(LedgerError::Invalid("author already committed"));
                }
                if active.commitments.len() as u64
                    >= self.genesis.profile().limits().commitments_per_attempt
                {
                    return Err(LedgerError::Limit("commitment slots"));
                }
                let limits = self.genesis.profile().limits();
                let reserved_bytes = limits
                    .package_bytes
                    .checked_mul(2)
                    .and_then(|x| {
                        limits
                            .dependency_bytes
                            .checked_mul(2)
                            .and_then(|y| x.checked_add(y))
                    })
                    .ok_or(LedgerError::Overflow)?;
                active.commitments.insert(
                    operation.author(),
                    CommitmentEntry {
                        id: commitment,
                        receipt,
                        reserved_bytes,
                        reveal: None,
                    },
                );
                true
            }
            OperationBody::Reveal {
                round,
                secret,
                original,
            } => {
                self.require_parent_phase(parent, Phase::Reveal)?;
                original.verify_signature(&self.genesis, round, operation.author())?;
                let active = self
                    .active
                    .as_ref()
                    .ok_or(LedgerError::Invalid("reveal without attempt"))?;
                if active.round != Some(round) {
                    return Err(LedgerError::Invalid("reveal solution round"));
                }
                let commitment = active
                    .commitments
                    .get(&operation.author())
                    .ok_or(LedgerError::Invalid("reveal without commitment"))?;
                if commitment.reveal.is_some() {
                    return Err(LedgerError::Invalid("commitment already revealed"));
                }
                let expected = CommitmentId::for_original(
                    &self.genesis,
                    round,
                    operation.author(),
                    original.original_hash(),
                    &secret,
                );
                if commitment.id != expected {
                    return Err(LedgerError::Invalid("reveal commitment mismatch"));
                }
                let question = &self.questions[&active.submission].question;
                let _normalized = self.library.normalize_with_work(
                    original.package(),
                    question,
                    self.genesis.profile(),
                    work,
                )?;
                self.active
                    .as_mut()
                    .expect("active reveal checked")
                    .commitments
                    .get_mut(&operation.author())
                    .expect("commitment checked")
                    .reveal = Some(AcceptedReveal {
                    receipt,
                    original: Arc::new(original),
                });
                true
            }
        };
        let next = expected.checked_add(1).ok_or(LedgerError::Overflow)?;
        self.next_nonce.insert(operation.author(), next);
        self.receipts.insert(id, receipt);
        self.nonce_receipts
            .insert((operation.author(), operation.nonce()), id);
        effect(effects, 14, |w| encode_receipt(w, &receipt));
        Ok((true, active_progress))
    }

    fn require_parent_phase(&self, parent: &LedgerState, phase: Phase) -> Result<(), LedgerError> {
        let previous = parent.active.as_ref().ok_or(LedgerError::Invalid(
            "phase operation without parent attempt",
        ))?;
        let current = self
            .active
            .as_ref()
            .ok_or(LedgerError::Invalid("phase already closed"))?;
        if previous.phase != phase
            || current.phase != phase
            || previous.question_id != current.question_id
            || previous.number != current.number
            || self.time
                >= previous
                    .deadline
                    .ok_or(LedgerError::Invalid("phase deadline absent"))?
        {
            return Err(LedgerError::Invalid("operation outside open parent phase"));
        }
        Ok(())
    }

    fn settle(
        &mut self,
        parent: &LedgerState,
        attempt: &Attempt,
        effects: &mut Vec<Vec<u8>>,
        work: &mut VerificationWork,
    ) -> Result<(), LedgerError> {
        if self.families.contains_key(&attempt.family) {
            return Err(LedgerError::Invalid("settlement family already closed"));
        }
        let winner = attempt
            .commitments
            .values()
            .filter(|commitment| commitment.reveal.is_some())
            .min_by_key(|commitment| commitment.receipt.coordinate);
        let Some(winner) = winner else {
            self.set_question_status(attempt.submission, QuestionStatus::Unresolved)?;
            effect(effects, 11, |w| w.fixed(attempt.family.as_bytes()));
            return Ok(());
        };
        let reveal = winner.reveal.as_ref().expect("selected eligible reveal");
        let question = &self.questions[&attempt.submission].question;
        reveal.original.verify_signature(
            &self.genesis,
            attempt.round.expect("settlement round"),
            winner.receipt.author,
        )?;
        let normalized = self.library.normalize_with_work(
            reveal.original.package(),
            question,
            self.genesis.profile(),
            work,
        )?;
        let citations = normalized
            .citations()
            .iter()
            .map(|&proof| {
                self.library
                    .lookup(proof)
                    .map(|stored| CitationRecipient {
                        proof,
                        recipient: stored.recipient(),
                    })
                    .ok_or(LedgerError::Invalid("citation not in sealed parent"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rewards = RewardPlan::new(&self.genesis, normalized.author(), citations)?;
        let receipt = normalization_receipt(parent, attempt, winner, &normalized, &rewards)?;
        // System settlement has a separate fixed coordinate after the bounded
        // ordinary-operation index range, so it cannot collide with a user receipt.
        let coordinate = AdmissionCoordinate {
            height: self.height,
            operation_index: self.genesis.profile().limits().operations_per_record as u32,
        };
        self.library.publish(&normalized, coordinate)?;
        self.balances
            .apply(&rewards, &self.genesis, &self.accounts)?;
        let ordinal = self.balances.paid_completions();
        self.claims.insert(
            attempt.family,
            EligibilityClaim {
                family: attempt.family,
                author: normalized.author(),
                completion_ordinal: ordinal,
            },
        );
        self.families.insert(
            attempt.family,
            FamilyResult::Completed {
                proof: normalized.root(),
                author: normalized.author(),
                outcome: normalized.outcome(),
                ordinal,
                normalization_receipt: Arc::from(receipt.clone()),
            },
        );
        self.set_question_status(attempt.submission, QuestionStatus::Completed)?;
        effect(effects, 10, |w| {
            w.fixed(attempt.family.as_bytes());
            w.u64(ordinal);
            w.u8(outcome_tag(normalized.outcome()));
            w.bytes(&receipt).expect("bounded normalization receipt");
        });
        Ok(())
    }
}

fn effect(effects: &mut Vec<Vec<u8>>, tag: u8, write: impl FnOnce(&mut Writer)) {
    let mut w = Writer::new();
    w.u8(tag);
    write(&mut w);
    effects.push(w.finish());
}

fn normalization_receipt(
    parent: &LedgerState,
    attempt: &Attempt,
    commitment: &CommitmentEntry,
    normalized: &NormalizedPackage,
    rewards: &RewardPlan,
) -> Result<Vec<u8>, LedgerError> {
    let mut w = Writer::new();
    w.u16(1);
    w.fixed(parent.genesis.id().as_bytes());
    w.fixed(
        attempt
            .round
            .ok_or(LedgerError::Invalid("normalization solution round"))?
            .as_bytes(),
    );
    encode_receipt(&mut w, &commitment.receipt);
    w.fixed(commitment.id.as_bytes());
    w.fixed(normalized.original_hash().as_bytes());
    w.fixed(parent.commitment().as_bytes());
    w.fixed(parent.genesis.profile().id().as_bytes());
    w.u32(normalized.substitutions().len() as u32);
    for (old, new) in normalized.substitutions() {
        w.fixed(old.as_bytes());
        w.fixed(new.as_bytes());
    }
    w.bytes(normalized.final_bytes())?;
    w.fixed(normalized.root().as_bytes());
    w.fixed(normalized.author().as_bytes());
    w.u32(normalized.new_proofs().len() as u32);
    for proof in normalized.new_proofs() {
        w.fixed(proof.proof_id().as_bytes());
        w.fixed(proof.author().as_bytes());
    }
    w.u32(normalized.citations().len() as u32);
    for id in normalized.citations() {
        let proof = parent
            .library
            .lookup(*id)
            .ok_or(LedgerError::Invalid("normalization citation"))?;
        w.fixed(id.as_bytes());
        w.fixed(proof.author().as_bytes());
    }
    rewards.encode_into(&mut w);
    Ok(w.finish())
}
