use super::super::historical_conflict::HistoricalFinalityProofV0;
use super::*;
use FixedValidatorHistoricalFinalityConflictErrorV0 as ConflictError;

#[derive(Clone)]
struct Proof {
    value: ConsensusValueV0,
    envelope_id: ConsensusEnvelopeId,
    envelope: Vec<u8>,
    payload: Vec<u8>,
    control: Vec<u8>,
    votes: Vec<Vec<u8>>,
    round: ConsensusRound,
}

impl Proof {
    fn new(fixture: &Fixture, transition: &OwnedVerifiedFixedConsensusTransitionV0) -> Self {
        Self {
            value: transition.value(),
            envelope_id: transition.envelope_id(),
            envelope: transition.canonical_envelope_bytes().to_vec(),
            payload: transition.canonical_artifact_bytes().to_vec(),
            control: proposal_control_bytes(
                transition.value(),
                transition.position(),
                &fixture.proposer,
            ),
            votes: vec![signed_precommit_bytes(
                fixture.context,
                transition.position(),
                transition.value().proposal_signing_root(),
                &fixture.proposer,
            )],
            round: transition.position().round(),
        }
    }

    fn submit<F: StoreIo>(
        &self,
        journal: &mut FixedValidatorFinalityJournalCore<F>,
        batch: bool,
        ceiling: u64,
    ) -> Result<FixedValidatorFinalityHaltV0, ConflictError> {
        let votes: Vec<_> = self.votes.iter().map(Vec::as_slice).collect();
        let proof = if batch {
            HistoricalFinalityProofV0::VoteBatch {
                proposal: &self.control,
                precommits: &votes,
                evidence_round: self.round,
            }
        } else {
            HistoricalFinalityProofV0::Envelope(&self.envelope)
        };
        journal.commit_historical_finality_conflict(
            proof,
            self.payload.clone(),
            ConsensusRound::new(ceiling),
        )
    }
}

struct History {
    first: Proof,
    second: Proof,
    sibling: Proof,
    selected_variant: Proof,
    next: Proof,
    other_parent: Proof,
}

fn history(fixture: &Fixture, journal: &mut FixedValidatorFinalityJournalCore<File>) -> History {
    let genesis = journal.branches[0].clone();
    let mut selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(&genesis, &mut selected, ZfcAxiom::Pairing, 0);
    let first_proof = Proof::new(fixture, &first);
    let selected_variant = Proof::new(
        fixture,
        &fixture.transition(&genesis, &mut selected, ZfcAxiom::Pairing, 2),
    );
    let mut other_state = ArtifactChainState::new(fixture.definition);
    let sibling = fixture.transition(&genesis, &mut other_state, ZfcAxiom::Union, 2);
    let sibling_proof = Proof::new(fixture, &sibling);
    other_state
        .apply_block(
            &sibling.value().artifact_block(),
            sibling.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let other_parent = Proof::new(
        fixture,
        &fixture.transition(
            &sibling.into_branch(),
            &mut other_state,
            ZfcAxiom::PowerSet,
            0,
        ),
    );
    selected
        .apply_block(
            &first.value().artifact_block(),
            first.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let _ = journal.commit_verified(first).unwrap();
    let second = fixture.transition(
        journal.branches.last().unwrap(),
        &mut selected,
        ZfcAxiom::PowerSet,
        0,
    );
    let second_proof = Proof::new(fixture, &second);
    selected
        .apply_block(
            &second.value().artifact_block(),
            second.canonical_artifact_bytes().to_vec(),
        )
        .unwrap();
    let _ = journal.commit_verified(second).unwrap();
    let next = Proof::new(
        fixture,
        &fixture.transition(
            journal.branches.last().unwrap(),
            &mut selected,
            ZfcAxiom::Union,
            0,
        ),
    );
    History {
        first: first_proof,
        second: second_proof,
        sibling: sibling_proof,
        selected_variant,
        next,
        other_parent,
    }
}

#[cfg(unix)]
#[test]
fn historical_direct_forms_match_stored_proof_halt_and_retain_the_entire_selected_prefix() {
    for batch in [false, true] {
        let fixture = Fixture::new();
        let directory = TestDirectory::new("direct-historical-finality");
        let anchor = TestDirectory::new("direct-historical-anchor");
        let mut journal = fixture.create_anchored(&directory, &anchor);
        let history = history(&fixture, &mut journal.journal.core);
        let prefix = fs::read(directory.journal()).unwrap();
        let retained: Vec<_> = journal
            .journal
            .core
            .records
            .iter()
            .map(|record| record.canonical_record_body().to_vec())
            .collect();
        assert_eq!(retained.len(), 2);
        assert_eq!(
            journal.head().unwrap().artifact_snapshot().head_block_id(),
            history.second.value.artifact_block().id()
        );
        let sibling = &history.sibling;
        let halt = if batch {
            journal.commit_historical_finality_conflict_vote_batch(
                &sibling.control,
                sibling.payload.clone(),
                &[&sibling.votes[0]],
                sibling.round,
                ConsensusRound::new(2),
            )
        } else {
            journal.commit_historical_finality_conflict(
                &sibling.envelope,
                sibling.payload.clone(),
                ConsensusRound::new(2),
            )
        }
        .unwrap();
        assert_eq!(
            halt.kind(),
            FixedValidatorFinalityHaltKindV0::SelectedSibling
        );
        assert_eq!(halt.height().value(), 1);
        assert_eq!(halt.first_ancestry(), history.first.value.ancestry_id());
        assert_eq!(halt.first_envelope_id(), history.first.envelope_id);
        assert_eq!(halt.second_ancestry(), sibling.value.ancestry_id());
        assert_eq!(halt.second_envelope_id(), sibling.envelope_id);
        assert_eq!(journal.journal.core.record_sequence, 3);
        assert_eq!(
            journal
                .journal
                .core
                .records
                .iter()
                .map(|record| record.canonical_record_body().to_vec())
                .collect::<Vec<_>>(),
            retained
        );
        let images = [
            fs::read(directory.journal()).unwrap(),
            fs::read(anchor.finality_anchor()).unwrap(),
        ];
        assert!(images[0].starts_with(&prefix));
        assert!(matches!(
            journal.head(),
            Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. })
        ));
        let mut malformed = sibling.clone();
        malformed.control.clear();
        malformed.envelope.clear();
        malformed.round = ConsensusRound::new(u64::MAX);
        assert!(matches!(
            malformed.submit(&mut journal.journal.core, batch, u64::MAX),
            Err(ConflictError::FinalityJournal(
                FixedValidatorFinalityJournalErrorV0::TerminalHalt { .. }
            ))
        ));
        assert_eq!(fs::read(directory.journal()).unwrap(), images[0]);
        drop(journal);
        let reopened = fixture.open_anchored(&directory, &anchor).unwrap();
        assert_eq!(reopened.halt().unwrap(), Some(halt));
        assert_eq!(
            reopened
                .journal
                .core
                .records
                .iter()
                .map(|record| record.canonical_record_body().to_vec())
                .collect::<Vec<_>>(),
            retained
        );
        assert_eq!(
            [
                fs::read(directory.journal()).unwrap(),
                fs::read(anchor.finality_anchor()).unwrap()
            ],
            images
        );
        let (stored_halt, stored_images) =
            candidate_commit::candidate_backed_historical_sibling_terminal_case(
                "direct-historical-equivalence",
                batch,
            );
        assert_eq!(halt, stored_halt);
        assert_eq!(images, [stored_images[0].clone(), stored_images[1].clone()]);
    }
}

#[test]
fn historical_direct_preflight_rejects_valid_next_child_and_selected_evidence_variants() {
    for batch in [false, true] {
        let fixture = Fixture::new();
        let directory = TestDirectory::new("historical-preflight");
        let mut journal = fixture.create(&directory);
        let history = history(&fixture, &mut journal.core);
        let before = fs::read(directory.journal()).unwrap();
        let state = journal.state_id().unwrap();
        assert_eq!(history.first.value, history.selected_variant.value);
        assert_ne!(
            history.first.envelope_id,
            history.selected_variant.envelope_id
        );
        assert!(
            matches!(history.next.submit(&mut journal.core, batch, 2), Err(ConflictError::SelectedHeightUnavailable { height }) if height.value() == 3)
        );
        assert!(
            matches!(history.selected_variant.submit(&mut journal.core, batch, 2), Err(ConflictError::SelectedValueNotDistinct { height }) if height.value() == 1)
        );
        let error = history
            .other_parent
            .submit(&mut journal.core, batch, 2)
            .unwrap_err();
        assert!(matches!(
            error,
            ConflictError::Envelope(_) | ConflictError::Proposal(_)
        ));
        assert_eq!(journal.finalized_len().unwrap(), 2);
        assert_eq!(journal.state_id().unwrap(), state);
        assert_eq!(fs::read(directory.journal()).unwrap(), before);
        drop(journal);
        let reopened = fixture.open(&directory, state).unwrap();
        assert_eq!(reopened.finalized_len().unwrap(), 2);
        assert_eq!(
            reopened.head().unwrap().artifact_snapshot().head_block_id(),
            history.second.value.artifact_block().id()
        );
        assert_eq!(fs::read(directory.journal()).unwrap(), before);
    }
}

#[test]
fn historical_direct_full_verification_and_ceiling_precedence_leave_no_partial_effect() {
    for batch in [false, true] {
        let fixture = Fixture::new();
        let directory = TestDirectory::new("historical-verification");
        let mut journal = fixture.create(&directory);
        let history = history(&fixture, &mut journal.core);
        let before = fs::read(directory.journal()).unwrap();
        let state = journal.state_id().unwrap();
        for mode in [
            "short",
            "trailing",
            "context",
            "parent",
            "payload",
            "signature",
            "wrong-role",
            "wrong-round",
            "empty",
            "duplicate",
            "extra-malformed",
        ] {
            if !batch && matches!(mode, "empty" | "duplicate" | "extra-malformed") {
                continue;
            }
            let mut proof = history.sibling.clone();
            match mode {
                "short" => {
                    proof.envelope = vec![0];
                    proof.control = vec![0];
                }
                "trailing" => {
                    proof.envelope.push(0);
                    proof.control.push(0);
                }
                "context" => {
                    proof.envelope[0] ^= 1;
                    proof.control[0] ^= 1;
                }
                "parent" => {
                    proof.envelope[76] ^= 1;
                    proof.control[76] ^= 1;
                }
                "payload" => proof.payload = vec![0],
                "signature" => {
                    *proof.envelope.last_mut().unwrap() ^= 1;
                    *proof.votes[0].last_mut().unwrap() ^= 1;
                }
                "wrong-role" => {
                    let offset = ConsensusValueV0::BYTE_LENGTH
                        + VerifiedProducerAuthorizationV0::BYTE_LENGTH;
                    proof.envelope[offset] = 1;
                    proof.votes[0][0] = 1;
                }
                "wrong-round" => {
                    let offset = ConsensusValueV0::BYTE_LENGTH
                        + VerifiedProducerAuthorizationV0::BYTE_LENGTH;
                    proof.envelope[offset + 84] ^= 1;
                    proof.round = ConsensusRound::new(1);
                }
                "empty" => proof.votes.clear(),
                "duplicate" => proof.votes.push(proof.votes[0].clone()),
                "extra-malformed" => proof.votes.push(vec![0]),
                _ => unreachable!(),
            }
            assert!(proof.submit(&mut journal.core, batch, 2).is_err(), "{mode}");
            assert_eq!(journal.state_id().unwrap(), state, "{mode}");
            assert_eq!(fs::read(directory.journal()).unwrap(), before, "{mode}");
        }
        let mut malformed = history.sibling.clone();
        malformed.envelope.clear();
        malformed.control.clear();
        malformed.round = ConsensusRound::new(u64::MAX);
        assert!(matches!(
            malformed.submit(&mut journal.core, batch, fixture.limit.max_round() + 1),
            Err(ConflictError::RoundWorkLimitExceedsJournal { .. })
        ));
        if batch {
            assert!(matches!(
                malformed.submit(&mut journal.core, true, 2),
                Err(ConflictError::EvidenceRoundWorkLimitExceeded { .. })
            ));
        }
        assert!(history.sibling.submit(&mut journal.core, batch, 1).is_err());
        assert_eq!(fs::read(directory.journal()).unwrap(), before);
        let halt = history.sibling.submit(&mut journal.core, batch, 2).unwrap();
        assert_eq!(journal.halt().unwrap(), Some(halt));
    }
}
