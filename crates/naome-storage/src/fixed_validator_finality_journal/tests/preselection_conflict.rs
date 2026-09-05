use super::*;

#[cfg(unix)]
#[test]
fn anchored_preselection_conflict_writes_one_canonical_terminal_pair_without_selection() {
    let fixture = Fixture::new();
    let first_journal_directory = TestDirectory::new("preselection-pair-first-journal");
    let first_anchor_directory = TestDirectory::new("preselection-pair-first-anchor");
    let second_journal_directory = TestDirectory::new("preselection-pair-second-journal");
    let second_anchor_directory = TestDirectory::new("preselection-pair-second-anchor");
    let mut first_journal =
        fixture.create_anchored(&first_journal_directory, &first_anchor_directory);
    let initial_image = fs::read(first_journal_directory.journal()).unwrap();
    let initial_state = first_journal.state_id().unwrap();
    let parent = first_journal.head().unwrap().clone();
    let (left, right) = fixture.preselection_conflict_pair(&parent, 2);
    let left_root = left.value().proposal_signing_root();
    let right_root = right.value().proposal_signing_root();
    let (canonical_first, canonical_second) = if left_root < right_root {
        (&left, &right)
    } else {
        (&right, &left)
    };
    let expected_first_ancestry = canonical_first.value().ancestry_id();
    let expected_first_envelope = canonical_first.envelope_id();
    let expected_second_ancestry = canonical_second.value().ancestry_id();
    let expected_second_envelope = canonical_second.envelope_id();
    let mut expected_body = Vec::new();
    expected_body.push(PRESELECTION_CONFLICT_HALT_RECORD);
    expected_body.extend_from_slice(&2_u64.to_be_bytes());
    for length in [
        canonical_first.canonical_envelope_bytes().len(),
        canonical_first.canonical_artifact_bytes().len(),
        canonical_second.canonical_envelope_bytes().len(),
        canonical_second.canonical_artifact_bytes().len(),
    ] {
        expected_body.extend_from_slice(&u32::try_from(length).unwrap().to_be_bytes());
    }
    expected_body.extend_from_slice(canonical_first.canonical_envelope_bytes());
    expected_body.extend_from_slice(canonical_first.canonical_artifact_bytes());
    expected_body.extend_from_slice(canonical_second.canonical_envelope_bytes());
    expected_body.extend_from_slice(canonical_second.canonical_artifact_bytes());
    assert_eq!(PRESELECTION_CONFLICT_RECORD_HEADER_BYTES, 25);
    assert_eq!(MIN_PRESELECTION_CONFLICT_RECORD_BODY_BYTES, 1_419);
    assert_eq!(MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES, 8_438_987);
    assert_eq!(MIN_PRESELECTION_CONFLICT_RECORD_BODY_BYTES + 4 + 32, 1_455);
    assert_eq!(
        MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES + 4 + 32,
        8_439_023
    );
    assert_eq!(
        expected_body.len(),
        PRESELECTION_CONFLICT_RECORD_HEADER_BYTES
            + canonical_first.canonical_envelope_bytes().len()
            + canonical_first.canonical_artifact_bytes().len()
            + canonical_second.canonical_envelope_bytes().len()
            + canonical_second.canonical_artifact_bytes().len()
    );
    assert!(
        (MIN_PRESELECTION_CONFLICT_RECORD_BODY_BYTES..=MAX_PRESELECTION_CONFLICT_RECORD_BODY_BYTES)
            .contains(&expected_body.len())
    );
    let body_length = u32::try_from(expected_body.len()).unwrap().to_be_bytes();
    let expected_state = step_state_id(initial_state, body_length, &expected_body);
    let halt = if left_root < right_root {
        first_journal
            .commit_verified_preselection_conflict(right, left)
            .unwrap()
    } else {
        first_journal
            .commit_verified_preselection_conflict(left, right)
            .unwrap()
    };

    assert_eq!(
        halt.kind(),
        FixedValidatorFinalityHaltKindV0::PreselectionPair
    );
    assert_eq!(halt.height(), ConsensusHeight::new(1));
    assert_eq!(halt.first_ancestry(), expected_first_ancestry);
    assert_eq!(halt.first_envelope_id(), expected_first_envelope);
    assert_eq!(halt.second_ancestry(), expected_second_ancestry);
    assert_eq!(halt.second_envelope_id(), expected_second_envelope);
    assert_eq!(halt.state_id(), expected_state);
    assert_eq!(first_journal.state_id().unwrap(), expected_state);
    assert_eq!(first_journal.halt().unwrap(), Some(halt));
    assert_eq!(first_journal.journal.core.record_sequence, 1);
    assert_eq!(first_journal.journal.core.records.len(), 0);
    assert_eq!(first_journal.journal.core.branches.len(), 1);
    assert_eq!(first_journal.journal.core.snapshot_index.len(), 1);
    assert!(matches!(
        first_journal.head(),
        Err(FixedValidatorFinalityJournalErrorV0::TerminalHalt { height })
            if height == ConsensusHeight::new(1)
    ));
    let mut expected_image = initial_image.clone();
    expected_image.extend_from_slice(&body_length);
    expected_image.extend_from_slice(&expected_body);
    expected_image.extend_from_slice(expected_state.as_bytes());
    assert_eq!(
        expected_image.len() - initial_image.len(),
        expected_body.len() + 36
    );
    assert_eq!(
        fs::read(first_journal_directory.journal()).unwrap(),
        expected_image
    );
    let anchor_image = fs::read(first_anchor_directory.finality_anchor()).unwrap();
    assert_eq!(&anchor_image[149..157], &1_u64.to_be_bytes());
    assert_eq!(&anchor_image[157..189], expected_state.as_bytes());
    drop(first_journal);

    let raw_reopened = fixture
        .open(&first_journal_directory, expected_state)
        .unwrap();
    assert_eq!(raw_reopened.halt().unwrap(), Some(halt));
    assert_eq!(raw_reopened.core.record_sequence, 1);
    assert_eq!(raw_reopened.core.records.len(), 0);
    assert_eq!(raw_reopened.core.branches.len(), 1);
    assert_eq!(raw_reopened.core.snapshot_index.len(), 1);
    drop(raw_reopened);
    let anchored_reopened = fixture
        .open_anchored(&first_journal_directory, &first_anchor_directory)
        .unwrap();
    assert_eq!(anchored_reopened.halt().unwrap(), Some(halt));
    drop(anchored_reopened);

    let mut second_journal =
        fixture.create_anchored(&second_journal_directory, &second_anchor_directory);
    let second_parent = second_journal.head().unwrap().clone();
    let (second_left, second_right) = fixture.preselection_conflict_pair(&second_parent, 2);
    let second_halt = if second_left.value().proposal_signing_root()
        < second_right.value().proposal_signing_root()
    {
        second_journal
            .commit_verified_preselection_conflict(second_left, second_right)
            .unwrap()
    } else {
        second_journal
            .commit_verified_preselection_conflict(second_right, second_left)
            .unwrap()
    };
    assert_eq!(second_halt, halt);
    assert_eq!(
        fs::read(second_journal_directory.journal()).unwrap(),
        expected_image
    );
    assert_eq!(
        fs::read(second_anchor_directory.finality_anchor()).unwrap(),
        anchor_image
    );
}

#[cfg(unix)]
#[test]
fn preselection_conflict_replay_rejects_reordered_lengths_framing_and_payload_tampering() {
    let fixture = Fixture::new();
    let journal_directory = TestDirectory::new("preselection-pair-replay-journal");
    let anchor_directory = TestDirectory::new("preselection-pair-replay-anchor");
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let prefix = fs::read(journal_directory.journal()).unwrap();
    let genesis = journal.state_id().unwrap();
    let parent = journal.head().unwrap().clone();
    let (left, right) = fixture.preselection_conflict_pair(&parent, 2);
    let _ = journal
        .commit_verified_preselection_conflict(left, right)
        .unwrap();
    let valid_image = fs::read(journal_directory.journal()).unwrap();
    drop(journal);

    let body_length = u32::from_be_bytes(
        valid_image[JOURNAL_PREFIX_BYTES..JOURNAL_PREFIX_BYTES + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let body_start = JOURNAL_PREFIX_BYTES + 4;
    let body_end = body_start + body_length;
    let body = &valid_image[body_start..body_end];
    assert_eq!(body[0], PRESELECTION_CONFLICT_HALT_RECORD);
    let lengths = [9_usize, 13, 17, 21]
        .map(|offset| u32::from_be_bytes(body[offset..offset + 4].try_into().unwrap()) as usize);
    let first_envelope_start = PRESELECTION_CONFLICT_RECORD_HEADER_BYTES;
    let first_payload_start = first_envelope_start + lengths[0];
    let second_envelope_start = first_payload_start + lengths[1];
    let second_payload_start = second_envelope_start + lengths[2];
    assert_eq!(second_payload_start + lengths[3], body.len());

    let mut reordered_body = Vec::with_capacity(body.len());
    reordered_body.extend_from_slice(&body[..9]);
    for length in [lengths[2], lengths[3], lengths[0], lengths[1]] {
        reordered_body.extend_from_slice(&u32::try_from(length).unwrap().to_be_bytes());
    }
    reordered_body
        .extend_from_slice(&body[second_envelope_start..second_envelope_start + lengths[2]]);
    reordered_body.extend_from_slice(&body[second_payload_start..]);
    reordered_body.extend_from_slice(&body[first_envelope_start..first_payload_start]);
    reordered_body.extend_from_slice(&body[first_payload_start..second_envelope_start]);
    assert_eq!(reordered_body.len(), body.len());
    let (reordered_image, reordered_state) = single_entry_image(&prefix, genesis, &reordered_body);
    fs::write(journal_directory.journal(), &reordered_image).unwrap();
    assert!(matches!(
        fixture.open(&journal_directory, reordered_state),
        Err(FixedValidatorFinalityJournalErrorV0::InvalidPreselectionConflict {
            entry: 0,
            height,
        }) if height == ConsensusHeight::new(1)
    ));
    assert_eq!(
        fs::read(journal_directory.journal()).unwrap(),
        reordered_image
    );

    for (offset, envelope) in [(9_usize, true), (13, false), (17, true), (21, false)] {
        let mut zero_length_body = body.to_vec();
        zero_length_body[offset..offset + 4].fill(0);
        let (zero_length_image, zero_length_state) =
            single_entry_image(&prefix, genesis, &zero_length_body);
        fs::write(journal_directory.journal(), &zero_length_image).unwrap();
        let error = fixture.open(&journal_directory, zero_length_state);
        if envelope {
            assert!(matches!(
                error,
                Err(
                    FixedValidatorFinalityJournalErrorV0::InvalidEnvelopeLength {
                        entry: 0,
                        actual: 0,
                    }
                )
            ));
        } else {
            assert!(matches!(
                error,
                Err(FixedValidatorFinalityJournalErrorV0::InvalidPayloadLength {
                    entry: 0,
                    actual: 0,
                })
            ));
        }
        assert_eq!(
            fs::read(journal_directory.journal()).unwrap(),
            zero_length_image
        );
    }

    let mut trailing_body = body.to_vec();
    trailing_body.push(0);
    let (trailing_image, trailing_state) = single_entry_image(&prefix, genesis, &trailing_body);
    fs::write(journal_directory.journal(), &trailing_image).unwrap();
    assert!(matches!(
        fixture.open(&journal_directory, trailing_state),
        Err(FixedValidatorFinalityJournalErrorV0::InvalidRecordFraming { entry: 0 })
    ));
    assert_eq!(
        fs::read(journal_directory.journal()).unwrap(),
        trailing_image
    );

    let mut payload_tamper_body = body.to_vec();
    *payload_tamper_body.last_mut().unwrap() ^= 0x01;
    let (payload_tamper_image, payload_tamper_state) =
        single_entry_image(&prefix, genesis, &payload_tamper_body);
    fs::write(journal_directory.journal(), &payload_tamper_image).unwrap();
    assert!(matches!(
        fixture.open(&journal_directory, payload_tamper_state),
        Err(FixedValidatorFinalityJournalErrorV0::Replay { entry: 0, .. })
    ));
    assert_eq!(
        fs::read(journal_directory.journal()).unwrap(),
        payload_tamper_image
    );
}

#[cfg(unix)]
#[test]
fn preselection_conflict_rejects_mismatched_or_duplicate_evidence_without_write() {
    let fixture = Fixture::new();
    let journal_directory = TestDirectory::new("preselection-pair-invalid-journal");
    let anchor_directory = TestDirectory::new("preselection-pair-invalid-anchor");
    let mut journal = fixture.create_anchored(&journal_directory, &anchor_directory);
    let parent = journal.head().unwrap().clone();
    let journal_before = fs::read(journal_directory.journal()).unwrap();
    let anchor_before = fs::read(anchor_directory.finality_anchor()).unwrap();
    let state_before = journal.state_id().unwrap();

    let mut first_selected = ArtifactChainState::new(fixture.definition);
    let first = fixture.transition(&parent, &mut first_selected, ZfcAxiom::Pairing, 0);
    let mut second_selected = ArtifactChainState::new(fixture.definition);
    let second = fixture.transition(&parent, &mut second_selected, ZfcAxiom::Union, 1);
    assert!(matches!(
        journal.commit_verified_preselection_conflict(first, second),
        Err(FixedValidatorFinalityJournalErrorV0::PreselectionConflictPositionMismatch { .. })
    ));

    let mut duplicate_left_state = ArtifactChainState::new(fixture.definition);
    let duplicate_left =
        fixture.transition(&parent, &mut duplicate_left_state, ZfcAxiom::Pairing, 0);
    let mut duplicate_right_state = ArtifactChainState::new(fixture.definition);
    let duplicate_right =
        fixture.transition(&parent, &mut duplicate_right_state, ZfcAxiom::Pairing, 0);
    assert!(matches!(
        journal.commit_verified_preselection_conflict(duplicate_left, duplicate_right),
        Err(FixedValidatorFinalityJournalErrorV0::PreselectionConflictNotDistinct { height })
            if height == ConsensusHeight::new(1)
    ));
    let (above_limit_left, above_limit_right) =
        fixture.preselection_conflict_pair(&parent, fixture.limit.max_round() + 1);
    assert!(matches!(
        journal.commit_verified_preselection_conflict(above_limit_left, above_limit_right),
        Err(FixedValidatorFinalityJournalErrorV0::RoundLimitExceeded { round, maximum })
            if round == fixture.limit.max_round() + 1 && maximum == fixture.limit.max_round()
    ));
    assert_eq!(journal.state_id().unwrap(), state_before);
    assert_eq!(journal.halt().unwrap(), None);
    assert_eq!(journal.journal.core.record_sequence, 0);
    assert_eq!(
        fs::read(journal_directory.journal()).unwrap(),
        journal_before
    );
    assert_eq!(
        fs::read(anchor_directory.finality_anchor()).unwrap(),
        anchor_before
    );
}
