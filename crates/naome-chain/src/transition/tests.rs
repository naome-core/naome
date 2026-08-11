use super::*;

const PREVIOUS_ROOT_BYTE: u8 = 0x11;
const RESULTING_ROOT_BYTE: u8 = 0x22;

fn proof_set_root(byte: u8) -> ProofSetRoot {
    ProofSetRoot::from_bytes([byte; 32])
}

fn proof_id(byte: u8) -> ProofId {
    ProofId::from_bytes([byte; 32])
}

fn transition(proof_ids: Vec<ProofId>) -> ProofTransition {
    ProofTransition::new(
        proof_set_root(PREVIOUS_ROOT_BYTE),
        proof_set_root(RESULTING_ROOT_BYTE),
        proof_ids,
    )
    .unwrap()
}

fn raw_encoding(proof_ids: &[ProofId]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PREFIX_BYTES + proof_ids.len() * PROOF_ID_BYTES);
    bytes.extend_from_slice(&[PREVIOUS_ROOT_BYTE; ROOT_BYTES]);
    bytes.extend_from_slice(&[RESULTING_ROOT_BYTE; ROOT_BYTES]);
    bytes.push(proof_ids.len() as u8);
    for proof_id in proof_ids {
        bytes.extend_from_slice(proof_id.as_bytes());
    }
    bytes
}

#[test]
fn canonical_bytes_and_transition_id_match_fixed_golden() {
    let proof_ids = vec![proof_id(0x33), proof_id(0x44)];
    let transition = transition(proof_ids.clone());
    let expected_bytes = raw_encoding(&proof_ids);
    let expected_id = ProofTransitionId::from_bytes([
        0x75, 0x88, 0x94, 0x14, 0x22, 0xcb, 0x21, 0x02, 0xd8, 0xc0, 0x3f, 0x6a, 0xa8, 0xc1, 0xfc,
        0x2c, 0x68, 0x3d, 0x57, 0x9f, 0x67, 0xb7, 0xf9, 0x6e, 0x22, 0xea, 0xbd, 0x5b, 0x68, 0xc5,
        0x00, 0x70,
    ]);

    assert_eq!(expected_bytes.len(), 129);
    assert_eq!(transition.to_canonical_bytes(), expected_bytes);
    assert_eq!(transition.id(), expected_id);
    assert_eq!(
        ProofTransition::from_canonical_bytes(&transition.to_canonical_bytes()),
        Ok(transition.clone())
    );
    assert_eq!(
        transition.previous_proof_set_root(),
        proof_set_root(PREVIOUS_ROOT_BYTE)
    );
    assert_eq!(
        transition.resulting_proof_set_root(),
        proof_set_root(RESULTING_ROOT_BYTE)
    );
    assert_eq!(transition.proof_ids(), proof_ids);
    assert_eq!(transition.root_proof_id(), proof_id(0x44));
    assert_eq!(
        ProofTransitionId::from_bytes(*expected_id.as_bytes()),
        expected_id
    );
}

#[test]
fn every_canonical_prefix_is_rejected_as_truncated() {
    for count in 1..=PROOF_BATCH_MAX_CANDIDATES {
        let proof_ids = (0..count)
            .map(|index| proof_id(u8::try_from(index + 1).unwrap()))
            .collect();
        let bytes = transition(proof_ids).to_canonical_bytes();

        for end in 0..bytes.len() {
            assert_eq!(
                ProofTransition::from_canonical_bytes(&bytes[..end]),
                Err(ProofTransitionError::UnexpectedEnd),
                "count {count}, prefix length {end}"
            );
        }
        assert!(ProofTransition::from_canonical_bytes(&bytes).is_ok());
    }
}

#[test]
fn zero_and_nine_counts_fail_before_body_decoding() {
    let mut zero = vec![0x11; PREFIX_BYTES];
    zero[ROOT_BYTES..ROOT_BYTES * 2].fill(0x22);
    zero[ROOT_BYTES * 2] = 0;
    assert_eq!(
        ProofTransition::from_canonical_bytes(&zero),
        Err(ProofTransitionError::Empty)
    );

    let mut nine = zero;
    nine[ROOT_BYTES * 2] = 9;
    assert_eq!(
        ProofTransition::from_canonical_bytes(&nine),
        Err(ProofTransitionError::TooManyProofs {
            actual: 9,
            maximum: PROOF_BATCH_MAX_CANDIDATES,
        })
    );

    assert_eq!(
        ProofTransition::new(
            proof_set_root(PREVIOUS_ROOT_BYTE),
            proof_set_root(RESULTING_ROOT_BYTE),
            Vec::new(),
        ),
        Err(ProofTransitionError::Empty)
    );
    assert_eq!(
        ProofTransition::new(
            proof_set_root(PREVIOUS_ROOT_BYTE),
            proof_set_root(RESULTING_ROOT_BYTE),
            (0..=PROOF_BATCH_MAX_CANDIDATES)
                .map(|index| proof_id(u8::try_from(index + 1).unwrap()))
                .collect(),
        ),
        Err(ProofTransitionError::TooManyProofs {
            actual: PROOF_BATCH_MAX_CANDIDATES + 1,
            maximum: PROOF_BATCH_MAX_CANDIDATES,
        })
    );
}

#[test]
fn trailing_bytes_and_absolute_input_limit_have_stable_precedence() {
    let mut bytes = transition(vec![proof_id(0x33)]).to_canonical_bytes();
    bytes.extend(vec![0xaa; PROOF_TRANSITION_MAX_BYTES - bytes.len()]);
    assert_eq!(bytes.len(), PROOF_TRANSITION_MAX_BYTES);
    assert_eq!(
        ProofTransition::from_canonical_bytes(&bytes),
        Err(ProofTransitionError::TrailingBytes {
            remaining: PROOF_TRANSITION_MAX_BYTES - (PREFIX_BYTES + PROOF_ID_BYTES),
        })
    );

    bytes.push(0xbb);
    assert_eq!(
        ProofTransition::from_canonical_bytes(&bytes),
        Err(ProofTransitionError::InputTooLong {
            actual: PROOF_TRANSITION_MAX_BYTES + 1,
            maximum: PROOF_TRANSITION_MAX_BYTES,
        })
    );
}

#[test]
fn duplicate_identity_reports_first_and_duplicate_positions() {
    let duplicate = proof_id(0x33);
    let proof_ids = vec![duplicate, proof_id(0x44), duplicate];
    let expected = ProofTransitionError::DuplicateProofId {
        first_index: 0,
        duplicate_index: 2,
        proof_id: duplicate,
    };

    assert_eq!(
        ProofTransition::new(
            proof_set_root(PREVIOUS_ROOT_BYTE),
            proof_set_root(RESULTING_ROOT_BYTE),
            proof_ids.clone(),
        ),
        Err(expected)
    );

    let mut bytes = raw_encoding(&proof_ids);
    assert_eq!(ProofTransition::from_canonical_bytes(&bytes), Err(expected));

    bytes.push(0xff);
    assert_eq!(
        ProofTransition::from_canonical_bytes(&bytes),
        Err(ProofTransitionError::TrailingBytes { remaining: 1 })
    );
    bytes.pop();
    bytes.pop();
    assert_eq!(
        ProofTransition::from_canonical_bytes(&bytes),
        Err(ProofTransitionError::UnexpectedEnd)
    );
}

#[test]
fn every_valid_count_round_trips_at_the_exact_encoded_length() {
    assert_eq!(PROOF_BATCH_MAX_CANDIDATES, 8);
    assert_eq!(PROOF_TRANSITION_MAX_BYTES, 321);

    for count in 1..=PROOF_BATCH_MAX_CANDIDATES {
        let proof_ids = (0..count)
            .map(|index| proof_id(u8::try_from(0x30 + index).unwrap()))
            .collect::<Vec<_>>();
        let transition = transition(proof_ids.clone());
        let bytes = transition.to_canonical_bytes();

        assert_eq!(bytes.len(), PREFIX_BYTES + count * PROOF_ID_BYTES);
        assert_eq!(
            ProofTransition::from_canonical_bytes(&bytes),
            Ok(transition.clone())
        );
        assert_eq!(transition.proof_ids(), proof_ids);
        assert_eq!(transition.root_proof_id(), *proof_ids.last().unwrap());
    }

    let maximal = transition(
        (0..PROOF_BATCH_MAX_CANDIDATES)
            .map(|index| proof_id(u8::try_from(index + 1).unwrap()))
            .collect(),
    );
    assert_eq!(
        maximal.to_canonical_bytes().len(),
        PROOF_TRANSITION_MAX_BYTES
    );
}

#[test]
fn dependency_order_is_preserved_and_changes_identity() {
    let first = transition(vec![proof_id(0x31), proof_id(0x32), proof_id(0x33)]);
    let permuted = transition(vec![proof_id(0x32), proof_id(0x31), proof_id(0x33)]);

    assert_eq!(first.root_proof_id(), permuted.root_proof_id());
    assert_ne!(first.proof_ids(), permuted.proof_ids());
    assert_ne!(first.to_canonical_bytes(), permuted.to_canonical_bytes());
    assert_ne!(first.id(), permuted.id());
    assert_eq!(
        ProofTransition::from_canonical_bytes(&permuted.to_canonical_bytes())
            .unwrap()
            .proof_ids(),
        permuted.proof_ids()
    );
}

#[test]
fn flipping_every_root_or_proof_id_byte_changes_transition_identity() {
    let original = transition(vec![proof_id(0x33), proof_id(0x44)]);
    let original_id = original.id();
    let encoded = original.to_canonical_bytes();
    let count_offset = ROOT_BYTES * 2;

    for index in 0..encoded.len() {
        if index == count_offset {
            continue;
        }
        let mut mutated = encoded.clone();
        mutated[index] ^= 0x01;
        let mutated = ProofTransition::from_canonical_bytes(&mutated)
            .unwrap_or_else(|error| panic!("byte {index} produced {error:?}"));
        assert_ne!(mutated.id(), original_id, "byte {index}");
    }

    let different_count = transition(vec![proof_id(0x33)]);
    assert_ne!(different_count.id(), original_id);
}
