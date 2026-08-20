use std::fmt::Write;

use super::{
    ARTIFACT_SET_PROOF_MAX_BYTES, EMPTY_TERMINAL_TAG, MEMBER_TERMINAL_TAG, NON_MEMBER_TERMINAL_TAG,
    PATH_STEP_BYTES,
};
use crate::artifact_set::{
    ArtifactSetMembership, ArtifactSetProof, ArtifactSetProofError, ArtifactSetRoot,
    ArtifactSetValue, AuthenticatedArtifactSet,
};
use naome_proof::ArtifactId;

#[derive(Clone, Copy)]
struct TestValue(ArtifactId);

impl ArtifactSetValue for TestValue {
    fn artifact_id(&self) -> ArtifactId {
        self.0
    }
}

fn id(bytes: [u8; 32]) -> ArtifactId {
    ArtifactId::from_bytes(bytes)
}

fn single_bit_id(bit: usize) -> ArtifactId {
    let mut bytes = [0; 32];
    bytes[bit / 8] = 1 << (7 - bit % 8);
    id(bytes)
}

fn set_for(keys: &[ArtifactId]) -> AuthenticatedArtifactSet<TestValue> {
    let mut set = AuthenticatedArtifactSet::new();
    for key in keys {
        assert!(set.insert(TestValue(*key)).is_some());
    }
    set
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn round_trip(
    proof: &ArtifactSetProof,
    root: ArtifactSetRoot,
    query: ArtifactId,
    expected: ArtifactSetMembership,
) {
    let encoded = proof.to_canonical_bytes();
    let decoded = ArtifactSetProof::from_canonical_bytes(&encoded).unwrap();
    assert_eq!(decoded, *proof);
    assert_eq!(decoded.to_canonical_bytes(), encoded);
    assert_eq!(decoded.verify(root, query), Ok(expected));
}

fn permute(
    values: &mut [ArtifactId],
    start: usize,
    query: ArtifactId,
    expected_root: &mut Option<ArtifactSetRoot>,
    expected_bytes: &mut Option<Vec<u8>>,
) {
    if start == values.len() {
        let set = set_for(values);
        let root = set.root();
        let bytes = set.proof(query).to_canonical_bytes();
        assert_eq!(*expected_root.get_or_insert(root), root);
        assert_eq!(*expected_bytes.get_or_insert(bytes.clone()), bytes);
        return;
    }
    for index in start..values.len() {
        values.swap(start, index);
        permute(values, start + 1, query, expected_root, expected_bytes);
        values.swap(start, index);
    }
}

#[test]
fn terminal_and_one_step_encodings_have_stable_goldens() {
    let zero = id([0; 32]);
    let high = single_bit_id(0);
    let quarter = single_bit_id(1);
    let empty = AuthenticatedArtifactSet::<TestValue>::new();
    let singleton = set_for(&[zero]);
    let pair = set_for(&[zero, high]);

    assert_eq!(hex(&empty.proof(zero).to_canonical_bytes()), "00");
    assert_eq!(hex(&singleton.proof(zero).to_canonical_bytes()), "01");
    assert_eq!(
        hex(&singleton.proof(high).to_canonical_bytes()),
        concat!(
            "02",
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
    );
    assert_eq!(
        hex(&pair.proof(zero).to_canonical_bytes()),
        concat!(
            "0100",
            "6d26aa7e37e2964bebfd2cd1cc91629a3783135876a754a2fd33bdb5277e5d9c"
        )
    );
    assert_eq!(
        hex(&pair.proof(quarter).to_canonical_bytes()),
        concat!(
            "02",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00",
            "6d26aa7e37e2964bebfd2cd1cc91629a3783135876a754a2fd33bdb5277e5d9c"
        )
    );
}

#[test]
fn generated_proofs_round_trip_and_ignore_insertion_order() {
    let zero = id([0; 32]);
    let member = id([0x55; 32]);
    let absent = id([0x33; 32]);
    let empty = AuthenticatedArtifactSet::<TestValue>::new();
    round_trip(
        &empty.proof(absent),
        empty.root(),
        absent,
        ArtifactSetMembership::Absent,
    );

    let mut values = [zero, member, id([0xaa; 32]), id([0xff; 32])];
    let set = set_for(&values);
    round_trip(
        &set.proof(member),
        set.root(),
        member,
        ArtifactSetMembership::Present,
    );
    round_trip(
        &set.proof(absent),
        set.root(),
        absent,
        ArtifactSetMembership::Absent,
    );

    for query in [member, absent] {
        let mut expected_root = None;
        let mut expected_bytes = None;
        permute(
            &mut values,
            0,
            query,
            &mut expected_root,
            &mut expected_bytes,
        );
    }
}

#[test]
fn complete_step_prefixes_are_structural_but_partial_steps_are_not() {
    let zero = id([0; 32]);
    let set = set_for(&[zero, single_bit_id(0), single_bit_id(1)]);
    let root = set.root();

    let member = set.proof(zero).to_canonical_bytes();
    assert_eq!(member.len(), 1 + 2 * PATH_STEP_BYTES);
    for length in 0..=member.len() {
        let decoded = ArtifactSetProof::from_canonical_bytes(&member[..length]);
        if matches!(length, 1 | 34 | 67) {
            let decoded = decoded.unwrap();
            if length == member.len() {
                assert_eq!(
                    decoded.verify(root, zero),
                    Ok(ArtifactSetMembership::Present)
                );
            } else {
                assert!(matches!(
                    decoded.verify(root, zero),
                    Err(ArtifactSetProofError::RootMismatch { .. })
                ));
            }
        } else {
            assert_eq!(decoded, Err(ArtifactSetProofError::UnexpectedEnd));
        }
    }

    let query = single_bit_id(2);
    let non_member = set.proof(query).to_canonical_bytes();
    assert_eq!(non_member.len(), 33 + 2 * PATH_STEP_BYTES);
    for length in 0..=non_member.len() {
        let decoded = ArtifactSetProof::from_canonical_bytes(&non_member[..length]);
        if matches!(length, 33 | 66 | 99) {
            let decoded = decoded.unwrap();
            if length == non_member.len() {
                assert_eq!(
                    decoded.verify(root, query),
                    Ok(ArtifactSetMembership::Absent)
                );
            } else {
                assert!(matches!(
                    decoded.verify(root, query),
                    Err(ArtifactSetProofError::RootMismatch { .. })
                ));
            }
        } else {
            assert_eq!(decoded, Err(ArtifactSetProofError::UnexpectedEnd));
        }
    }

    let singleton = set_for(&[zero]);
    let singleton_root = singleton.root();
    let mut extended_member = singleton.proof(zero).to_canonical_bytes();
    extended_member.push(0);
    extended_member.extend_from_slice(&[0; 32]);
    let decoded = ArtifactSetProof::from_canonical_bytes(&extended_member).unwrap();
    assert!(matches!(
        decoded.verify(singleton_root, zero),
        Err(ArtifactSetProofError::RootMismatch { .. })
    ));

    for suffix_len in 1..PATH_STEP_BYTES {
        let mut partial = vec![MEMBER_TERMINAL_TAG];
        partial.resize(1 + suffix_len, 0);
        assert_eq!(
            ArtifactSetProof::from_canonical_bytes(&partial),
            Err(ArtifactSetProofError::UnexpectedEnd)
        );
    }
}

#[test]
fn decoding_preflights_framing_and_path_shape() {
    assert_eq!(
        ArtifactSetProof::from_canonical_bytes(&[]),
        Err(ArtifactSetProofError::UnexpectedEnd)
    );
    for tag in [0x03, 0xff] {
        assert_eq!(
            ArtifactSetProof::from_canonical_bytes(&[tag]),
            Err(ArtifactSetProofError::UnknownTerminalTag(tag))
        );
    }
    assert_eq!(
        ArtifactSetProof::from_canonical_bytes(&[EMPTY_TERMINAL_TAG, 0]),
        Err(ArtifactSetProofError::TrailingBytes { remaining: 1 })
    );
    for terminal_len in 0..32 {
        let mut bytes = vec![NON_MEMBER_TERMINAL_TAG];
        bytes.resize(1 + terminal_len, 0);
        assert_eq!(
            ArtifactSetProof::from_canonical_bytes(&bytes),
            Err(ArtifactSetProofError::UnexpectedEnd)
        );
    }

    let mut oversized = vec![0xff; ARTIFACT_SET_PROOF_MAX_BYTES + 1];
    assert_eq!(
        ArtifactSetProof::from_canonical_bytes(&oversized),
        Err(ArtifactSetProofError::InputTooLong {
            actual: ARTIFACT_SET_PROOF_MAX_BYTES + 1,
            maximum: ARTIFACT_SET_PROOF_MAX_BYTES,
        })
    );
    oversized[0] = MEMBER_TERMINAL_TAG;
    assert!(matches!(
        ArtifactSetProof::from_canonical_bytes(&oversized),
        Err(ArtifactSetProofError::InputTooLong { .. })
    ));

    let sibling = [0x44; 32];
    for bits in [[0, 1], [0, 255], [254, 255]] {
        let mut bytes = vec![MEMBER_TERMINAL_TAG];
        for bit in bits {
            bytes.push(bit);
            bytes.extend_from_slice(&sibling);
        }
        assert!(ArtifactSetProof::from_canonical_bytes(&bytes).is_ok());
    }
    for bits in [[5, 5], [5, 4], [255, 0]] {
        let mut bytes = vec![MEMBER_TERMINAL_TAG];
        for bit in bits {
            bytes.push(bit);
            bytes.extend_from_slice(&sibling);
        }
        assert!(matches!(
            ArtifactSetProof::from_canonical_bytes(&bytes),
            Err(ArtifactSetProofError::NonIncreasingBits { .. })
        ));
    }

    let mut empty_sibling = vec![MEMBER_TERMINAL_TAG, 7];
    empty_sibling.extend_from_slice(ArtifactSetRoot::empty().as_bytes());
    assert_eq!(
        ArtifactSetProof::from_canonical_bytes(&empty_sibling),
        Err(ArtifactSetProofError::EmptySibling { bit: 7 })
    );

    let mut zero_sibling = vec![MEMBER_TERMINAL_TAG, 7];
    zero_sibling.extend_from_slice(&[0; 32]);
    assert_eq!(
        ArtifactSetProof::from_canonical_bytes(&zero_sibling)
            .unwrap()
            .to_canonical_bytes(),
        zero_sibling
    );
}

#[test]
fn maximum_member_and_nonmember_proofs_round_trip() {
    let zero = id([0; 32]);
    let mut member_set = AuthenticatedArtifactSet::new();
    let _ = member_set.insert(TestValue(zero)).unwrap();
    for bit in 0..256 {
        let _ = member_set.insert(TestValue(single_bit_id(bit))).unwrap();
    }
    let member = member_set.proof(zero);
    let member_bytes = member.to_canonical_bytes();
    assert_eq!(member_set.len(), 257);
    assert_eq!(member.sibling_count(), 256);
    assert_eq!(member_bytes.len(), ARTIFACT_SET_PROOF_MAX_BYTES);
    round_trip(
        &member,
        member_set.root(),
        zero,
        ArtifactSetMembership::Present,
    );

    let mut non_member_set = AuthenticatedArtifactSet::new();
    let _ = non_member_set.insert(TestValue(zero)).unwrap();
    for bit in 0..255 {
        let _ = non_member_set
            .insert(TestValue(single_bit_id(bit)))
            .unwrap();
    }
    let query = single_bit_id(255);
    let non_member = non_member_set.proof(query);
    let non_member_bytes = non_member.to_canonical_bytes();
    assert_eq!(non_member.sibling_count(), 255);
    assert_eq!(non_member_bytes.len(), ARTIFACT_SET_PROOF_MAX_BYTES - 1);
    round_trip(
        &non_member,
        non_member_set.root(),
        query,
        ArtifactSetMembership::Absent,
    );

    let mut member_too_long = vec![MEMBER_TERMINAL_TAG];
    for bit in 0..=u8::MAX {
        member_too_long.push(bit);
        member_too_long.extend_from_slice(&[0x44; 32]);
    }
    member_too_long.push(0xff);
    member_too_long.extend_from_slice(&[0x44; 32]);
    assert!(matches!(
        ArtifactSetProof::from_canonical_bytes(&member_too_long),
        Err(ArtifactSetProofError::InputTooLong { .. })
    ));

    let mut non_member_too_long = vec![NON_MEMBER_TERMINAL_TAG];
    non_member_too_long.extend_from_slice(zero.as_bytes());
    for bit in 0..=u8::MAX {
        non_member_too_long.push(bit);
        non_member_too_long.extend_from_slice(&[0x44; 32]);
    }
    assert!(matches!(
        ArtifactSetProof::from_canonical_bytes(&non_member_too_long),
        Err(ArtifactSetProofError::InputTooLong { .. })
    ));
}

#[test]
fn decoded_proofs_still_require_the_original_root_and_query() {
    let zero = id([0; 32]);
    let high = single_bit_id(0);
    let query = single_bit_id(255);
    let mut set = set_for(&[zero, high]);
    let root = set.root();
    let bytes = set.proof(query).to_canonical_bytes();
    let decoded = ArtifactSetProof::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(
        decoded.verify(root, query),
        Ok(ArtifactSetMembership::Absent)
    );
    assert_eq!(
        decoded.verify(root, zero),
        Err(ArtifactSetProofError::NonMemberMatchesQuery)
    );

    let mut wrong_root = *root.as_bytes();
    wrong_root[31] ^= 1;
    assert!(matches!(
        decoded.verify(ArtifactSetRoot::from_bytes(wrong_root), query),
        Err(ArtifactSetProofError::RootMismatch { .. })
    ));

    let mut changed_terminal = bytes.clone();
    changed_terminal[1] ^= 0x80;
    let changed_terminal = ArtifactSetProof::from_canonical_bytes(&changed_terminal).unwrap();
    assert_eq!(
        changed_terminal.verify(root, query),
        Err(ArtifactSetProofError::TerminalPathMismatch { bit: 0 })
    );

    let mut changed_bit = bytes.clone();
    changed_bit[33] = 1;
    let changed_bit = ArtifactSetProof::from_canonical_bytes(&changed_bit).unwrap();
    assert!(matches!(
        changed_bit.verify(root, query),
        Err(ArtifactSetProofError::RootMismatch { .. })
    ));

    let mut changed_sibling_bytes = bytes.clone();
    *changed_sibling_bytes.last_mut().unwrap() ^= 1;
    let changed_sibling = ArtifactSetProof::from_canonical_bytes(&changed_sibling_bytes).unwrap();
    assert_eq!(changed_sibling.to_canonical_bytes(), changed_sibling_bytes);
    assert!(matches!(
        changed_sibling.verify(root, query),
        Err(ArtifactSetProofError::RootMismatch { .. })
    ));

    let _ = set.insert(TestValue(id([0x55; 32]))).unwrap();
    assert_ne!(set.root(), root);
    assert_eq!(
        decoded.verify(root, query),
        Ok(ArtifactSetMembership::Absent)
    );
    assert!(matches!(
        decoded.verify(set.root(), query),
        Err(ArtifactSetProofError::RootMismatch { .. })
    ));

    let singleton = set_for(&[zero]);
    let singleton_proof =
        ArtifactSetProof::from_canonical_bytes(&singleton.proof(query).to_canonical_bytes())
            .unwrap();
    for different_query in [query, id([0x55; 32]), high] {
        assert_eq!(
            singleton_proof.verify(singleton.root(), different_query),
            Ok(ArtifactSetMembership::Absent)
        );
    }
}
