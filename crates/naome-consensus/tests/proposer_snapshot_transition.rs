use naome_consensus::{
    ActiveAgreementEntry, ActiveAgreementSnapshot, AgreementWeight, ConsensusHeight, ConsensusKey,
    ConsensusPosition, ConsensusRound, PreselectedProposerStateV0, ProposerSelectionError,
};

fn key(byte: u8) -> ConsensusKey {
    ConsensusKey::from_bytes([byte; 32])
}

fn entry(byte: u8, weight: u128) -> ActiveAgreementEntry {
    ActiveAgreementEntry::new(key(byte), AgreementWeight::new(weight))
}

fn snapshot(entries: &[ActiveAgreementEntry]) -> ActiveAgreementSnapshot {
    ActiveAgreementSnapshot::try_from_preselected(
        ConsensusPosition::new(ConsensusHeight::new(2), ConsensusRound::new(0)),
        entries,
    )
    .unwrap()
}

fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    let mut bytes = [0_u8; N];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |value: u8| match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid lowercase hexadecimal test vector"),
        };
        bytes[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    bytes
}

#[test]
fn public_reference_boundary_applies_and_advances_the_approved_transition() {
    let zero = PreselectedProposerStateV0::from_zeroed_preselected_snapshot(&snapshot(&[
        entry(1, 80),
        entry(2, 20),
    ]));
    let (first_proposer, source) = zero.select_next().unwrap();
    assert_eq!(first_proposer, key(1));
    let source_before = source.clone();

    let transitioned = source
        .transition_to_preselected_snapshot(&snapshot(&[entry(3, 1), entry(2, 20)]))
        .unwrap();

    assert_eq!(source, source_before);
    assert_eq!(
        transitioned.fixed_agreement_set_id().as_bytes(),
        &hex_array("01f3134e16aa9855302fe8da5ae57939f28b07e06ffe5bb2bb6067ad9cad6890")
    );
    assert_eq!(
        transitioned.proposer_priority_state_id().as_bytes(),
        &hex_array("827d82d324f3bd624829d801d8988cead29d9bb70b6e262aa46bcf0d34fc69ca")
    );

    let (next_proposer, successor) = transitioned.select_next().unwrap();
    assert_eq!(next_proposer, key(2));
    assert_eq!(
        successor.proposer_priority_state_id().as_bytes(),
        &hex_array("12941d6af01babf91664d79e5eaf1ef6d78592e5bc4050e6a5d9062839ac2743")
    );

    let halted = successor
        .transition_to_preselected_snapshot(&snapshot(&[]))
        .unwrap();
    assert_eq!(
        halted.select_next(),
        Err(ProposerSelectionError::NoActiveValidators)
    );
}
