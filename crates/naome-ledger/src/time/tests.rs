use super::*;
use crate::test_support::{account, genesis, validator};

fn genesis_time_report(
    genesis: &Genesis,
    parent: RecordId,
    height: u64,
    seconds: u64,
    key: &SigningKey,
) -> Result<SignedTimeReport, LedgerError> {
    let authority = AuthoritySnapshot::from_genesis(genesis)?;
    SignedTimeReport::sign(genesis, &authority, parent, height, seconds, key)
}
fn genesis_time_certificate(
    reports: Vec<SignedTimeReport>,
    genesis: &Genesis,
    parent: RecordId,
    height: u64,
    previous: u64,
) -> Result<TimeCertificate, LedgerError> {
    let authority = AuthoritySnapshot::from_genesis(genesis)?;
    TimeCertificate::new(reports, genesis, &authority, parent, height, previous)
}
fn decode_genesis_time_certificate(
    bytes: &[u8],
    genesis: &Genesis,
    parent: RecordId,
    height: u64,
    previous: u64,
) -> Result<TimeCertificate, LedgerError> {
    let authority = AuthoritySnapshot::from_genesis(genesis)?;
    TimeCertificate::decode(bytes, genesis, &authority, parent, height, previous)
}

fn reports(times: &[u64]) -> Vec<super::SignedTimeReport> {
    let genesis = genesis();
    times
        .iter()
        .enumerate()
        .map(|(i, t)| {
            genesis_time_report(
                &genesis,
                RecordId::from_bytes([4; 32]),
                1,
                *t,
                &validator(i as u8),
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn lower_median_and_parent_time_are_exact() {
    let genesis = genesis();
    let parent = RecordId::from_bytes([4; 32]);
    for (times, expected) in [
        (vec![5, 100, 110], 100),
        (vec![5, 100, 110, u64::MAX], 100),
        (vec![1, 2, 3, 4], 90),
    ] {
        let certificate =
            genesis_time_certificate(reports(&times), &genesis, parent, 1, 90).unwrap();
        assert_eq!(certificate.time(), expected);
        assert_eq!(
            decode_genesis_time_certificate(&certificate.encode(), &genesis, parent, 1, 90)
                .unwrap(),
            certificate
        );
    }
}

#[test]
fn chosen_report_set_is_frozen_content() {
    let genesis = genesis();
    let parent = RecordId::from_bytes([4; 32]);
    let all = reports(&[100, 100, 102, 102]);
    let low = genesis_time_certificate(all[..3].to_vec(), &genesis, parent, 1, 0).unwrap();
    let high = genesis_time_certificate(all[1..].to_vec(), &genesis, parent, 1, 0).unwrap();
    assert_eq!(low.time(), 100);
    assert_eq!(high.time(), 102);
    assert_ne!(low.encode(), high.encode());
}

#[test]
fn distinct_registered_quorum_and_context_required() {
    let genesis = genesis();
    let parent = RecordId::from_bytes([4; 32]);
    let all = reports(&[100, 101, 102]);
    assert!(genesis_time_certificate(all[..2].to_vec(), &genesis, parent, 1, 0).is_err());
    let mut duplicate = all.clone();
    duplicate[2] = duplicate[0].clone();
    assert!(genesis_time_certificate(duplicate, &genesis, parent, 1, 0).is_err());
    assert!(
        genesis_time_certificate(all.clone(), &genesis, RecordId::from_bytes([5; 32]), 1, 0)
            .is_err()
    );
    assert!(genesis_time_certificate(all.clone(), &genesis, parent, 2, 0).is_err());
    assert!(genesis_time_report(&genesis, parent, 1, 100, &account(0)).is_err());
    assert!(genesis_time_report(&genesis, parent, 0, 100, &validator(0)).is_err());
}

#[test]
fn strict_order_and_signed_bytes_reject_mutation() {
    let genesis = genesis();
    let parent = RecordId::from_bytes([4; 32]);
    let certificate =
        genesis_time_certificate(reports(&[100, 101, 102, 103]), &genesis, parent, 1, 0).unwrap();
    let bytes = certificate.encode();
    let mut reordered = bytes.clone();
    let first = reordered[1..1 + TIME_REPORT_BYTES].to_vec();
    let second = reordered[1 + TIME_REPORT_BYTES..1 + 2 * TIME_REPORT_BYTES].to_vec();
    reordered[1..1 + TIME_REPORT_BYTES].copy_from_slice(&second);
    reordered[1 + TIME_REPORT_BYTES..1 + 2 * TIME_REPORT_BYTES].copy_from_slice(&first);
    assert!(decode_genesis_time_certificate(&reordered, &genesis, parent, 1, 0).is_err());
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(
            decode_genesis_time_certificate(&changed, &genesis, parent, 1, 0).is_err(),
            "unbound byte {index}"
        );
    }
    for end in 0..bytes.len() {
        assert!(decode_genesis_time_certificate(&bytes[..end], &genesis, parent, 1, 0).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_genesis_time_certificate(&trailing, &genesis, parent, 1, 0).is_err());
}
