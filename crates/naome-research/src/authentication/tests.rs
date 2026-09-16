use super::*;
use crate::test_support::{account, genesis, validator};

#[test]
fn exact_action_roundtrip_and_roles() {
    let genesis = genesis();
    let signed = SignedOperation::sign(&genesis, 1, vec![1, 2, 3], &account(4)).unwrap();
    assert_eq!(
        signed.author(),
        AccountId::for_key(account(4).verifying_key().as_bytes())
    );
    assert_eq!(signed.nonce(), 1);
    assert_eq!(signed.payload(), [1, 2, 3]);
    assert_eq!(SignedOperation::decode(&signed.encode()).unwrap(), signed);
    signed.verify(&genesis).unwrap();
    assert!(SignedOperation::sign(&genesis, 1, vec![1], &validator(0)).is_err());
    assert!(SignedOperation::sign(&genesis, 0, vec![1], &account(0)).is_err());
    assert!(SignedOperation::sign(&genesis, 1, vec![], &account(0)).is_err());
    assert!(
        SignedOperation::sign(
            &genesis,
            1,
            vec![0; SIGNED_OPERATION_MAX_BYTES - OVERHEAD + 1],
            &account(0)
        )
        .is_err()
    );
}

#[test]
fn every_wire_byte_is_bound_or_strictly_rejected() {
    let genesis = genesis();
    let signed = SignedOperation::sign(&genesis, 1, vec![1, 2, 3], &account(0)).unwrap();
    let bytes = signed.encode();
    for index in 0..bytes.len() {
        let mut altered = bytes.clone();
        altered[index] ^= 1;
        if let Ok(decoded) = SignedOperation::decode(&altered) {
            assert!(decoded.verify(&genesis).is_err(), "unbound byte {index}");
        }
    }
    for end in 0..bytes.len() {
        assert!(SignedOperation::decode(&bytes[..end]).is_err());
    }
    let mut extra = bytes;
    extra.push(0);
    assert_eq!(
        SignedOperation::decode(&extra),
        Err(ResearchError::TrailingBytes)
    );
}

#[test]
fn action_identity_binds_nonce_and_content() {
    let genesis = genesis();
    let a = SignedOperation::sign(&genesis, 1, vec![1], &account(0)).unwrap();
    let same = SignedOperation::sign(&genesis, 1, vec![1], &account(0)).unwrap();
    let next = SignedOperation::sign(&genesis, 2, vec![1], &account(0)).unwrap();
    let different = SignedOperation::sign(&genesis, 1, vec![2], &account(0)).unwrap();
    assert_eq!(a, same);
    assert_eq!(a.id(), same.id());
    assert_ne!(a.id(), next.id());
    assert_ne!(a.id(), different.id());
    let mut altered = a.clone();
    altered.genesis = GenesisId::from_bytes([5; 32]);
    assert!(altered.verify(&genesis).is_err());
    assert_ne!(a.id(), altered.id());
}
