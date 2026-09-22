use super::*;
use crate::test_support::{account, genesis};

#[test]
fn exact_action_roundtrip_without_registration_authority() {
    let genesis = genesis();
    let signed = SignedOperation::sign(&genesis, 1, vec![1, 2, 3], &account(9)).unwrap();
    assert_eq!(
        signed.author(),
        AccountId::for_key(account(9).verifying_key().as_bytes())
    );
    assert!(genesis.account_key(signed.author()).is_none());
    assert_eq!(signed.public_key(), account(9).verifying_key().as_bytes());
    assert_eq!(signed.nonce(), 1);
    assert_eq!(signed.payload(), [1, 2, 3]);
    assert_eq!(SignedOperation::decode(&signed.encode()).unwrap(), signed);
    signed.verify_signature(&genesis).unwrap();
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
            assert!(
                decoded.verify_signature(&genesis).is_err(),
                "unbound byte {index}"
            );
        }
    }
    for end in 0..bytes.len() {
        assert!(SignedOperation::decode(&bytes[..end]).is_err());
    }
    let mut extra = bytes;
    extra.push(0);
    assert_eq!(
        SignedOperation::decode(&extra),
        Err(LedgerError::TrailingBytes)
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
    assert!(altered.verify_signature(&genesis).is_err());
    assert_ne!(a.id(), altered.id());
}

#[test]
fn a_valid_signature_cannot_claim_another_keys_address() {
    let genesis = genesis();
    let mut signed = SignedOperation::sign(&genesis, 1, vec![2, 5], &account(4)).unwrap();
    signed.public_key = account(9).verifying_key().to_bytes();
    signed.signature = account(9).sign(&signed.signing_bytes()).to_bytes();
    assert_eq!(
        signed.verify_signature(&genesis),
        Err(LedgerError::Invalid("account key address"))
    );
    assert!(SignedOperation::decode(&signed.encode()).is_err());
}

#[test]
fn weak_key_is_rejected_even_with_its_matching_address() {
    let genesis = genesis();
    let mut signed = SignedOperation::sign(&genesis, 1, vec![2, 5], &account(4)).unwrap();
    signed.public_key = [0; 32];
    signed.public_key[0] = 1;
    signed.author = AccountId::for_key(&signed.public_key);
    assert_eq!(
        signed.verify_signature(&genesis),
        Err(LedgerError::Invalid("weak account key"))
    );
    assert!(SignedOperation::decode(&signed.encode()).is_err());
}

#[test]
fn v1_action_and_old_signature_domain_are_not_admission_authority() {
    let genesis = genesis();
    let key = account(4);
    let mut signed = SignedOperation::sign(&genesis, 1, vec![2, 5], &key).unwrap();
    let mut legacy = Writer::new();
    legacy.fixed(MAGIC);
    legacy.u16(1);
    legacy.fixed(genesis.id().as_bytes());
    legacy.fixed(signed.author().as_bytes());
    legacy.u64(1);
    legacy.bytes(&[1, 1]).unwrap();
    let mut legacy = legacy.finish();
    let mut old_message = b"naome:state:user-action:v1\0".to_vec();
    old_message.extend_from_slice(&legacy);
    legacy.extend_from_slice(&key.sign(&old_message).to_bytes());
    assert!(SignedOperation::decode(&legacy).is_err());
    legacy[4..6].copy_from_slice(&VERSION.to_be_bytes());
    assert!(SignedOperation::decode(&legacy).is_err());

    let mut old_message = b"naome:state:user-action:v1\0".to_vec();
    old_message.extend(signed.unsigned_bytes());
    signed.signature = key.sign(&old_message).to_bytes();
    assert!(signed.verify_signature(&genesis).is_err());

    let mut v2 = SignedOperation::sign(&genesis, 1, vec![2, 5], &key).unwrap();
    let mut old_wire = v2.encode();
    old_wire[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert!(SignedOperation::decode(&old_wire).is_err());
    let mut old_message = b"naome:state:user-action:v2\0".to_vec();
    old_message.extend(v2.unsigned_bytes());
    v2.signature = key.sign(&old_message).to_bytes();
    assert!(v2.verify_signature(&genesis).is_err());
}
