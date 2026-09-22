use super::*;
use crate::test_support::{account, genesis};
use naome_foundation::FreeVariable;
use naome_proof::{ProofCertificate, ProofStep};

fn package(genesis: &Genesis, author: AccountId) -> ProofPackage {
    let x = FreeVariable::new(0);
    let checked = naome_checker::normalize_and_check(
        ProofCertificate::new(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ])
        .unwrap(),
    )
    .unwrap();
    let root = checked.proof_id();
    ProofPackage::new(
        author,
        root,
        vec![(root, checked.normal_form().canonical_bytes().to_vec())],
        genesis.profile(),
    )
    .unwrap()
}

#[test]
fn registration_body_has_no_second_identity_or_extra_payload() {
    let genesis = genesis();
    let bytes = OperationBody::Register.encode().unwrap();
    assert_eq!(bytes, [3, 5]);
    assert_eq!(
        OperationBody::decode(&bytes, &genesis).unwrap(),
        OperationBody::Register
    );
    for invalid in [&[2, 5][..], &[3, 5, 0], &[3, 6], &[3]] {
        assert!(OperationBody::decode(invalid, &genesis).is_err());
    }
    let operation = OperationBody::Register
        .sign(&genesis, 1, &account(9))
        .unwrap();
    operation.verify_signature(&genesis).unwrap();
    assert!(genesis.account_key(operation.author()).is_none());
    assert_eq!(
        operation.public_key(),
        account(9).verifying_key().as_bytes()
    );
}

#[test]
fn original_signature_proves_a_non_genesis_authors_key_and_exact_context() {
    let genesis = genesis();
    let key = account(9);
    let author = AccountId::for_key(key.verifying_key().as_bytes());
    let round = SolutionRoundId::from_bytes([7; 32]);
    let package = package(&genesis, author);
    assert!(genesis.account_key(author).is_none());
    assert!(SignedOriginal::sign(&genesis, round, package.clone(), &account(4)).is_err());
    let original = SignedOriginal::sign(&genesis, round, package, &key).unwrap();
    original.verify_signature(&genesis, round, author).unwrap();
    assert_eq!(
        SignedOriginal::decode(&original.encode().unwrap(), &genesis).unwrap(),
        original
    );
    assert!(
        original
            .verify_signature(&genesis, SolutionRoundId::from_bytes([8; 32]), author)
            .is_err()
    );
    assert!(
        original
            .verify_signature(
                &genesis,
                round,
                AccountId::for_key(account(4).verifying_key().as_bytes())
            )
            .is_err()
    );
    let mut impersonation = original.clone();
    impersonation.public_key = account(4).verifying_key().to_bytes();
    impersonation.signature = account(4)
        .sign(&impersonation.signing_bytes().unwrap())
        .to_bytes();
    assert!(
        impersonation
            .verify_signature(&genesis, round, author)
            .is_err()
    );
    assert!(SignedOriginal::decode(&impersonation.encode().unwrap(), &genesis).is_err());
}

#[test]
fn every_original_byte_is_bound_or_strictly_rejected() {
    let genesis = genesis();
    let key = account(9);
    let author = AccountId::for_key(key.verifying_key().as_bytes());
    let round = SolutionRoundId::from_bytes([7; 32]);
    let original = SignedOriginal::sign(&genesis, round, package(&genesis, author), &key).unwrap();
    let bytes = original.encode().unwrap();
    for index in 0..bytes.len() {
        let mut altered = bytes.clone();
        altered[index] ^= 1;
        if let Ok(decoded) = SignedOriginal::decode(&altered, &genesis) {
            assert!(
                decoded.verify_signature(&genesis, round, author).is_err(),
                "unbound byte {index}"
            );
        }
    }
    for end in 0..bytes.len() {
        assert!(SignedOriginal::decode(&bytes[..end], &genesis).is_err());
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(SignedOriginal::decode(&extra, &genesis).is_err());
}

#[test]
fn v1_original_and_old_signature_domain_are_rejected() {
    let genesis = genesis();
    let key = account(4);
    let author = AccountId::for_key(key.verifying_key().as_bytes());
    let round = SolutionRoundId::from_bytes([7; 32]);
    let mut original =
        SignedOriginal::sign(&genesis, round, package(&genesis, author), &key).unwrap();
    let mut legacy = Writer::new();
    legacy.fixed(ORIGINAL_MAGIC);
    legacy.u16(1);
    legacy.fixed(genesis.id().as_bytes());
    legacy.fixed(genesis.profile().id().as_bytes());
    legacy.fixed(round.as_bytes());
    legacy.bytes(&original.package.encode().unwrap()).unwrap();
    let mut legacy = legacy.finish();
    let mut old_message = b"naome:state:original-authorization:v1\0".to_vec();
    old_message.extend_from_slice(&legacy);
    legacy.extend_from_slice(&key.sign(&old_message).to_bytes());
    assert!(SignedOriginal::decode(&legacy, &genesis).is_err());
    legacy[4..6].copy_from_slice(&ORIGINAL_VERSION.to_be_bytes());
    assert!(SignedOriginal::decode(&legacy, &genesis).is_err());

    let mut old_message = b"naome:state:original-authorization:v1\0".to_vec();
    old_message.extend(original.unsigned_bytes().unwrap());
    original.signature = key.sign(&old_message).to_bytes();
    assert!(original.verify_signature(&genesis, round, author).is_err());

    let mut v2 = SignedOriginal::sign(&genesis, round, package(&genesis, author), &key).unwrap();
    let mut old_wire = v2.encode().unwrap();
    old_wire[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert!(SignedOriginal::decode(&old_wire, &genesis).is_err());
    let mut old_message = b"naome:state:original-authorization:v2\0".to_vec();
    old_message.extend(v2.unsigned_bytes().unwrap());
    v2.signature = key.sign(&old_message).to_bytes();
    assert!(v2.verify_signature(&genesis, round, author).is_err());
}
