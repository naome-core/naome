use super::*;
use crate::{
    operations::OperationBody,
    test_support::{account, genesis, validator},
};

fn candidate(genesis: &Genesis, author: AccountId, nonce: u64) -> JoinIntent {
    JoinIntent::new(
        genesis,
        author,
        nonce,
        ResolutionId::from_bytes([37; 32]),
        1,
        &account(50),
        &account(51),
        "127.0.0.1:42000".into(),
    )
    .unwrap()
}

#[test]
fn exact_join_intent_roundtrip_and_context_bound_key_possession() {
    let genesis = genesis();
    let author = AccountId::for_key(account(4).verifying_key().as_bytes());
    let nonce = 2;
    let intent = candidate(&genesis, author, nonce);
    assert_eq!(intent.family(), ResolutionId::from_bytes([37; 32]));
    assert_eq!(intent.completion_ordinal(), 1);
    assert_eq!(
        intent.consensus_key(),
        account(50).verifying_key().as_bytes()
    );
    assert_eq!(
        intent.transport_key(),
        account(51).verifying_key().as_bytes()
    );
    assert_eq!(intent.endpoint(), "127.0.0.1:42000");
    intent.verify(&genesis, author, nonce).unwrap();
    let body = OperationBody::JoinIntent(intent.clone());
    let decoded = OperationBody::decode(&body.encode().unwrap(), &genesis).unwrap();
    assert_eq!(decoded, body);
    let operation = body.sign(&genesis, nonce, &account(4)).unwrap();
    operation.verify_signature(&genesis).unwrap();
    assert_eq!(operation.payload(), body.encode().unwrap());
    assert!(intent.verify(&genesis, author, nonce + 1).is_err());
    let other_genesis = Genesis::new(
        genesis.profile().clone(),
        genesis.foundation().into(),
        genesis.checker_profile().into(),
        genesis.protocol_version(),
        genesis.start_utc(),
        [10; 32],
        genesis
            .accounts()
            .iter()
            .map(|account| *account.key())
            .collect(),
        genesis.validators().to_vec(),
        genesis.retirement_order().to_vec(),
    )
    .unwrap();
    assert_ne!(genesis.id(), other_genesis.id());
    assert!(intent.verify(&other_genesis, author, nonce).is_err());
    assert!(
        intent
            .verify(
                &genesis,
                AccountId::for_key(account(5).verifying_key().as_bytes()),
                nonce
            )
            .is_err()
    );
}

#[test]
fn all_join_intent_bytes_are_bound_or_rejected() {
    let genesis = genesis();
    let author = AccountId::for_key(account(4).verifying_key().as_bytes());
    let bytes = OperationBody::JoinIntent(candidate(&genesis, author, 2))
        .encode()
        .unwrap();
    for index in 0..bytes.len() {
        let mut altered = bytes.clone();
        altered[index] ^= 1;
        if let Ok(OperationBody::JoinIntent(intent)) = OperationBody::decode(&altered, &genesis) {
            assert!(
                intent.verify(&genesis, author, 2).is_err(),
                "unbound join byte {index}"
            );
        }
    }
    for end in 0..bytes.len() {
        assert!(OperationBody::decode(&bytes[..end], &genesis).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(
        OperationBody::decode(&extra, &genesis),
        Err(LedgerError::TrailingBytes)
    );
    let mut old_version = bytes;
    old_version[0] = 2;
    assert!(OperationBody::decode(&old_version, &genesis).is_err());
}

#[test]
fn possession_roles_and_claim_fields_cannot_be_exchanged() {
    let genesis = genesis();
    let author = AccountId::for_key(account(4).verifying_key().as_bytes());
    let mut intent = candidate(&genesis, author, 2);
    std::mem::swap(
        &mut intent.consensus_signature,
        &mut intent.transport_signature,
    );
    assert!(intent.verify(&genesis, author, 2).is_err());
    let mut intent = candidate(&genesis, author, 2);
    intent.family = ResolutionId::from_bytes([38; 32]);
    assert!(intent.verify(&genesis, author, 2).is_err());
    let mut intent = candidate(&genesis, author, 2);
    intent.completion_ordinal = 2;
    assert!(intent.verify(&genesis, author, 2).is_err());
    let mut intent = candidate(&genesis, author, 2);
    intent.transport_key = account(52).verifying_key().to_bytes();
    assert!(intent.verify(&genesis, author, 2).is_err());
}

#[test]
fn weak_duplicate_or_reused_keys_and_noncanonical_endpoints_fail() {
    let genesis = genesis();
    let author = AccountId::for_key(account(4).verifying_key().as_bytes());
    let make = |consensus: &SigningKey, transport: &SigningKey, endpoint: &str| {
        JoinIntent::new(
            &genesis,
            author,
            2,
            ResolutionId::from_bytes([37; 32]),
            1,
            consensus,
            transport,
            endpoint.into(),
        )
    };
    assert!(make(&account(50), &account(50), "127.0.0.1:42000").is_err());
    assert!(make(&account(4), &account(51), "127.0.0.1:42000").is_err());
    assert!(make(&account(5), &account(51), "127.0.0.1:42000").is_err());
    assert!(make(&validator(0), &account(51), "127.0.0.1:42000").is_err());
    assert!(make(&account(50), &account(51), "127.0.0.1:41000").is_err());
    for endpoint in [
        "",
        "127.0.0.1:0",
        "0.0.0.0:42000",
        "239.0.0.1:42000",
        "127.0.0.1:042000",
        "localhost:42000",
    ] {
        assert!(
            make(&account(50), &account(51), endpoint).is_err(),
            "{endpoint}"
        );
    }
    let mut weak = candidate(&genesis, author, 2);
    weak.consensus_key = [0; 32];
    weak.consensus_key[0] = 1;
    assert!(weak.verify(&genesis, author, 2).is_err());
    assert!(
        JoinIntent::new(
            &genesis,
            author,
            0,
            ResolutionId::from_bytes([37; 32]),
            1,
            &account(50),
            &account(51),
            "127.0.0.1:42000".into()
        )
        .is_err()
    );
    assert!(
        JoinIntent::new(
            &genesis,
            author,
            2,
            ResolutionId::from_bytes([37; 32]),
            0,
            &account(50),
            &account(51),
            "127.0.0.1:42000".into()
        )
        .is_err()
    );
}
