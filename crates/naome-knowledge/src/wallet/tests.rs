use super::*;

fn key() -> SigningKey {
    // RFC 8032, section 7.1, test 1. The address must retain this public key.
    let seed =
        crate::unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    SigningKey::from_bytes(&seed.try_into().unwrap())
}

fn challenge() -> OwnershipChallenge {
    OwnershipChallenge {
        version: 1,
        audience: "test-verifier".into(),
        nonce: "01".repeat(32),
    }
}

#[test]
fn wallet_address_is_checksummed_canonical_and_rejects_weak_keys() {
    let address = Address::from_key(key().verifying_key()).unwrap();
    assert_eq!(
        crate::hex(&address.0),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let text = address.to_string();
    assert_eq!(text.parse::<Address>().unwrap(), address);
    assert!(text.starts_with("nao1"));
    assert!(text.to_uppercase().parse::<Address>().is_err());
    let mut changed = text.into_bytes();
    changed[5] = if changed[5] == b'q' { b'p' } else { b'q' };
    assert!(
        String::from_utf8(changed)
            .unwrap()
            .parse::<Address>()
            .is_err()
    );
    for (hrp, bytes) in [
        ("other", vec![0; 32]),
        ("nao", vec![0; 33]),
        ("nao", vec![0; 32]),
    ] {
        let encoded = bech32::encode::<Bech32m>(Hrp::parse(hrp).unwrap(), &bytes).unwrap();
        assert!(encoded.parse::<Address>().is_err());
    }
    let old_checksum =
        bech32::encode::<bech32::Bech32>(Hrp::parse("nao").unwrap(), &address.0).unwrap();
    assert!(old_checksum.parse::<Address>().is_err());
}

#[test]
fn ownership_proof_binds_address_nonce_audience_and_message_domain() {
    let key = key();
    let expected = challenge();
    let proof = OwnershipProof::sign(&key, expected.clone()).unwrap();
    proof.verify(proof.address, &expected).unwrap();

    let mut independent_message = b"naome:wallet-key-ownership:v1\0\x00\x0dtest-verifier".to_vec();
    independent_message.extend_from_slice(&[1u8; 32]);
    independent_message.extend_from_slice(
        &crate::unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap(),
    );
    key.verifying_key()
        .verify_strict(
            &independent_message,
            &Signature::from_slice(&crate::unhex(&proof.signature).unwrap()).unwrap(),
        )
        .unwrap();

    let other = Address::from_key(SigningKey::from_bytes(&[7; 32]).verifying_key()).unwrap();
    assert!(proof.verify(other, &expected).is_err());
    for changed in [
        OwnershipChallenge {
            nonce: "02".repeat(32),
            ..expected.clone()
        },
        OwnershipChallenge {
            audience: "another-verifier".into(),
            ..expected.clone()
        },
    ] {
        assert!(proof.verify(proof.address, &changed).is_err());
        let mut forged = proof.clone();
        forged.challenge = changed.clone();
        assert!(forged.verify(proof.address, &changed).is_err());
    }
    let mut forged = proof.clone();
    forged.signature = crate::hex(&key.sign(b"a payment or a different protocol").to_bytes());
    assert!(forged.verify(proof.address, &expected).is_err());
    forged = proof.clone();
    forged.signature.replace_range(..2, "ff");
    assert!(forged.verify(proof.address, &expected).is_err());

    let encoded = serde_json::to_string(&proof).unwrap();
    assert!(!encoded.contains("9d61b19deffd5a60"));
    assert!(!encoded.contains("balance"));
    let decoded: OwnershipProof = serde_json::from_str(&encoded).unwrap();
    decoded.verify(proof.address, &expected).unwrap();
    let mut unknown = serde_json::to_value(proof).unwrap();
    unknown["balance"] = serde_json::json!(100);
    assert!(serde_json::from_value::<OwnershipProof>(unknown).is_err());
}

#[test]
fn challenge_generation_and_validation_bound_the_signed_contract() {
    let first = OwnershipChallenge::new("verifier".into()).unwrap();
    let second = OwnershipChallenge::new("verifier".into()).unwrap();
    assert_ne!(first.nonce, second.nonce);
    assert_eq!(first.nonce.len(), 64);
    for invalid in [
        OwnershipChallenge {
            version: 2,
            ..challenge()
        },
        OwnershipChallenge {
            audience: String::new(),
            ..challenge()
        },
        OwnershipChallenge {
            audience: "🦀".repeat(65),
            ..challenge()
        },
        OwnershipChallenge {
            nonce: "AB".repeat(32),
            ..challenge()
        },
        OwnershipChallenge {
            nonce: "00".repeat(33),
            ..challenge()
        },
    ] {
        assert!(OwnershipProof::sign(&key(), invalid).is_err());
    }
    let mut proof = OwnershipProof::sign(&key(), challenge()).unwrap();
    proof.version = 2;
    assert!(proof.verify(proof.address, &challenge()).is_err());
}
