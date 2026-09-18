use super::*;
use ed25519_dalek::SigningKey;

fn key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}
fn inputs() -> (Vec<[u8; 32]>, Vec<ValidatorRegistration>) {
    let accounts: Vec<_> = (1..=5).map(key).collect();
    let validators = (0..4)
        .map(|i| ValidatorRegistration {
            owner: AccountId::for_key(&accounts[i]),
            consensus_key: key(20 + i as u8),
            transport_key: key(40 + i as u8),
            endpoint: format!("127.0.0.1:{}", 5000 + i),
        })
        .collect();
    (accounts, validators)
}
fn genesis(
    accounts: Vec<[u8; 32]>,
    validators: Vec<ValidatorRegistration>,
) -> Result<Genesis, ResearchError> {
    Genesis::new(
        Profile::lab(),
        "naome:zfc".into(),
        RESEARCH_CHECKER_PROFILE.into(),
        1,
        1800000000,
        [42; 32],
        accounts,
        validators,
    )
}
fn fixture() -> Genesis {
    let (a, v) = inputs();
    genesis(a, v).unwrap()
}

#[test]
fn profile_presets_and_storage_reservation() {
    let lab = Profile::lab();
    let research = Profile::research();
    let short = Profile::short_test();
    assert_eq!(lab.timing().voting_seconds, 300);
    assert_eq!(lab.timing().commitment_seconds, 120);
    assert_eq!(lab.timing().reveal_seconds, 120);
    assert_eq!(research.timing().voting_seconds, 604800);
    assert_eq!(research.timing().queue_seconds, 2592000);
    assert_eq!(short.name(), "state-v1-short-test");
    assert_ne!(lab.id(), research.id());
    assert_ne!(lab.id(), short.id());
    assert_eq!(
        lab.limits.record_bytes * lab.limits.run_records,
        8 * 1024 * 1024 * 1024
    );
    // Full 8192-record run, all 65 consensus rounds per height, complete signer
    // journal, two archive allocations, reveal staging, and a 100% margin.
    assert_eq!(lab.required_storage_bytes().unwrap(), 3_453_995_466_906);
    assert_eq!(lab.maximum_issuance_atoms().unwrap(), 8_192_000_000_000);
    for p in [lab, research, short] {
        assert_eq!(Profile::decode(&p.encode()).unwrap(), p);
    }
}

#[test]
fn rewards_are_exact_and_immutable_on_wire() {
    let p = Profile::lab();
    let r = p.rewards();
    assert_eq!(
        r.author_with_citations_atoms + r.citation_pool_atoms,
        r.author_without_citations_atoms
    );
    assert_eq!(
        r.author_without_citations_atoms + 4 * r.validator_atoms_each + r.reserve_atoms,
        r.issuance_atoms
    );
    let mut bytes = p.encode();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(Profile::decode(&bytes).is_err());
}

#[test]
fn profile_rejects_noncanonical_limits_variants_and_every_truncation() {
    let bytes = Profile::lab().encode();
    for end in 0..bytes.len() {
        assert!(Profile::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert_eq!(Profile::decode(&bad), Err(ResearchError::TrailingBytes));
    let mut bad = bytes.clone();
    bad[8] = 3;
    assert!(Profile::decode(&bad).is_err());
    let mut bad = bytes;
    bad[9..17].copy_from_slice(&301u64.to_be_bytes());
    assert!(Profile::decode(&bad).is_err());
    let limits = Limits {
        completion_records: 43,
        ..Limits::default()
    };
    assert!(Profile::with_limits(TimingKind::Lab, limits).is_err());
    let limits = Limits {
        run_records: 64,
        ..Limits::default()
    };
    assert!(Profile::with_limits(TimingKind::Lab, limits).is_err());
    let limits = Limits {
        accounts: 3,
        ..Limits::default()
    };
    assert!(Profile::with_limits(TimingKind::Lab, limits).is_err());
    let limits = Limits {
        package_bytes: u64::MAX,
        ..Limits::default()
    };
    assert!(Profile::with_limits(TimingKind::Lab, limits).is_err());
    let limits = Limits {
        queued_questions: 16,
        ..Limits::default()
    };
    let reduced = Profile::with_limits(TimingKind::Lab, limits).unwrap();
    assert_ne!(reduced.id(), Profile::lab().id());
    assert_eq!(Profile::decode(&reduced.encode()).unwrap(), reduced);
}

#[test]
fn storage_arithmetic_never_wraps() {
    let mut p = Profile::lab();
    p.limits.run_records = u64::MAX;
    assert_eq!(p.required_storage_bytes(), Err(ResearchError::Overflow));
}

#[test]
fn constructor_normalizes_but_decoder_rejects_membership_order() {
    let (mut a, mut v) = inputs();
    let g = genesis(a.clone(), v.clone()).unwrap();
    a.reverse();
    v.reverse();
    assert_eq!(genesis(a, v).unwrap(), g);
    assert_eq!(Genesis::decode(&g.encode()).unwrap(), g);
    let mut bad = g.clone();
    bad.accounts.swap(0, 1);
    assert!(Genesis::decode(&bad.encode()).is_err());
    let mut bad = g.clone();
    bad.validators.swap(0, 1);
    assert!(Genesis::decode(&bad.encode()).is_err());
    for a in g.accounts() {
        assert_eq!(g.account_key(a.id()), Some(a.key()));
    }
    for v in g.validators() {
        assert_eq!(g.validator(v.id()), Some(v));
    }
    assert!(g.account_key(AccountId::from_bytes([0; 32])).is_none());
    assert!(g.validator(ValidatorId::from_bytes([0; 32])).is_none());
}

#[test]
fn genesis_rejects_every_truncation_trailing_data_and_oversize() {
    let bytes = fixture().encode();
    for end in 0..bytes.len() {
        assert!(Genesis::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut bad = bytes;
    bad.push(0);
    assert_eq!(Genesis::decode(&bad), Err(ResearchError::TrailingBytes));
    assert!(Genesis::decode(&vec![0; MAX_GENESIS_BYTES + 1]).is_err());
}

#[test]
fn rejects_duplicate_keys_roles_and_owners() {
    let (mut a, v) = inputs();
    a.push(a[0]);
    assert!(genesis(a, v).is_err());
    let (a, mut v) = inputs();
    v[1].consensus_key = v[0].consensus_key;
    assert!(genesis(a, v).is_err());
    let (a, mut v) = inputs();
    v[0].consensus_key = a[4];
    assert!(genesis(a, v).is_err());
    let (a, mut v) = inputs();
    v[1].owner = v[0].owner;
    assert!(genesis(a, v).is_err());
    let (a, mut v) = inputs();
    v[0].owner = AccountId::for_key(&key(99));
    assert!(genesis(a, v).is_err());
    let (mut a, v) = inputs();
    a[4] = [0; 32];
    assert!(genesis(a, v).is_err());
    let (a, mut v) = inputs();
    v[0].consensus_key = [0; 32];
    assert!(genesis(a, v).is_err());
    let (a, mut v) = inputs();
    v[0].transport_key = [0; 32];
    assert!(genesis(a, v).is_err());
    let (a, mut v) = inputs();
    v[0].transport_key = v[1].transport_key;
    assert!(genesis(a, v).is_err());
    let (a, mut v) = inputs();
    v[0].transport_key = v[1].consensus_key;
    assert!(genesis(a, v).is_err());
    let (a, mut v) = inputs();
    v[0].transport_key = a[4];
    assert!(genesis(a, v).is_err());
    let (a, mut v) = inputs();
    v.pop();
    assert!(genesis(a, v).is_err());
}

#[test]
fn rejects_invalid_duplicate_and_noncanonical_transport_assignments() {
    for endpoint in [
        "127.0.0.1:0",
        "0.0.0.0:5000",
        "224.0.0.1:5000",
        "example.com:5000",
        "127.0.0.1:05000",
        "[0:0:0:0:0:0:0:1]:5000",
        "[::ffff:127.0.0.1]:5000",
        "[fe80::1%3]:5000",
        "127.0.0.1:5001",
    ] {
        let (a, mut v) = inputs();
        v[0].endpoint = endpoint.into();
        assert!(genesis(a, v).is_err(), "{endpoint}");
    }
    let (a, mut v) = inputs();
    v[0].endpoint = "[::1]:5000".into();
    assert!(genesis(a, v).is_ok());
}

#[test]
fn genesis_identity_binds_all_configuration_and_keys() {
    let g = fixture();
    let mut variations = Vec::new();
    let mut v = g.clone();
    v.profile = Profile::research();
    variations.push(v);
    let mut v = g.clone();
    v.foundation.push('2');
    assert!(v.validate().is_err());
    assert_ne!(g.id(), v.id());
    let mut v = g.clone();
    v.checker_profile.push('2');
    assert!(v.validate().is_err());
    assert_ne!(g.id(), v.id());
    let mut v = g.clone();
    v.validators[0].transport_key = key(90);
    variations.push(v);
    let mut v = g.clone();
    v.start_utc += 1;
    variations.push(v);
    let mut v = g.clone();
    v.run_nonce[0] ^= 1;
    variations.push(v);
    let mut v = g.clone();
    v.validators[0].endpoint = "127.0.0.1:9000".into();
    variations.push(v);
    let mut v = g.clone();
    let owner = v.validators[0].owner;
    v.validators[0].owner = v.validators[1].owner;
    v.validators[1].owner = owner;
    variations.push(v);
    for v in variations {
        v.validate().unwrap();
        assert_ne!(g.id(), v.id());
    }
    let mut bad = g.clone();
    bad.protocol_version = 2;
    assert!(bad.validate().is_err());
    let mut bad = g.clone();
    bad.run_nonce = [0; 32];
    assert!(bad.validate().is_err());
    let mut bad = g;
    bad.start_utc = u64::MAX;
    assert_eq!(bad.validate(), Err(ResearchError::Overflow));
}

#[test]
fn lab_profile_golden_encoding_and_identity() {
    // Independently written protocol vector: magic, variant, timing, bounds,
    // rewards. Changes require an explicit new encoding/profile decision.
    let values: [u64; 37] = [
        300, 120, 120, 1800, 2, 60, 1, 32, 16, 1, 16384, 1024, 32, 16, 262144, 65536, 4096, 64,
        2097152, 32, 64, 16, 1, 1048576, 8192, 64, 1, 2, 4, 4194304, 2592, 75497472, 10616832,
        1114112, 1114112, 64, 64,
    ];
    let mut bytes = b"NAOPROF1\0".to_vec();
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for value in [
        1_000_000_000u128,
        700_000_000,
        600_000_000,
        100_000_000,
        50_000_000,
        100_000_000,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    assert_eq!(bytes.len(), 401);
    assert_eq!(Profile::lab().encode(), bytes);
    assert_eq!(
        Profile::lab().id().as_bytes(),
        &[
            171, 87, 52, 240, 226, 92, 116, 178, 137, 70, 211, 150, 0, 23, 151, 77, 128, 57, 245,
            126, 84, 101, 202, 56, 188, 150, 212, 152, 177, 31, 47, 63
        ]
    );
}

#[test]
fn reduced_profiles_preserve_complete_record_and_frame_room() {
    let limits = Limits {
        record_bytes: 256 * 1024,
        ..Limits::default()
    };
    assert!(Profile::with_limits(TimingKind::Lab, limits).is_err());
    let limits = Limits {
        transport_frame_bytes: 1024 * 1024,
        ..Limits::default()
    };
    assert!(Profile::with_limits(TimingKind::Lab, limits).is_err());
    let limits = Limits {
        package_bytes: 16384,
        certificate_bytes: 16384,
        record_bytes: 32768,
        ..Limits::default()
    };
    assert!(Profile::with_limits(TimingKind::Lab, limits).is_err());
    let limits = Limits {
        package_bytes: 16384,
        certificate_bytes: 16384,
        record_bytes: 32768 + DOMAIN_RECORD_OVERHEAD_BYTES,
        transport_frame_bytes: 32768
            + DOMAIN_RECORD_OVERHEAD_BYTES
            + TRANSPORT_ENVELOPE_OVERHEAD_BYTES,
        ..Limits::default()
    };
    let valid = Profile::with_limits(TimingKind::Lab, limits).unwrap();
    assert_eq!(Profile::decode(&valid.encode()).unwrap(), valid);
}

#[test]
fn finite_signer_budget_includes_every_round_and_terminal_capacity() {
    let p = Profile::lab();
    assert_eq!(p.limits().consensus_rounds, 64); // Inclusive: 65 rounds.
    assert_eq!(p.signer_height_frames().unwrap(), 456);
    assert_eq!(p.signer_height_bytes().unwrap(), 208577429);
    assert_eq!(p.signer_journal_bytes().unwrap(), 1708666331213);
    let reduced = Profile::with_limits(
        TimingKind::Lab,
        Limits {
            run_records: 256,
            record_bytes: 128 * 1024,
            package_bytes: 64 * 1024,
            transport_frame_bytes: 192 * 1024,
            consensus_rounds: 8,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(reduced.required_storage_bytes().unwrap(), 2_441_919_130);
    assert!(reduced.required_storage_bytes().unwrap() < p.required_storage_bytes().unwrap());
    assert!(reduced.signer_journal_bytes().unwrap() > reduced.signer_height_bytes().unwrap() * 256);
    assert_eq!(Profile::decode(&reduced.encode()).unwrap(), reduced);
}
