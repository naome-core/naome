use super::*;
use crate::authority::AuthoritySnapshot;
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
) -> Result<Genesis, LedgerError> {
    let retirement_order = if validators.len() == 4 {
        [2, 0, 3, 1].map(|i| validators[i].id()).to_vec()
    } else {
        Vec::new()
    };
    Genesis::new(
        Profile::lab(),
        "naome:zfc".into(),
        STATE_CHECKER_PROFILE.into(),
        STATE_PROTOCOL_VERSION,
        1800000000,
        [42; 32],
        accounts,
        validators,
        retirement_order,
    )
}
fn fixture() -> Genesis {
    let (a, v) = inputs();
    genesis(a, v).unwrap()
}

#[test]
fn genesis_and_authority_accept_four_through_256_installed_seats() {
    let signing_key = |index: u16, role: u8| {
        let mut seed = [0; 32];
        seed[..2].copy_from_slice(&index.to_be_bytes());
        seed[2] = role;
        seed[3] = 1;
        SigningKey::from_bytes(&seed)
    };
    let public_key = |index: u16, role: u8| signing_key(index, role).verifying_key().to_bytes();
    for (count, quorum) in [(4, 3), (5, 4), (32, 22), (256, 171)] {
        let accounts = (0..count)
            .map(|index| public_key(index as u16, 1))
            .collect::<Vec<_>>();
        let validators = (0..count)
            .map(|index| ValidatorRegistration {
                owner: AccountId::for_key(&accounts[index]),
                consensus_key: public_key(index as u16, 2),
                transport_key: public_key(index as u16, 3),
                endpoint: format!("127.0.0.1:{}", 5000 + index),
            })
            .collect::<Vec<_>>();
        let retirement = validators.iter().map(ValidatorRegistration::id).collect();
        let g = Genesis::new(
            Profile::lab(),
            "naome:zfc".into(),
            STATE_CHECKER_PROFILE.into(),
            STATE_PROTOCOL_VERSION,
            1_800_000_000,
            [42; 32],
            accounts,
            validators,
            retirement,
        )
        .unwrap();
        assert_eq!(Genesis::decode(&g.encode()).unwrap(), g);
        if count == 256 {
            let undersized = Profile::with_limits(
                TimingKind::ShortTest,
                Limits {
                    run_records: 295,
                    ..Limits::default()
                },
            )
            .unwrap();
            assert!(
                Genesis::new(
                    undersized,
                    "naome:zfc".into(),
                    STATE_CHECKER_PROFILE.into(),
                    STATE_PROTOCOL_VERSION,
                    1_800_000_000,
                    [42; 32],
                    g.accounts().iter().map(|account| account.key).collect(),
                    g.validators().to_vec(),
                    g.retirement_order().to_vec(),
                )
                .is_err()
            );
        }
        let authority = AuthoritySnapshot::from_genesis(&g).unwrap();
        assert_eq!(authority.units().len(), count);
        assert_eq!(authority.quorum(), quorum);
        assert_eq!(
            AuthoritySnapshot::decode(&authority.encode()).unwrap(),
            authority
        );
        let parent = crate::RecordId::from_bytes([7; 32]);
        let reports = (0..quorum)
            .map(|index| {
                crate::time::SignedTimeReport::sign(
                    &g,
                    &authority,
                    parent,
                    1,
                    g.start_utc(),
                    &signing_key(index as u16, 2),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(
            crate::time::TimeCertificate::new(
                reports[..quorum - 1].to_vec(),
                &g,
                &authority,
                parent,
                1,
                g.start_utc(),
            )
            .is_err()
        );
        let certificate =
            crate::time::TimeCertificate::new(reports, &g, &authority, parent, 1, g.start_utc())
                .unwrap();
        assert_eq!(certificate.reports().len(), quorum);
        assert_eq!(
            crate::time::TimeCertificate::decode(
                &certificate.encode(),
                &g,
                &authority,
                parent,
                1,
                g.start_utc(),
            )
            .unwrap(),
            certificate
        );
        if count == 4 || count == 256 {
            let oldest = authority.oldest();
            let old_slot = oldest.slot();
            let old_unit = oldest.id();
            let owner = AccountId::for_key(&public_key(1_000, 1));
            let successor = authority
                .install_candidate(
                    old_unit,
                    crate::ResolutionId::from_bytes([9; 32]),
                    1,
                    owner,
                    crate::authority::PeriodKeys::new(
                        public_key(1_000, 2),
                        public_key(1_000, 3),
                        "127.0.0.1:61000".into(),
                    )
                    .unwrap(),
                )
                .unwrap();
            assert_eq!(successor.units().len(), count + usize::from(count < 256));
            assert!(successor.owner(owner).is_some());
            if count == 4 {
                assert!(successor.unit(old_unit).is_some());
                assert!(
                    successor
                        .slot(old_slot)
                        .is_some_and(|unit| unit.id() == old_unit)
                );
            } else {
                assert!(successor.unit(old_unit).is_none());
                assert!(
                    successor
                        .slot(old_slot)
                        .is_some_and(|unit| unit.owner() == owner)
                );
            }
        }
    }
}

#[test]
fn profile_presets_and_storage_reservation() {
    let lab = Profile::lab();
    let research = Profile::research();
    let short = Profile::short_test();
    let ci = Profile::ci_test();
    assert_eq!(lab.timing().voting_seconds, 300);
    assert_eq!(lab.timing().commitment_seconds, 120);
    assert_eq!(lab.timing().reveal_seconds, 120);
    assert_eq!(research.timing().voting_seconds, 604800);
    assert_eq!(research.timing().queue_seconds, 2592000);
    assert_eq!(short.name(), "state-v6-short-test");
    assert_eq!(ci.timing().voting_seconds, 1);
    assert_eq!(ci.name(), "state-v6-ci-test");
    assert_ne!(lab.id(), research.id());
    assert_ne!(lab.id(), short.id());
    assert_ne!(short.id(), ci.id());
    assert_eq!(
        lab.limits.record_bytes * lab.limits.run_records,
        8 * 1024 * 1024 * 1024
    );
    // Full 8192-record run, all 65 consensus rounds per height, complete signer
    // journals, per-height handoff/custody, two archives, reveal staging and 100% margin.
    assert_eq!(lab.required_storage_bytes().unwrap(), 5_644_006_522_880);
    assert_eq!(lab.maximum_issuance_atoms().unwrap(), 8_192_000_000_000);
    for p in [lab, research, short, ci] {
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
        r.author_without_citations_atoms + r.validator_pool_atoms + r.reserve_atoms,
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
    assert_eq!(Profile::decode(&bad), Err(LedgerError::TrailingBytes));
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
        genesis_accounts: 3,
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
    assert_eq!(p.required_storage_bytes(), Err(LedgerError::Overflow));
}

#[test]
fn registration_capacity_is_independent_of_genesis_and_reveal_work() {
    let standard = Profile::lab();
    assert_eq!(standard.limits().genesis_accounts, 512);
    assert_eq!(standard.limits().registered_accounts, 1024);
    assert_eq!(standard.limits().commitments_per_attempt, 16);
    let smaller_registry = Profile::with_limits(
        TimingKind::Lab,
        Limits {
            registered_accounts: 512,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_ne!(smaller_registry.id(), standard.id());
    assert_eq!(
        smaller_registry.required_storage_bytes().unwrap(),
        standard.required_storage_bytes().unwrap()
    );
    let fewer_commitments = Profile::with_limits(
        TimingKind::Lab,
        Limits {
            commitments_per_attempt: 8,
            ..Limits::default()
        },
    )
    .unwrap();
    let staging_per_commitment =
        2 * (standard.limits().package_bytes + standard.limits().dependency_bytes);
    assert_eq!(
        standard.required_storage_bytes().unwrap()
            - fewer_commitments.required_storage_bytes().unwrap(),
        2 * 8 * staging_per_commitment
    );
    assert_eq!(fewer_commitments.limits().completion_records, 64);
    assert_eq!(
        fewer_commitments.limits().checker_calls_per_record,
        standard.limits().checker_calls_per_record
    );
    for limits in [
        Limits {
            genesis_accounts: 513,
            ..Limits::default()
        },
        Limits {
            registered_accounts: 1025,
            ..Limits::default()
        },
        Limits {
            registered_accounts: 511,
            ..Limits::default()
        },
        Limits {
            commitments_per_attempt: 17,
            ..Limits::default()
        },
        Limits {
            commitments_per_attempt: 0,
            ..Limits::default()
        },
    ] {
        assert!(Profile::with_limits(TimingKind::Lab, limits).is_err());
    }
    let (_, validators) = inputs();
    let mut accounts = (1..=5).map(key).collect::<Vec<_>>();
    for index in 0..508u16 {
        let mut seed = [0; 32];
        seed[..2].copy_from_slice(&(index + 256).to_be_bytes());
        accounts.push(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
    }
    assert!(genesis(accounts, validators).is_err());
}

#[test]
fn old_profile_and_genesis_versions_are_not_reinterpreted() {
    let mut old_profile = Profile::lab().encode();
    // The former encoding omitted registered_accounts and commitments_per_attempt.
    let extra_limits_start = 9 + 6 * 8 + 3 * 8;
    old_profile.drain(extra_limits_start..extra_limits_start + 16);
    old_profile[..8].copy_from_slice(b"NAOPROF1");
    assert_eq!(
        Profile::decode(&old_profile),
        Err(LedgerError::Invalid("profile version"))
    );
    old_profile[..8].copy_from_slice(b"NAOPROF2");
    assert!(Profile::decode(&old_profile).is_err());
    old_profile[..8].copy_from_slice(b"NAOPROF3");
    assert!(Profile::decode(&old_profile).is_err());
    for old_magic in [b"NAOPROF4", b"NAOPROF5"] {
        let mut incompatible = Profile::lab().encode();
        incompatible[..8].copy_from_slice(old_magic);
        assert_eq!(
            Profile::decode(&incompatible),
            Err(LedgerError::Invalid("profile version"))
        );
    }

    let genesis = fixture();
    let mut old_genesis = genesis.encode();
    for old_magic in [
        b"NAOGENS1",
        b"NAOGENS2",
        b"NAOGENS3",
        b"NAOGENS4",
        b"NAOGENS5",
    ] {
        old_genesis[..8].copy_from_slice(old_magic);
        assert_eq!(
            Genesis::decode(&old_genesis),
            Err(LedgerError::Invalid("genesis version"))
        );
    }
    for protocol_version in [1, 2, 3, 4, 5] {
        let mut unsupported = genesis.clone();
        unsupported.protocol_version = protocol_version;
        assert!(Genesis::decode(&unsupported.encode()).is_err());
    }
}

#[test]
fn constructor_normalizes_but_decoder_rejects_membership_order() {
    let (mut a, mut v) = inputs();
    let g = genesis(a.clone(), v.clone()).unwrap();
    a.reverse();
    v.reverse();
    assert_ne!(genesis(a.clone(), v.clone()).unwrap().id(), g.id());
    let same_order = Genesis::new(
        Profile::lab(),
        "naome:zfc".into(),
        STATE_CHECKER_PROFILE.into(),
        STATE_PROTOCOL_VERSION,
        1800000000,
        [42; 32],
        a,
        v,
        g.retirement_order().to_vec(),
    )
    .unwrap();
    assert_eq!(same_order, g);
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
fn explicit_retirement_order_is_exact_genesis_bound_and_replay_stable() {
    let g = fixture();
    assert_eq!(g.retirement_order().len(), 4);
    let (_, registrations) = inputs();
    assert_eq!(
        g.retirement_order(),
        &[
            registrations[2].id(),
            registrations[0].id(),
            registrations[3].id(),
            registrations[1].id()
        ]
    );
    let decoded = Genesis::decode(&g.encode()).unwrap();
    assert_eq!(decoded.retirement_order(), g.retirement_order());
    assert_eq!(decoded.id(), g.id());
    assert_eq!(
        crate::LedgerState::new(decoded).commitment(),
        crate::LedgerState::new(g.clone()).commitment()
    );

    let mut reversed = g.clone();
    reversed.retirement_order.reverse();
    reversed.validate().unwrap();
    assert_eq!(reversed.validators(), g.validators());
    assert_ne!(reversed.id(), g.id());
    assert_ne!(
        crate::LedgerState::new(reversed).commitment(),
        crate::LedgerState::new(g.clone()).commitment()
    );

    let mut duplicate = g.clone();
    duplicate.retirement_order[1] = duplicate.retirement_order[0];
    assert_eq!(
        duplicate.validate(),
        Err(LedgerError::Invalid("bootstrap retirement order"))
    );
    assert!(Genesis::decode(&duplicate.encode()).is_err());
    let mut unknown = g.clone();
    unknown.retirement_order[0] = ValidatorId::from_bytes([0; 32]);
    assert!(unknown.validate().is_err());
    assert!(Genesis::decode(&unknown.encode()).is_err());
    let mut missing = g;
    missing.retirement_order.pop();
    assert!(missing.validate().is_err());
    assert!(Genesis::decode(&missing.encode()).is_err());
}

#[test]
fn genesis_rejects_every_truncation_trailing_data_and_oversize() {
    let bytes = fixture().encode();
    for end in 0..bytes.len() {
        assert!(Genesis::decode(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut bad = bytes;
    bad.push(0);
    assert_eq!(Genesis::decode(&bad), Err(LedgerError::TrailingBytes));
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
    bad.protocol_version = 1;
    assert!(bad.validate().is_err());
    let mut bad = g.clone();
    bad.run_nonce = [0; 32];
    assert!(bad.validate().is_err());
    let mut bad = g;
    bad.start_utc = u64::MAX;
    assert_eq!(bad.validate(), Err(LedgerError::Overflow));
}

#[test]
fn lab_profile_golden_encoding_and_identity() {
    // Independently written protocol vector: magic, variant, timing, bounds,
    // rewards. Changes require an explicit new encoding/profile decision.
    let values: [u64; 39] = [
        300, 120, 120, 1800, 2, 60, 1, 32, 512, 1024, 16, 1, 16384, 1024, 32, 16, 262144, 65536,
        4096, 64, 2097152, 32, 64, 16, 1, 1048576, 8192, 64, 1, 2, 4, 4194304, 2592, 75497472,
        10616832, 1114112, 1310720, 64, 64,
    ];
    let mut bytes = b"NAOPROF6\0".to_vec();
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for value in [
        1_000_000_000u128,
        700_000_000,
        600_000_000,
        100_000_000,
        200_000_000,
        100_000_000,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    assert_eq!(bytes.len(), 417);
    assert_eq!(Profile::lab().encode(), bytes);
    assert_eq!(
        Profile::lab().id().as_bytes(),
        &[
            57, 145, 65, 102, 224, 142, 55, 136, 11, 205, 47, 101, 51, 206, 114, 171, 116, 58, 17,
            153, 65, 146, 102, 18, 177, 135, 97, 220, 238, 103, 196, 164
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
    assert_eq!(p.signer_height_bytes().unwrap(), 333942111);
    assert_eq!(p.signer_journal_bytes().unwrap(), 2735922839552);
    let reduced = Profile::with_limits(
        TimingKind::Lab,
        Limits {
            run_records: 256,
            record_bytes: 512 * 1024,
            package_bytes: 64 * 1024,
            transport_frame_bytes: 768 * 1024,
            consensus_rounds: 8,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(reduced.required_storage_bytes().unwrap(), 20_295_559_168);
    assert!(reduced.required_storage_bytes().unwrap() < p.required_storage_bytes().unwrap());
    assert!(reduced.signer_journal_bytes().unwrap() > reduced.signer_height_bytes().unwrap() * 256);
    assert_eq!(Profile::decode(&reduced.encode()).unwrap(), reduced);
}
