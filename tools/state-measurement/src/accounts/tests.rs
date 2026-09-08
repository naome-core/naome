use super::corpus::*;
use super::*;

type Records = Vec<(Vec<u8>, Vec<u8>)>;
fn snapshot(s: &State) -> (Hash, Hash, Records, Records) {
    let collect = |m: &Map| {
        m.entries()
            .into_iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect()
    };
    (
        s.accounts.root_hash(),
        s.accounting.root_hash(),
        collect(&s.accounts),
        collect(&s.accounting),
    )
}
fn rejected(s: &mut State, input: Vec<u8>) {
    let before = snapshot(s);
    assert!(s.apply_batch(&[input], CORPUS).is_err());
    assert_eq!(snapshot(s), before);
}
fn apply(f: &mut Fixture, op: &Operation) -> Hash {
    let input = signed(&f.state, op, &f.keys, 0);
    let id = f.state.apply_batch(&[input], CORPUS).unwrap()[0];
    f.state.validate_fixture(CORPUS).unwrap();
    id
}
#[test]
fn all_six_operations_have_expected_records_nonces_and_fee_custody() {
    for tag in 0..6 {
        for alias in [false, true] {
            if alias && (tag == 0 || tag == 4) {
                continue;
            }
            let mut f = fixture(4, 2);
            let mut op = operation(&f, tag, alias);
            if tag == 5 {
                op.kind = Kind::Cancel(pending(&mut f));
            }
            let old = f.state.account(f.target, CORPUS).unwrap();
            let payer = f.state.account(op.payer, CORPUS).unwrap();
            let accounting =
                Accounting::read(&f.state.accounting, &f.state.height, CORPUS).unwrap();
            let id = apply(&mut f, &op);
            let a = f.state.account(op.target, CORPUS).unwrap();
            let paid = f.state.account(op.payer, CORPUS).unwrap();
            assert_eq!(paid.n, payer.n + one());
            let cost = &op.fee
                + if tag == 0 {
                    BigUint::from(100u32)
                } else {
                    zero()
                };
            assert_eq!(paid.liquid, payer.liquid - cost);
            assert_eq!(a.n, if tag == 0 { one() } else { old.n + one() });
            assert_eq!(
                a.g,
                if [1, 2, 3].contains(&tag) {
                    &old.g + one()
                } else {
                    old.g.clone()
                }
            );
            if tag != 0 {
                assert_eq!(a.initial, old.initial);
                assert_eq!(a.credit, old.credit);
            }
            match tag {
                0 => {
                    assert_eq!(a.owner, f.proposed);
                    assert_eq!(a.liquid, BigUint::from(100u32));
                    assert_eq!(a.credit, (zero(), one()));
                    assert!(a.recovery.is_none() && a.pending.is_none());
                }
                1 => {
                    assert_eq!(a.owner, f.proposed);
                    assert!(a.pending.is_none());
                }
                2 => assert_eq!(a.recovery, Some(f.proposed)),
                3 => assert!(a.recovery.is_none() && a.pending.is_none()),
                4 => {
                    let p = a.pending.unwrap();
                    assert_eq!(p.operation, id);
                    assert_eq!(p.source, one());
                    assert_eq!(a.owner, old.owner);
                }
                5 => assert!(a.pending.is_none()),
                _ => unreachable!(),
            }
            let after = Accounting::read(&f.state.accounting, &f.state.height, CORPUS).unwrap();
            assert_eq!(after.issued, accounting.issued);
            assert_eq!(after.reserve, accounting.reserve);
            assert_eq!(after.pool, accounting.pool + 2u32);
            assert_eq!(after.burned, accounting.burned + 9u32);
        }
    }
}
#[test]
fn every_frame_prefix_trailing_bytes_and_corpus_bound_reject_atomically() {
    for tag in 0..6 {
        let mut f = fixture(1, 1);
        let mut op = operation(&f, tag, false);
        if tag == 5 {
            op.kind = Kind::Cancel(pending(&mut f));
        }
        let input = signed(&f.state, &op, &f.keys, 0);
        for end in 0..input.len() {
            rejected(&mut f.state, input[..end].to_vec());
        }
        let mut extra = input.clone();
        extra.push(0);
        rejected(&mut f.state, extra);
        let before = snapshot(&f.state);
        assert!(
            f.state
                .apply_batch(
                    std::slice::from_ref(&input),
                    Limits {
                        input: input.len() - 1,
                        ..CORPUS
                    }
                )
                .is_err()
        );
        assert_eq!(before, snapshot(&f.state));
        let decoded = Frame::decode(&input, CORPUS).unwrap();
        let intent = intent(&decoded.context, &decoded.operation, &decoded.rows);
        assert_eq!(frame(&intent, decoded.witness, decoded.consent), input);
    }
}
#[test]
fn policy_admission_rejects_noncanonical_identity_torsion_and_threshold_shapes() {
    let mut enc = Vec::new();
    count(&mut enc, 1);
    count(&mut enc, 1);
    for key in [
        [0; 32],
        {
            let mut x = [0; 32];
            x[0] = 1;
            x
        },
        [255; 32],
    ] {
        let mut b = enc.clone();
        b.extend(key);
        assert!(Policy::decode(&b, CORPUS).is_err());
    }
    let f = fixture(4, 2);
    // Canonical, non-small-order mixed torsion passes the legacy weak-key
    // check, but is excluded by the selected prime-order admission rule.
    let prime = CompressedEdwardsY(f.owner.keys[0].to_bytes())
        .decompress()
        .unwrap();
    let mixed = prime + curve25519_dalek::constants::EIGHT_TORSION[1];
    let raw = mixed.compress().to_bytes();
    assert!(!VerifyingKey::from_bytes(&raw).unwrap().is_weak());
    assert!(!mixed.is_torsion_free());
    let mut encoded = enc.clone();
    encoded.extend(raw);
    assert!(Policy::decode(&encoded, CORPUS).is_err());
    let p = f.owner;
    for (m, n) in [(0, 4), (5, 4), (1, 0)] {
        let mut b = Vec::new();
        count(&mut b, m);
        count(&mut b, n);
        for k in &p.keys {
            b.extend(k.to_bytes());
        }
        assert!(Policy::decode(&b, CORPUS).is_err());
    }
    let mut duplicate = p.clone();
    duplicate.keys[1] = duplicate.keys[0];
    assert!(Policy::decode(&duplicate.encode(), CORPUS).is_err());
    let mut reversed = p.clone();
    reversed.keys.reverse();
    assert!(Policy::decode(&reversed.encode(), CORPUS).is_err());
    assert!(Policy::decode(&p.encode(), Limits { keys: 3, ..CORPUS }).is_err());
}
#[test]
fn alternate_threshold_subsets_preserve_operation_id_and_both_roots() {
    for tag in 0..6 {
        let mut f = fixture(4, 2);
        let mut op = operation(&f, tag, false);
        if tag == 5 {
            op.kind = Kind::Cancel(pending(&mut f));
        }
        let a = signed(&f.state, &op, &f.keys, 0);
        let b = signed(&f.state, &op, &f.keys, 2);
        assert_ne!(a, b);
        assert_eq!(
            Frame::decode(&a, CORPUS).unwrap().id,
            Frame::decode(&b, CORPUS).unwrap().id
        );
        let mut other = f.state.clone();
        f.state.apply_batch(&[a], CORPUS).unwrap();
        other.apply_batch(&[b], CORPUS).unwrap();
        assert_eq!(snapshot(&f.state), snapshot(&other));
    }
}
#[test]
fn changed_context_semantics_and_every_auth_field_invalidate_existing_witnesses() {
    let mut f = fixture(4, 2);
    let op = operation(&f, 1, false);
    let input = signed(&f.state, &op, &f.keys, 0);
    let decoded = Frame::decode(&input, CORPUS).unwrap();
    for field in 0..11 {
        let mut context = decoded.context.clone();
        let mut op = decoded.operation.clone();
        let mut rows = decoded.rows.clone();
        match field {
            0 => context.chain[0] ^= 1,
            1 => context.genesis[0] ^= 1,
            2 => context.version += one(),
            3 => op.fee += one(),
            4 => op.target = f.payer,
            5 => op.payer = f.target,
            6 => op.kind = Kind::Set(f.proposed.clone()),
            7 => rows[0].id[0] ^= 1,
            8 => rows[0].policy[0] ^= 1,
            9 => rows[0].g += one(),
            10 => rows[0].n += one(),
            _ => unreachable!(),
        }
        rejected(
            &mut f.state,
            frame(
                &intent(&context, &op, &rows),
                decoded.witness,
                decoded.consent,
            ),
        );
    }
}
#[test]
fn witness_shape_strict_signatures_and_wrong_consent_role_reject() {
    let mut f = fixture(4, 2);
    let op = operation(&f, 1, false);
    let input = signed(&f.state, &op, &f.keys, 0);
    let d = Frame::decode(&input, CORPUS).unwrap();
    let i = intent(&d.context, &d.operation, &d.rows);
    for w in [
        Vec::new(),
        {
            let mut b = d.witness.to_vec();
            b.push(0);
            b
        },
        {
            let mut b = d.witness.to_vec();
            b[1] = 1;
            b
        },
        {
            let mut b = d.witness.to_vec();
            let last = b.len() - 1;
            b[last] = 255;
            b
        },
    ] {
        rejected(&mut f.state, frame(&i, &w, d.consent));
    }
    let wrong = hash(
        RECOVERY,
        &[&d.context.encode(), &d.id, &op.target, &f.proposed.hash()],
    );
    let w = witness(&f.proposed, &f.keys[&f.proposed.hash()], wrong, 0);
    rejected(&mut f.state, frame(&i, d.witness, &w));
    rejected(&mut f.state, frame(&i, d.witness, &[]));
    // Build duplicate, descending and out-of-range indexed consent witnesses.
    for indices in [[0usize, 0], [1, 0], [0, 4]] {
        let digest = hash(
            OWNER,
            &[&d.context.encode(), &d.id, &op.target, &f.proposed.hash()],
        );
        let mut c = Vec::new();
        count(&mut c, 2);
        for index in indices {
            use ed25519_dalek::Signer;
            count(&mut c, index);
            c.extend(
                f.keys[&f.proposed.hash()][index.min(3)]
                    .sign(&digest)
                    .to_bytes(),
            );
        }
        rejected(&mut f.state, frame(&i, d.witness, &c));
    }
}
#[test]
fn restored_keys_do_not_restore_old_generation_authority() {
    let mut f = fixture(1, 1);
    let mut future = f.state.clone();
    let mut a = future.account(f.target, CORPUS).unwrap();
    a.n = BigUint::from(2u32);
    future.put(&a).unwrap();
    let stale_op = operation(&f, 3, true);
    let stale = signed(&future, &stale_op, &f.keys, 0);
    let first = operation(&f, 1, true);
    apply(&mut f, &first);
    let mut second = operation(&f, 1, true);
    second.kind = Kind::Rotate(f.owner.clone());
    apply(&mut f, &second);
    let a = f.state.account(f.target, CORPUS).unwrap();
    assert_eq!(a.owner, f.owner);
    assert_eq!(a.n, BigUint::from(2u32));
    assert_eq!(a.g, BigUint::from(2u32));
    rejected(&mut f.state, stale);
}
#[test]
fn combined_creation_cost_and_late_batch_failure_preserve_all_records() {
    let mut f = fixture(1, 1);
    let mut op = operation(&f, 0, false);
    if let Kind::Create { funding, .. } = &mut op.kind {
        *funding = BigUint::from(999_995u32);
    }
    let input = signed(&f.state, &op, &f.keys, 0);
    rejected(&mut f.state, input);
    let first = operation(&f, 1, true);
    let input = signed(&f.state, &first, &f.keys, 0);
    let mut evolving = f.state.clone();
    evolving
        .apply_batch(std::slice::from_ref(&input), CORPUS)
        .unwrap();
    let second = Operation {
        kind: Kind::Cancel([9; 32]),
        target: f.target,
        payer: f.target,
        fee: one(),
    };
    let invalid = signed(&evolving, &second, &f.keys, 0);
    let before = snapshot(&f.state);
    assert!(f.state.apply_batch(&[input, invalid], CORPUS).is_err());
    assert_eq!(before, snapshot(&f.state));
}

fn at_height(f: &mut Fixture, height: u32) {
    let a = Accounting::read(&f.state.accounting, &f.state.height, CORPUS).unwrap();
    f.state.height = BigUint::from(height);
    a.write(&mut f.state.accounting, &f.state.height).unwrap();
    f.state.validate_fixture(CORPUS).unwrap();
}
#[test]
fn recovery_activates_only_at_first_e_plus_two_height_without_consuming_nonce() {
    for source in [1u32, 8192, 8193] {
        let mut f = fixture(1, 1);
        at_height(&mut f, source);
        pending(&mut f);
        // Advance target nonce using its ordinary owner as another account's fee
        // sponsor. This preserves its accepted request and generation.
        let op = Operation {
            kind: Kind::Disable,
            target: f.payer,
            payer: f.target,
            fee: one(),
        };
        apply(&mut f, &op);
        let initial = f.state.account(f.target, CORPUS).unwrap();
        assert_eq!(initial.n, BigUint::from(2u32));
        let activation = ((source - 1) / 8192 + 2) * 8192 + 1;
        at_height(&mut f, activation - 2);
        let before = snapshot(&f.state);
        let unchanged = f
            .state
            .prepare_due_accounts(&BigUint::from(activation - 1), CORPUS)
            .unwrap();
        assert_eq!(unchanged.root_hash(), f.state.accounts.root_hash());
        assert!(
            f.state
                .prepare_due_accounts(&BigUint::from(activation), CORPUS)
                .is_err()
        );
        assert_eq!(before, snapshot(&f.state));
        at_height(&mut f, activation - 1);
        let before = snapshot(&f.state);
        let prepared = f
            .state
            .prepare_due_accounts(&BigUint::from(activation), CORPUS)
            .unwrap();
        let a = Account::decode(prepared.get(&f.target).unwrap().unwrap(), CORPUS).unwrap();
        assert_eq!(a.owner, f.proposed);
        assert_eq!(a.g, initial.g + one());
        assert_eq!(a.n, initial.n);
        assert_eq!(a.liquid, initial.liquid);
        assert_eq!(a.recovery, initial.recovery);
        assert!(a.pending.is_none());
        assert_eq!(snapshot(&f.state), before); // projection never installs either root
    }
}
#[test]
fn pending_request_cancellation_replacement_and_recovery_authority_are_exact() {
    for tag in [1, 2, 3, 5] {
        let mut f = fixture(1, 1);
        let id = pending(&mut f);
        let duplicate = operation(&f, 4, false);
        assert!(f.state.authorization(&duplicate, CORPUS).is_err());
        let mut op = operation(&f, tag, true);
        if tag == 5 {
            op.kind = Kind::Cancel(id);
        }
        apply(&mut f, &op);
        assert!(f.state.account(f.target, CORPUS).unwrap().pending.is_none());
    }
    let mut f = fixture(1, 1);
    let op = operation(&f, 4, true);
    assert!(f.state.authorization(&op, CORPUS).is_err());
    // A recovery-policy signature cannot satisfy the ordinary owner's target row.
    let op = operation(&f, 3, true);
    let input = signed(&f.state, &op, &f.keys, 0);
    let d = Frame::decode(&input, CORPUS).unwrap();
    let digest = d.rows[0].digest(&d.context, d.id);
    let mut w = Vec::new();
    count(&mut w, 1);
    w.extend(witness(&f.recovery, &f.keys[&f.recovery.hash()], digest, 0));
    rejected(
        &mut f.state,
        frame(&intent(&d.context, &d.operation, &d.rows), &w, d.consent),
    );
    pending(&mut f);
    let bad = Operation {
        kind: Kind::Cancel([9; 32]),
        target: f.target,
        payer: f.target,
        fee: one(),
    };
    let input = signed(&f.state, &bad, &f.keys, 0);
    rejected(&mut f.state, input);
}
#[test]
fn account_record_roundtrip_rejects_invalid_rational_options_identity_and_pending_context() {
    let mut f = fixture(1, 1);
    pending(&mut f);
    let a = f.state.account(f.target, CORPUS).unwrap();
    let encoded = a.encode();
    assert_eq!(Account::decode(&encoded, CORPUS).unwrap(), a);
    for end in 0..encoded.len() {
        assert!(Account::decode(&encoded[..end], CORPUS).is_err());
    }
    let mut extra = encoded.clone();
    extra.push(0);
    assert!(Account::decode(&extra, CORPUS).is_err());
    for credit in [(0u32, 2u32), (2, 4), (1, 0)] {
        let mut bad = a.clone();
        bad.credit = (BigUint::from(credit.0), BigUint::from(credit.1));
        assert!(Account::decode(&bad.encode(), CORPUS).is_err());
    }
    let mut bad = a.clone();
    bad.discriminator[0] ^= 1;
    assert!(bad.validate_at(f.target, &one()).is_err());
    for variant in 0..4 {
        let mut bad = a.clone();
        let p = bad.pending.as_mut().unwrap();
        match variant {
            0 => p.source = zero(),
            1 => p.source = BigUint::from(2u32),
            2 => p.g += one(),
            3 => p.recovery[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(bad.validate_at(f.target, &one()).is_err());
    }
    assert!(a.validate_at(f.target, &BigUint::from(16385u32)).is_err());
    // Both option fields are single-byte discriminants.
    let plain = fixture(1, 1).state.account(f.target, CORPUS).unwrap();
    let mut raw = plain.encode();
    *raw.last_mut().unwrap() = 2;
    assert!(Account::decode(&raw, CORPUS).is_err());
    let mut offset = Vec::new();
    policy(&mut offset, &plain.initial);
    offset.extend(plain.discriminator);
    policy(&mut offset, &plain.owner);
    let mut raw = plain.encode();
    raw[offset.len()] = 2;
    assert!(Account::decode(&raw, CORPUS).is_err());
}
#[test]
fn growing_numbers_and_minimal_natural_framing_are_enforced() {
    let mut f = fixture(1, 1);
    let mut a = f.state.account(f.target, CORPUS).unwrap();
    a.g = one() << 200usize;
    a.n = one() << 300usize;
    f.state.put(&a).unwrap();
    let op = operation(&f, 3, true);
    apply(&mut f, &op);
    let b = f.state.account(f.target, CORPUS).unwrap();
    assert_eq!(b.g, a.g + one());
    assert_eq!(b.n, a.n + one());
    for bytes in [
        vec![0x80, 0],
        vec![1, 0],
        vec![0x81, 0, 1],
        vec![2, 1],
        vec![0xff; 32],
    ] {
        assert!(Reader::new(&bytes, CORPUS).unwrap().nat().is_err());
    }
    let mut encoded = Vec::new();
    nat(&mut encoded, &(one() << 4096usize));
    assert!(Reader::new(&encoded, CORPUS).unwrap().nat().is_err());
}

#[test]
fn independent_python_hash_vectors_fix_domains_and_exact_natural_transcripts() {
    fn h(s: &str) -> Hash {
        let mut b = [0u8; 32];
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            b[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        b
    }
    let raw = h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let mut encoded = vec![1, 1, 1, 1];
    encoded.extend(raw);
    let p = Policy::decode(&encoded, CORPUS).unwrap();
    assert_eq!(
        p.hash(),
        h("93bcbaec94e5ff65b92874d32f0449d3e52c62ef450db3f3fbe2d73875c1dc55")
    );
    let id = account_id(&p, &[7; 32]);
    assert_eq!(
        id,
        h("4ca606d747416a7529b4c14eb14fbefa065a1374b0a9c04b446f6e706c8dcee3")
    );
    let context = Context {
        chain: [1; 32],
        genesis: [2; 32],
        version: one(),
    };
    let op = Operation {
        kind: Kind::Disable,
        target: id,
        payer: id,
        fee: BigUint::from(11u32),
    };
    let row = Row {
        id,
        policy: p.hash(),
        g: BigUint::from(256u32),
        n: BigUint::from(65536u32),
    };
    let oid = hash(OP, &[&intent(&context, &op, std::slice::from_ref(&row))]);
    assert_eq!(
        oid,
        h("69d0d378cbc02c20a68269720634dfd88ec8206559a0ece0e45fae114195cc75")
    );
    assert_eq!(
        row.digest(&context, oid),
        h("fc595fc44b4c509376b92d593e8f049ec2420d6c4a75070542997a43dbbd4723")
    );
}

#[test]
fn first_and_last_account_signatures_and_strict_r_s_encodings_reject() {
    let mut f = fixture(4, 2);
    let op = operation(&f, 1, false);
    let input = signed(&f.state, &op, &f.keys, 0);
    let d = Frame::decode(&input, CORPUS).unwrap();
    let i = intent(&d.context, &d.operation, &d.rows);
    let mut r = Reader::new(d.witness, CORPUS).unwrap();
    let row_count = r.count(2).unwrap();
    let mut offsets = Vec::new();
    for _ in 0..row_count {
        let threshold = r.count(4).unwrap();
        for _ in 0..threshold {
            r.count(4).unwrap();
            let signature = r.take(64).unwrap();
            offsets.push(signature.as_ptr() as usize - d.witness.as_ptr() as usize);
        }
    }
    r.end().unwrap();
    let first = offsets[0];
    let last = *offsets.last().unwrap();
    for offset in [first, last] {
        for mode in 0..3 {
            let mut w = d.witness.to_vec();
            match mode {
                0 => w[offset] ^= 1,
                1 => w[offset + 32..offset + 64].fill(255), // noncanonical S
                2 => {
                    w[offset..offset + 32].fill(0);
                    w[offset] = 1;
                } // identity R
                _ => unreachable!(),
            }
            rejected(&mut f.state, frame(&i, &w, d.consent));
        }
    }
}
#[test]
fn duplicate_creation_and_consumed_nonce_replay_reject_without_effects() {
    for tag in [0, 3, 4] {
        let mut f = fixture(1, 1);
        let op = operation(&f, tag, false);
        let input = signed(&f.state, &op, &f.keys, 0);
        f.state
            .apply_batch(std::slice::from_ref(&input), CORPUS)
            .unwrap();
        rejected(&mut f.state, input);
    }
}
