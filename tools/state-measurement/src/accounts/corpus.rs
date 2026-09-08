use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::hint::black_box;

pub(super) struct Fixture {
    pub state: State,
    pub target: Hash,
    pub payer: Hash,
    #[cfg(test)]
    pub owner: Policy,
    #[cfg(test)]
    pub recovery: Policy,
    pub proposed: Policy,
    pub keys: BTreeMap<Hash, Vec<SigningKey>>,
}
fn keyset(n: usize, m: usize, seed: u8) -> (Policy, Vec<SigningKey>) {
    let mut keys: Vec<_> = (0..n)
        .map(|i| {
            let mut raw = [seed; 32];
            raw[..8].copy_from_slice(&(i as u64).to_be_bytes());
            SigningKey::from_bytes(&raw)
        })
        .collect();
    keys.sort_by_key(|key| key.verifying_key().to_bytes());
    let p = Policy {
        threshold: m,
        keys: keys.iter().map(SigningKey::verifying_key).collect(),
    };
    (Policy::decode(&p.encode(), CORPUS).unwrap(), keys)
}
pub(super) fn fixture(n: usize, m: usize) -> Fixture {
    let (owner, owner_keys) = keyset(n, m, 1);
    let (recovery, recovery_keys) = keyset(n, m, 2);
    let (proposed, proposed_keys) = keyset(n, m, 3);
    let a = Account {
        initial: owner.clone(),
        discriminator: [1; 32],
        owner: owner.clone(),
        recovery: Some(recovery.clone()),
        g: zero(),
        n: zero(),
        liquid: BigUint::from(1_000_000u32),
        credit: (zero(), one()),
        pending: None,
    };
    let mut b = a.clone();
    b.discriminator = [2; 32];
    let mut state = State {
        accounts: Map::new(BigUint::from(9001u32)),
        accounting: Map::new(BigUint::from(9002u32)),
        context: Context {
            chain: [0xa1; 32],
            genesis: [0xb2; 32],
            version: one(),
        },
        height: one(),
    };
    state.put(&a).unwrap();
    state.put(&b).unwrap();
    Accounting {
        issued: &a.liquid + &b.liquid,
        burned: zero(),
        reserve: zero(),
        pool: zero(),
    }
    .write(&mut state.accounting, &state.height)
    .unwrap();
    state.validate_fixture(CORPUS).unwrap();
    Fixture {
        state,
        target: a.id(),
        payer: b.id(),
        #[cfg(test)]
        owner: owner.clone(),
        #[cfg(test)]
        recovery: recovery.clone(),
        proposed: proposed.clone(),
        keys: [
            (owner.hash(), owner_keys),
            (recovery.hash(), recovery_keys),
            (proposed.hash(), proposed_keys),
        ]
        .into(),
    }
}
pub(super) fn intent(context: &Context, op: &Operation, rows: &[Row]) -> Vec<u8> {
    let mut b = context.encode();
    count(&mut b, op.tag());
    bytes(&mut b, &op.payload());
    count(&mut b, rows.len());
    for row in rows {
        row.encode(&mut b);
    }
    b
}
pub(super) fn witness(p: &Policy, keys: &[SigningKey], digest: Hash, offset: usize) -> Vec<u8> {
    let mut b = Vec::new();
    count(&mut b, p.threshold);
    for (index, key) in keys.iter().enumerate().skip(offset).take(p.threshold) {
        count(&mut b, index);
        b.extend(key.sign(&digest).to_bytes());
    }
    b
}
pub(super) fn frame(intent: &[u8], witness: &[u8], consent: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    bytes(&mut b, intent);
    bytes(&mut b, witness);
    bytes(&mut b, consent);
    b
}
pub(super) fn signed(
    state: &State,
    op: &Operation,
    keys: &BTreeMap<Hash, Vec<SigningKey>>,
    offset: usize,
) -> Vec<u8> {
    let auth = state.authorization(op, CORPUS).unwrap();
    let rows: Vec<_> = auth.iter().map(|(row, _)| row.clone()).collect();
    let intent = intent(&state.context, op, &rows);
    let id = hash(OP, &[&intent]);
    let mut w = Vec::new();
    count(&mut w, auth.len());
    for (row, p) in auth {
        w.extend(witness(
            &p,
            &keys[&p.hash()],
            row.digest(&state.context, id),
            offset,
        ));
    }
    let consent = op.consent().map_or_else(Vec::new, |(domain, p)| {
        let digest = hash(
            domain,
            &[&state.context.encode(), &id, &op.target, &p.hash()],
        );
        witness(p, &keys[&p.hash()], digest, offset)
    });
    frame(&intent, &w, &consent)
}
pub(super) fn operation(f: &Fixture, tag: usize, alias: bool) -> Operation {
    let kind = match tag {
        0 => Kind::Create {
            initial: f.proposed.clone(),
            discriminator: [3; 32],
            funding: BigUint::from(100u32),
        },
        1 => Kind::Rotate(f.proposed.clone()),
        2 => Kind::Set(f.proposed.clone()),
        3 => Kind::Disable,
        4 => Kind::Start(f.proposed.clone()),
        5 => Kind::Cancel([0; 32]),
        _ => unreachable!(),
    };
    let target = if let Kind::Create {
        initial,
        discriminator,
        ..
    } = &kind
    {
        account_id(initial, discriminator)
    } else {
        f.target
    };
    Operation {
        kind,
        target,
        payer: if alias { target } else { f.payer },
        fee: BigUint::from(11u32),
    }
}
pub(super) fn pending(f: &mut Fixture) -> Hash {
    let op = operation(f, 4, false);
    let bytes = signed(&f.state, &op, &f.keys, 0);
    f.state.apply_batch(&[bytes], CORPUS).unwrap()[0]
}
fn hex(hash: Hash) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn record_bytes(map: &Map) -> usize {
    map.entries()
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum()
}
pub(super) fn calibrate() {
    println!(
        "{{\"kind\":\"account_family_calibration\",\"account_tag\":9001,\"accounting_tag\":9002,\"supplied_context_and_height\":true,\"input_bound\":{},\"natural_bound\":{},\"policy_key_bound\":{},\"canonical_admission\":false,\"full_height_settlement\":false}}",
        CORPUS.input, CORPUS.natural, CORPUS.keys
    );
    for n in [1usize, 4, 16] {
        for m in [1, n]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
        {
            for tag in 0..6 {
                for alias in [false, true] {
                    if alias && (tag == 0 || tag == 4) {
                        continue;
                    }
                    let mut f = fixture(n, m);
                    let mut op = operation(&f, tag, alias);
                    if tag == 5 {
                        op.kind = Kind::Cancel(pending(&mut f));
                    }
                    let input = signed(&f.state, &op, &f.keys, 0);
                    let mut result = f.state.clone();
                    result
                        .apply_batch(std::slice::from_ref(&input), CORPUS)
                        .unwrap();
                    result.validate_fixture(CORPUS).unwrap();
                    let accounting =
                        Accounting::read(&result.accounting, &result.height, CORPUS).unwrap();
                    let name = format!("account_kind{tag}_n{n}_m{m}_alias{alias}");
                    println!(
                        "{{\"kind\":\"account_corpus\",\"case\":\"{name}\",\"frame_bytes\":{},\"account_records\":{},\"before_account_record_bytes\":{},\"after_account_record_bytes\":{},\"after_accounting_record_bytes\":{},\"pool\":\"{}\",\"burned\":\"{}\",\"account_root\":\"{}\",\"accounting_root\":\"{}\"}}",
                        input.len(),
                        result.accounts.entries().len(),
                        record_bytes(&f.state.accounts),
                        record_bytes(&result.accounts),
                        record_bytes(&result.accounting),
                        accounting.pool,
                        accounting.burned,
                        hex(result.accounts.root_hash()),
                        hex(result.accounting.root_hash())
                    );
                    crate::measure(&name, || {
                        let mut candidate = f.state.clone();
                        black_box(candidate.apply_batch(std::slice::from_ref(&input), CORPUS))
                            .is_ok()
                    });
                }
            }
            let mut f = fixture(n, m);
            pending(&mut f);
            // Synthetic source fixture at the last height before E+2. Retargeting
            // its pool cursor constructs a corpus; it is not a height transition.
            f.state.height = BigUint::from(16384u32);
            let accounting = Accounting::read(&f.state.accounting, &one(), CORPUS).unwrap();
            accounting
                .write(&mut f.state.accounting, &f.state.height)
                .unwrap();
            f.state.validate_fixture(CORPUS).unwrap();
            let next = BigUint::from(16385u32);
            let projected = f.state.prepare_due_accounts(&next, CORPUS).unwrap();
            let name = format!("account_due_projection_n{n}_m{m}");
            println!(
                "{{\"kind\":\"account_projection_corpus\",\"case\":\"{name}\",\"account_records\":{},\"before_record_bytes\":{},\"after_record_bytes\":{},\"source_height\":16384,\"target_height\":16385,\"account_root\":\"{}\",\"installs_state\":false}}",
                f.state.accounts.entries().len(),
                record_bytes(&f.state.accounts),
                record_bytes(&projected),
                hex(projected.root_hash())
            );
            crate::measure(&name, || {
                black_box(f.state.prepare_due_accounts(&next, CORPUS)).is_ok()
            });
        }
    }
}
