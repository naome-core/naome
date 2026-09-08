//! Isolated six-operation account calibration. Supplied context/heights, fixture
//! custody, namespace tags, and limits carry no canonical execution authority.
use crate::typed_map::Map;
use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use ed25519_dalek::{Signature, VerifyingKey};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
mod codec;
use codec::{CORPUS, Limits, Reader, bytes, count, nat, policy};

type Hash = [u8; 32];
#[derive(Debug, PartialEq, Eq)]
struct Invalid;
type Result<T> = std::result::Result<T, Invalid>;
fn ensure(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(Invalid) }
}
fn zero() -> BigUint {
    BigUint::from(0u8)
}
fn one() -> BigUint {
    BigUint::from(1u8)
}
fn hash(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
const POLICY: &[u8] = b"naome/consensus/v1/account-policy\0";
const ID: &[u8] = b"naome/consensus/v1/account-id\0";
const OP: &[u8] = b"naome/consensus/v1/operation-id\0";
const AUTH: &[u8] = b"naome/consensus/v1/account-authorization\0";
const OWNER: &[u8] = b"naome/consensus/v1/new-owner-policy-consent\0";
const RECOVERY: &[u8] = b"naome/consensus/v1/new-recovery-policy-consent\0";
#[derive(Clone, Debug, PartialEq, Eq)]
struct Policy {
    threshold: usize,
    keys: Vec<VerifyingKey>,
}
impl Policy {
    fn hash(&self) -> Hash {
        hash(POLICY, &[&self.encode()])
    }
    fn verify(&self, digest: Hash, r: &mut Reader<'_>) -> Result<()> {
        ensure(r.count(self.keys.len())? == self.threshold)?;
        let mut previous = None;
        for _ in 0..self.threshold {
            let index = r.count(self.keys.len())?;
            ensure(previous.is_none_or(|p| p < index))?;
            let key = self.keys.get(index).ok_or(Invalid)?;
            key.verify_strict(&digest, &Signature::from_bytes(&r.fixed()?))
                .map_err(|_| Invalid)?;
            previous = Some(index);
        }
        Ok(())
    }
}
fn account_id(p: &Policy, discriminator: &Hash) -> Hash {
    let mut framed = Vec::new();
    policy(&mut framed, p);
    hash(ID, &[&framed, discriminator])
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    operation: Hash,
    recovery: Hash,
    g: BigUint,
    owner: Policy,
    source: BigUint,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Account {
    initial: Policy,
    discriminator: Hash,
    owner: Policy,
    recovery: Option<Policy>,
    g: BigUint,
    n: BigUint,
    liquid: BigUint,
    credit: (BigUint, BigUint),
    pending: Option<Pending>,
}
fn epoch(height: &BigUint) -> Result<BigUint> {
    ensure(*height > zero())?;
    Ok((height - one()) / 8192u32)
}
impl Account {
    fn id(&self) -> Hash {
        account_id(&self.initial, &self.discriminator)
    }
    fn validate_at(&self, id: Hash, height: &BigUint) -> Result<()> {
        ensure(self.id() == id)?;
        if let Some(p) = &self.pending {
            ensure(p.source > zero() && p.source <= *height && p.g == self.g)?;
            ensure(
                self.recovery
                    .as_ref()
                    .is_some_and(|r| r.hash() == p.recovery),
            )?;
            ensure(epoch(&p.source)? + 2u32 > epoch(height)?)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Context {
    chain: Hash,
    genesis: Hash,
    version: BigUint,
}
impl Context {
    fn encode(&self) -> Vec<u8> {
        let mut b = self.chain.to_vec();
        b.extend(self.genesis);
        nat(&mut b, &self.version);
        b
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            chain: r.fixed()?,
            genesis: r.fixed()?,
            version: r.nat()?,
        })
    }
}
#[derive(Clone, Debug)]
enum Kind {
    Create {
        initial: Policy,
        discriminator: Hash,
        funding: BigUint,
    },
    Rotate(Policy),
    Set(Policy),
    Disable,
    Start(Policy),
    Cancel(Hash),
}
#[derive(Clone, Debug)]
struct Operation {
    kind: Kind,
    target: Hash,
    payer: Hash,
    fee: BigUint,
}
impl Operation {
    fn tag(&self) -> usize {
        match self.kind {
            Kind::Create { .. } => 0,
            Kind::Rotate(_) => 1,
            Kind::Set(_) => 2,
            Kind::Disable => 3,
            Kind::Start(_) => 4,
            Kind::Cancel(_) => 5,
        }
    }
    fn consent(&self) -> Option<(&'static [u8], &Policy)> {
        match &self.kind {
            Kind::Rotate(p) | Kind::Start(p) => Some((OWNER, p)),
            Kind::Set(p) => Some((RECOVERY, p)),
            _ => None,
        }
    }
    fn payload(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match &self.kind {
            Kind::Create {
                initial,
                discriminator,
                ..
            } => {
                policy(&mut b, initial);
                b.extend(discriminator);
            }
            _ => b.extend(self.target),
        }
        match &self.kind {
            Kind::Rotate(p) | Kind::Set(p) | Kind::Start(p) => policy(&mut b, p),
            Kind::Cancel(id) => b.extend(id),
            _ => (),
        }
        b.extend(self.payer);
        if let Kind::Create { funding, .. } = &self.kind {
            nat(&mut b, funding);
        }
        nat(&mut b, &self.fee);
        b
    }
    fn decode(tag: usize, payload: &[u8], limits: Limits) -> Result<Self> {
        let mut r = Reader::new(payload, limits)?;
        let (target, kind) = match tag {
            0 => {
                let initial = r.policy()?;
                let discriminator = r.fixed()?;
                let target = account_id(&initial, &discriminator);
                (
                    target,
                    Kind::Create {
                        initial,
                        discriminator,
                        funding: zero(),
                    },
                )
            }
            1 => (r.fixed()?, Kind::Rotate(r.policy()?)),
            2 => (r.fixed()?, Kind::Set(r.policy()?)),
            3 => (r.fixed()?, Kind::Disable),
            4 => (r.fixed()?, Kind::Start(r.policy()?)),
            5 => (r.fixed()?, Kind::Cancel(r.fixed()?)),
            _ => return Err(Invalid),
        };
        let payer = r.fixed()?;
        let mut kind = kind;
        if let Kind::Create { funding, .. } = &mut kind {
            *funding = r.nat()?;
        }
        let fee = r.nat()?;
        ensure(fee > zero())?;
        r.end()?;
        Ok(Self {
            kind,
            target,
            payer,
            fee,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    id: Hash,
    policy: Hash,
    g: BigUint,
    n: BigUint,
}
impl Row {
    fn encode(&self, b: &mut Vec<u8>) {
        b.extend(self.id);
        b.extend(self.policy);
        nat(b, &self.g);
        nat(b, &self.n);
    }
    fn digest(&self, context: &Context, operation: Hash) -> Hash {
        hash(
            AUTH,
            &[&context.encode(), &operation, &self.id, &self.policy],
        )
    }
}
struct Frame<'a> {
    context: Context,
    operation: Operation,
    rows: Vec<Row>,
    id: Hash,
    witness: &'a [u8],
    consent: &'a [u8],
}
impl<'a> Frame<'a> {
    fn decode(input: &'a [u8], limits: Limits) -> Result<Self> {
        let mut outer = Reader::new(input, limits)?;
        let intent = outer.bytes()?;
        let witness = outer.bytes()?;
        let consent = outer.bytes()?;
        outer.end()?;
        let mut r = Reader::new(intent, limits)?;
        let context = Context::decode(&mut r)?;
        let tag = r.count(5)?;
        let operation = Operation::decode(tag, r.bytes()?, limits)?;
        let n = r.count(2)?;
        let mut rows = Vec::with_capacity(n);
        for _ in 0..n {
            let row = Row {
                id: r.fixed()?,
                policy: r.fixed()?,
                g: r.nat()?,
                n: r.nat()?,
            };
            ensure(rows.last().is_none_or(|p: &Row| p.id < row.id))?;
            rows.push(row);
        }
        r.end()?;
        Ok(Self {
            context,
            operation,
            rows,
            id: hash(OP, &[intent]),
            witness,
            consent,
        })
    }
}

#[derive(Clone)]
struct State {
    accounts: Map,
    accounting: Map,
    context: Context,
    height: BigUint,
}
struct Accounting {
    issued: BigUint,
    burned: BigUint,
    reserve: BigUint,
    pool: BigUint,
}
impl Accounting {
    fn read(map: &Map, height: &BigUint, limits: Limits) -> Result<Self> {
        ensure(map.entries().len() == 3 && *height > zero())?;
        let get = |key| map.get(&[key]).map_err(|_| Invalid)?.ok_or(Invalid);
        let mut r = Reader::new(get(0)?, limits)?;
        let issued = r.nat()?;
        let burned = r.nat()?;
        r.end()?;
        ensure(burned <= issued)?;
        let mut r = Reader::new(get(1)?, limits)?;
        let reserve = r.nat()?;
        r.end()?;
        let mut r = Reader::new(get(2)?, limits)?;
        ensure(r.tag()? == 1 && r.nat()? == *height)?;
        let pool = r.nat()?;
        r.end()?;
        Ok(Self {
            issued,
            burned,
            reserve,
            pool,
        })
    }
    fn write(&self, map: &mut Map, height: &BigUint) -> Result<()> {
        ensure(self.burned <= self.issued && *height > zero())?;
        let mut supply = Vec::new();
        nat(&mut supply, &self.issued);
        nat(&mut supply, &self.burned);
        let mut reserve = Vec::new();
        nat(&mut reserve, &self.reserve);
        let mut pool = vec![1];
        nat(&mut pool, height);
        nat(&mut pool, &self.pool);
        for (key, value) in [(0, supply), (1, reserve), (2, pool)] {
            map.insert(vec![key], value).map_err(|_| Invalid)?;
        }
        Ok(())
    }
}
impl State {
    fn account(&self, id: Hash, limits: Limits) -> Result<Account> {
        let raw = self
            .accounts
            .get(&id)
            .map_err(|_| Invalid)?
            .ok_or(Invalid)?;
        let a = Account::decode(raw, limits)?;
        a.validate_at(id, &self.height)?;
        Ok(a)
    }
    fn put(&mut self, a: &Account) -> Result<()> {
        self.accounts
            .insert(a.id().to_vec(), a.encode())
            .map_err(|_| Invalid)
    }
    fn authorization(&self, op: &Operation, limits: Limits) -> Result<Vec<(Row, Policy)>> {
        let (target, p) = match &op.kind {
            Kind::Create {
                initial,
                discriminator,
                ..
            } => {
                ensure(account_id(initial, discriminator) == op.target && op.target != op.payer)?;
                ensure(
                    self.accounts
                        .get(&op.target)
                        .map_err(|_| Invalid)?
                        .is_none(),
                )?;
                (
                    Row {
                        id: op.target,
                        policy: initial.hash(),
                        g: zero(),
                        n: zero(),
                    },
                    initial.clone(),
                )
            }
            _ => {
                let a = self.account(op.target, limits)?;
                let p = if matches!(op.kind, Kind::Start(_)) {
                    ensure(op.target != op.payer && a.pending.is_none())?;
                    a.recovery.ok_or(Invalid)?
                } else {
                    a.owner
                };
                (
                    Row {
                        id: op.target,
                        policy: p.hash(),
                        g: a.g,
                        n: a.n,
                    },
                    p,
                )
            }
        };
        let mut rows = vec![(target, p)];
        if op.payer != op.target {
            let a = self.account(op.payer, limits)?;
            rows.push((
                Row {
                    id: op.payer,
                    policy: a.owner.hash(),
                    g: a.g,
                    n: a.n,
                },
                a.owner,
            ));
        }
        rows.sort_by_key(|(row, _)| row.id);
        Ok(rows)
    }
    /// Complete synthetic account-only fixture invariant; not a real-world
    /// proof that omitted custody namespaces are empty or canonically installed.
    fn validate_fixture(&self, limits: Limits) -> Result<()> {
        ensure(self.accounts.validate() && self.accounting.validate())?;
        let accounting = Accounting::read(&self.accounting, &self.height, limits)?;
        let mut liquid = zero();
        for (id, raw) in self.accounts.entries() {
            let id = id.try_into().map_err(|_| Invalid)?;
            let a = Account::decode(raw, limits)?;
            a.validate_at(id, &self.height)?;
            liquid += a.liquid;
        }
        ensure(
            liquid + accounting.reserve + accounting.pool == accounting.issued - accounting.burned,
        )
    }
    fn apply_batch(&mut self, inputs: &[Vec<u8>], limits: Limits) -> Result<Vec<Hash>> {
        let mut prepared = self.clone();
        let mut ids = Vec::with_capacity(inputs.len());
        for input in inputs {
            ids.push(prepared.apply_one(input, limits)?);
        }
        *self = prepared;
        Ok(ids)
    }
    fn apply_one(&mut self, input: &[u8], limits: Limits) -> Result<Hash> {
        let f = Frame::decode(input, limits)?;
        ensure(f.context == self.context)?;
        let op = &f.operation;
        let expected = self.authorization(op, limits)?;
        ensure(
            f.rows.len() == expected.len()
                && f.rows.iter().zip(&expected).all(|(a, (b, _))| a == b),
        )?;
        let mut r = Reader::new(f.witness, limits)?;
        ensure(r.count(2)? == expected.len())?;
        for (row, p) in &expected {
            p.verify(row.digest(&self.context, f.id), &mut r)?;
        }
        r.end()?;
        if let Some((domain, p)) = op.consent() {
            let digest = hash(
                domain,
                &[&self.context.encode(), &f.id, &op.target, &p.hash()],
            );
            let mut r = Reader::new(f.consent, limits)?;
            p.verify(digest, &mut r)?;
            r.end()?;
        } else {
            ensure(f.consent.is_empty())?;
        }
        let mut changed = BTreeMap::new();
        for (row, _) in &expected {
            let mut a = if row.id == op.target {
                if let Kind::Create {
                    initial,
                    discriminator,
                    funding,
                } = &op.kind
                {
                    Account {
                        initial: initial.clone(),
                        discriminator: *discriminator,
                        owner: initial.clone(),
                        recovery: None,
                        g: zero(),
                        n: zero(),
                        liquid: funding.clone(),
                        credit: (zero(), one()),
                        pending: None,
                    }
                } else {
                    self.account(row.id, limits)?
                }
            } else {
                self.account(row.id, limits)?
            };
            a.n += one();
            changed.insert(row.id, a);
        }
        let mut cost = op.fee.clone();
        if let Kind::Create { funding, .. } = &op.kind {
            cost += funding;
        }
        let payer = changed.get_mut(&op.payer).ok_or(Invalid)?;
        ensure(payer.liquid >= cost)?;
        payer.liquid -= cost;
        let target = changed.get_mut(&op.target).ok_or(Invalid)?;
        match &op.kind {
            Kind::Create { .. } => (),
            Kind::Rotate(p) => {
                target.owner = p.clone();
                target.g += one();
                target.pending = None;
            }
            Kind::Set(p) => {
                target.recovery = Some(p.clone());
                target.g += one();
                target.pending = None;
            }
            Kind::Disable => {
                target.recovery = None;
                target.g += one();
                target.pending = None;
            }
            Kind::Start(p) => {
                target.pending = Some(Pending {
                    operation: f.id,
                    recovery: target.recovery.as_ref().ok_or(Invalid)?.hash(),
                    g: target.g.clone(),
                    owner: p.clone(),
                    source: self.height.clone(),
                });
            }
            Kind::Cancel(id) => {
                ensure(target.pending.as_ref().is_some_and(|p| p.operation == *id))?;
                target.pending = None;
            }
        }
        let mut accounting = Accounting::read(&self.accounting, &self.height, limits)?;
        let reward = &op.fee / 5u32;
        accounting.pool += &reward;
        accounting.burned += &op.fee - reward;
        // All writes target the disposable batch clone. No map handle escapes
        // on a later operation failure, collision, or accounting rejection.
        for a in changed.values() {
            a.validate_at(a.id(), &self.height)?;
            self.put(a)?;
        }
        accounting.write(&mut self.accounting, &self.height)?;
        Ok(f.id)
    }
    /// Measure complete fixture account traversal at one supplied next height.
    /// Returns only an account map: fee settlement, certificates, and complete
    /// height transitions are deliberately absent, so this does not install State.
    fn prepare_due_accounts(&self, next: &BigUint, limits: Limits) -> Result<Map> {
        ensure(*next == &self.height + one())?;
        let next_epoch = epoch(next)?;
        let mut prepared = self.accounts.clone();
        for (id, raw) in self.accounts.entries() {
            let mut a = Account::decode(raw, limits)?;
            let id = id.try_into().map_err(|_| Invalid)?;
            a.validate_at(id, &self.height)?;
            if let Some(p) = &a.pending {
                let activation = epoch(&p.source)? + 2u32;
                ensure(activation >= next_epoch)?;
                if activation == next_epoch {
                    ensure(*next == &activation * 8192u32 + one())?;
                    a.owner = p.owner.clone();
                    a.g += one();
                    a.pending = None;
                    a.validate_at(id, next)?;
                    prepared
                        .insert(id.to_vec(), a.encode())
                        .map_err(|_| Invalid)?;
                }
            }
        }
        Ok(prepared)
    }
}

mod corpus;
pub(super) fn calibrate() {
    corpus::calibrate();
}
#[cfg(test)]
mod tests;
