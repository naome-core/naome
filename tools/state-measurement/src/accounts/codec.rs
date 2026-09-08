//! Corpus-bounded slice codec. These limits are not protocol allowances.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub input: usize,
    pub natural: usize,
    pub keys: usize,
}
pub(super) const CORPUS: Limits = Limits {
    input: 1 << 20,
    natural: 512,
    keys: 64,
};
pub(super) struct Reader<'a> {
    rest: &'a [u8],
    limits: Limits,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], limits: Limits) -> Result<Self> {
        ensure(bytes.len() <= limits.input)?;
        Ok(Self {
            rest: bytes,
            limits,
        })
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure(n <= self.rest.len())?;
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Invalid)
    }
    pub fn tag(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }
    pub fn nat(&mut self) -> Result<BigUint> {
        let mut len = 0usize;
        for index in 0..usize::BITS.div_ceil(7) as usize {
            let byte = self.tag()?;
            let group = usize::from(byte & 127);
            let shift = index * 7;
            ensure(group <= usize::MAX >> shift)?;
            len |= group << shift;
            ensure(len <= self.limits.natural)?;
            if byte & 128 == 0 {
                ensure(index == 0 || group != 0)?;
                let bytes = self.take(len)?;
                ensure(bytes.first() != Some(&0))?;
                return Ok(BigUint::from_bytes_be(bytes));
            }
        }
        Err(Invalid)
    }
    pub fn count(&mut self, max: usize) -> Result<usize> {
        let n = usize::try_from(self.nat()?).map_err(|_| Invalid)?;
        ensure(n <= max)?;
        Ok(n)
    }
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.count(self.limits.input)?;
        self.take(n)
    }
    pub fn policy(&mut self) -> Result<Policy> {
        Policy::decode(self.bytes()?, self.limits)
    }
    pub fn end(self) -> Result<()> {
        ensure(self.rest.is_empty())
    }
}
pub(super) fn nat(out: &mut Vec<u8>, n: &BigUint) {
    out.extend(crate::numbers::encode_length_be(n));
}
pub(super) fn count(out: &mut Vec<u8>, n: usize) {
    nat(out, &BigUint::from(n));
}
pub(super) fn bytes(out: &mut Vec<u8>, b: &[u8]) {
    count(out, b.len());
    out.extend(b);
}
pub(super) fn policy(out: &mut Vec<u8>, p: &Policy) {
    bytes(out, &p.encode());
}

impl Policy {
    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self> {
        let mut r = Reader::new(bytes, limits)?;
        let threshold = r.count(limits.keys)?;
        let n = r.count(limits.keys)?;
        ensure(threshold > 0 && threshold <= n)?;
        // Check the complete fixed-width key span before allocating.
        ensure(n.checked_mul(32).is_some_and(|len| len <= r.rest.len()))?;
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n {
            let raw = r.fixed()?;
            ensure(
                keys.last()
                    .is_none_or(|previous: &VerifyingKey| previous.to_bytes() < raw),
            )?;
            let point = CompressedEdwardsY(raw).decompress().ok_or(Invalid)?;
            ensure(
                point.compress().to_bytes() == raw
                    && !point.is_identity()
                    && point.is_torsion_free(),
            )?;
            keys.push(VerifyingKey::from_bytes(&raw).map_err(|_| Invalid)?);
        }
        r.end()?;
        Ok(Self { threshold, keys })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        count(&mut out, self.threshold);
        count(&mut out, self.keys.len());
        for key in &self.keys {
            out.extend(key.to_bytes());
        }
        out
    }
}
impl Account {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        policy(&mut out, &self.initial);
        out.extend(self.discriminator);
        policy(&mut out, &self.owner);
        out.push(u8::from(self.recovery.is_some()));
        if let Some(p) = &self.recovery {
            policy(&mut out, p);
        }
        for n in [
            &self.g,
            &self.n,
            &self.liquid,
            &self.credit.0,
            &self.credit.1,
        ] {
            nat(&mut out, n);
        }
        out.push(u8::from(self.pending.is_some()));
        if let Some(p) = &self.pending {
            out.extend(p.operation);
            out.extend(p.recovery);
            nat(&mut out, &p.g);
            policy(&mut out, &p.owner);
            nat(&mut out, &p.source);
        }
        out
    }
    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self> {
        let mut r = Reader::new(bytes, limits)?;
        let initial = r.policy()?;
        let discriminator = r.fixed()?;
        let owner = r.policy()?;
        let recovery = match r.tag()? {
            0 => None,
            1 => Some(r.policy()?),
            _ => return Err(Invalid),
        };
        let g = r.nat()?;
        let n = r.nat()?;
        let liquid = r.nat()?;
        let credit = (r.nat()?, r.nat()?);
        ensure(credit.1 != zero())?;
        let (mut a, mut b) = credit.clone();
        while b != zero() {
            let rem = &a % &b;
            a = b;
            b = rem;
        }
        ensure(a == one())?;
        let pending = match r.tag()? {
            0 => None,
            1 => Some(Pending {
                operation: r.fixed()?,
                recovery: r.fixed()?,
                g: r.nat()?,
                owner: r.policy()?,
                source: r.nat()?,
            }),
            _ => return Err(Invalid),
        };
        r.end()?;
        Ok(Self {
            initial,
            discriminator,
            owner,
            recovery,
            g,
            n,
            liquid,
            credit,
            pending,
        })
    }
}
