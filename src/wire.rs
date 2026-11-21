use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

pub const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 48;
const MAX_TERMS: usize = 500_000;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, clap::ValueEnum)]
pub enum Format {
    A,
    B,
}
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Id {
    suite: u8,
    class: u8,
    digest: [u8; 32],
}

impl Id {
    fn new(suite: u8, class: u8, tag: &[u8], bytes: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(tag);
        hash.update([0]);
        hash.update(bytes);
        Self {
            suite,
            class,
            digest: hash.finalize().into(),
        }
    }
    pub fn record(f: Format, bytes: &[u8]) -> Self {
        match f {
            Format::A => Self::new(1, 0, b"REP-record", bytes),
            Format::B => Self::new(2, 0, b"REP-json-record", bytes),
        }
    }
    pub fn blob(bytes: &[u8]) -> Self {
        Self::new(1, 1, b"REP-blob", bytes)
    }
    pub fn format(self) -> Option<Format> {
        match (self.suite, self.class) {
            (1, 0) => Some(Format::A),
            (2, 0) => Some(Format::B),
            _ => None,
        }
    }
    pub fn verify(self, bytes: &[u8]) -> Result<()> {
        let actual = self
            .format()
            .map_or_else(|| Self::blob(bytes), |f| Self::record(f, bytes));
        ensure!(actual == self, "identity mismatch for {self}");
        Ok(())
    }
    fn term(self) -> Term {
        Term::Array(vec![
            Term::Uint(self.suite.into()),
            Term::Uint(self.class.into()),
            Term::Bytes(self.digest.to_vec()),
        ])
    }
    fn read(t: &Term) -> Result<Self> {
        let [Term::Uint(s), Term::Uint(c), Term::Bytes(d)] = t.array()? else {
            bail!("invalid reference")
        };
        ensure!(
            matches!((s, c), (1, 0) | (2, 0) | (1, 1)),
            "unknown reference suite or class"
        );
        Ok(Self {
            suite: *s as u8,
            class: *c as u8,
            digest: d.as_slice().try_into().context("invalid digest length")?,
        })
    }
}
impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.suite,
            self.class,
            hex::encode(self.digest)
        )
    }
}
impl FromStr for Id {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split(':');
        let suite = parts.next().context("missing suite")?.parse()?;
        let class = parts.next().context("missing class")?.parse()?;
        let d = hex::decode(parts.next().context("missing digest")?)?;
        let id = Self::read(&Term::Array(vec![
            Term::Uint(suite),
            Term::Uint(class),
            Term::Bytes(d),
        ]))?;
        ensure!(id.to_string() == s, "noncanonical identifier");
        Ok(id)
    }
}
impl Serialize for Id {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Term {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Term>),
}
impl Term {
    fn array(&self) -> Result<&[Term]> {
        if let Self::Array(x) = self {
            Ok(x)
        } else {
            bail!("expected array")
        }
    }
    fn uint(&self) -> Result<u64> {
        if let Self::Uint(x) = self {
            Ok(*x)
        } else {
            bail!("expected uint")
        }
    }
    fn tagged(&self) -> Value {
        use serde_json::json;
        match self {
            Self::Uint(n) => json!(["u", n.to_string()]),
            Self::Text(t) => json!(["t", t]),
            Self::Bytes(b) => json!(["b", hex::encode(b)]),
            Self::Array(a) => Value::Array(
                std::iter::once(Value::from("a"))
                    .chain(a.iter().map(Self::tagged))
                    .collect(),
            ),
        }
    }
    fn from_tagged(v: &Value, depth: usize, left: &mut usize) -> Result<Self> {
        charge(depth, left)?;
        let arr = v.as_array().context("expected tagged array")?;
        let (tag, tail) = arr.split_first().context("missing tag")?;
        if tag == "a" {
            return Ok(Self::Array(
                tail.iter()
                    .map(|x| Self::from_tagged(x, depth + 1, left))
                    .collect::<Result<_>>()?,
            ));
        }
        let [Value::String(value)] = tail else {
            bail!("invalid scalar")
        };
        match tag.as_str() {
            Some("u") => Ok(Self::Uint(value.parse()?)),
            Some("b") => Ok(Self::Bytes(hex::decode(value)?)),
            Some("t") => Ok(Self::Text(value.clone())),
            _ => bail!("unknown tag"),
        }
    }
    fn cbor(&self, out: &mut Vec<u8>) {
        match self {
            Self::Uint(n) => header(0, *n, out),
            Self::Bytes(b) => {
                header(2, b.len() as u64, out);
                out.extend(b)
            }
            Self::Text(t) => {
                header(3, t.len() as u64, out);
                out.extend(t.as_bytes())
            }
            Self::Array(a) => {
                header(4, a.len() as u64, out);
                for t in a {
                    t.cbor(out)
                }
            }
        }
    }
    pub fn encode(&self, f: Format) -> Vec<u8> {
        match f {
            Format::A => {
                let mut out = Vec::new();
                self.cbor(&mut out);
                out
            }
            Format::B => serde_json::to_vec(&self.tagged()).expect("serializable term"),
        }
    }
    pub fn decode(bytes: &[u8], f: Format) -> Result<Self> {
        ensure!(bytes.len() <= MAX_BYTES, "byte budget exhausted");
        let mut left = MAX_TERMS;
        let term = match f {
            Format::A => {
                let mut input = bytes;
                let t = read_cbor(&mut input, 0, &mut left)?;
                ensure!(input.is_empty(), "trailing bytes");
                t
            }
            Format::B => {
                check_json_budget(bytes)?;
                Self::from_tagged(&serde_json::from_slice(bytes)?, 0, &mut left)?
            }
        };
        ensure!(term.encode(f) == bytes, "noncanonical encoding");
        Ok(term)
    }
}
// Count structural nesting before allocating a generic JSON tree. Brackets inside text are data.
fn check_json_budget(bytes: &[u8]) -> Result<()> {
    let mut depth = 0usize;
    let mut arrays = 0;
    let mut quoted = false;
    let mut escaped = false;
    for &b in bytes {
        if quoted {
            if escaped {
                escaped = false
            } else if b == 92 {
                escaped = true
            } else if b == 34 {
                quoted = false
            }
            continue;
        }
        match b {
            34 => quoted = true,
            b'[' | b'{' => {
                depth += 1;
                arrays += 1;
                ensure!(
                    depth <= MAX_DEPTH + 1 && arrays <= MAX_TERMS,
                    "decoder budget exhausted"
                )
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => (),
        }
    }
    Ok(())
}
fn charge(depth: usize, left: &mut usize) -> Result<()> {
    ensure!(depth <= MAX_DEPTH && *left > 0, "decoder budget exhausted");
    *left -= 1;
    Ok(())
}
fn header(major: u8, n: u64, out: &mut Vec<u8>) {
    let tag = major << 5;
    match n {
        0..=23 => out.push(tag | n as u8),
        24..=255 => out.extend([tag | 24, n as u8]),
        256..=65535 => {
            out.push(tag | 25);
            out.extend((n as u16).to_be_bytes())
        }
        65536..=4294967295 => {
            out.push(tag | 26);
            out.extend((n as u32).to_be_bytes())
        }
        _ => {
            out.push(tag | 27);
            out.extend(n.to_be_bytes())
        }
    }
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    let (a, b) = input.split_at_checked(n).context("truncated CBOR")?;
    *input = b;
    Ok(a)
}
fn read_cbor(input: &mut &[u8], depth: usize, left: &mut usize) -> Result<Term> {
    charge(depth, left)?;
    let tag = take(input, 1)?[0];
    let n = match tag & 31 {
        v @ 0..=23 => u64::from(v),
        v @ 24..=27 => {
            let mut buf = [0; 8];
            let count = 1usize << (v - 24);
            buf[8 - count..].copy_from_slice(take(input, count)?);
            u64::from_be_bytes(buf)
        }
        _ => bail!("invalid length"),
    };
    if tag >> 5 == 0 {
        return Ok(Term::Uint(n));
    }
    let len = usize::try_from(n)?;
    match tag >> 5 {
        2 => Ok(Term::Bytes(take(input, len)?.to_vec())),
        3 => Ok(Term::Text(std::str::from_utf8(take(input, len)?)?.into())),
        4 => {
            ensure!(len <= input.len(), "truncated array");
            ensure!(len <= *left, "decoder budget exhausted");
            Ok(Term::Array(
                (0..len)
                    .map(|_| read_cbor(input, depth + 1, left))
                    .collect::<Result<_>>()?,
            ))
        }
        _ => bail!("unknown CBOR type"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    pub role: u64,
    pub target: Id,
    pub qualifier: Term,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub kind: u64,
    pub profile: Id,
    pub body: Term,
    pub edges: Vec<Edge>,
    pub access: Id,
    pub critical: Vec<u64>,
}
impl Record {
    pub fn encode(&self, f: Format) -> Vec<u8> {
        Term::Array(vec![
            Term::Uint(self.kind),
            self.profile.term(),
            self.body.clone(),
            Term::Array(
                self.edges
                    .iter()
                    .map(|e| {
                        Term::Array(vec![
                            Term::Uint(e.role),
                            e.target.term(),
                            e.qualifier.clone(),
                        ])
                    })
                    .collect(),
            ),
            self.access.term(),
            Term::Array(self.critical.iter().map(|x| Term::Uint(*x)).collect()),
        ])
        .encode(f)
    }
    pub fn decode(bytes: &[u8], f: Format) -> Result<Self> {
        let t = Term::decode(bytes, f)?;
        let [kind, p, body, edges, a, x] = t.array()? else {
            bail!("invalid envelope")
        };
        let critical = x
            .array()?
            .iter()
            .map(Term::uint)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            critical.windows(2).all(|w| w[0] < w[1]),
            "unordered critical extensions"
        );
        let edges = edges
            .array()?
            .iter()
            .map(|t| {
                let [k, r, q] = t.array()? else {
                    bail!("invalid edge")
                };
                Ok(Edge {
                    role: k.uint()?,
                    target: Id::read(r)?,
                    qualifier: q.clone(),
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            kind: kind.uint()?,
            profile: Id::read(p)?,
            body: body.clone(),
            edges,
            access: Id::read(a)?,
            critical,
        })
    }
    pub fn inputs(&self) -> impl Iterator<Item = Id> + '_ {
        std::iter::once(self.profile)
            .chain(std::iter::once(self.access))
            .chain(self.edges.iter().map(|e| e.target))
    }
}
