//! Parameterized research implementation of the matrix PoUW in
//! Komargodski–Weinstein, arXiv:2504.09971v4, §§2 and 6.1–6.5.
//!
//! This crate has no chain authority. A caller must select a public parameter
//! profile, supply an unpredictable challenge, and define difficulty policy.
//! The SHA-256 oracle below is a reproducible concrete research candidate for
//! the paper's ideal random oracle; it is not a proof of Assumption 6.4.

mod codec;
mod field;
mod oracle;

pub use field::Matrix;
use field::{add, combine, is_prime, mul, product};
pub use oracle::ResearchSha256Oracle;
use std::{error::Error as StdError, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Limit(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::Limit(message) => f.write_str(message),
        }
    }
}
impl StdError for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Algebra parameters, not an adopted NAOME consensus profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    q: u64,
    n: usize,
    r: usize,
}
impl Parameters {
    pub fn new(q: u64, n: usize, r: usize) -> Result<Self> {
        if !is_prime(q) {
            return Err(Error::Invalid("q must be prime"));
        }
        if n == 0 || n > u32::MAX as usize || r == 0 || r > n || !n.is_multiple_of(r) {
            return Err(Error::Invalid("n and r must form square tiles"));
        }
        n.checked_mul(n)
            .and_then(|cells| cells.checked_mul(n / r))
            .ok_or(Error::Limit("transcript size overflow"))?;
        Ok(Self { q, n, r })
    }
    pub fn q(self) -> u64 {
        self.q
    }
    pub fn n(self) -> usize {
        self.n
    }
    pub fn r(self) -> usize {
        self.r
    }

    fn check_limits(self, limits: WorkLimits) -> Result<()> {
        let cells = self.n * self.n;
        let transcript = cells * (self.n / self.r);
        if cells > limits.max_matrix_cells || transcript > limits.max_transcript_cells {
            return Err(Error::Limit("matrix or transcript cell budget"));
        }
        Ok(())
    }
}

/// Caller supplied resource bounds. These are not difficulty or security parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkLimits {
    pub max_matrix_cells: usize,
    pub max_transcript_cells: usize,
}

/// Four independently sampled factors for E=E_L E_R and F=F_L F_R (§6.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Factors {
    pub el: Matrix,
    pub er: Matrix,
    pub fl: Matrix,
    pub fr: Matrix,
}
impl Factors {
    fn check(&self, p: Parameters) -> Result<()> {
        self.el.check(p.n, p.r, p.q)?;
        self.er.check(p.r, p.n, p.q)?;
        self.fl.check(p.n, p.r, p.q)?;
        self.fr.check(p.r, p.n, p.q)
    }
}

/// All cumulative r×r tiles in lexicographic (i,j,ell,x,y) order (§6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    entries: Vec<u64>,
}
impl Transcript {
    pub fn entries(&self) -> &[u64] {
        &self.entries
    }
    pub fn encode(&self, p: Parameters) -> Result<Vec<u8>> {
        codec::encode_transcript(p, self)
    }
}

/// Model for O(sigma,A,B) and O(transcript). The oracle must be deterministic
/// for verification; challenge freshness is an external protocol obligation.
pub trait Oracle {
    fn factors(
        &self,
        p: Parameters,
        challenge: &[u8; 32],
        a: &Matrix,
        b: &Matrix,
    ) -> Result<Factors>;
    fn transcript_hash(&self, p: Parameters, transcript: &Transcript) -> Result<[u8; 32]>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub a: Matrix,
    pub b: Matrix,
    pub z: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Solution {
    pub c: Matrix,
    pub proof: Proof,
}
impl Solution {
    /// Research v1 framing. Decoding these bytes never grants block authority.
    pub fn encode(&self, p: Parameters, limits: WorkLimits) -> Result<Vec<u8>> {
        codec::encode_solution(self, p, limits)
    }
    pub fn decode(bytes: &[u8], p: Parameters, limits: WorkLimits) -> Result<Self> {
        codec::decode_solution(bytes, p, limits)
    }
}

fn check_inputs(p: Parameters, a: &Matrix, b: &Matrix, limits: WorkLimits) -> Result<()> {
    p.check_limits(limits)?;
    a.check(p.n, p.n, p.q)?;
    b.check(p.n, p.n, p.q)
}

/// Algorithm 6.4 Encode, with factors supplied by the oracle boundary.
pub fn encode(
    p: Parameters,
    factors: &Factors,
    a: &Matrix,
    b: &Matrix,
) -> Result<(Matrix, Matrix)> {
    factors.check(p)?;
    a.check(p.n, p.n, p.q)?;
    b.check(p.n, p.n, p.q)?;
    let e = product(&factors.el, &factors.er, p.q)?;
    let f = product(&factors.fl, &factors.fr, p.q)?;
    Ok((combine(a, &e, p.q, false)?, combine(b, &f, p.q, false)?))
}

/// Algorithm 6.1 MatMul_r: retain each cumulative tile, not only final C'.
pub fn tiled_product(
    p: Parameters,
    a: &Matrix,
    b: &Matrix,
    limits: WorkLimits,
) -> Result<(Matrix, Transcript)> {
    check_inputs(p, a, b, limits)?;
    let blocks = p.n / p.r;
    let mut output = vec![0; p.n * p.n];
    let mut entries = Vec::with_capacity(p.n * p.n * blocks);
    for i in 0..blocks {
        for j in 0..blocks {
            let mut partial = vec![0; p.r * p.r];
            for ell in 0..blocks {
                for x in 0..p.r {
                    for y in 0..p.r {
                        let index = x * p.r + y;
                        for t in 0..p.r {
                            partial[index] = add(
                                partial[index],
                                mul(
                                    a.get(i * p.r + x, ell * p.r + t),
                                    b.get(ell * p.r + t, j * p.r + y),
                                    p.q,
                                ),
                                p.q,
                            );
                        }
                    }
                }
                entries.extend_from_slice(&partial);
            }
            for x in 0..p.r {
                for y in 0..p.r {
                    output[(i * p.r + x) * p.n + j * p.r + y] = partial[x * p.r + y];
                }
            }
        }
    }
    Ok((Matrix::new(p.n, p.n, output, p.q)?, Transcript { entries }))
}

/// Algorithm 6.4 Decode. A and B are explicit because the printed body uses
/// them even though the paper abbreviates the Decode signature.
pub fn decode(
    p: Parameters,
    factors: &Factors,
    a: &Matrix,
    b: &Matrix,
    c_prime: &Matrix,
) -> Result<Matrix> {
    factors.check(p)?;
    for matrix in [a, b, c_prime] {
        matrix.check(p.n, p.n, p.q)?;
    }
    let f = product(&factors.fl, &factors.fr, p.q)?;
    let af = product(&product(a, &factors.fl, p.q)?, &factors.fr, p.q)?;
    let ebf = product(
        &factors.el,
        &product(&factors.er, &combine(b, &f, p.q, false)?, p.q)?,
        p.q,
    )?;
    combine(&combine(c_prime, &af, p.q, true)?, &ebf, p.q, true)
}

/// §2 Solve: z=O(complete transcript). A chain must still decide whether this
/// attempt meets its difficulty threshold; this function performs the work.
pub fn solve<O: Oracle>(
    p: Parameters,
    challenge: &[u8; 32],
    a: Matrix,
    b: Matrix,
    oracle: &O,
    limits: WorkLimits,
) -> Result<Solution> {
    check_inputs(p, &a, &b, limits)?;
    let factors = oracle.factors(p, challenge, &a, &b)?;
    let (a_prime, b_prime) = encode(p, &factors, &a, &b)?;
    let (c_prime, transcript) = tiled_product(p, &a_prime, &b_prime, limits)?;
    let c = decode(p, &factors, &a, &b, &c_prime)?;
    let z = oracle.transcript_hash(p, &transcript)?;
    Ok(Solution {
        c,
        proof: Proof { a, b, z },
    })
}

/// The §2 strict threshold z < 2^(256-d), where epsilon = 2^-d.
pub fn meets_threshold(z: &[u8; 32], difficulty_bits: u16) -> Result<bool> {
    if difficulty_bits > 256 {
        return Err(Error::Invalid("difficulty bits"));
    }
    let whole = usize::from(difficulty_bits / 8);
    let rest = difficulty_bits % 8;
    if z[..whole].iter().any(|&byte| byte != 0) {
        return Ok(false);
    }
    Ok(rest == 0 || z[whole] >> (8 - rest) == 0)
}

/// Independently recompute every tile and decoded product before checking the
/// §2 transcript hash and threshold. This is not a cheap verifier or a SNARK.
pub fn verify<O: Oracle>(
    p: Parameters,
    challenge: &[u8; 32],
    solution: &Solution,
    oracle: &O,
    limits: WorkLimits,
    difficulty_bits: u16,
) -> Result<bool> {
    check_inputs(p, &solution.proof.a, &solution.proof.b, limits)?;
    solution.c.check(p.n, p.n, p.q)?;
    if !meets_threshold(&solution.proof.z, difficulty_bits)? {
        return Ok(false);
    }
    let factors = oracle.factors(p, challenge, &solution.proof.a, &solution.proof.b)?;
    let (a_prime, b_prime) = encode(p, &factors, &solution.proof.a, &solution.proof.b)?;
    let (c_prime, transcript) = tiled_product(p, &a_prime, &b_prime, limits)?;
    let expected_c = decode(p, &factors, &solution.proof.a, &solution.proof.b, &c_prime)?;
    Ok(solution.c == expected_c && solution.proof.z == oracle.transcript_hash(p, &transcript)?)
}

#[cfg(test)]
mod tests;
