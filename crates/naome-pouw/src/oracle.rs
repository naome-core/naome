use crate::{Error, Factors, Matrix, Oracle, Parameters, Result, Transcript, codec};
use sha2::{Digest, Sha256};

const FACTOR_DOMAIN: &[u8] = b"naome:research:pouw:factor:v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"naome:research:pouw:transcript:v1\0";

/// Reproducible research instantiation of the paper's ideal oracle. It does
/// not define NAOME's challenge source, network profile, or difficulty policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResearchSha256Oracle;

fn digest(hasher: Sha256) -> [u8; 32] {
    hasher.finalize().into()
}

fn sample(root: &[u8; 32], factor: u8, rows: usize, cols: usize, q: u64) -> Result<Matrix> {
    let count = rows
        .checked_mul(cols)
        .ok_or(Error::Limit("factor dimensions"))?;
    let mut entries = Vec::with_capacity(count);
    // Rejection sampling avoids modulo bias, including when q is near 2^64.
    let range = 1u128 << 64;
    let bound = range - range % u128::from(q);
    let mut counter = 0u64;
    while entries.len() < count {
        let mut hasher = Sha256::new();
        hasher.update(FACTOR_DOMAIN);
        hasher.update(root);
        hasher.update([factor]);
        hasher.update(counter.to_be_bytes());
        let bytes = digest(hasher);
        let value = u64::from_be_bytes(bytes[..8].try_into().expect("digest width"));
        if u128::from(value) < bound {
            entries.push(value % q);
        }
        counter = counter
            .checked_add(1)
            .ok_or(Error::Limit("oracle counter"))?;
    }
    Matrix::new(rows, cols, entries, q)
}

impl Oracle for ResearchSha256Oracle {
    fn factors(
        &self,
        p: Parameters,
        challenge: &[u8; 32],
        a: &Matrix,
        b: &Matrix,
    ) -> Result<Factors> {
        a.check(p.n(), p.n(), p.q())?;
        b.check(p.n(), p.n(), p.q())?;
        let mut hasher = Sha256::new();
        hasher.update(FACTOR_DOMAIN);
        hasher.update(codec::parameter_bytes(p));
        hasher.update(challenge);
        for matrix in [a, b] {
            for &entry in matrix.entries() {
                hasher.update(entry.to_be_bytes());
            }
        }
        let root = digest(hasher);
        let factors = Factors {
            el: sample(&root, 0, p.n(), p.r(), p.q())?,
            er: sample(&root, 1, p.r(), p.n(), p.q())?,
            fl: sample(&root, 2, p.n(), p.r(), p.q())?,
            fr: sample(&root, 3, p.r(), p.n(), p.q())?,
        };
        Ok(factors)
    }

    fn transcript_hash(&self, p: Parameters, transcript: &Transcript) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(TRANSCRIPT_DOMAIN);
        hasher.update(transcript.encode(p)?);
        Ok(digest(hasher))
    }
}
