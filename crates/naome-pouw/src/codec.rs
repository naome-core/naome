use crate::{Error, Matrix, Parameters, Proof, Result, Solution, Transcript, WorkLimits};

const PARAMETERS_MAGIC: &[u8; 5] = b"NPMP1";
const TRANSCRIPT_MAGIC: &[u8; 5] = b"NPMT1";
const SOLUTION_MAGIC: &[u8; 5] = b"NPMS1";

pub(crate) fn parameter_bytes(p: Parameters) -> Vec<u8> {
    let mut out = Vec::with_capacity(21);
    out.extend_from_slice(PARAMETERS_MAGIC);
    out.extend_from_slice(&p.q().to_be_bytes());
    out.extend_from_slice(&(p.n() as u32).to_be_bytes());
    out.extend_from_slice(&(p.r() as u32).to_be_bytes());
    out
}

fn matrix_bytes(out: &mut Vec<u8>, matrix: &Matrix) {
    for &entry in matrix.entries() {
        out.extend_from_slice(&entry.to_be_bytes());
    }
}

pub(crate) fn encode_transcript(p: Parameters, transcript: &Transcript) -> Result<Vec<u8>> {
    let count = p.n() * p.n() * (p.n() / p.r());
    if transcript.entries.len() != count || transcript.entries.iter().any(|&x| x >= p.q()) {
        return Err(Error::Invalid("transcript shape or field"));
    }
    let capacity = 5usize
        .checked_add(21)
        .and_then(|length| length.checked_add(8))
        .and_then(|length| length.checked_add(count.checked_mul(8)?))
        .ok_or(Error::Limit("transcript byte size"))?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(TRANSCRIPT_MAGIC);
    out.extend_from_slice(&parameter_bytes(p));
    out.extend_from_slice(&(count as u64).to_be_bytes());
    for &entry in &transcript.entries {
        out.extend_from_slice(&entry.to_be_bytes());
    }
    Ok(out)
}

pub(crate) fn encode_solution(
    solution: &Solution,
    p: Parameters,
    limits: WorkLimits,
) -> Result<Vec<u8>> {
    p.check_limits(limits)?;
    for matrix in [&solution.proof.a, &solution.proof.b, &solution.c] {
        matrix.check(p.n(), p.n(), p.q())?;
    }
    let capacity = 5usize
        .checked_add(21)
        .and_then(|length| length.checked_add(3usize.checked_mul(p.n() * p.n())?.checked_mul(8)?))
        .and_then(|length| length.checked_add(32))
        .ok_or(Error::Limit("solution byte size"))?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(SOLUTION_MAGIC);
    out.extend_from_slice(&parameter_bytes(p));
    matrix_bytes(&mut out, &solution.proof.a);
    matrix_bytes(&mut out, &solution.proof.b);
    matrix_bytes(&mut out, &solution.c);
    out.extend_from_slice(&solution.proof.z);
    Ok(out)
}

pub(crate) fn decode_solution(bytes: &[u8], p: Parameters, limits: WorkLimits) -> Result<Solution> {
    p.check_limits(limits)?;
    let cells = p.n() * p.n();
    let expected = 5usize
        .checked_add(21)
        .and_then(|length| length.checked_add(3usize.checked_mul(cells)?.checked_mul(8)?))
        .and_then(|length| length.checked_add(32))
        .ok_or(Error::Limit("solution byte size"))?;
    if bytes.len() != expected
        || &bytes[..5] != SOLUTION_MAGIC
        || bytes[5..26] != parameter_bytes(p)
    {
        return Err(Error::Invalid("solution framing or parameters"));
    }
    let mut offset = 26;
    let mut read_matrix = || -> Result<Matrix> {
        let mut entries = Vec::with_capacity(cells);
        for _ in 0..cells {
            let next = offset + 8;
            let entry = u64::from_be_bytes(bytes[offset..next].try_into().expect("checked length"));
            entries.push(entry);
            offset = next;
        }
        Matrix::new(p.n(), p.n(), entries, p.q())
    };
    let a = read_matrix()?;
    let b = read_matrix()?;
    let c = read_matrix()?;
    let z = bytes[offset..offset + 32]
        .try_into()
        .expect("checked length");
    Ok(Solution {
        c,
        proof: Proof { a, b, z },
    })
}
