use crate::{Error, Result};

pub(crate) fn add(a: u64, b: u64, q: u64) -> u64 {
    ((u128::from(a) + u128::from(b)) % u128::from(q)) as u64
}

pub(crate) fn sub(a: u64, b: u64, q: u64) -> u64 {
    ((u128::from(a) + u128::from(q) - u128::from(b)) % u128::from(q)) as u64
}

pub(crate) fn mul(a: u64, b: u64, q: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) % u128::from(q)) as u64
}

fn pow(mut base: u64, mut exponent: u64, q: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mul(result, base, q);
        }
        exponent >>= 1;
        base = mul(base, base, q);
    }
    result
}

// These bases are deterministic for every unsigned 64-bit integer.
pub(crate) fn is_prime(q: u64) -> bool {
    if q < 2 {
        return false;
    }
    for small in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if q.is_multiple_of(small) {
            return q == small;
        }
    }
    let shifts = (q - 1).trailing_zeros();
    let odd = (q - 1) >> shifts;
    for witness in [2, 325, 9375, 28178, 450775, 9780504, 1795265022] {
        let witness = witness % q;
        if witness == 0 {
            continue;
        }
        let mut value = pow(witness, odd, q);
        if value == 1 || value == q - 1 {
            continue;
        }
        let mut passed = false;
        for _ in 1..shifts {
            value = mul(value, value, q);
            if value == q - 1 {
                passed = true;
                break;
            }
        }
        if !passed {
            return false;
        }
    }
    true
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix {
    rows: usize,
    cols: usize,
    entries: Vec<u64>,
}

impl Matrix {
    pub fn new(rows: usize, cols: usize, entries: Vec<u64>, q: u64) -> Result<Self> {
        if rows == 0 || cols == 0 || rows.checked_mul(cols) != Some(entries.len()) {
            return Err(Error::Invalid("matrix dimensions"));
        }
        if entries.iter().any(|&entry| entry >= q) {
            return Err(Error::Invalid("noncanonical field element"));
        }
        Ok(Self {
            rows,
            cols,
            entries,
        })
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn entries(&self) -> &[u64] {
        &self.entries
    }

    pub(crate) fn get(&self, row: usize, col: usize) -> u64 {
        self.entries[row * self.cols + col]
    }

    pub(crate) fn check(&self, rows: usize, cols: usize, q: u64) -> Result<()> {
        if self.rows != rows || self.cols != cols || self.entries.iter().any(|&x| x >= q) {
            return Err(Error::Invalid("matrix shape or field"));
        }
        Ok(())
    }
}

pub(crate) fn combine(a: &Matrix, b: &Matrix, q: u64, subtract: bool) -> Result<Matrix> {
    if a.rows != b.rows || a.cols != b.cols {
        return Err(Error::Invalid("matrix sum shape"));
    }
    let entries = a
        .entries
        .iter()
        .zip(&b.entries)
        .map(|(&left, &right)| {
            if subtract {
                sub(left, right, q)
            } else {
                add(left, right, q)
            }
        })
        .collect();
    Matrix::new(a.rows, a.cols, entries, q)
}

pub(crate) fn product(a: &Matrix, b: &Matrix, q: u64) -> Result<Matrix> {
    if a.cols != b.rows {
        return Err(Error::Invalid("matrix product shape"));
    }
    let len = a
        .rows
        .checked_mul(b.cols)
        .ok_or(Error::Limit("matrix product size"))?;
    let mut entries = vec![0; len];
    for row in 0..a.rows {
        for inner in 0..a.cols {
            for col in 0..b.cols {
                let index = row * b.cols + col;
                entries[index] = add(
                    entries[index],
                    mul(a.get(row, inner), b.get(inner, col), q),
                    q,
                );
            }
        }
    }
    Matrix::new(a.rows, b.cols, entries, q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prime_and_wide_arithmetic_boundaries() {
        for q in [2, 3, 7, 101, 65521, 18446744073709551557] {
            assert!(is_prime(q));
        }
        for q in [0, 1, 4, 9, 341, u64::MAX] {
            assert!(!is_prime(q));
        }
        let q = 18446744073709551557;
        assert_eq!(add(q - 1, q - 1, q), q - 2);
        assert_eq!(sub(0, 1, q), q - 1);
        assert_eq!(mul(q - 1, q - 1, q), 1);
    }
}
