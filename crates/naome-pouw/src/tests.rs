use super::*;
use sha2::{Digest, Sha256};

fn matrix(rows: usize, cols: usize, values: &[u64], q: u64) -> Matrix {
    Matrix::new(rows, cols, values.to_vec(), q).unwrap()
}

fn limits() -> WorkLimits {
    WorkLimits {
        max_matrix_cells: 4096,
        max_transcript_cells: 32768,
    }
}

struct FixedOracle(Factors);
impl Oracle for FixedOracle {
    fn factors(
        &self,
        _p: Parameters,
        _challenge: &[u8; 32],
        _a: &Matrix,
        _b: &Matrix,
    ) -> Result<Factors> {
        Ok(self.0.clone())
    }
    fn transcript_hash(&self, p: Parameters, transcript: &Transcript) -> Result<[u8; 32]> {
        Ok(Sha256::digest(transcript.encode(p)?).into())
    }
}

fn hand_vector() -> (Parameters, FixedOracle, Matrix, Matrix) {
    let p = Parameters::new(7, 2, 1).unwrap();
    let factors = Factors {
        el: matrix(2, 1, &[1, 2], 7),
        er: matrix(1, 2, &[1, 3], 7),
        fl: matrix(2, 1, &[2, 1], 7),
        fr: matrix(1, 2, &[1, 2], 7),
    };
    (
        p,
        FixedOracle(factors),
        matrix(2, 2, &[1, 2, 3, 4], 7),
        matrix(2, 2, &[5, 6, 0, 1], 7),
    )
}

fn scalar_product(a: &Matrix, b: &Matrix, q: u64) -> Vec<u64> {
    (0..a.rows())
        .flat_map(|i| {
            (0..b.cols()).map(move |j| {
                (0..a.cols())
                    .fold(0u128, |sum, k| {
                        sum + u128::from(a.get(i, k)) * u128::from(b.get(k, j))
                    })
                    .rem_euclid(u128::from(q)) as u64
            })
        })
        .collect()
}

fn scalar_transcript(p: Parameters, a: &Matrix, b: &Matrix) -> Vec<u64> {
    let mut result = Vec::new();
    for i in (0..p.n()).step_by(p.r()) {
        for j in (0..p.n()).step_by(p.r()) {
            for ell in (p.r()..=p.n()).step_by(p.r()) {
                for x in 0..p.r() {
                    for y in 0..p.r() {
                        let value = (0..ell).fold(0u128, |sum, k| {
                            sum + u128::from(a.get(i + x, k)) * u128::from(b.get(k, j + y))
                        });
                        result.push((value % u128::from(p.q())) as u64);
                    }
                }
            }
        }
    }
    result
}

#[test]
fn hand_calculated_paper_vector() {
    let (p, oracle, a, b) = hand_vector();
    let (ap, bp) = encode(p, &oracle.0, &a, &b).unwrap();
    assert_eq!(ap.entries(), &[2, 5, 5, 3]);
    assert_eq!(bp.entries(), &[0, 3, 1, 3]);
    let (cp, transcript) = tiled_product(p, &ap, &bp, limits()).unwrap();
    assert_eq!(cp.entries(), &[5, 0, 3, 3]);
    assert_eq!(transcript.entries(), &[0, 5, 6, 0, 0, 3, 1, 3]);
    let solution = solve(p, &[9; 32], a, b, &oracle, limits()).unwrap();
    assert_eq!(solution.c.entries(), &[5, 1, 1, 1]);
    assert!(verify(p, &[9; 32], &solution, &oracle, limits(), 0).unwrap());
}

#[test]
fn independent_scalar_and_tiled_vectors() {
    let p = Parameters::new(101, 4, 2).unwrap();
    for shift in 0..20 {
        let data = |length: usize, salt: usize| {
            (0..length)
                .map(|i| ((i * 37 + shift * 29 + salt * 13) % 101) as u64)
                .collect::<Vec<_>>()
        };
        let a = matrix(4, 4, &data(16, 0), 101);
        let b = matrix(4, 4, &data(16, 1), 101);
        let factors = Factors {
            el: matrix(4, 2, &data(8, 2), 101),
            er: matrix(2, 4, &data(8, 3), 101),
            fl: matrix(4, 2, &data(8, 4), 101),
            fr: matrix(2, 4, &data(8, 5), 101),
        };
        let oracle = FixedOracle(factors);
        let (ap, bp) = encode(p, &oracle.0, &a, &b).unwrap();
        let (cp, transcript) = tiled_product(p, &ap, &bp, limits()).unwrap();
        assert_eq!(cp.entries(), scalar_product(&ap, &bp, 101));
        assert_eq!(transcript.entries(), scalar_transcript(p, &ap, &bp));
        let solution = solve(
            p,
            &[shift as u8; 32],
            a.clone(),
            b.clone(),
            &oracle,
            limits(),
        )
        .unwrap();
        assert_eq!(solution.c.entries(), scalar_product(&a, &b, 101));
        assert!(verify(p, &[shift as u8; 32], &solution, &oracle, limits(), 0).unwrap());
    }
}

#[test]
fn full_size_tile_and_single_cell_are_valid_parameter_boundaries() {
    for n in [1, 2] {
        let p = Parameters::new(7, n, n).unwrap();
        let cells = n * n;
        let zero = matrix(n, n, &vec![0; cells], 7);
        let a = matrix(n, n, &vec![1; cells], 7);
        let b = matrix(n, n, &vec![2; cells], 7);
        let factors = Factors {
            el: zero.clone(),
            er: zero.clone(),
            fl: zero.clone(),
            fr: zero,
        };
        let oracle = FixedOracle(factors);
        let solution = solve(p, &[7; 32], a, b, &oracle, limits()).unwrap();
        assert_eq!(solution.c.entries(), &vec![(2 * n as u64) % 7; cells]);
        assert!(verify(p, &[7; 32], &solution, &oracle, limits(), 0).unwrap());
    }
}

#[test]
fn tampering_and_strict_threshold_are_rejected() {
    let (p, oracle, a, b) = hand_vector();
    let solution = solve(p, &[9; 32], a, b, &oracle, limits()).unwrap();
    let mut changed = solution.clone();
    changed.proof.z[0] ^= 1;
    assert!(!verify(p, &[9; 32], &changed, &oracle, limits(), 0).unwrap());
    let mut changed = solution.clone();
    changed.c = matrix(2, 2, &[0, 1, 1, 1], 7);
    assert!(!verify(p, &[9; 32], &changed, &oracle, limits(), 0).unwrap());
    let mut changed = solution.clone();
    changed.proof.a = matrix(2, 2, &[2, 2, 3, 4], 7);
    assert!(!verify(p, &[9; 32], &changed, &oracle, limits(), 0).unwrap());
    let mut changed_factors = oracle.0.clone();
    changed_factors.el = matrix(2, 1, &[2, 2], 7);
    assert!(
        !verify(
            p,
            &[9; 32],
            &solution,
            &FixedOracle(changed_factors),
            limits(),
            0
        )
        .unwrap()
    );
    assert!(meets_threshold(&[0; 32], 256).unwrap());
    let mut boundary = [0; 32];
    boundary[31] = 2;
    assert!(meets_threshold(&boundary, 254).unwrap());
    assert!(!meets_threshold(&boundary, 255).unwrap());
    assert!(meets_threshold(&[255; 32], 0).unwrap());
    assert!(meets_threshold(&[0; 32], 257).is_err());
}

#[test]
fn research_oracle_binds_challenge_and_work_even_for_zero_product() {
    let p = Parameters::new(101, 4, 2).unwrap();
    let zero = matrix(4, 4, &[0; 16], 101);
    let oracle = ResearchSha256Oracle;
    let first = solve(p, &[1; 32], zero.clone(), zero.clone(), &oracle, limits()).unwrap();
    // Independent hashlib/Python vector for the v1 parameter and oracle bytes.
    let factors = oracle.factors(p, &[1; 32], &zero, &zero).unwrap();
    assert_eq!(factors.el.entries(), &[92, 0, 63, 62, 84, 38, 68, 58]);
    assert_eq!(factors.er.entries(), &[41, 91, 69, 58, 2, 21, 61, 24]);
    assert_eq!(factors.fl.entries(), &[34, 15, 84, 58, 96, 15, 51, 75]);
    assert_eq!(factors.fr.entries(), &[1, 62, 100, 2, 13, 26, 3, 86]);
    let z_hex = first
        .proof
        .z
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        z_hex,
        "3057dfc7994cf1d1bfff462c4bdd58a0112c514cc09b0c6539649761fd37f5ec"
    );
    let second = solve(p, &[2; 32], zero.clone(), zero.clone(), &oracle, limits()).unwrap();
    assert_eq!(first.c, second.c);
    assert_ne!(first.proof.z, second.proof.z);
    assert!(verify(p, &[1; 32], &first, &oracle, limits(), 0).unwrap());
    assert!(!verify(p, &[2; 32], &first, &oracle, limits(), 0).unwrap());
    // An unchanged ordinary product cannot satisfy a fresh transcript check.
    let mut reused = second;
    reused.proof.z = first.proof.z;
    assert!(!verify(p, &[2; 32], &reused, &oracle, limits(), 0).unwrap());
}

#[test]
fn versioned_solution_codec_rejects_malformed_and_noncanonical_bytes() {
    let (p, oracle, a, b) = hand_vector();
    let solution = solve(p, &[9; 32], a, b, &oracle, limits()).unwrap();
    let encoded = solution.encode(p, limits()).unwrap();
    assert_eq!(&encoded[..5], b"NPMS1");
    assert_eq!(encoded.len(), 154);
    let encoded_hash = Sha256::digest(&encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        encoded_hash,
        "547eac3b8385e9c19b9e970293f7769e936ad735709f904584fe696b258c1770"
    );
    assert_eq!(Solution::decode(&encoded, p, limits()).unwrap(), solution);
    let mut changed = encoded.clone();
    changed[0] ^= 1;
    assert!(Solution::decode(&changed, p, limits()).is_err());
    let mut changed = encoded.clone();
    // First field element begins after the 5-byte solution and 21-byte parameter header.
    changed[33] = 7;
    assert!(Solution::decode(&changed, p, limits()).is_err());
    assert!(Solution::decode(&encoded[..encoded.len() - 1], p, limits()).is_err());
    assert!(Solution::decode(&[encoded.as_slice(), &[0]].concat(), p, limits()).is_err());
    assert!(Solution::decode(&encoded, Parameters::new(11, 2, 1).unwrap(), limits()).is_err());
}

#[test]
fn invalid_parameters_and_resource_limits_fail_closed() {
    for q in [0, 1, 4, 9, u64::MAX] {
        assert!(Parameters::new(q, 4, 2).is_err());
    }
    for (n, r) in [(0, 0), (4, 0), (4, 3), (4, 5)] {
        assert!(Parameters::new(101, n, r).is_err());
    }
    let (p, oracle, a, b) = hand_vector();
    let tiny = WorkLimits {
        max_matrix_cells: 4,
        max_transcript_cells: 7,
    };
    assert!(solve(p, &[0; 32], a, b, &oracle, tiny).is_err());
    assert!(Matrix::new(2, 2, vec![0, 1, 2, 7], 7).is_err());
}

#[test]
#[ignore = "explicit local performance measurement"]
fn measure_reference_prover_and_verifier() {
    use std::time::Instant;
    let oracle = ResearchSha256Oracle;
    for (n, r) in [(32, 4), (128, 8)] {
        let p = Parameters::new(65521, n, r).unwrap();
        let data = |salt: usize| {
            (0..n * n)
                .map(|i| ((i * 43 + salt * 59) % 65521) as u64)
                .collect()
        };
        let a = Matrix::new(n, n, data(1), p.q()).unwrap();
        let b = Matrix::new(n, n, data(2), p.q()).unwrap();
        let budget = WorkLimits {
            max_matrix_cells: n * n,
            max_transcript_cells: n * n * (n / r),
        };
        let mut prover = Vec::new();
        let mut verifier = Vec::new();
        for nonce in 0..10 {
            let challenge = [nonce; 32];
            let start = Instant::now();
            let solution = solve(p, &challenge, a.clone(), b.clone(), &oracle, budget).unwrap();
            prover.push(start.elapsed());
            let start = Instant::now();
            assert!(verify(p, &challenge, &solution, &oracle, budget, 0).unwrap());
            verifier.push(start.elapsed());
        }
        prover.sort();
        verifier.sort();
        println!(
            "n={n} r={r} q=65521; median Solve={:?}; median Verify={:?}",
            prover[5], verifier[5]
        );
    }
}
