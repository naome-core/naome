# Pinned paper implementation checklist

Source: Komargodski and Weinstein, [arXiv:2504.09971v4](https://arxiv.org/pdf/2504.09971v4), §§2, 5, 6.1–6.5. This checklist records the paper's requirements and separates executable algebra from protocol choices the paper leaves open. It does not claim the paper's hardness conjecture is proven.

| Clause | Required behavior | Status in this research path |
| --- | --- | --- |
| §6 opening | Inputs and output are square `n×n` matrices over a finite field `F_q`. | Implemented as parameterized prime `q<2^64`, `n`, and proper divisor `r`; no production parameter set chosen. |
| §6.1, Algorithm 6.1 | `MatMul_r` uses `r×r` tiles and retains every cumulative tile after each inner tile product, indexed by `(i,j,ℓ)`. | Implemented with exact field arithmetic and complete transcript. |
| §6.2, Definition 6.2 | Decode always returns `A·B`; transcript unpredictability is a computational condition. | Completeness tested against an independent scalar product; unpredictability cannot be established by functional tests. |
| §6.3, Algorithm 6.2 | Solve encodes, computes the full `MatMul_r` transcript and product, decodes, and returns `(C, π)` with `π=(A,B,z)` and `z` the transcript. Verify recomputes and compares the full transcript. | Retained in `solve`/`verify` as a literal reference. This printed algorithm does **not** include a transcript hash or threshold and is **not** the selected acceptance rule. |
| §6.5, Algorithm 6.4 | Noise factors `E_L,F_L∈F_q^{n×r}` and `E_R,F_R∈F_q^{r×n}` give `E=E_L E_R`, `F=F_L F_R`; encode adds them, decode subtracts `(A F_L)F_R + E_L(E_R(B+F_L F_R))`. | Implemented with exact arithmetic. The printed Decoder signature omits `A,B` although its body uses them; the reference passes them explicitly. |
| §6.5.1, Lemma 6.5 | Independent uniform factor entries yield rank-`r` noise with the paper's small statistical error from rare rank deficiency. | Implemented entry sampling without rejection, matching the paper's stated distribution; no claim about a deployed entropy source. |
| §2 overview | Oracle derives factors from an unpredictable `σ` bound to `A,B`; `z=O(transcript)` must meet a threshold corresponding to `ε`. | **Selected acceptance interpretation.** `solve_overview`/`verify_overview` model `O(σ,A,B)` and `O(transcript)` through a typed ideal-oracle interface, recompute `z`, and enforce `z < 2^(λ-d)` for a supplied `d=log₂(1/ε)`. This explicitly resolves the discrepancy with §6.3 in favor of §2; the two algorithms are not identical. No concrete hash encoding, oracle instantiation, challenge source, parameter profile, or difficulty schedule has been selected. |
| §5, Definition 5.1 | Verify has constant-factor lower work than Solve; prover overhead approaches zero. | Unverified for this research path. Literal §6.3 Verify repeats encoded multiplication; practical cost and the formal efficiency claim need separate evaluation. |
| §6.5, Assumption 6.4 | No asymptotically faster way to compute all intermediate values for random rank-`r` inputs. | Conjectural in the paper; functional vectors cannot validate it. |
| §7 | A native useful matrix operation can consume the exact decoded product. | Blocked for Gemma: the existing int7 rectangular projection is not native exact Gemma work. No paper-level claim or chain integration. |

The selected §2 rule remains an **oracle-level reference**, not a deployable chain rule. A real implementation still needs the canonical encoding and hash for `O(σ,A,B)` and `O(transcript)`, an unpredictable challenge source, a fixed field/size/rank/security profile, and a difficulty policy. The paper leaves these concrete choices open. It also does not establish compatibility with native Gemma arithmetic or prove Assumption 6.4.

Reproduce the arithmetic and acceptance-boundary tests from the repository root with:

```sh
python3 -m unittest discover -s research/paper_matrix_pouw -p 'test_*.py' -v
```
