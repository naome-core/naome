"""Oracle-level reference for §§2, 6.1, 6.3, and 6.5 of arXiv:2504.09971v4.

The section 2 hash-and-threshold rule is modeled with an abstract random
oracle. No concrete hash encoding, challenge source, or parameter profile is
selected here. The literal section 6.3 full-transcript variant is retained
separately because Algorithm 6.2 prints a different proof/Verify rule.
"""

from dataclasses import dataclass
import secrets
from typing import Callable, Protocol


Matrix = tuple[tuple[int, ...], ...]
Transcript = tuple[Matrix, ...]  # (i, j, ell) in lexicographic order


def _prime(q: int) -> bool:
    """Deterministic Miller-Rabin for the supported 64-bit prime field sizes."""
    if not isinstance(q, int) or isinstance(q, bool) or q < 2 or q >= 1 << 64:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if q % p == 0:
            return q == p
    d, s = q - 1, 0
    while d & 1 == 0:
        d >>= 1
        s += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        base %= q
        if base == 0:
            continue
        x = pow(base, d, q)
        if x in (1, q - 1):
            continue
        for _ in range(s - 1):
            x = x * x % q
            if x == q - 1:
                break
        else:
            return False
    return True


@dataclass(frozen=True)
class Parameters:
    q: int
    n: int
    r: int

    def __post_init__(self) -> None:
        if not _prime(self.q):
            raise ValueError("q must be a prime smaller than 2^64")
        if not isinstance(self.n, int) or isinstance(self.n, bool) or self.n < 2:
            raise ValueError("n must be at least two")
        if not isinstance(self.r, int) or isinstance(self.r, bool) or not 0 < self.r < self.n or self.n % self.r:
            raise ValueError("r must be a proper positive divisor of n")


@dataclass(frozen=True)
class Sigma:
    # Algorithm 6.4 parses sigma into these four matrices. Sampling is external
    # to Solve, preserving the paper's fresh-challenge assumption as a boundary.
    el: Matrix  # n × r
    er: Matrix  # r × n
    fl: Matrix  # n × r
    fr: Matrix  # r × n


@dataclass(frozen=True)
class Proof:
    a: Matrix
    b: Matrix
    z: Transcript  # Algorithm 6.2: z is the entire transcript, not its hash


@dataclass(frozen=True)
class OverviewProof:
    a: Matrix
    b: Matrix
    z: int  # §2: oracle value of the complete transcript, in [0, 2^lambda)


class RandomOracle(Protocol):
    """The ideal oracle operations in §2; no wire encoding is implied."""

    def factors(self, p: Parameters, challenge: int, a: Matrix, b: Matrix) -> Sigma:
        """Derive the four independent uniform factors from O(sigma, A, B)."""

    def transcript_value(self, p: Parameters, transcript: Transcript, lambda_bits: int) -> int:
        """Return O(transcript) as a uniform lambda-bit integer."""


def _check(m: Matrix, rows: int, cols: int, q: int) -> None:
    if not isinstance(m, tuple) or len(m) != rows:
        raise ValueError("wrong matrix row count")
    for row in m:
        if not isinstance(row, tuple) or len(row) != cols:
            raise ValueError("wrong matrix column count")
        if any(not isinstance(x, int) or isinstance(x, bool) or not 0 <= x < q for x in row):
            raise ValueError("noncanonical field element")


def _check_sigma(p: Parameters, sigma: Sigma) -> None:
    _check(sigma.el, p.n, p.r, p.q)
    _check(sigma.er, p.r, p.n, p.q)
    _check(sigma.fl, p.n, p.r, p.q)
    _check(sigma.fr, p.r, p.n, p.q)


def sample_sigma(p: Parameters, randbelow: Callable[[int], int] = secrets.randbelow) -> Sigma:
    """Sample independent uniform factor entries, as in §6.5.1.

    Rank deficiency has the small probability described in Lemma 6.5; it is
    intentionally not rejected because the paper samples entries uniformly.
    The caller must supply freshness and unpredictability of this challenge.
    """
    def sample(rows: int, cols: int) -> Matrix:
        result = tuple(tuple(randbelow(p.q) for _ in range(cols)) for _ in range(rows))
        _check(result, rows, cols, p.q)
        return result

    return Sigma(sample(p.n, p.r), sample(p.r, p.n), sample(p.n, p.r), sample(p.r, p.n))


def multiply(a: Matrix, b: Matrix, q: int) -> Matrix:
    """Ordinary rectangular field multiplication for the low-rank corrections."""
    rows, inner, cols = len(a), len(b), len(b[0])
    _check(a, rows, inner, q)
    _check(b, inner, cols, q)
    return tuple(tuple(sum(a[i][k] * b[k][j] for k in range(inner)) % q
                       for j in range(cols)) for i in range(rows))


def _combine(a: Matrix, b: Matrix, q: int, sign: int) -> Matrix:
    return tuple(tuple((x + sign * y) % q for x, y in zip(left, right))
                 for left, right in zip(a, b))


def encode(p: Parameters, sigma: Sigma, a: Matrix, b: Matrix) -> tuple[Matrix, Matrix]:
    _check_sigma(p, sigma)
    _check(a, p.n, p.n, p.q)
    _check(b, p.n, p.n, p.q)
    e = multiply(sigma.el, sigma.er, p.q)
    f = multiply(sigma.fl, sigma.fr, p.q)
    return _combine(a, e, p.q, 1), _combine(b, f, p.q, 1)


def tiled_product(p: Parameters, a: Matrix, b: Matrix) -> tuple[Matrix, Transcript]:
    """Algorithm 6.1: every cumulative r×r tile, ordered (i,j,ell)."""
    _check(a, p.n, p.n, p.q)
    _check(b, p.n, p.n, p.q)
    blocks = p.n // p.r
    output = [[0] * p.n for _ in range(p.n)]
    trace: list[Matrix] = []
    for i in range(blocks):
        for j in range(blocks):
            partial = [[0] * p.r for _ in range(p.r)]
            for ell in range(blocks):
                for x in range(p.r):
                    for y in range(p.r):
                        partial[x][y] = (partial[x][y] + sum(
                            a[i * p.r + x][ell * p.r + t] * b[ell * p.r + t][j * p.r + y]
                            for t in range(p.r))) % p.q
                trace.append(tuple(tuple(row) for row in partial))
            for x in range(p.r):
                for y in range(p.r):
                    output[i * p.r + x][j * p.r + y] = partial[x][y]
    return tuple(tuple(row) for row in output), tuple(trace)


def decode(p: Parameters, sigma: Sigma, a: Matrix, b: Matrix, c_prime: Matrix) -> Matrix:
    """Algorithm 6.4; A and B are explicit because its printed body uses them."""
    _check_sigma(p, sigma)
    _check(a, p.n, p.n, p.q)
    _check(b, p.n, p.n, p.q)
    _check(c_prime, p.n, p.n, p.q)
    f = multiply(sigma.fl, sigma.fr, p.q)
    af = multiply(multiply(a, sigma.fl, p.q), sigma.fr, p.q)
    ebf = multiply(sigma.el, multiply(sigma.er, _combine(b, f, p.q, 1), p.q), p.q)
    return _combine(_combine(c_prime, af, p.q, -1), ebf, p.q, -1)


def solve(p: Parameters, sigma: Sigma, a: Matrix, b: Matrix) -> tuple[Matrix, Proof]:
    a_prime, b_prime = encode(p, sigma, a, b)
    c_prime, trace = tiled_product(p, a_prime, b_prime)
    return decode(p, sigma, a, b, c_prime), Proof(a, b, trace)


def verify(p: Parameters, sigma: Sigma, proof: Proof) -> bool:
    """Algorithm 6.2: recompute z, compare every entry, and return one bit."""
    try:
        a_prime, b_prime = encode(p, sigma, proof.a, proof.b)
        _, expected = tiled_product(p, a_prime, b_prime)
        if len(proof.z) != len(expected):
            return False
        for tile in proof.z:
            _check(tile, p.r, p.r, p.q)
        return proof.z == expected
    except (AttributeError, TypeError, ValueError):
        return False


def _threshold(lambda_bits: int, difficulty_bits: int) -> int:
    """§2 threshold 2^(lambda - log2(1/epsilon)), for epsilon=2^-difficulty."""
    if (not isinstance(lambda_bits, int) or isinstance(lambda_bits, bool) or lambda_bits < 1
            or not isinstance(difficulty_bits, int) or isinstance(difficulty_bits, bool)
            or not 0 <= difficulty_bits <= lambda_bits):
        raise ValueError("need 0 <= difficulty_bits <= lambda_bits and lambda_bits > 0")
    return 1 << (lambda_bits - difficulty_bits)


def _challenge(challenge: int, lambda_bits: int) -> None:
    if (not isinstance(challenge, int) or isinstance(challenge, bool)
            or not 0 <= challenge < 1 << lambda_bits):
        raise ValueError("challenge must be a lambda-bit string represented as an integer")


def _oracle_value(value: int, lambda_bits: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << lambda_bits:
        raise ValueError("oracle value must be a lambda-bit string represented as an integer")


def solve_overview(p: Parameters, challenge: int, a: Matrix, b: Matrix,
                   oracle: RandomOracle, lambda_bits: int) -> tuple[Matrix, OverviewProof]:
    """§2 Solve, resolving the §6.3 discrepancy in favor of a hashed transcript."""
    _threshold(lambda_bits, 0)
    _challenge(challenge, lambda_bits)
    # The oracle, not this reference, owns the still-undecided concrete
    # challenge binding and uniform factor expansion.
    sigma = oracle.factors(p, challenge, a, b)
    a_prime, b_prime = encode(p, sigma, a, b)
    c_prime, trace = tiled_product(p, a_prime, b_prime)
    z = oracle.transcript_value(p, trace, lambda_bits)
    _oracle_value(z, lambda_bits)
    return decode(p, sigma, a, b, c_prime), OverviewProof(a, b, z)


def verify_overview(p: Parameters, challenge: int, proof: OverviewProof,
                    oracle: RandomOracle, lambda_bits: int, difficulty_bits: int) -> bool:
    """§2 Verify: recompute O(transcript), compare z, then apply the threshold."""
    threshold = _threshold(lambda_bits, difficulty_bits)
    try:
        _challenge(challenge, lambda_bits)
        _oracle_value(proof.z, lambda_bits)
        sigma = oracle.factors(p, challenge, proof.a, proof.b)
        a_prime, b_prime = encode(p, sigma, proof.a, proof.b)
        _, trace = tiled_product(p, a_prime, b_prime)
        expected = oracle.transcript_value(p, trace, lambda_bits)
        _oracle_value(expected, lambda_bits)
        return proof.z == expected and proof.z < threshold
    except (AttributeError, TypeError, ValueError):
        return False
