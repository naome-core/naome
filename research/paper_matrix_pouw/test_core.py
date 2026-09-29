"""Independent scalar vectors and negative cases for the paper arithmetic reference."""

from dataclasses import replace
import random
import unittest

from core import Parameters, Proof, Sigma, encode, sample_sigma, solve, tiled_product, verify


def reference_product(a, b, q):
    # Independently compute each scalar dot product without calling core.multiply.
    return tuple(tuple(sum(x * y for x, y in zip(a[i], (row[j] for row in b))) % q
                       for j in range(len(b[0]))) for i in range(len(a)))


def reference_transcript(a, b, q, r):
    n = len(a)
    result = []
    for i in range(0, n, r):
        for j in range(0, n, r):
            for ell in range(r, n + 1, r):
                result.append(tuple(tuple(sum(a[i + x][k] * b[k][j + y]
                                              for k in range(ell)) % q
                                          for y in range(r)) for x in range(r)))
    return tuple(result)


class PaperCoreTests(unittest.TestCase):
    def setUp(self):
        self.p = Parameters(q=101, n=4, r=2)
        self.sigma = Sigma(
            el=((1, 2), (0, 1), (3, 4), (2, 5)),
            er=((2, 0, 1, 3), (1, 4, 2, 0)),
            fl=((2, 1), (3, 0), (1, 2), (0, 4)),
            fr=((1, 3, 0, 2), (4, 1, 2, 3)),
        )
        self.a = ((1, 2, 3, 4), (5, 6, 7, 8), (9, 10, 11, 12), (13, 14, 15, 16))
        self.b = ((2, 3, 5, 7), (11, 13, 17, 19), (23, 29, 31, 37), (41, 43, 47, 53))

    def test_hand_calculated_two_by_two_vector(self):
        p = Parameters(7, 2, 1)
        sigma = Sigma(el=((1,), (2,)), er=((1, 3),),
                      fl=((2,), (1,)), fr=((1, 2),))
        a = ((1, 2), (3, 4))
        b = ((5, 6), (0, 1))
        self.assertEqual(encode(p, sigma, a, b),
                         (((2, 5), (5, 3)), ((0, 3), (1, 3))))
        c_prime, trace = tiled_product(p, *encode(p, sigma, a, b))
        self.assertEqual(c_prime, ((5, 0), (3, 3)))
        self.assertEqual(trace, (((0,),), ((5,),), ((6,),), ((0,),),
                                 ((0,),), ((3,),), ((1,),), ((3,),)))
        c, proof = solve(p, sigma, a, b)
        self.assertEqual(c, ((5, 1), (1, 1)))
        self.assertEqual(proof.z, trace)
        self.assertTrue(verify(p, sigma, proof))

    def test_paper_vectors_against_independent_scalar_reference(self):
        for a, b in ((self.a, self.b),
                     (((0,) * 4,) * 4, ((0,) * 4,) * 4),
                     (tuple(tuple(int(i == j) for j in range(4)) for i in range(4)), self.b)):
            with self.subTest(a=a, b=b):
                ap, bp = encode(self.p, self.sigma, a, b)
                cp, trace = tiled_product(self.p, ap, bp)
                self.assertEqual(cp, reference_product(ap, bp, self.p.q))
                self.assertEqual(trace, reference_transcript(ap, bp, self.p.q, self.p.r))
                self.assertEqual(len(trace), (self.p.n // self.p.r) ** 3)
                c, proof = solve(self.p, self.sigma, a, b)
                self.assertEqual(c, reference_product(a, b, self.p.q))
                self.assertEqual(proof, Proof(a, b, trace))
                self.assertTrue(verify(self.p, self.sigma, proof))

    def test_negative_vectors(self):
        _, proof = solve(self.p, self.sigma, self.a, self.b)
        first = list(proof.z[0])
        first[0] = ((first[0][0] + 1) % self.p.q,) + first[0][1:]
        changed = (tuple(first),) + proof.z[1:]
        self.assertFalse(verify(self.p, self.sigma, replace(proof, z=changed)))
        self.assertFalse(verify(self.p, self.sigma, replace(proof, z=proof.z[:-1])))
        self.assertFalse(verify(self.p, self.sigma, replace(proof, z=(((-1, 0), (0, 0)),) + proof.z[1:])))
        changed_a = ((self.a[0][0] + 1,) + self.a[0][1:],) + self.a[1:]
        self.assertFalse(verify(self.p, self.sigma, replace(proof, a=changed_a)))
        changed_el = ((self.sigma.el[0][0] + 1,) + self.sigma.el[0][1:],) + self.sigma.el[1:]
        self.assertFalse(verify(self.p, replace(self.sigma, el=changed_el), proof))

    def test_uniform_factor_sampling_and_random_cases(self):
        rng = random.Random(1402)
        for _ in range(20):
            sigma = sample_sigma(self.p, rng.randrange)
            a = tuple(tuple(rng.randrange(self.p.q) for _ in range(4)) for _ in range(4))
            b = tuple(tuple(rng.randrange(self.p.q) for _ in range(4)) for _ in range(4))
            c, proof = solve(self.p, sigma, a, b)
            self.assertEqual(c, reference_product(a, b, self.p.q))
            self.assertTrue(verify(self.p, sigma, proof))

    def test_invalid_parameters_and_noncanonical_inputs(self):
        for q in (1, 4, 9, 2**64):
            with self.assertRaises(ValueError):
                Parameters(q, 4, 2)
        for n, r in ((4, 0), (4, 3), (4, 4)):
            with self.assertRaises(ValueError):
                Parameters(101, n, r)
        with self.assertRaises(ValueError):
            solve(self.p, self.sigma, ((101,) * 4,) * 4, self.b)


if __name__ == "__main__":
    unittest.main()
