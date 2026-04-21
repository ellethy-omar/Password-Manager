"""Unit tests for the shared crypto helpers."""

import unittest

from shared.crypto_utils import sha256_bytes, sha256_int, modular_inverse
from shared.prime_utils import is_probable_prime, generate_safe_prime, find_generator_for_safe_prime


class TestCryptoUtils(unittest.TestCase):
    def test_sha256_bytes_known_value(self):
        digest = sha256_bytes(b"hello")
        self.assertEqual(len(digest), 32)
        # known SHA-256("hello")
        import hashlib
        self.assertEqual(digest, hashlib.sha256(b"hello").digest())

    def test_sha256_int_is_big_endian(self):
        digest_bytes = sha256_bytes(b"abc")
        digest_int = sha256_int(b"abc")
        self.assertEqual(digest_int, int.from_bytes(digest_bytes, "big"))

    def test_modular_inverse_basic(self):
        # 3 * 7 = 21 ≡ 0 (mod 11), actually gcd(3,11)=1 so inverse exists
        inv = modular_inverse(3, 11)
        self.assertEqual((3 * inv) % 11, 1)

    def test_modular_inverse_larger(self):
        p = 10007  # prime
        for a in [2, 3, 100, 999, 5003]:
            self.assertEqual((a * modular_inverse(a, p)) % p, 1)


class TestPrimeUtils(unittest.TestCase):
    def test_known_primes(self):
        for n in [2, 3, 5, 7, 11, 13, 97, 101, 1009]:
            self.assertTrue(is_probable_prime(n), f"{n} should be prime")

    def test_known_composites(self):
        for n in [1, 4, 6, 9, 15, 100, 1001]:
            self.assertFalse(is_probable_prime(n), f"{n} should be composite")

    def test_generate_safe_prime_structure(self):
        p, q = generate_safe_prime(bits=128)
        self.assertEqual(p, 2 * q + 1)
        self.assertTrue(is_probable_prime(p))
        self.assertTrue(is_probable_prime(q))

    def test_find_generator(self):
        p, q = generate_safe_prime(bits=128)
        g = find_generator_for_safe_prime(p, q)
        # g must NOT be a trivial element
        self.assertNotEqual(pow(g, 2, p), 1)
        self.assertNotEqual(pow(g, q, p), 1)


if __name__ == "__main__":
    unittest.main()
