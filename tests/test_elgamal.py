"""Unit tests for the elGamal module (Module 1)."""

import unittest

from shared.prime_utils import generate_safe_prime, find_generator_for_safe_prime
from elGamal.keys import ElGamalPrivateKey, ElGamalPublicKey
from elGamal.signature import ElGamalSignature
from elGamal.diffie_hellman import DiffieHellman
from shared.crypto_utils import sha256_int


def _small_params():
    """Return a small but valid (p, alpha) for fast tests."""
    p, q = generate_safe_prime(bits=128)
    alpha = find_generator_for_safe_prime(p, q)
    return p, alpha


class TestElGamalSignature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p, cls.alpha = _small_params()

    def test_keygen_types(self):
        priv, pub = ElGamalSignature.keygen(self.p, self.alpha)
        self.assertIsInstance(priv, ElGamalPrivateKey)
        self.assertIsInstance(pub, ElGamalPublicKey)

    def test_keygen_public_key_relation(self):
        priv, pub = ElGamalSignature.keygen(self.p, self.alpha)
        # y = alpha^x mod p
        self.assertEqual(pow(priv.alpha, priv.x, priv.p), pub.y)

    def test_sign_and_verify_valid(self):
        priv, pub = ElGamalSignature.keygen(self.p, self.alpha)
        msg_hash = sha256_int(b"test message")
        sig = ElGamalSignature.sign(priv, msg_hash)
        self.assertTrue(ElGamalSignature.verify(pub, msg_hash, sig))

    def test_verify_wrong_message_fails(self):
        priv, pub = ElGamalSignature.keygen(self.p, self.alpha)
        msg_hash = sha256_int(b"original")
        sig = ElGamalSignature.sign(priv, msg_hash)
        wrong_hash = sha256_int(b"tampered")
        self.assertFalse(ElGamalSignature.verify(pub, wrong_hash, sig))

    def test_verify_wrong_key_fails(self):
        priv, pub = ElGamalSignature.keygen(self.p, self.alpha)
        _, wrong_pub = ElGamalSignature.keygen(self.p, self.alpha)
        msg_hash = sha256_int(b"message")
        sig = ElGamalSignature.sign(priv, msg_hash)
        self.assertFalse(ElGamalSignature.verify(wrong_pub, msg_hash, sig))

    def test_verify_invalid_r_rejected(self):
        priv, pub = ElGamalSignature.keygen(self.p, self.alpha)
        msg_hash = sha256_int(b"msg")
        r, s = ElGamalSignature.sign(priv, msg_hash)
        # r = 0 is out of range [1, p-1]
        self.assertFalse(ElGamalSignature.verify(pub, msg_hash, (0, s)))


class TestDiffieHellman(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p, q = generate_safe_prime(bits=128)
        cls.q = p   # use safe prime as DH modulus
        cls.alpha = find_generator_for_safe_prime(p, q)

    def test_shared_secret_matches(self):
        priv_a, pub_a = DiffieHellman.generate_keypair(self.q, self.alpha)
        priv_b, pub_b = DiffieHellman.generate_keypair(self.q, self.alpha)
        secret_a = DiffieHellman.shared_secret(pub_b, priv_a, self.q)
        secret_b = DiffieHellman.shared_secret(pub_a, priv_b, self.q)
        self.assertEqual(secret_a, secret_b)

    def test_different_sessions_different_keys(self):
        priv1, pub1 = DiffieHellman.generate_keypair(self.q, self.alpha)
        priv2, pub2 = DiffieHellman.generate_keypair(self.q, self.alpha)
        # Distinct private keys should produce distinct public keys (with very high probability)
        # A collision here would be an astronomically unlikely coincidence.
        if priv1 != priv2:
            self.assertNotEqual(pub1, pub2)


if __name__ == "__main__":
    unittest.main()
