"""Unit tests for the vaultManager module (Module 2)."""

import json
import tempfile
import unittest
from pathlib import Path

from vaultManager.crypto import VaultCrypto


class TestVaultCrypto(unittest.TestCase):
    def test_derive_data_key_length(self):
        key = VaultCrypto.derive_data_key("my-password")
        self.assertEqual(len(key), 32)

    def test_derive_data_key_deterministic(self):
        key1 = VaultCrypto.derive_data_key("password123")
        key2 = VaultCrypto.derive_data_key("password123")
        self.assertEqual(key1, key2)

    def test_derive_data_key_different_passwords(self):
        key1 = VaultCrypto.derive_data_key("password123")
        key2 = VaultCrypto.derive_data_key("different")
        self.assertNotEqual(key1, key2)

    def test_encrypt_decrypt_roundtrip(self):
        key = VaultCrypto.derive_data_key("test-pass")
        plaintext = b'[{"site":"github.com","username":"alice","password":"s3cr3t"}]'
        blob = VaultCrypto.aes_gcm_encrypt(key, plaintext)
        self.assertIn("nonce", blob)
        self.assertIn("ciphertext", blob)
        self.assertIn("tag", blob)
        recovered = VaultCrypto.aes_gcm_decrypt(key, blob)
        self.assertEqual(recovered, plaintext)

    def test_decrypt_with_wrong_key_fails(self):
        key = VaultCrypto.derive_data_key("correct")
        blob = VaultCrypto.aes_gcm_encrypt(key, b"secret data")
        wrong_key = VaultCrypto.derive_data_key("wrong")
        with self.assertRaises(Exception):
            VaultCrypto.aes_gcm_decrypt(wrong_key, blob)

    def test_each_encryption_uses_fresh_nonce(self):
        key = VaultCrypto.derive_data_key("test")
        blob1 = VaultCrypto.aes_gcm_encrypt(key, b"data")
        blob2 = VaultCrypto.aes_gcm_encrypt(key, b"data")
        # AES-GCM nonce should be random each call
        self.assertNotEqual(blob1["nonce"], blob2["nonce"])


if __name__ == "__main__":
    unittest.main()
