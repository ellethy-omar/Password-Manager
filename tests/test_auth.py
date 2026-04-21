"""Unit tests for the auth module (Module 3 – vault signing and verification)."""

import json
import tempfile
import unittest
from pathlib import Path

from CLI.app import PasswordManagerApp


class TestVaultSigner(unittest.TestCase):
    """Tests for the VaultSigner class exercised through PasswordManagerApp."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.app = PasswordManagerApp(self.base)
        self.app.initialize_user("alice", "alice-secret")

    def tearDown(self):
        self.tmp.cleanup()

    def _vault(self):
        return json.loads((self.base / "users" / "alice" / "vault.json").read_text(encoding="utf-8"))

    def test_fresh_vault_is_valid(self):
        self.assertTrue(self.app.verify_vault("alice"))

    def test_vault_valid_after_add(self):
        self.app.add_credential("alice", "alice-secret", "site.com", "alice", "pw")
        self.assertTrue(self.app.verify_vault("alice"))

    def test_tampered_ciphertext_fails(self):
        v = self._vault()
        v["ciphertext"] = ("Z" if v["ciphertext"][0] != "Z" else "A") + v["ciphertext"][1:]
        (self.base / "users" / "alice" / "vault.json").write_text(json.dumps(v), encoding="utf-8")
        self.assertFalse(self.app.verify_vault("alice"))

    def test_tampered_nonce_fails(self):
        v = self._vault()
        v["nonce"] = ("Z" if v["nonce"][0] != "Z" else "A") + v["nonce"][1:]
        (self.base / "users" / "alice" / "vault.json").write_text(json.dumps(v), encoding="utf-8")
        self.assertFalse(self.app.verify_vault("alice"))

    def test_tampered_tag_fails(self):
        v = self._vault()
        v["tag"] = ("Z" if v["tag"][0] != "Z" else "A") + v["tag"][1:]
        (self.base / "users" / "alice" / "vault.json").write_text(json.dumps(v), encoding="utf-8")
        self.assertFalse(self.app.verify_vault("alice"))

    def test_tampered_signer_fails(self):
        v = self._vault()
        v["signer"] = "mallory"
        (self.base / "users" / "alice" / "vault.json").write_text(json.dumps(v), encoding="utf-8")
        self.assertFalse(self.app.verify_vault("alice"))

    def test_invalid_vault_blocks_read(self):
        v = self._vault()
        v["ciphertext"] = ("Z" if v["ciphertext"][0] != "Z" else "A") + v["ciphertext"][1:]
        (self.base / "users" / "alice" / "vault.json").write_text(json.dumps(v), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.app.list_credentials("alice", "alice-secret")


if __name__ == "__main__":
    unittest.main()
