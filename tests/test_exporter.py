"""Unit tests for the exporter module (Module 4 – DH vault transfer)."""

import json
import tempfile
import unittest
from pathlib import Path

from CLI.app import PasswordManagerApp


class TestVaultExporter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.app = PasswordManagerApp(self.base)
        self.app.initialize_user("alice", "alice-secret")
        self.app.initialize_user("bob", "bob-secret")

    def tearDown(self):
        self.tmp.cleanup()

    def _paths(self):
        handshake = self.base / "transfer" / "handshake.json"
        package = self.base / "transfer" / "package.json"
        return handshake, package

    def test_basic_export_import(self):
        self.app.add_credential("alice", "alice-secret", "site.com", "alice", "pw1")
        handshake, package = self._paths()
        self.app.prepare_import_session("bob", "alice", handshake)
        self.app.export_vault("alice", "alice-secret", handshake, package)
        self.app.import_vault("bob", "alice", "bob-secret", package)
        entry = self.app.retrieve_credential("bob", "bob-secret", "site.com", "alice")
        self.assertEqual(entry["password"], "pw1")

    def test_bob_vault_re_signed_after_import(self):
        self.app.add_credential("alice", "alice-secret", "site.com", "alice", "pw1")
        handshake, package = self._paths()
        self.app.prepare_import_session("bob", "alice", handshake)
        self.app.export_vault("alice", "alice-secret", handshake, package)
        self.app.import_vault("bob", "alice", "bob-secret", package)
        # Vault should now be signed by bob (not alice)
        vault = json.loads((self.base / "users" / "bob" / "vault.json").read_text(encoding="utf-8"))
        self.assertEqual(vault["signer"], "bob")
        self.assertTrue(self.app.verify_vault("bob"))

    def test_tampered_package_payload_rejected(self):
        self.app.add_credential("alice", "alice-secret", "site.com", "alice", "pw")
        handshake, package = self._paths()
        self.app.prepare_import_session("bob", "alice", handshake)
        self.app.export_vault("alice", "alice-secret", handshake, package)

        pkg = json.loads(package.read_text(encoding="utf-8"))
        ct = pkg["payload"]["ciphertext"]
        pkg["payload"]["ciphertext"] = ("Z" if ct[0] != "Z" else "A") + ct[1:]
        package.write_text(json.dumps(pkg), encoding="utf-8")

        with self.assertRaises(ValueError):
            self.app.import_vault("bob", "alice", "bob-secret", package)

    def test_wrong_sender_rejected(self):
        handshake, package = self._paths()
        self.app.prepare_import_session("bob", "alice", handshake)
        with self.assertRaises(ValueError):
            # "charlie" is not the expected sender
            self.app.export_vault("charlie", "charlie-secret", handshake, package)

    def test_session_state_cleaned_up_after_import(self):
        self.app.add_credential("alice", "alice-secret", "site.com", "alice", "pw")
        handshake, package = self._paths()
        self.app.prepare_import_session("bob", "alice", handshake)
        self.app.export_vault("alice", "alice-secret", handshake, package)
        self.app.import_vault("bob", "alice", "bob-secret", package)
        # Session state file should have been removed
        sessions = list((self.base / "users" / "bob" / "sessions").iterdir())
        self.assertEqual(len(sessions), 0)


if __name__ == "__main__":
    unittest.main()
