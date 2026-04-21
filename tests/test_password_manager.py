import json
import tempfile
import unittest
from pathlib import Path

from password_manager import PasswordManager


class PasswordManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.manager = PasswordManager(self.base)
        self.manager.initialize_user("alice", "alice-secret")
        self.manager.initialize_user("bob", "bob-secret")

    def tearDown(self):
        self.tmp.cleanup()

    def test_vault_crud_and_signature_verification(self):
        self.manager.add_credential("alice", "alice-secret", "github.com", "alice", "pass1")
        entry = self.manager.retrieve_credential("alice", "alice-secret", "github.com", "alice")
        self.assertEqual(entry["password"], "pass1")

        self.manager.update_credential("alice", "alice-secret", "github.com", "alice", "pass2")
        updated = self.manager.retrieve_credential("alice", "alice-secret", "github.com", "alice")
        self.assertEqual(updated["password"], "pass2")

        vault = json.loads((self.base / "users" / "alice" / "vault.json").read_text(encoding="utf-8"))
        self.assertTrue(self.manager._verify_vault_signature("alice", vault))

        for field, value in [("ciphertext", "A"), ("nonce", "B"), ("tag", "C"), ("signer", "mallory")]:
            tampered = dict(vault)
            if field != "signer":
                replacement = value if tampered[field][0] != value else "Z"
                tampered[field] = replacement + tampered[field][1:]
            else:
                tampered[field] = value
            (self.base / "users" / "alice" / "vault.json").write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(ValueError):
                self.manager.list_credentials("alice", "alice-secret")

    def test_export_import_workflow(self):
        self.manager.add_credential("alice", "alice-secret", "github.com", "alice", "pass1")
        package_path = self.base / "transfer" / "package.json"
        recipient_session_path = self.base / "transfer" / "recipient-session.json"

        self.manager.prepare_import_session("bob", "alice", recipient_session_path)
        self.manager.export_vault("alice", "alice-secret", recipient_session_path, package_path)
        self.manager.import_vault("bob", "alice", "bob-secret", package_path)

        imported = self.manager.retrieve_credential("bob", "bob-secret", "github.com", "alice")
        self.assertEqual(imported["password"], "pass1")


if __name__ == "__main__":
    unittest.main()
