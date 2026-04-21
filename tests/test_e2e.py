"""End-to-end integration tests covering the full password-manager workflow."""

import json
import tempfile
import unittest
from pathlib import Path

from CLI.app import PasswordManagerApp


class TestE2EWorkflow(unittest.TestCase):
    """Tests that exercise the full stack from CLI app through every module."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.app = PasswordManagerApp(self.base)
        self.app.initialize_user("alice", "alice-pw")
        self.app.initialize_user("bob", "bob-pw")

    def tearDown(self):
        self.tmp.cleanup()

    # ------------------------------------------------------------------
    # Full CRUD + signature flow
    # ------------------------------------------------------------------

    def test_full_credential_lifecycle(self):
        """Add → retrieve → update → delete → verify empty."""
        # Add
        self.app.add_credential("alice", "alice-pw", "github.com", "alice", "pass1")
        entry = self.app.retrieve_credential("alice", "alice-pw", "github.com", "alice")
        self.assertEqual(entry["password"], "pass1")

        # List
        entries = self.app.list_credentials("alice", "alice-pw")
        self.assertEqual(len(entries), 1)

        # Update
        self.app.update_credential("alice", "alice-pw", "github.com", "alice", "pass2")
        updated = self.app.retrieve_credential("alice", "alice-pw", "github.com", "alice")
        self.assertEqual(updated["password"], "pass2")

        # Vault should still be valid after every operation
        self.assertTrue(self.app.verify_vault("alice"))

        # Delete
        self.app.delete_credential("alice", "alice-pw", "github.com", "alice")
        entries = self.app.list_credentials("alice", "alice-pw")
        self.assertEqual(len(entries), 0)

    def test_vault_invalid_after_tamper_blocks_all_reads(self):
        """Any field modification must prevent reading credentials."""
        self.app.add_credential("alice", "alice-pw", "x.com", "a", "p")
        v = json.loads((self.base / "users" / "alice" / "vault.json").read_text())
        v["ciphertext"] = ("Z" if v["ciphertext"][0] != "Z" else "A") + v["ciphertext"][1:]
        (self.base / "users" / "alice" / "vault.json").write_text(json.dumps(v))
        with self.assertRaises(ValueError):
            self.app.retrieve_credential("alice", "alice-pw", "x.com", "a")
        with self.assertRaises(ValueError):
            self.app.list_credentials("alice", "alice-pw")

    # ------------------------------------------------------------------
    # Full export / import flow
    # ------------------------------------------------------------------

    def test_full_export_import(self):
        """Alice stores creds → exports to Bob → Bob retrieves them."""
        self.app.add_credential("alice", "alice-pw", "example.com", "alice", "hunter2")
        self.app.add_credential("alice", "alice-pw", "other.com", "alice", "s3cr3t")

        handshake = self.base / "xfer" / "handshake.json"
        package = self.base / "xfer" / "package.json"

        self.app.prepare_import_session("bob", "alice", handshake)
        self.app.export_vault("alice", "alice-pw", handshake, package)
        self.app.import_vault("bob", "alice", "bob-pw", package)

        entries = self.app.list_credentials("bob", "bob-pw")
        self.assertEqual(len(entries), 2)
        sites = {e["site"] for e in entries}
        self.assertIn("example.com", sites)
        self.assertIn("other.com", sites)

    def test_export_import_uses_recipient_master_password(self):
        """Bob's vault should be accessible only with Bob's master password."""
        self.app.add_credential("alice", "alice-pw", "site.com", "alice", "pw")
        handshake = self.base / "xfer" / "handshake.json"
        package = self.base / "xfer" / "package.json"
        self.app.prepare_import_session("bob", "alice", handshake)
        self.app.export_vault("alice", "alice-pw", handshake, package)
        self.app.import_vault("bob", "alice", "bob-pw", package)

        # Alice's master password must NOT open Bob's vault
        with self.assertRaises(Exception):
            self.app.list_credentials("bob", "alice-pw")

    def test_signatures_protect_against_mitm(self):
        """Tampering with the package payload must abort import."""
        self.app.add_credential("alice", "alice-pw", "site.com", "alice", "pw")
        handshake = self.base / "xfer" / "handshake.json"
        package = self.base / "xfer" / "package.json"
        self.app.prepare_import_session("bob", "alice", handshake)
        self.app.export_vault("alice", "alice-pw", handshake, package)

        pkg = json.loads(package.read_text())
        ct = pkg["payload"]["ciphertext"]
        pkg["payload"]["ciphertext"] = ("Z" if ct[0] != "Z" else "A") + ct[1:]
        package.write_text(json.dumps(pkg))

        with self.assertRaises(ValueError):
            self.app.import_vault("bob", "alice", "bob-pw", package)


if __name__ == "__main__":
    unittest.main()
