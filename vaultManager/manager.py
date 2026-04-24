"""Credential CRUD operations over an AES-GCM encrypted vault.

VaultManager is responsible for:
- Loading and storing credential entries (add / retrieve / update / delete / list).
- Encrypting the vault with the AES key derived from the master password.
- Delegating signing / verification to the auth.VaultSigner.

It does NOT own the ElGamal keys directly – it asks VaultSigner to sign.
"""

import json
from pathlib import Path
from typing import Dict, List

from vaultManager.crypto import VaultCrypto


class VaultManager:
    """Manages credential storage inside an encrypted, signed vault."""

    def __init__(self, base_dir: Path, signer):
        """
        Parameters
        ----------
        base_dir : Path
            Root directory that holds *users/* and *config/* subdirectories.
        signer : auth.VaultSigner
            The signer instance used to sign/verify vault files.
        """
        self.base_dir = base_dir
        self.signer = signer

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def user_dir(self, username: str) -> Path:
        return self.base_dir / "users" / username

    def vault_path(self, username: str) -> Path:
        return self.user_dir(username) / "vault.json"

    def sessions_dir(self, username: str) -> Path:
        return self.user_dir(username) / "sessions"

    # ------------------------------------------------------------------
    # Low-level encrypt / decrypt
    # ------------------------------------------------------------------

    def _load_entries(self, username: str, master_password: str) -> List[Dict[str, str]]:
        """Read, signature-verify, decrypt, and return the credential list."""
        vault = json.loads(self.vault_path(username).read_text(encoding="utf-8"))

        if not self.signer.verify(vault, username):
            raise ValueError("Vault signature verification failed. Possible tampering detected.")
        
        data_key = VaultCrypto.derive_data_key(master_password)
        plaintext = VaultCrypto.aes_gcm_decrypt(data_key, vault["encrypted_vault"])
        return json.loads(plaintext.decode("utf-8"))

    def _store_entries(
        self,
        username: str,
        master_password: str,
        entries: List[Dict[str, str]],
    ) -> None:
        """Encrypt entries, sign the vault, and write it to disk."""
        data_key = VaultCrypto.derive_data_key(master_password)
        encrypted = VaultCrypto.aes_gcm_encrypt(
            data_key,
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        self.signer.sign_and_save(username, encrypted, signer=username)

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def initialize_vault(self, username: str, master_password: str) -> None:
        """Create an empty encrypted vault for *username* and sign it."""
        data_key = VaultCrypto.derive_data_key(master_password)
        encrypted = VaultCrypto.aes_gcm_encrypt(data_key, b"[]")
        encrypted = VaultCrypto.aes_gcm_encrypt(data_key, b"[]")
        self.signer.sign_and_save(username, encrypted, signer=username)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_credential(
        self,
        username: str,
        master_password: str,
        site: str,
        login: str,
        password: str,
    ) -> None:
        entries = self._load_entries(username, master_password)
        entries.append({"site": site, "username": login, "password": password})
        self._store_entries(username, master_password, entries)

    def list_credentials(
        self, username: str, master_password: str
    ) -> List[Dict[str, str]]:
        return self._load_entries(username, master_password)

    def retrieve_credential(
        self,
        username: str,
        master_password: str,
        site: str,
        login: str = "",
    ) -> Dict[str, str]:
        for entry in self._load_entries(username, master_password):
            if entry["site"] == site:
                return entry
        raise ValueError("Credential not found")

    def update_credential(
        self,
        username: str,
        master_password: str,
        site: str,
        login: str,
        new_password: str,
    ) -> None:
        """Update the password for the matching credential entry."""
        entries = self._load_entries(username, master_password)
        for entry in entries:
            if entry["site"] == site and entry["username"] == login:
                entry["password"] = new_password
                self._store_entries(username, master_password, entries)
                return
        raise ValueError("Credential not found")

    def delete_credential(
        self,
        username: str,
        master_password: str,
        site: str,
        login: str,
    ) -> None:
        """Remove the matching credential entry from the vault."""
        entries = self._load_entries(username, master_password)
        updated = [
            e for e in entries
            if not (e["site"] == site and e["username"] == login)
        ]
        if len(updated) == len(entries):
            raise ValueError("Credential not found")
        self._store_entries(username, master_password, updated)
