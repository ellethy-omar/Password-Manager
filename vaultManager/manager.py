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
    def __init__(self, base_dir: Path, signer):
        self.base_dir = base_dir
        self.signer = signer

    def user_dir(self, username: str) -> Path:
        return self.base_dir / "users" / username

    def vault_path(self, username: str) -> Path:
        return self.user_dir(username) / "vault.json"

    def sessions_dir(self, username: str) -> Path:
        return self.user_dir(username) / "sessions"

    def _load_entries(self, username: str, master_password: str) -> List[Dict[str, str]]:
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

    def initialize_vault(self, username: str, master_password: str) -> None:
        """Create an empty encrypted vault for *username* and sign it."""
        data_key = VaultCrypto.derive_data_key(master_password)
        encrypted = VaultCrypto.aes_gcm_encrypt(data_key, b"[]")
        self.signer.sign_and_save(username, encrypted, signer=username)

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
        entries = self._load_entries(username, master_password)
        updated = [
            e for e in entries
            if not (e["site"] == site and e["username"] == login)
        ]
        if len(updated) == len(entries):
            raise ValueError("Credential not found")
        self._store_entries(username, master_password, updated)
