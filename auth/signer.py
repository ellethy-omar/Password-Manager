"""Vault signing and verification using ElGamal digital signatures (Module 3).

Every vault write is signed; every vault read verifies the signature before
any plaintext is returned to the caller.
"""

import json
from pathlib import Path
from typing import Dict

from elGamal.keys import ElGamalPrivateKey, ElGamalPublicKey
from elGamal.signature import ElGamalSignature
from shared.crypto_utils import sha256_int


class VaultSigner:
    """Signs and verifies vault files using long-lived ElGamal keys.

    This class does not generate keys.  It loads them from the paths provided
    by the caller (which are controlled by the key-management layer).
    """

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir

    def _private_key_path(self, username: str) -> Path:
        return self.base_dir / "users" / username / "elgamal_private.json"

    def _public_key_path(self, username: str) -> Path:
        return self.base_dir / "users" / username / "elgamal_public.json"

    def _vault_path(self, username: str) -> Path:
        return self.base_dir / "users" / username / "vault.json"

    def load_private_key(self, username: str) -> ElGamalPrivateKey:
        raw = json.loads(self._private_key_path(username).read_text(encoding="utf-8"))
        return ElGamalPrivateKey(p=raw["p"], alpha=raw["alpha"], x=raw["x"])

    def load_public_key(self, username: str) -> ElGamalPublicKey:
        """Load and return the ElGamal public key for *username*."""
        raw = json.loads(self._public_key_path(username).read_text(encoding="utf-8"))
        return ElGamalPublicKey(p=raw["p"], alpha=raw["alpha"], y=raw["y"])

    def sign_and_save(self, owner: str, encrypted_blob: str, signer: str) -> None:
        private_key = self.load_private_key(signer)
        vault = {"encrypted_vault": encrypted_blob}
        digest = sha256_int(encrypted_blob.encode("utf-8"))
        r, s = ElGamalSignature.sign(private_key, digest)
        vault["signature"] = f"{r}:{s}"
        self._vault_path(owner).write_text(json.dumps(vault, indent=2), encoding="utf-8")

    def verify(self, vault: Dict[str, str], username: str) -> bool:
        try:
            public_key = self.load_public_key(username)
            digest = sha256_int(vault["encrypted_vault"].encode("utf-8"))
            r, s = (int(x) for x in vault["signature"].split(":"))
            is_valid = ElGamalSignature.verify(public_key, digest, (r, s))
            if is_valid:
                print("Vault integrity verified. No tampering detected.")
            else:
                print("ALERT: Vault signature INVALID. The vault may have been tampered with!")
            return is_valid
        except (FileNotFoundError, KeyError, TypeError):
            return False