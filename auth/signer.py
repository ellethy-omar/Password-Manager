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
        shaKey = sha256_int(encrypted_blob.encode("utf-8"))
        privatKey = self.load_private_key(signer)
        signature = ElGamalSignature.sign(privatKey, shaKey)

        r_val, s_val = signature
        vault_data = {
            "encrypted_vault": encrypted_blob,
            "signature": {
                "r": r_val,
                "s": s_val
            }
        }

        vault_path = self._vault_path(owner)
        vault_path.parent.mkdir(parents=True, exist_ok=True)
        with open(vault_path, 'w') as f:
            json.dump(vault_data, f, indent=4)

    def verify(self, vault: Dict[str, str], username: str) -> bool:
        encrypted_blob = vault.get("encrypted_vault")
        signature_data = vault.get("signature")

        if not encrypted_blob or not signature_data:
            return False
        shaKey = sha256_int(encrypted_blob.encode("utf-8"))
        pubKey = self.load_public_key(username)
        r_val = signature_data.get("r")
        s_val = signature_data.get("s")
        if r_val is None or s_val is None:
            return False
        
        
        signature_tuple = (int(r_val), int(s_val))
        is_valid = ElGamalSignature.verify(pubKey, shaKey, signature_tuple)
        if is_valid:
            print("Vault integrity verified. No tampering detected.")
        else:
            print("ALERT: Vault signature INVALID. The vault may have been tampered with!")
            
        return is_valid