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

    # ------------------------------------------------------------------
    # Key paths
    # ------------------------------------------------------------------

    def _private_key_path(self, username: str) -> Path:
        return self.base_dir / "users" / username / "elgamal_private.json"

    def _public_key_path(self, username: str) -> Path:
        return self.base_dir / "users" / username / "elgamal_public.json"

    def _vault_path(self, username: str) -> Path:
        return self.base_dir / "users" / username / "vault.json"

    # ------------------------------------------------------------------
    # Key loading
    # ------------------------------------------------------------------

    def load_private_key(self, username: str) -> ElGamalPrivateKey:
        """Load and return the ElGamal private key for *username*."""
        raw = json.loads(self._private_key_path(username).read_text(encoding="utf-8"))
        return ElGamalPrivateKey(p=raw["p"], alpha=raw["alpha"], x=raw["x"])

    def load_public_key(self, username: str) -> ElGamalPublicKey:
        """Load and return the ElGamal public key for *username*."""
        raw = json.loads(self._public_key_path(username).read_text(encoding="utf-8"))
        return ElGamalPublicKey(p=raw["p"], alpha=raw["alpha"], y=raw["y"])

    # ------------------------------------------------------------------
    # Signature payload
    # ------------------------------------------------------------------

    @staticmethod
    def signature_payload(vault_like: Dict[str, str]) -> bytes:
        """Return the canonical bytes to sign/verify for *vault_like*.

        Only the fields that comprise the protected content are included so
        that the stored signature field itself is not part of what is signed.
        """
        payload = {
            "ciphertext": vault_like["ciphertext"],
            "nonce": vault_like["nonce"],
            "tag": vault_like["tag"],
            "signer": vault_like["signer"],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # ------------------------------------------------------------------
    # Sign / verify
    # ------------------------------------------------------------------

    def sign_and_save(
        self,
        owner: str,
        encrypted_blob: Dict[str, str],
        signer: str,
    ) -> None:
        """Sign *encrypted_blob* with *signer*'s private key and write to disk.

        Parameters
        ----------
        owner : str
            The username whose vault file is being written.
        encrypted_blob : dict
            Dict with *nonce*, *ciphertext*, *tag* keys from AES-GCM.
        signer : str
            The username whose ElGamal private key should be used to sign.
        """
        private_key = self.load_private_key(signer)
        vault = {**encrypted_blob, "signer": signer}
        digest = sha256_int(self.signature_payload(vault))
        r, s = ElGamalSignature.sign(private_key, digest)
        vault["signature"] = {"r": r, "s": s}
        self._vault_path(owner).write_text(json.dumps(vault, indent=2), encoding="utf-8")

    def verify(self, vault: Dict[str, str]) -> bool:
        """Return True when the stored ElGamal signature over *vault* is valid.

        Returns False (instead of raising) for any structural problem so that
        callers can decide how to surface the error.
        """
        try:
            signer = vault["signer"]
            public_key = self.load_public_key(signer)
            digest = sha256_int(self.signature_payload(vault))
            sig = vault["signature"]
            return ElGamalSignature.verify(public_key, digest, (sig["r"], sig["s"]))
        except (FileNotFoundError, KeyError, TypeError):
            return False
