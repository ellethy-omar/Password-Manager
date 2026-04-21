"""AES-GCM symmetric encryption helpers used by the vault manager."""

import base64
from typing import Dict

from Crypto.Cipher import AES

from shared.crypto_utils import sha256_bytes


class VaultCrypto:
    """AES-GCM encryption / decryption for vault payloads."""

    @staticmethod
    def derive_data_key(master_password: str) -> bytes:
        """Derive a 256-bit AES key from *master_password* using SHA-256."""
        return sha256_bytes(master_password.encode("utf-8"))

    @staticmethod
    def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Dict[str, str]:
        """Encrypt *plaintext* with AES-GCM and return a JSON-serialisable dict.

        The returned dict contains base64-encoded *nonce*, *ciphertext*, and
        authentication *tag*.
        """
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return {
            "nonce": base64.b64encode(cipher.nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
        }

    @staticmethod
    def aes_gcm_decrypt(key: bytes, encrypted_blob: Dict[str, str]) -> bytes:
        """Decrypt *encrypted_blob* (produced by :meth:`aes_gcm_encrypt`) using *key*.

        Raises :class:`ValueError` if authentication fails.
        """
        nonce = base64.b64decode(encrypted_blob["nonce"])
        ciphertext = base64.b64decode(encrypted_blob["ciphertext"])
        tag = base64.b64decode(encrypted_blob["tag"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
