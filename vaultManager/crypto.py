"""AES-GCM symmetric encryption helpers used by the vault manager."""

import base64
from Crypto.Cipher import AES

from shared.crypto_utils import sha256_bytes


class VaultCrypto:
    """AES-GCM encryption / decryption for vault payloads."""

    @staticmethod
    def derive_data_key(master_password: str) -> bytes:
        """Derive a 256-bit AES key from *master_password* using SHA-256."""
        return sha256_bytes(master_password.encode("utf-8"))

    # AFTER
    @staticmethod
    def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> str:
        """Returns a single base64 string: nonce(16) + tag(16) + ciphertext."""
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        combined = cipher.nonce + tag + ciphertext   # type: ignore
        return base64.b64encode(combined).decode("utf-8")

    @staticmethod
    def aes_gcm_decrypt(key: bytes, encrypted_blob: str) -> bytes:
        """Accepts the single base64 string produced by aes_gcm_encrypt."""
        raw = base64.b64decode(encrypted_blob)
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
