import json
import time
from pathlib import Path

from elGamal.diffie_hellman import DiffieHellman
from elGamal.signature import ElGamalSignature
from elGamal.keys import ElGamalPublicKey
from shared.crypto_utils import sha256_bytes, sha256_int
from vaultManager.crypto import VaultCrypto
from vaultManager import VaultManager
from auth.signer import VaultSigner


_HANDSHAKE_TIMEOUT = 120
_POLL_INTERVAL = 1


def _wait_for_file(path: Path, timeout: int = _HANDSHAKE_TIMEOUT) -> None:
    elapsed = 0
    while True:
        if path.exists() and path.stat().st_size > 0:
            return
        time.sleep(_POLL_INTERVAL)
        elapsed += _POLL_INTERVAL
        if elapsed >= timeout:
            raise TimeoutError(
                f"Timed out after {timeout}s waiting for {path}. "
                "Make sure the sender terminal has started."
            )


def _public_key_to_dict(key: ElGamalPublicKey) -> dict:
    return { 
        "p": key.p, 
        "alpha": key.alpha, 
        "y": key.y
    }


def _public_key_from_dict(d: dict) -> ElGamalPublicKey:
    return ElGamalPublicKey(p=d["p"], alpha=d["alpha"], y=d["y"])


class VaultReceiver:

    def __init__(
        self, base_dir: Path, vault_manager: VaultManager, signer: VaultSigner
    ):
        self.base_dir = base_dir
        self.vault_manager = vault_manager
        self.signer = signer

    def _params_path(self) -> Path:
        return self.base_dir / "config" / "crypto_params.json"

    def _dh_params(self):
        return json.loads(self._params_path().read_text(encoding="utf-8"))[
            "diffie_hellman"
        ]

    def _sessions_dir(self, username: str) -> Path:
        return self.base_dir / "users" / username / "sessions"

    def init_parameters(self, sender: str, receiver: str) -> None:
        self.sender = sender
        self.receiver = receiver

        self.receiver_gamal_public_key = self.signer.load_public_key(receiver)
        self.receiver_gamal_private_key = self.signer.load_private_key(receiver)

        dh_params = self._dh_params()
        self.q = dh_params["q"]
        self.alpha = dh_params["alpha"]

    def key_exchange_receiver(self) -> None:
        # 1 — ephemeral DH keypair
        self.receiver_DH_pair = DiffieHellman.generate_DH_key_pair(self.q, self.alpha)

        # 2 — sign H(DH_public)
        public_dh_receiver_hashed = sha256_int(
            str(self.receiver_DH_pair[1]).encode("utf-8")
        )
        self.r_dh, self.s_dh = ElGamalSignature.sign(
            self.receiver_gamal_private_key, public_dh_receiver_hashed
        )

        # 3 — write handshake file
        # ElGamalPublicKey must be a plain dict — custom objects are not JSON-serializable.
        data = {
            "sender": self.sender,
            "receiver": self.receiver,
            "dh_public_key": self.receiver_DH_pair[1],
            "receiver_gamal_public_key": _public_key_to_dict(self.receiver_gamal_public_key),
            "signature": {
                "r": self.r_dh, 
                "s": self.s_dh
            },
        }
        sessions_dir = self._sessions_dir(self.receiver)
        sessions_dir.mkdir(parents=True, exist_ok=True)
        receiver_file = sessions_dir / f"{self.receiver}.json"
        receiver_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"[Receiver] Handshake written. Waiting for sender ({self.sender})...")

        # 4 — poll for sender's handshake file
        sender_file = sessions_dir / f"{self.sender}.json"
        _wait_for_file(sender_file)

        other_data = json.loads(sender_file.read_text(encoding="utf-8"))

        # Reconstruct the ElGamalPublicKey object from the deserialized dict
        self.sender_gamal_public_key = _public_key_from_dict(
            other_data["sender_gamal_public_key"]
        )
        self.sender_dh_public = other_data["dh_public_key"]
        sender_dh_sig = other_data["signature"]

        # 5 — verify sender's DH public key signature
        public_dh_sender_hashed = sha256_int(
            str(self.sender_dh_public).encode("utf-8")
        )
        if not ElGamalSignature.verify(
            self.sender_gamal_public_key,
            public_dh_sender_hashed,
            (sender_dh_sig["r"], sender_dh_sig["s"]),
        ):
            self._cleanup_session(sessions_dir)
            raise ValueError("Sender DH key signature verification failed — aborting.")

        # 6 — derive session key
        shared_secret = DiffieHellman.generate_shared_secret(
            self.receiver_DH_pair[0], self.sender_dh_public, self.q
        )
        self.session_key = sha256_bytes(str(shared_secret).encode("utf-8"))
        print("[Receiver] Key exchange complete.")

    def import_vault(self, receiver_master_password: str) -> None:
        """
        Import Phase.

        1. Poll until the sender's vault package appears.
        2. Verify the payload signature using sender's ElGamal public key.
        3. Decrypt the payload with the session key.
        4. Re-encrypt entries under the receiver's master password and re-sign (Module 3).
        5. Delete all session files now that the transfer is complete.
        """
        sessions_dir = self._sessions_dir(self.receiver)
        vault_file = sessions_dir / f"{self.sender}_vault.json"

        # 1 — wait for vault package
        print(f"[Receiver] Waiting for vault package from {self.sender}...")
        _wait_for_file(vault_file)

        sender_package = json.loads(vault_file.read_text(encoding="utf-8"))

        # 2 — verify encrypted payload signature
        encrypted_blob = sender_package["payload"]["encrypted_blob"]
        encrypted_blob_signature = sender_package["payload"]["signature"]

        encrypted_blob_digest = sha256_int(encrypted_blob.encode("utf-8"))
        if not ElGamalSignature.verify(
            self.sender_gamal_public_key,
            encrypted_blob_digest,
            (encrypted_blob_signature["r"], encrypted_blob_signature["s"]),
        ):
            self._cleanup_session(sessions_dir)
            raise ValueError("Sender payload signature verification failed — aborting.")

        # 3 — decrypt with session key
        decrypted_payload = VaultCrypto.aes_gcm_decrypt(
            self.session_key,
            encrypted_blob,
        )
        entries = json.loads(decrypted_payload.decode("utf-8"))

        # 4 — re-encrypt under receiver's master password and re-sign (Module 3)
        self.vault_manager._store_entries(
            self.receiver, receiver_master_password, entries
        )
        print("[Receiver] Vault imported and re-signed successfully.")

        # 5 — clean up all session files so ephemeral keys and ciphertext
        #     don't linger on disk after the transfer is complete.
        self._cleanup_session(sessions_dir)

    def _cleanup_session(self, sessions_dir: Path) -> None:
        """Delete all files written during this session."""
        files_to_delete = [
            sessions_dir / f"{self.sender}.json",
            sessions_dir / f"{self.receiver}.json",
            sessions_dir / f"{self.sender}_vault.json",
        ]
        for f in files_to_delete:
            try:
                f.unlink()
            except FileNotFoundError:
                pass  # already gone, nothing to do
        print("[Receiver] Session files deleted.")