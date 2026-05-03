import json
import time
from pathlib import Path

from elGamal.diffie_hellman import DiffieHellman
from elGamal.signature import ElGamalSignature
from elGamal.keys import ElGamalPublicKey
from shared.crypto_utils import sha256_bytes, sha256_int
from vaultManager import VaultManager
from vaultManager.crypto import VaultCrypto
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
                "Make sure the receiver terminal has started."
            )


def _public_key_to_dict(key: ElGamalPublicKey) -> dict:
    return {
        "p": key.p, 
        "alpha": key.alpha, 
        "y": key.y
    }


def _public_key_from_dict(d: dict) -> ElGamalPublicKey:
    return ElGamalPublicKey(p=d["p"], alpha=d["alpha"], y=d["y"])


class VaultSender:

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

        self.sender_gamal_public_key = self.signer.load_public_key(sender)
        self.sender_gamal_private_key = self.signer.load_private_key(sender)

        dh_params = self._dh_params()
        self.q = dh_params["q"]
        self.alpha = dh_params["alpha"]

    def key_exchange_sender(self) -> None:
        """
        Key Exchange Phase (sender side).

        1. Generate ephemeral DH keypair.
        2. Sign H(DH_public) with sender's ElGamal private key.
        3. Write {sender}.json to the shared sessions folder.
        4. Poll until {receiver}.json appears.
        5. Verify receiver's DH public key signature.
        6. Derive shared session AES key via SHA-256(shared_secret).
        """
        # 1 — ephemeral DH keypair
        self.sender_DH_pair = DiffieHellman.generate_DH_key_pair(self.q, self.alpha)

        # 2 — sign H(DH_public)
        public_dh_sender_hashed = sha256_int(
            str(self.sender_DH_pair[1]).encode("utf-8")
        )
        self.r_dh, self.s_dh = ElGamalSignature.sign(
            self.sender_gamal_private_key, public_dh_sender_hashed
        )

        # 3 — write handshake file
        # ElGamalPublicKey must be a plain dict — custom objects are not JSON-serializable.
        data = {
            "sender": self.sender,
            "receiver": self.receiver,
            "dh_public_key": self.sender_DH_pair[1],
            "sender_gamal_public_key": _public_key_to_dict(self.sender_gamal_public_key),
            "signature": {"r": self.r_dh, "s": self.s_dh},
        }
        sessions_dir = self._sessions_dir(self.receiver)
        sessions_dir.mkdir(parents=True, exist_ok=True)
        sender_file = sessions_dir / f"{self.sender}.json"
        sender_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"[Sender] Handshake written. Waiting for receiver ({self.receiver})...")

        # 4 — poll for receiver's handshake file
        receiver_file = sessions_dir / f"{self.receiver}.json"
        _wait_for_file(receiver_file)

        other_data = json.loads(receiver_file.read_text(encoding="utf-8"))

        # Reconstruct the ElGamalPublicKey object from the deserialized dict
        self.receiver_gamal_public_key = _public_key_from_dict(
            other_data["receiver_gamal_public_key"]
        )
        self.recipient_dh_public = other_data["dh_public_key"]
        recipient_dh_sig = other_data["signature"]

        # 5 — verify receiver's DH public key signature
        public_dh_receiver_hashed = sha256_int(
            str(self.recipient_dh_public).encode("utf-8")
        )
        if not ElGamalSignature.verify(
            self.receiver_gamal_public_key,
            public_dh_receiver_hashed,
            (recipient_dh_sig["r"], recipient_dh_sig["s"]),
        ):
            raise ValueError("Receiver DH key signature verification failed — aborting.")

        # 6 — derive session key
        shared_secret = DiffieHellman.generate_shared_secret(
            self.sender_DH_pair[0], self.recipient_dh_public, self.q
        )
        self.session_key = sha256_bytes(str(shared_secret).encode("utf-8"))
        print("[Sender] Key exchange complete.")

    def transfer_vault(self, sender_master_password: str) -> None:
        """
        Transfer Phase.

        1. Decrypt vault entries in memory using master password.
        2. Re-encrypt with the session key.
        3. Sign the session-encrypted ciphertext with sender's ElGamal private key.
        4. Write the export package to the shared sessions folder.
        """
        # 1 — decrypt vault in memory
        entries = self.vault_manager._load_entries(self.sender, sender_master_password)

        # 2 — re-encrypt with session key
        encrypted_payload = VaultCrypto.aes_gcm_encrypt(
            self.session_key,
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

        # 3 — sign the encrypted payload
        payload_digest = sha256_int(encrypted_payload.encode("utf-8"))
        sig_r, sig_s = ElGamalSignature.sign(
            self.sender_gamal_private_key, payload_digest
        )

        # 4 — write export package
        package = {
            "sender": self.sender,
            "receiver": self.receiver,
            "sender_dh_signature": {"r": self.r_dh, "s": self.s_dh},
            "payload": {
                "encrypted_blob": encrypted_payload,
                "signer": self.sender,
                "signature": {"r": sig_r, "s": sig_s},
            },
        }
        sessions_dir = self._sessions_dir(self.receiver)
        vault_file = sessions_dir / f"{self.sender}_vault.json"
        vault_file.write_text(json.dumps(package, indent=2), encoding="utf-8")
        print(f"[Sender] Vault package written to {vault_file}")

    def _cleanup_on_failure(self, sessions_dir: Path) -> None:
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