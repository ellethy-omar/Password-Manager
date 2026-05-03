import json
from pathlib import Path

from elGamal.diffie_hellman import DiffieHellman
from elGamal.signature import ElGamalSignature
from elGamal.keys import ElGamalPublicKey
from shared.crypto_utils import sha256_bytes, sha256_int
from vaultManager.crypto import VaultCrypto
from vaultManager import VaultManager
from auth.signer import VaultSigner
from shared.export_import_helpers import file_pooling


class VaultReceiver:

    def __init__(
        self, base_dir: Path, vault_manager: VaultManager, signer: VaultSigner
    ):
        self.base_dir = base_dir
        self.vault_manager = vault_manager
        self.signer = signer

    def params_path(self) -> Path:
        return self.base_dir / "config" / "crypto_params.json"

    def dh_params(self):
        return json.loads(self.params_path().read_text(encoding="utf-8"))[
            "diffie_hellman"
        ]

    def sessions_dir(self, username: str) -> Path:
        return self.base_dir / "users" / username / "sessions"

    def init_parameters(self, sender: str, receiver: str) -> None:
        self.sender = sender
        self.receiver = receiver

        self.receiver_gamal_public_key = self.signer.load_public_key(receiver)
        self.receiver_gamal_private_key = self.signer.load_private_key(receiver)

        dh_params = self.dh_params()
        self.q = dh_params["q"]
        self.alpha = dh_params["alpha"]

    def key_exchange_receiver(self) -> None:
        # Receiver Generates DH keypair
        self.receiver_DH_pair = DiffieHellman.generate_DH_key_pair(self.q, self.alpha)

        # Hash Public Key Pair
        public_dh_receiver_hashed = sha256_int(
            str(self.receiver_DH_pair[1]).encode("utf-8")
        )

        # Sign Hash with private key
        self.r_dh, self.s_dh = ElGamalSignature.sign(
            self.receiver_gamal_private_key, public_dh_receiver_hashed
        )

        # generate data to be sent
        data = {
            "sender": self.sender,
            "receiver": self.receiver,
            "dh_public_key": self.receiver_DH_pair[1],
            "receiver_gamal_public_key": {
                "p": self.receiver_gamal_public_key.p,
                "alpha": self.receiver_gamal_public_key.alpha,
                "y": self.receiver_gamal_public_key.y,
            },
            "signature": {"r": self.r_dh, "s": self.s_dh},
        }

        # send in dir exchange file
        sessions_dir = self.sessions_dir(self.receiver)
        sessions_dir.mkdir(parents=True, exist_ok=True)
        receiver_file = sessions_dir / f"{self.receiver}.json"
        receiver_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"[Receiver] Handshake written. Waiting for sender ({self.sender})...")

        # poll for sender's handshake file
        sender_file = sessions_dir / f"{self.sender}.json"
        file_pooling(sender_file)

        other_data = json.loads(sender_file.read_text(encoding="utf-8"))

        # Reconstruct the ElGamalPublicKey
        self.sender_gamal_public_key = ElGamalPublicKey(
            p=other_data["sender_gamal_public_key"]["p"],
            alpha=other_data["sender_gamal_public_key"]["alpha"],
            y=other_data["sender_gamal_public_key"]["y"],
        )

        self.sender_dh_public = other_data["dh_public_key"]
        sender_dh_sig = other_data["signature"]

        # verify senders DH public key signature
        public_dh_sender_hashed = sha256_int(str(self.sender_dh_public).encode("utf-8"))
        if not ElGamalSignature.verify(
            self.sender_gamal_public_key,
            public_dh_sender_hashed,
            (sender_dh_sig["r"], sender_dh_sig["s"]),
        ):
            self.cleanup_session(sessions_dir)
            raise ValueError("Sender DH key signature verification failed — aborting.")

        # calc session key
        shared_secret = DiffieHellman.generate_shared_secret(
            self.receiver_DH_pair[0], self.sender_dh_public, self.q
        )
        self.session_key = sha256_bytes(str(shared_secret).encode("utf-8"))
        print("[Receiver] Key exchange complete.")

    def import_vault(self, receiver_master_password: str) -> str:
        sessions_dir = self.sessions_dir(self.receiver)
        vault_file = sessions_dir / f"{self.sender}_vault.json"

        # wait for vault package
        print(f"[Receiver] Waiting for vault package from {self.sender}...")
        file_pooling(vault_file)

        sender_package = json.loads(vault_file.read_text(encoding="utf-8"))

        # verify encrypted payload signature
        encrypted_blob = sender_package["payload"]["encrypted_blob"]
        encrypted_blob_signature = sender_package["payload"]["signature"]

        encrypted_blob_digest = sha256_int(encrypted_blob.encode("utf-8"))
        if not ElGamalSignature.verify(
            self.sender_gamal_public_key,
            encrypted_blob_digest,
            (encrypted_blob_signature["r"], encrypted_blob_signature["s"]),
        ):
            self.cleanup_session(sessions_dir)
            raise ValueError("Sender payload signature verification failed — aborting.")

        # decrypt with session key
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

        # 5 clean up all session files and ephemeral keys and ciphertext
        return self.cleanup_session(sessions_dir)

    def cleanup_session(self, sessions_dir: Path) -> str:
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
        return f"[Receiver : {self.receiver}] Session files deleted."
