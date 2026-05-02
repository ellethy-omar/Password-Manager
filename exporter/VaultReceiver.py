import json
import time
import os
from pathlib import Path

from elGamal.diffie_hellman import DiffieHellman
from elGamal.signature import ElGamalSignature
from shared.crypto_utils import sha256_bytes, sha256_int
from vaultManager.crypto import VaultCrypto
from vaultManager import VaultManager
from auth.signer import VaultSigner


import secrets


class VaultReceiver:

    def __init__(
        self, base_dir: Path, vault_manager: VaultManager, signer: VaultSigner
    ):
        # base dir -> base directory path
        # vault_manager : Used to read credential entries from the sender's vault.
        # signer :  Used to load ElGamal keys and sign/verify payloads.
        self.base_dir = base_dir
        self.vault_manager = vault_manager
        self.signer = signer

    def _params_path(self) -> Path:
        # return path to configuration parameters
        return self.base_dir / "config" / "crypto_params.json"

    def _dh_params(self):
        return json.loads(self._params_path().read_text(encoding="utf-8"))[
            "diffie_hellman"
        ]

    def _sessions_dir(self, username: str) -> Path:
        return self.base_dir / "users" / username / "sessions"

    def init_parameters(self, sender, receiver):
        self.sender = sender
        self.receiver = receiver

        # Loads Gamal Public and Private Keys
        self.receiver_gamal_public_key = self.signer.load_public_key(receiver)
        self.receiver_gamal_private_key = self.signer.load_private_key(receiver)

        # read DH Parameters
        DH_params = self._dh_params()
        self.q = DH_params["q"]
        self.alpha = DH_params["alpha"]

    def key_exchange_receiver(self):
        # receiver Generates His DH Key
        self.receiver_DH_pair = DiffieHellman.generate_DH_key_pair(self.q, self.alpha)

        # Take public DH key hash it  {m = Hash(A)}
        public_dh_sender_hashed = sha256_int(
            str(self.receiver_DH_pair[1]).encode("utf-8")
        )

        # Sign Hash with Private Gamal Key
        self.r_dh, self.s_dh = ElGamalSignature.sign(
            self.receiver_gamal_private_key, public_dh_sender_hashed
        )

        # Send To Other User A | r | s
        data = {
            "sender": self.sender,
            "receiver": self.receiver,
            "dh_public_key": self.receiver_DH_pair[1],
            "receiver_gamal_public_key": self.receiver_gamal_public_key,
            "signature": {"r": self.r_dh, "s": self.s_dh},
        }

        folder = self._sessions_dir(self.receiver)
        with open(os.path.join(folder, f"{self.receiver}.json"), "w") as f:
            time.sleep(10)
            json.dump(data, f, indent=2)
        print("Waiting for Sender...")

        # Take Data From Receiver
        with open(os.path.join(folder, f"{self.sender}.json"), "r") as f:
            other_data = json.load(f)

        self.sender_gamal_public_key = other_data["sender_gamal_public_key"]
        self.sender_dh_public = other_data["dh_public_key"]
        sender_dh_sig = other_data["signature"]

        # Hash Public key of Device 1 (A) m = H(A)
        public_dh_receiver_hashed = sha256_int(self.sender_dh_public)

        # Receober verifies the signature
        did_receiver_verify = ElGamalSignature.verify(
            self.sender_gamal_public_key,
            public_dh_receiver_hashed,
            (sender_dh_sig["r"], sender_dh_sig["s"]),
        )

        if not did_receiver_verify:
            raise ValueError("Sender DH key signature verification failed")

        # compute the shared secret.
        shared_secret = DiffieHellman.generate_shared_secret(
            self.receiver_DH_pair[0], self.sender_dh_public, self.q
        )

        self.session_key = sha256_bytes(str(shared_secret).encode("utf-8"))

    def import_vault(self, receiver_master_password):
        time.sleep(10)
        folder = self._sessions_dir(self.receiver)
        with open(os.path.join(folder, f"{self.sender}_vault.json"), "r") as f:
            sender_package = json.load(f)

        # Hash Public key of Device 1 (A) m = H(A)
        public_dh_receiver_hashed = sha256_int(self.sender_dh_public)
        sender_dh_signature = sender_package["sender_dh_signature"]

        # Receiver verifies the signature
        did_receiver_verify = ElGamalSignature.verify(
            self.sender_gamal_public_key,
            public_dh_receiver_hashed,
            (sender_dh_signature["r"], sender_dh_signature["s"]),
        )

        if not did_receiver_verify:
            raise ValueError("Sender DH key signature verification failed")

        encrypted_blob = sender_package["payload"]["encrypted_blob"]
        encrypted_blob_signature = sender_package["payload"]["signature"]

        encrypted_blob_digest = sha256_int(encrypted_blob.encode("utf-8"))

        did_receiver_verify_payload = ElGamalSignature.verify(
            self.sender_gamal_public_key,
            encrypted_blob_digest,
            (encrypted_blob_signature["r"], encrypted_blob_signature["s"]),
        )

        if not did_receiver_verify_payload:
            raise ValueError("Sender Payload signature verification failed")

        decrypted_payload = VaultCrypto.aes_gcm_decrypt(
            self.session_key,
            encrypted_blob,
        )

        entries = json.loads(decrypted_payload.decode("utf-8"))
        self.vault_manager._store_entries(
            self.receiver, receiver_master_password, entries
        )
