import json
import time
import os
from pathlib import Path

from elGamal.diffie_hellman import DiffieHellman
from elGamal.signature import ElGamalSignature
from shared.crypto_utils import sha256_bytes, sha256_int
from vaultManager import VaultManager
from vaultManager.crypto import VaultCrypto
from auth.signer import VaultSigner

import secrets


class VaultSender:

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
        self.sender_gamal_public_key = self.signer.load_public_key(sender)
        self.sender_gamal_private_key = self.signer.load_private_key(sender)

        # read DH Parameters
        DH_params = self._dh_params()
        self.q = DH_params["q"]
        self.alpha = DH_params["alpha"]

    def key_exchange_sender(self):
        # Sender Generates His DH Key
        self.sender_DH_pair = DiffieHellman.generate_DH_key_pair(self.q, self.alpha)

        # Take public DH key hash it  {m = Hash(A)}
        public_dh_sender_hashed = sha256_int(
            str(self.sender_DH_pair[1]).encode("utf-8")
        )

        # Sign Hash with Private Gamal Key
        self.r_dh, self.s_dh = ElGamalSignature.sign(
            self.sender_gamal_private_key, public_dh_sender_hashed
        )

        # Send To Other User A | r | s
        data = {
            "sender": self.sender,
            "receiver": self.receiver,
            "dh_public_key": self.sender_DH_pair[1],
            "sender_gamal_public_key":  self.sender_gamal_public_key,
            "signature": {"r": self.r_dh, "s": self.s_dh},
        }

        folder = self._sessions_dir(self.receiver)
        with open(os.path.join(folder, f"{self.sender}.json"), "w") as f:
            json.dump(data, f, indent=2)
        print("Waiting for receiver...")
        time.sleep(10)

        # Take Data From Receiver
        with open(os.path.join(folder, f"{self.receiver}.json"), "r") as f:
            other_data = json.load(f)

        self.receiver_gamal_public_key = other_data["receiver_gamal_public_key"]
        self.recipient_dh_public = other_data["dh_public_key"]
        recipient_dh_sig = other_data["signature"]

        # Hash Public key of Device 1 (A) m = H(A)
        public_dh_receiver_hashed = sha256_int(self.recipient_dh_public)

        # Sender verifies the signature
        did_sender_verify = ElGamalSignature.verify(
            self.receiver_gamal_public_key,
            public_dh_receiver_hashed,
            (recipient_dh_sig["r"], recipient_dh_sig["s"]),
        )

        if not did_sender_verify:
            raise ValueError("Sender DH key signature verification failed")

        # compute the shared secret.
        shared_secret = DiffieHellman.generate_shared_secret(
            self.sender_DH_pair[0], self.recipient_dh_public, self.q
        )

        self.session_key = sha256_bytes(str(shared_secret).encode("utf-8"))

    def transfer_vault(self, sender_master_password):
        # Decrypt vault in memory
        entries = self.vault_manager._load_entries(self.sender, sender_master_password)

        # re-encrypt with the session key.
        encrypted_payload = VaultCrypto.aes_gcm_encrypt(
            self.session_key,
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

        # Sign the encrypted vault directly — same pattern as VaultSigner.sign_and_save.
        payload_digest = sha256_int(encrypted_payload.encode("utf-8"))
        sig_r, sig_s = ElGamalSignature.sign(
            self.sender_gamal_private_key, payload_digest
        )

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

        folder = self._sessions_dir(self.receiver)
        with open(os.path.join(folder, f"{self.sender}_vault.json"), "w") as f:
            json.dump(package, f, indent=2)
            time.sleep(10)
