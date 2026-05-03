import json
from pathlib import Path

from elGamal.diffie_hellman import DiffieHellman
from elGamal.signature import ElGamalSignature
from elGamal.keys import ElGamalPublicKey
from shared.crypto_utils import sha256_bytes, sha256_int
from vaultManager import VaultManager
from vaultManager.crypto import VaultCrypto
from auth.signer import VaultSigner
from shared.export_import_helpers import file_pooling


class VaultSender:

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

    def _sessions_dir(self, username: str) -> Path:
        return self.base_dir / "users" / username / "sessions"

    def init_parameters(self, sender: str, receiver: str) -> None:
        self.sender = sender
        self.receiver = receiver

        self.sender_gamal_public_key = self.signer.load_public_key(sender)
        self.sender_gamal_private_key = self.signer.load_private_key(sender)

        dh_params = self.dh_params()
        self.q = dh_params["q"]
        self.alpha = dh_params["alpha"]

    def key_exchange_sender(self) -> None:
        # sender generates DH keypair
        self.sender_DH_pair = DiffieHellman.generate_DH_key_pair(self.q, self.alpha)

        # hash public key
        public_dh_sender_hashed = sha256_int(
            str(self.sender_DH_pair[1]).encode("utf-8")
        )
        # sign the hash
        self.r_dh, self.s_dh = ElGamalSignature.sign(
            self.sender_gamal_private_key, public_dh_sender_hashed
        )

        data = {
            "sender": self.sender,
            "receiver": self.receiver,
            "dh_public_key": self.sender_DH_pair[1],
            "sender_gamal_public_key": {
                "p": self.sender_gamal_public_key.p,
                "alpha": self.sender_gamal_public_key.alpha,
                "y": self.sender_gamal_public_key.y,
            },
            "signature": {"r": self.r_dh, "s": self.s_dh},
        }

        # load to handshake folder
        sessions_dir = self._sessions_dir(self.receiver)
        sessions_dir.mkdir(parents=True, exist_ok=True)
        sender_file = sessions_dir / f"{self.sender}.json"
        sender_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"[Sender] Handshake written. Waiting for receiver ({self.receiver})...")

        # poll for receiver handshake file
        receiver_file = sessions_dir / f"{self.receiver}.json"
        file_pooling(receiver_file)

        other_data = json.loads(receiver_file.read_text(encoding="utf-8"))

        self.receiver_gamal_public_key = ElGamalPublicKey(
            p=other_data["receiver_gamal_public_key"]["p"],
            alpha=other_data["receiver_gamal_public_key"]["alpha"],
            y=other_data["receiver_gamal_public_key"]["y"],
        )

        self.recipient_dh_public = other_data["dh_public_key"]
        recipient_dh_sig = other_data["signature"]

        # verify receiver DH public key signature
        public_dh_receiver_hashed = sha256_int(
            str(self.recipient_dh_public).encode("utf-8")
        )
        if not ElGamalSignature.verify(
            self.receiver_gamal_public_key,
            public_dh_receiver_hashed,
            (recipient_dh_sig["r"], recipient_dh_sig["s"]),
        ):
            raise ValueError(
                "Receiver DH key signature verification failed — aborting."
            )

        # calc session key
        shared_secret = DiffieHellman.generate_shared_secret(
            self.sender_DH_pair[0], self.recipient_dh_public, self.q
        )
        self.session_key = sha256_bytes(str(shared_secret).encode("utf-8"))
        print("[Sender] Key exchange complete.")

    def transfer_vault(self, sender_master_password: str) -> str:
        # decrypt vault in memory
        entries = self.vault_manager._load_entries(self.sender, sender_master_password)

        # re-encrypt with session key
        encrypted_payload = VaultCrypto.aes_gcm_encrypt(
            self.session_key,
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

        # sign the encrypted payload
        payload_digest = sha256_int(encrypted_payload.encode("utf-8"))
        sig_r, sig_s = ElGamalSignature.sign(
            self.sender_gamal_private_key, payload_digest
        )

        # write export package
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
        return f"[{self.sender}] Vault package written to {vault_file}"

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
