"""Top-level application controller.

PasswordManagerApp wires together all modules and exposes the public methods
called by the CLI dispatcher.  It owns the shared parameters file, user
initialisation, and key-management paths.
"""

import json
import os
from pathlib import Path
from typing import Dict

from shared.constants import DEFAULT_DATA_DIR, PARAMS_PATH
from shared.prime_utils import generate_safe_prime, find_generator_for_safe_prime
from elGamal.signature import ElGamalSignature
from auth.signer import VaultSigner
from vaultManager.manager import VaultManager
from vaultManager.crypto import VaultCrypto
from exporter.VaultSender import VaultSender
from exporter.VaultReceiver import VaultReceiver


class PasswordManagerApp:
    def __init__(self, base_dir: Path = DEFAULT_DATA_DIR):
        self.base_dir = base_dir
        self.params_path = base_dir / PARAMS_PATH
 
        self.signer = VaultSigner(base_dir)
        self.vault_manager = VaultManager(base_dir, self.signer)
        self.sender = VaultSender(base_dir, self.vault_manager, self.signer)
        self.receiver = VaultReceiver(base_dir, self.vault_manager, self.signer)

    def ensure_parameters(self) -> Dict:
        if self.params_path.exists():
            return json.loads(self.params_path.read_text(encoding="utf-8"))

        self.params_path.parent.mkdir(parents=True, exist_ok=True)
        elgamal_p, elgamal_q = generate_safe_prime(bits=256)
        elgamal_alpha = find_generator_for_safe_prime(elgamal_p, elgamal_q)
        dh_q, dh_sub_q = generate_safe_prime(bits=256)
        dh_alpha = find_generator_for_safe_prime(dh_q, dh_sub_q)

        params = {
            "elgamal": {"p": elgamal_p, "alpha": elgamal_alpha},
            "diffie_hellman": {"q": dh_q, "alpha": dh_alpha},
        }
        self.params_path.write_text(json.dumps(params, indent=2), encoding="utf-8")
        return params

    def initialize_user(self, username: str, master_password: str) -> None:
        params = self.ensure_parameters()["elgamal"]
        user_dir = self.base_dir / "users" / username
        user_dir.mkdir(parents=True, exist_ok=True)

        private_key_path = user_dir / "elgamal_private.json"
        if private_key_path.exists():
            raise ValueError(f"User '{username}' already initialized")

        private_key, public_key = ElGamalSignature.keygen(params["p"], params["alpha"])

        private_key_path.write_text(
            json.dumps(
                {"p": private_key.p, "alpha": private_key.alpha, "x": private_key.x},
                indent=2,
            ),
            encoding="utf-8",
        )
        (user_dir / "elgamal_public.json").write_text(
            json.dumps(
                {"p": public_key.p, "alpha": public_key.alpha, "y": public_key.y},
                indent=2,
            ),
            encoding="utf-8",
        )

        os.chmod(private_key_path, 0o600)

        self.vault_manager.initialize_vault(username, master_password)

    def add_credential(self, username, master_password, site, login, password):
        self.vault_manager.add_credential(username, master_password, site, login, password)

    def list_credentials(self, username, master_password):
        return self.vault_manager.list_credentials(username, master_password)

    def retrieve_credential(self, username, master_password, site):
        return self.vault_manager.retrieve_credential(username, master_password, site)

    def update_credential(self, username, master_password, site, login, new_password):
        self.vault_manager.update_credential(username, master_password, site, login, new_password)

    def delete_credential(self, username, master_password, site, login):
        self.vault_manager.delete_credential(username, master_password, site, login)

    def verify_vault(self, username: str) -> bool:
        path = self.base_dir / "users" / username / "vault.json"
        vault = json.loads(path.read_text(encoding="utf-8"))
        return self.signer.verify(vault, username)

    def export_vault(self, sender: str, master_password: str, receiver: str) -> None:
        self.sender.init_parameters(sender, receiver)
        self.sender.key_exchange_sender()
        self.sender.transfer_vault(master_password)

    def import_vault(self, receiver: str, sender: str, master_password: str) -> None:
        self.receiver.init_parameters(sender, receiver)
        self.receiver.key_exchange_receiver()
        self.receiver.import_vault(master_password)
 
