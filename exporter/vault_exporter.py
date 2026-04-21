"""Secure vault export and import using Diffie-Hellman key exchange (Module 4).

Workflow
--------
1. Recipient calls :meth:`VaultExporter.prepare_import_session` to generate
   an ephemeral DH keypair, sign the public key, and write a handshake file
   for the sender.  A private session state is saved locally.

2. Sender calls :meth:`VaultExporter.export_vault` which:
   - Reads the recipient handshake file.
   - Verifies the recipient's signed DH public key.
   - Generates its own ephemeral DH keypair and signs it.
   - Derives the shared AES session key.
   - Decrypts the local vault in memory and re-encrypts with the session key.
   - Signs the encrypted payload.
   - Writes the transfer package.

3. Recipient calls :meth:`VaultExporter.import_vault` which:
   - Reads the package and the saved session state.
   - Verifies the sender's signed DH public key.
   - Verifies the payload signature.
   - Derives the same shared secret.
   - Decrypts the payload and stores the entries under the recipient's key.
"""

import json
import os
import secrets
from pathlib import Path
from typing import Dict

from elGamal.diffie_hellman import DiffieHellman
from elGamal.signature import ElGamalSignature
from shared.crypto_utils import sha256_bytes, sha256_int
from vaultManager.crypto import VaultCrypto
from auth.signer import VaultSigner


class VaultExporter:
    """Handles cross-device vault transfer with DH key exchange and ElGamal signatures."""

    def __init__(self, base_dir: Path, vault_manager, signer: VaultSigner):
        """
        Parameters
        ----------
        base_dir : Path
            Root directory for user data and shared config.
        vault_manager : vaultManager.VaultManager
            Used to read credential entries from the sender's vault.
        signer : auth.VaultSigner
            Used to load ElGamal keys and sign/verify payloads.
        """
        self.base_dir = base_dir
        self.vault_manager = vault_manager
        self.signer = signer

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _params_path(self) -> Path:
        return self.base_dir / "config" / "crypto_params.json"

    def _dh_params(self) -> Dict[str, int]:
        return json.loads(self._params_path().read_text(encoding="utf-8"))["diffie_hellman"]

    def _sessions_dir(self, username: str) -> Path:
        return self.base_dir / "users" / username / "sessions"

    # ------------------------------------------------------------------
    # Phase 1 – recipient prepares session
    # ------------------------------------------------------------------

    def prepare_import_session(
        self,
        recipient: str,
        sender: str,
        handshake_path: Path,
    ) -> None:
        """Generate an ephemeral DH keypair for *recipient*, sign the public key,
        and write a handshake file to *handshake_path* for the sender to read.

        A private session-state file is saved under the recipient's sessions dir.

        Parameters
        ----------
        recipient : str
            The username receiving the vault.
        sender : str
            The username who will send the vault (used for cross-checking).
        handshake_path : Path
            Where to write the handshake file for the sender.
        """
        dh_params = self._dh_params()
        q, alpha = dh_params["q"], dh_params["alpha"]

        recipient_private_key = self.signer.load_private_key(recipient)
        dh_private, dh_public = DiffieHellman.generate_keypair(q, alpha)

        # Sign the recipient's DH public key with their long-lived ElGamal key.
        dh_digest = sha256_int(str(dh_public).encode("utf-8"))
        sig_r, sig_s = ElGamalSignature.sign(recipient_private_key, dh_digest)
        session_id = secrets.token_hex(16)

        # --- Public handshake file (shared with sender) ---
        handshake = {
            "session_id": session_id,
            "recipient": recipient,
            "sender": sender,
            "recipient_dh_public": dh_public,
            "recipient_dh_signature": {"r": sig_r, "s": sig_s},
        }
        handshake_path.parent.mkdir(parents=True, exist_ok=True)
        handshake_path.write_text(json.dumps(handshake, indent=2), encoding="utf-8")

        # --- Private session state (stays on recipient device) ---
        sessions_dir = self._sessions_dir(recipient)
        sessions_dir.mkdir(parents=True, exist_ok=True)
        state_file = sessions_dir / f"{session_id}.json"
        state_file.write_text(
            json.dumps(
                {
                    "session_id": session_id,
                    "recipient": recipient,
                    "sender": sender,
                    "dh_private": dh_private,
                    "q": q,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        os.chmod(state_file, 0o600)

    # ------------------------------------------------------------------
    # Phase 2 – sender exports
    # ------------------------------------------------------------------

    def export_vault(
        self,
        sender: str,
        sender_master_password: str,
        recipient_handshake_path: Path,
        package_path: Path,
    ) -> None:
        """Verify the recipient's DH handshake, encrypt the vault, and write a
        signed transfer package to *package_path*.

        Parameters
        ----------
        sender : str
            Username of the exporting user.
        sender_master_password : str
            Master password used to decrypt the sender's local vault.
        recipient_handshake_path : Path
            Path to the handshake file produced by :meth:`prepare_import_session`.
        package_path : Path
            Destination for the signed transfer package.
        """
        handshake = json.loads(recipient_handshake_path.read_text(encoding="utf-8"))
        recipient = handshake["recipient"]
        if handshake["sender"] != sender:
            raise ValueError("Recipient session sender mismatch")

        dh_params = self._dh_params()
        q, alpha = dh_params["q"], dh_params["alpha"]

        # Verify the recipient's signed DH public key.
        recipient_dh_public = handshake["recipient_dh_public"]
        recipient_public_key = self.signer.load_public_key(recipient)
        recipient_dh_sig = handshake["recipient_dh_signature"]
        recipient_dh_digest = sha256_int(str(recipient_dh_public).encode("utf-8"))
        if not ElGamalSignature.verify(
            recipient_public_key,
            recipient_dh_digest,
            (recipient_dh_sig["r"], recipient_dh_sig["s"]),
        ):
            raise ValueError("Recipient DH key signature verification failed")

        # Generate sender's ephemeral DH keypair and sign the public key.
        sender_dh_private, sender_dh_public = DiffieHellman.generate_keypair(q, alpha)
        sender_private_key = self.signer.load_private_key(sender)
        sender_dh_digest = sha256_int(str(sender_dh_public).encode("utf-8"))
        sender_dh_sig = ElGamalSignature.sign(sender_private_key, sender_dh_digest)

        # Derive the session AES key from the Diffie-Hellman shared secret.
        shared_secret = DiffieHellman.shared_secret(recipient_dh_public, sender_dh_private, q)
        session_key = sha256_bytes(str(shared_secret).encode("utf-8"))

        # Decrypt the sender's vault in memory and re-encrypt with the session key.
        entries = self.vault_manager._load_entries(sender, sender_master_password)
        encrypted_payload = VaultCrypto.aes_gcm_encrypt(
            session_key,
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

        # Build the package and sign the encrypted payload.
        package: Dict = {
            "session_id": handshake["session_id"],
            "sender": sender,
            "recipient": recipient,
            "sender_dh_public": sender_dh_public,
            "sender_dh_signature": {"r": sender_dh_sig[0], "s": sender_dh_sig[1]},
            "recipient_dh_public": recipient_dh_public,
            "payload": {**encrypted_payload, "signer": sender},
        }
        payload_digest = sha256_int(self.signer.signature_payload(package["payload"]))
        sig_r, sig_s = ElGamalSignature.sign(sender_private_key, payload_digest)
        package["payload"]["signature"] = {"r": sig_r, "s": sig_s}

        package_path.parent.mkdir(parents=True, exist_ok=True)
        package_path.write_text(json.dumps(package, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # Phase 3 – recipient imports
    # ------------------------------------------------------------------

    def import_vault(
        self,
        recipient: str,
        sender: str,
        recipient_master_password: str,
        package_path: Path,
    ) -> None:
        """Verify, decrypt, and store the transfer package as the recipient's vault.

        Parameters
        ----------
        recipient : str
            Username of the receiving user.
        sender : str
            Username of the sending user.
        recipient_master_password : str
            Master password used to re-encrypt the vault on the recipient's side.
        package_path : Path
            Path to the transfer package written by :meth:`export_vault`.
        """
        package = json.loads(package_path.read_text(encoding="utf-8"))
        if package["sender"] != sender or package["recipient"] != recipient:
            raise ValueError("Package sender/recipient mismatch")

        # Load and validate the saved DH session state.
        state_file = self._sessions_dir(recipient) / f"{package['session_id']}.json"
        if not state_file.exists():
            raise ValueError("Missing DH session state for this import")
        session = json.loads(state_file.read_text(encoding="utf-8"))
        if session["sender"] != sender or session["recipient"] != recipient:
            raise ValueError("Session sender/recipient mismatch")

        sender_public_key = self.signer.load_public_key(sender)

        # Verify sender's signed DH public key.
        sender_dh_sig = package["sender_dh_signature"]
        sender_dh_digest = sha256_int(str(package["sender_dh_public"]).encode("utf-8"))
        if not ElGamalSignature.verify(
            sender_public_key, sender_dh_digest, (sender_dh_sig["r"], sender_dh_sig["s"])
        ):
            raise ValueError("Sender DH key signature verification failed")

        # Verify the encrypted payload signature.
        payload = package["payload"]
        payload_sig = payload["signature"]
        payload_digest = sha256_int(self.signer.signature_payload(payload))
        if not ElGamalSignature.verify(
            sender_public_key, payload_digest, (payload_sig["r"], payload_sig["s"])
        ):
            raise ValueError("Transferred vault signature verification failed")

        # Derive the shared session key and decrypt.
        shared_secret = DiffieHellman.shared_secret(
            package["sender_dh_public"],
            session["dh_private"],
            session["q"],
        )
        session_key = sha256_bytes(str(shared_secret).encode("utf-8"))
        plaintext = VaultCrypto.aes_gcm_decrypt(session_key, payload)

        # Re-encrypt under the recipient's master password and re-sign.
        import json as _json
        entries = _json.loads(plaintext.decode("utf-8"))
        self.vault_manager._store_entries(recipient, recipient_master_password, entries)

        # Clean up ephemeral session state.
        state_file.unlink(missing_ok=True)
