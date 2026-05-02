# import json
# import time
# from pathlib import Path

# from elGamal.diffie_hellman import DiffieHellman
# from elGamal.signature import ElGamalSignature
# from shared.crypto_utils import sha256_bytes, sha256_int
# from vaultManager.crypto import VaultCrypto
# from auth.signer import VaultSigner


# import secrets


# class VaultImporterExporter:

#     def __init__(self, base_dir: Path, vault_manager: VaultCrypto, signer: VaultSigner):
#         # base dir -> base directory path
#         # vault_manager : Used to read credential entries from the sender's vault.
#         # signer :  Used to load ElGamal keys and sign/verify payloads.
#         self.base_dir = base_dir
#         self.vault_manager = vault_manager
#         self.signer = signer

#     # path private helpers
#     def _params_path(self) -> Path:
#         return self.base_dir / "config" / "crypto_params.json"

#     def _dh_params(self):
#         return json.loads(self._params_path().read_text(encoding="utf-8"))[
#             "diffie_hellman"
#         ]

#     def init_params(self, sender, receiver, action):
#         self.sender = sender
#         self.sender = receiver
#         self.sender = action

#         # Loads Gamal Public and Private Keys
#         self.sender_gamal_public_key = self.signer.load_public_key(sender)
#         self.sender_gamal_private_key = self.signer.load_private_key(sender)

#         DH_params = self._dh_params()
#         self.q = DH_params["q"]
#         self.alpha = DH_params["alpha"]

#     def _sessions_dir(self, username: str) -> Path:
#         return self.base_dir / "users" / username / "sessions"

#     # phase 1 : key exchange
#     def key_exchage_phase(self, sender: str, receiver: str, action: str):
#         self.init_params(sender, receiver, action)

#         # Generate DH key pair of both parties
#         self.sender_DH_pair = DiffieHellman.generate_DH_key_pair(self.q, self.alpha)

#         # Take public DH key hash it  {m = Hash(A)}
#         public_dh_sender_hashed = sha256_int(self.sender_DH_pair[1])

#         # Sign Hash with Private Gamal Key
#         self.r, self.s = ElGamalSignature.sign(
#             self.sender_gamal_private_key, public_dh_sender_hashed
#         )

#         # Send To Other User A | r | s
#         data = {
#             "sender": sender,
#             "receiver": receiver,
#             "dh_public_key": sender_DH_pair[1],
#             "signature": {"r": r, "s": s},
#         }

#         folder = self._sessions_dir(receiver)

#         if action == "sender":
#             # SENDER: write first, then wait
#             with open(os.path.join(folder, f"{sender}.json"), "w") as f:
#                 json.dump(data, f, indent=2)
#             print("Waiting for receiver...")
#             time.sleep(10)

#         elif action == "receiver":
#             # RECEIVER: wait first, then write
#             print("Waiting for sender...")
#             time.sleep(10)
#             with open(os.path.join(folder, f"{sender}.json"), "w") as f:
#                 json.dump(data, f, indent=2)

#         # === READ OTHER DEVICE'S FILE ===
#         with open(os.path.join(folder, f"{receiver}.json"), "r") as f:
#             other_data = json.load(f)

#         receiver_gamal_public_key = self.signer.load_public_key(receiver)
#         self.recipient_dh_public = other_data["dh_public_key"]
#         recipient_dh_sig = other_data["signature"]

#         # Hash Public key of Device 1 (A) m = H(A)
#         public_dh_receiver_hashed = sha256_int(recipient_dh_public)

#         # Device verifies the signature
#         did_sender_verify = ElGamalSignature.verify(
#             receiver_gamal_public_key,
#             public_dh_receiver_hashed,
#             (recipient_dh_sig["r"], recipient_dh_sig["s"]),
#         )

#         if not did_sender_verify:
#             raise ValueError("Sender DH key signature verification failed")

#         # compute the shared secret.
#         shared_secret = DiffieHellman.generate_shared_secret(
#             sender_DH_pair[0], recipient_dh_public
#         )

#         self.session_key = sha256_bytes(shared_secret)

#     # Transfer Phase
#     def transfer_phase(sender: str, sender_master_password: str):
#         # Decrypt vault in memory
#         entries = self.vault_manager._load_entries(sender, sender_master_password)

#         # re-encrypt with the session key.
#         encrypted_payload = VaultCrypto.aes_gcm_encrypt(
#             self.session_key,
#             json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8"),
#         )

#         # Sign the encrypted vault directly — same pattern as VaultSigner.sign_and_save.
#         payload_digest = sha256_int(encrypted_payload.encode("utf-8"))
#         sig_r, sig_s = ElGamalSignature.sign(
#             self.sender_gamal_private_key, payload_digest
#         )

#         package: Dict = {
#             "sender": self.sender,
#             "recipient": self.recipient,
#             "sender_dh_public": self.sender_dh_public,
#             "sender_dh_signature": {"r": self.r, "s": self.s},
#             "recipient_dh_public": self.recipient_dh_public,
#             "payload": {
#                 "encrypted_blob": encrypted_payload,
#                 "signer": sender,
#                 "signature": {"r": sig_r, "s": sig_s},
#             },
#         }

#         folder = self._sessions_dir(receiver)

#         if self.action == "sender":
#             # SENDER: write first, then wait
#             with open(os.path.join(folder, f"{sender}_vault.json"), "w") as f:
#                 json.dump(data, f, indent=2)
#             time.sleep(10)

#     def import_phase(self, master_password):
#         with open(os.path.join(folder, f"{self.receiver}_vault.json"), "r") as f:
#             other_data = json.load(f)
            
#         receiver_gamal_public_key = self.signer.load_public_key(self.receiver)
#         self.recipient_dh_public = other_data["dh_public_key"]
#         recipient_dh_sig = other_data["signature"]
            
        
