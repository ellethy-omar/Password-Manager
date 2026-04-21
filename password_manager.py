#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import math
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from Crypto.Cipher import AES


DEFAULT_DATA_DIR = Path("data")
PARAMS_PATH = Path("config/crypto_params.json")


def _int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def sha256_bytes(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def sha256_int(payload: bytes) -> int:
    return int.from_bytes(sha256_bytes(payload), "big")


def modular_inverse(value: int, modulus: int) -> int:
    return pow(value, -1, modulus)


def is_probable_prime(value: int, rounds: int = 16) -> bool:
    if value in (2, 3):
        return True
    if value <= 1 or value % 2 == 0:
        return False

    d = value - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(value - 3) + 2
        x = pow(a, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, value)
            if x == value - 1:
                break
        else:
            return False
    return True


def generate_safe_prime(bits: int = 256) -> Tuple[int, int]:
    while True:
        q = secrets.randbits(bits - 1)
        q |= (1 << (bits - 2)) | 1
        if not is_probable_prime(q):
            continue
        p = 2 * q + 1
        if is_probable_prime(p):
            return p, q


def find_generator_for_safe_prime(p: int, q: int) -> int:
    for g in range(2, p - 1):
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g
    raise RuntimeError("No generator found")


@dataclass
class ElGamalPrivateKey:
    p: int
    alpha: int
    x: int


@dataclass
class ElGamalPublicKey:
    p: int
    alpha: int
    y: int


class ElGamalSignature:
    @staticmethod
    def keygen(p: int, alpha: int) -> Tuple[ElGamalPrivateKey, ElGamalPublicKey]:
        x = secrets.randbelow(p - 3) + 2
        y = pow(alpha, x, p)
        return ElGamalPrivateKey(p=p, alpha=alpha, x=x), ElGamalPublicKey(p=p, alpha=alpha, y=y)

    @staticmethod
    def sign(private_key: ElGamalPrivateKey, message_hash: int) -> Tuple[int, int]:
        p = private_key.p
        while True:
            k = secrets.randbelow(p - 3) + 2
            if math.gcd(k, p - 1) != 1:
                continue
            r = pow(private_key.alpha, k, p)
            k_inv = modular_inverse(k, p - 1)
            s = ((message_hash - private_key.x * r) * k_inv) % (p - 1)
            if s != 0:
                return r, s

    @staticmethod
    def verify(public_key: ElGamalPublicKey, message_hash: int, signature: Tuple[int, int]) -> bool:
        r, s = signature
        if not (1 <= r <= public_key.p - 1):
            return False
        if not (0 <= s <= public_key.p - 2):
            return False
        left = (pow(public_key.y, r, public_key.p) * pow(r, s, public_key.p)) % public_key.p
        right = pow(public_key.alpha, message_hash, public_key.p)
        return left == right


class DiffieHellman:
    @staticmethod
    def generate_keypair(q: int, alpha: int) -> Tuple[int, int]:
        private_key = secrets.randbelow(q - 3) + 2
        public_key = pow(alpha, private_key, q)
        return private_key, public_key

    @staticmethod
    def shared_secret(peer_public_key: int, own_private_key: int, q: int) -> int:
        return pow(peer_public_key, own_private_key, q)


class VaultCrypto:
    @staticmethod
    def derive_data_key(master_password: str) -> bytes:
        return sha256_bytes(master_password.encode("utf-8"))

    @staticmethod
    def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Dict[str, str]:
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return {
            "nonce": base64.b64encode(cipher.nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
        }

    @staticmethod
    def aes_gcm_decrypt(key: bytes, encrypted_blob: Dict[str, str]) -> bytes:
        nonce = base64.b64decode(encrypted_blob["nonce"])
        ciphertext = base64.b64decode(encrypted_blob["ciphertext"])
        tag = base64.b64decode(encrypted_blob["tag"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)


class PasswordManager:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.params_path = self.base_dir / PARAMS_PATH

    def ensure_parameters(self) -> Dict[str, int]:
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

    def _user_dir(self, username: str) -> Path:
        return self.base_dir / "users" / username

    def _private_key_path(self, username: str) -> Path:
        return self._user_dir(username) / "elgamal_private.json"

    def _public_key_path(self, username: str) -> Path:
        return self._user_dir(username) / "elgamal_public.json"

    def _vault_path(self, username: str) -> Path:
        return self._user_dir(username) / "vault.json"

    def _sessions_dir(self, username: str) -> Path:
        return self._user_dir(username) / "sessions"

    @staticmethod
    def _signature_payload(vault_like: Dict[str, str]) -> bytes:
        payload = {
            "ciphertext": vault_like["ciphertext"],
            "nonce": vault_like["nonce"],
            "tag": vault_like["tag"],
            "signer": vault_like["signer"],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _load_private_key(self, username: str) -> ElGamalPrivateKey:
        key = json.loads(self._private_key_path(username).read_text(encoding="utf-8"))
        return ElGamalPrivateKey(p=key["p"], alpha=key["alpha"], x=key["x"])

    def _load_public_key(self, username: str) -> ElGamalPublicKey:
        key = json.loads(self._public_key_path(username).read_text(encoding="utf-8"))
        return ElGamalPublicKey(p=key["p"], alpha=key["alpha"], y=key["y"])

    def _save_vault(self, username: str, encrypted_blob: Dict[str, str], signer: str) -> None:
        private_key = self._load_private_key(signer)
        vault = {**encrypted_blob, "signer": signer}
        digest = sha256_int(self._signature_payload(vault))
        r, s = ElGamalSignature.sign(private_key, digest)
        vault["signature"] = {"r": r, "s": s}
        self._vault_path(username).write_text(json.dumps(vault, indent=2), encoding="utf-8")

    def _verify_vault_signature(self, username: str, vault: Dict[str, str]) -> bool:
        signer = vault["signer"]
        public_key = self._load_public_key(signer)
        digest = sha256_int(self._signature_payload(vault))
        sig = vault["signature"]
        return ElGamalSignature.verify(public_key, digest, (sig["r"], sig["s"]))

    def initialize_user(self, username: str, master_password: str) -> None:
        params = self.ensure_parameters()["elgamal"]
        user_dir = self._user_dir(username)
        user_dir.mkdir(parents=True, exist_ok=True)

        if self._private_key_path(username).exists():
            raise ValueError(f"User '{username}' already initialized")

        private_key, public_key = ElGamalSignature.keygen(params["p"], params["alpha"])
        self._private_key_path(username).write_text(
            json.dumps({"p": private_key.p, "alpha": private_key.alpha, "x": private_key.x}, indent=2),
            encoding="utf-8",
        )
        self._public_key_path(username).write_text(
            json.dumps({"p": public_key.p, "alpha": public_key.alpha, "y": public_key.y}, indent=2),
            encoding="utf-8",
        )
        os.chmod(self._private_key_path(username), 0o600)

        data_key = VaultCrypto.derive_data_key(master_password)
        encrypted = VaultCrypto.aes_gcm_encrypt(data_key, b"[]")
        self._save_vault(username, encrypted, signer=username)

    def _load_entries(self, username: str, master_password: str) -> List[Dict[str, str]]:
        vault = json.loads(self._vault_path(username).read_text(encoding="utf-8"))
        if not self._verify_vault_signature(username, vault):
            raise ValueError("Vault signature verification failed. Possible tampering detected.")
        data_key = VaultCrypto.derive_data_key(master_password)
        plaintext = VaultCrypto.aes_gcm_decrypt(data_key, vault)
        return json.loads(plaintext.decode("utf-8"))

    def _store_entries(self, username: str, master_password: str, entries: List[Dict[str, str]]) -> None:
        data_key = VaultCrypto.derive_data_key(master_password)
        encrypted = VaultCrypto.aes_gcm_encrypt(
            data_key,
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        self._save_vault(username, encrypted, signer=username)

    def add_credential(self, username: str, master_password: str, site: str, login: str, password: str) -> None:
        entries = self._load_entries(username, master_password)
        entries.append({"site": site, "username": login, "password": password})
        self._store_entries(username, master_password, entries)

    def list_credentials(self, username: str, master_password: str) -> List[Dict[str, str]]:
        return self._load_entries(username, master_password)

    def retrieve_credential(self, username: str, master_password: str, site: str, login: str = "") -> Dict[str, str]:
        entries = self._load_entries(username, master_password)
        for entry in entries:
            if entry["site"] == site and (not login or entry["username"] == login):
                return entry
        raise ValueError("Credential not found")

    def update_credential(self, username: str, master_password: str, site: str, login: str, new_password: str) -> None:
        entries = self._load_entries(username, master_password)
        for entry in entries:
            if entry["site"] == site and entry["username"] == login:
                entry["password"] = new_password
                self._store_entries(username, master_password, entries)
                return
        raise ValueError("Credential not found")

    def delete_credential(self, username: str, master_password: str, site: str, login: str) -> None:
        entries = self._load_entries(username, master_password)
        updated = [e for e in entries if not (e["site"] == site and e["username"] == login)]
        if len(updated) == len(entries):
            raise ValueError("Credential not found")
        self._store_entries(username, master_password, updated)

    def export_vault(self, sender: str, recipient: str, sender_master_password: str, package_path: Path) -> None:
        params = self.ensure_parameters()["diffie_hellman"]
        q = params["q"]
        alpha = params["alpha"]

        sender_dh_private, sender_dh_public = DiffieHellman.generate_keypair(q, alpha)
        recipient_dh_private, recipient_dh_public = DiffieHellman.generate_keypair(q, alpha)

        sender_private = self._load_private_key(sender)
        sender_public = self._load_public_key(sender)
        recipient_private = self._load_private_key(recipient)
        recipient_public = self._load_public_key(recipient)

        sender_pub_hash = sha256_int(str(sender_dh_public).encode("utf-8"))
        sender_pub_sig = ElGamalSignature.sign(sender_private, sender_pub_hash)
        if not ElGamalSignature.verify(sender_public, sender_pub_hash, sender_pub_sig):
            raise ValueError("Sender DH key signature verification failed")

        recipient_pub_hash = sha256_int(str(recipient_dh_public).encode("utf-8"))
        recipient_pub_sig = ElGamalSignature.sign(recipient_private, recipient_pub_hash)
        if not ElGamalSignature.verify(recipient_public, recipient_pub_hash, recipient_pub_sig):
            raise ValueError("Recipient DH key signature verification failed")

        sender_secret = DiffieHellman.shared_secret(recipient_dh_public, sender_dh_private, q)
        recipient_secret = DiffieHellman.shared_secret(sender_dh_public, recipient_dh_private, q)
        if sender_secret != recipient_secret:
            raise ValueError("Diffie-Hellman shared secret mismatch")

        session_key = sha256_bytes(str(sender_secret).encode("utf-8"))
        entries = self._load_entries(sender, sender_master_password)
        encrypted_payload = VaultCrypto.aes_gcm_encrypt(
            session_key,
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

        package = {
            "session_id": secrets.token_hex(16),
            "sender": sender,
            "recipient": recipient,
            "sender_dh_public": sender_dh_public,
            "recipient_dh_public": recipient_dh_public,
            "payload": {**encrypted_payload, "signer": sender},
        }
        payload_digest = sha256_int(self._signature_payload(package["payload"]))
        sig_r, sig_s = ElGamalSignature.sign(sender_private, payload_digest)
        package["payload"]["signature"] = {"r": sig_r, "s": sig_s}

        package_path.parent.mkdir(parents=True, exist_ok=True)
        package_path.write_text(json.dumps(package, indent=2), encoding="utf-8")

        session_state = {
            "session_id": package["session_id"],
            "dh_private": recipient_dh_private,
            "sender_dh_public": sender_dh_public,
            "q": q,
        }
        sessions_dir = self._sessions_dir(recipient)
        sessions_dir.mkdir(parents=True, exist_ok=True)
        session_file = sessions_dir / f"{package['session_id']}.json"
        session_file.write_text(json.dumps(session_state, indent=2), encoding="utf-8")
        os.chmod(session_file, 0o600)

    def import_vault(self, recipient: str, sender: str, recipient_master_password: str, package_path: Path) -> None:
        package = json.loads(package_path.read_text(encoding="utf-8"))
        if package["sender"] != sender or package["recipient"] != recipient:
            raise ValueError("Package sender/recipient mismatch")

        session_file = self._sessions_dir(recipient) / f"{package['session_id']}.json"
        if not session_file.exists():
            raise ValueError("Missing DH session state for this import")
        session = json.loads(session_file.read_text(encoding="utf-8"))

        sender_public = self._load_public_key(sender)
        payload = package["payload"]
        sig = payload["signature"]
        payload_digest = sha256_int(self._signature_payload(payload))
        if not ElGamalSignature.verify(sender_public, payload_digest, (sig["r"], sig["s"])):
            raise ValueError("Transferred vault signature verification failed")

        shared_secret = DiffieHellman.shared_secret(
            session["sender_dh_public"],
            session["dh_private"],
            session["q"],
        )
        session_key = sha256_bytes(str(shared_secret).encode("utf-8"))
        plaintext = VaultCrypto.aes_gcm_decrypt(session_key, payload)

        entries = json.loads(plaintext.decode("utf-8"))
        self._store_entries(recipient, recipient_master_password, entries)
        session_file.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure Password Manager")
    parser.add_argument("--base-dir", type=Path, default=DEFAULT_DATA_DIR, help="Storage directory")

    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init-user", help="Initialize a user and vault")
    init.add_argument("--user", required=True)
    init.add_argument("--master-password", required=True)

    add = subparsers.add_parser("add", help="Add credential")
    add.add_argument("--user", required=True)
    add.add_argument("--master-password", required=True)
    add.add_argument("--site", required=True)
    add.add_argument("--username", required=True)
    add.add_argument("--password", required=True)

    retrieve = subparsers.add_parser("retrieve", help="Retrieve credential")
    retrieve.add_argument("--user", required=True)
    retrieve.add_argument("--master-password", required=True)
    retrieve.add_argument("--site", required=True)
    retrieve.add_argument("--username", default="")

    update = subparsers.add_parser("update", help="Update credential password")
    update.add_argument("--user", required=True)
    update.add_argument("--master-password", required=True)
    update.add_argument("--site", required=True)
    update.add_argument("--username", required=True)
    update.add_argument("--new-password", required=True)

    delete = subparsers.add_parser("delete", help="Delete credential")
    delete.add_argument("--user", required=True)
    delete.add_argument("--master-password", required=True)
    delete.add_argument("--site", required=True)
    delete.add_argument("--username", required=True)

    list_cmd = subparsers.add_parser("list", help="List all credentials")
    list_cmd.add_argument("--user", required=True)
    list_cmd.add_argument("--master-password", required=True)

    export_cmd = subparsers.add_parser("export", help="Export sender vault securely to recipient")
    export_cmd.add_argument("--sender", required=True)
    export_cmd.add_argument("--recipient", required=True)
    export_cmd.add_argument("--master-password", required=True)
    export_cmd.add_argument("--out", type=Path, required=True)

    import_cmd = subparsers.add_parser("import", help="Import transferred vault package")
    import_cmd.add_argument("--recipient", required=True)
    import_cmd.add_argument("--sender", required=True)
    import_cmd.add_argument("--master-password", required=True)
    import_cmd.add_argument("--package", type=Path, required=True)

    verify_cmd = subparsers.add_parser("verify", help="Verify vault signature")
    verify_cmd.add_argument("--user", required=True)

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manager = PasswordManager(args.base_dir)

    try:
        if args.command == "init-user":
            manager.initialize_user(args.user, args.master_password)
            print(f"Initialized user '{args.user}'")
        elif args.command == "add":
            manager.add_credential(args.user, args.master_password, args.site, args.username, args.password)
            print("Credential added and vault re-signed")
        elif args.command == "retrieve":
            item = manager.retrieve_credential(args.user, args.master_password, args.site, args.username)
            print(json.dumps(item, indent=2))
        elif args.command == "update":
            manager.update_credential(args.user, args.master_password, args.site, args.username, args.new_password)
            print("Credential updated and vault re-signed")
        elif args.command == "delete":
            manager.delete_credential(args.user, args.master_password, args.site, args.username)
            print("Credential deleted and vault re-signed")
        elif args.command == "list":
            print(json.dumps(manager.list_credentials(args.user, args.master_password), indent=2))
        elif args.command == "export":
            manager.export_vault(args.sender, args.recipient, args.master_password, args.out)
            print(f"Export package created at {args.out}")
        elif args.command == "import":
            manager.import_vault(args.recipient, args.sender, args.master_password, args.package)
            print("Vault imported and re-signed by recipient")
        elif args.command == "verify":
            vault = json.loads((manager._vault_path(args.user)).read_text(encoding="utf-8"))
            is_valid = manager._verify_vault_signature(args.user, vault)
            if is_valid:
                print("Vault signature is valid")
            else:
                print("Vault signature is INVALID")
                raise SystemExit(1)
    except Exception as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
