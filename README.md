# Secure Password Manager

This project is a command-line secure password manager implementing:

- **Module 1:** ElGamal key generation and key storage
- **Module 2:** Vault encryption/decryption with **AES-GCM** using a key from `SHA-256(master_password)`
- **Module 3:** ElGamal digital signatures for vault integrity
- **Module 4:** Diffie-Hellman based vault export/import with signature checks

## Requirements

- Python 3.10+

## Setup

```bash
python3 -m pip install -r requirements.txt
```

## CLI Usage

All commands accept `--base-dir` (default: `data`) to choose storage location.

### 1) Initialize users

```bash
python3 password_manager.py init-user --user alice --master-password alice-secret
python3 password_manager.py init-user --user bob --master-password bob-secret
```

### 2) Manage credentials

```bash
python3 password_manager.py add --user alice --master-password alice-secret --site github.com --username alice --password p@ssw0rd
python3 password_manager.py retrieve --user alice --master-password alice-secret --site github.com --username alice
python3 password_manager.py update --user alice --master-password alice-secret --site github.com --username alice --new-password n3w-p@ss
python3 password_manager.py delete --user alice --master-password alice-secret --site github.com --username alice
python3 password_manager.py list --user alice --master-password alice-secret
```

### 3) Verify integrity

```bash
python3 password_manager.py verify --user alice
```

If vault ciphertext/metadata is modified manually, verification fails and vault operations are blocked.

### 4) Secure export/import (Diffie-Hellman)

```bash
python3 password_manager.py prepare-import --recipient bob --sender alice --out transfer/recipient-session.json
python3 password_manager.py export --sender alice --master-password alice-secret --recipient-session transfer/recipient-session.json --out transfer/package.json
python3 password_manager.py import --recipient bob --sender alice --master-password bob-secret --package transfer/package.json
```

Export uses ephemeral Diffie-Hellman keys per session and signatures on key exchange + transferred encrypted payload.
Import re-encrypts the vault with recipient's master-password-derived AES key and re-signs with recipient's ElGamal key.

## Files Created

Under `--base-dir`:

- `config/crypto_params.json` shared ElGamal and DH parameters
- `users/<username>/elgamal_private.json` private key (permissions tightened)
- `users/<username>/elgamal_public.json` public key
- `users/<username>/vault.json` encrypted and signed vault
- `users/<username>/sessions/<session_id>.json` temporary DH import session state
