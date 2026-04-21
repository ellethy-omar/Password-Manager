# Secure Password Manager

A command-line password manager implementing four cryptographic modules:

- **Module 1 – ElGamal Key Management** (`elGamal/`)
- **Module 2 – Vault Encryption & Credential Management** (`vaultManager/`)
- **Module 3 – Digital Signatures for Vault Integrity** (`auth/`)
- **Module 4 – Secure Vault Export via Diffie-Hellman** (`exporter/`)

## Project Structure

```
.
├── run.py               # Entry-point – run this instead of python3 ...
├── requirements.txt
├── shared/              # Shared crypto helpers, prime utilities, constants
├── elGamal/             # ElGamal keygen, signature, and Diffie-Hellman (from scratch)
├── vaultManager/        # AES-GCM encryption and credential CRUD
├── auth/                # Vault signing and signature verification
├── exporter/            # DH-based secure vault export and import
├── CLI/                 # Argument parser, command dispatcher, and app wiring
└── tests/               # Unit tests per module + E2E tests + TESTING.md
```

## Requirements

```bash
python3 -m pip install -r requirements.txt
```

## Running the CLI

Use `run.py` from the repository root:

```bash
python3 run.py <command> [options]
python3 run.py --help
```

`--base-dir <path>` (default: `data/`) controls where all user data is stored.

### 1) Initialize users

```bash
python3 run.py init-user --user alice --master-password alice-secret
python3 run.py init-user --user bob   --master-password bob-secret
```

### 2) Manage credentials

```bash
python3 run.py add      --user alice --master-password alice-secret --site github.com --username alice --password p@ss
python3 run.py retrieve --user alice --master-password alice-secret --site github.com --username alice
python3 run.py list     --user alice --master-password alice-secret
python3 run.py update   --user alice --master-password alice-secret --site github.com --username alice --new-password n3wp@ss
python3 run.py delete   --user alice --master-password alice-secret --site github.com --username alice
```

### 3) Verify vault integrity

```bash
python3 run.py verify --user alice
```

### 4) Secure export / import (Diffie-Hellman)

Run on the **recipient** device first to create the authenticated DH handshake:

```bash
python3 run.py prepare-import \
    --recipient bob --sender alice \
    --out transfer/recipient-session.json
```

Then run on the **sender** device to export:

```bash
python3 run.py export \
    --sender alice --master-password alice-secret \
    --recipient-session transfer/recipient-session.json \
    --out transfer/package.json
```

Finally run on the **recipient** device to import:

```bash
python3 run.py import \
    --recipient bob --sender alice \
    --master-password bob-secret \
    --package transfer/package.json
```

## Running Tests

See [`tests/TESTING.md`](tests/TESTING.md) for detailed per-module instructions.

```bash
# Full suite
python3 -m unittest discover -s tests -p "test_*.py" -v

# Individual module
python3 -m unittest tests.test_elgamal -v
python3 -m unittest tests.test_vault_manager -v
python3 -m unittest tests.test_auth -v
python3 -m unittest tests.test_exporter -v
python3 -m unittest tests.test_e2e -v
```

## Files Created at Runtime

Under `--base-dir` (default `data/`):

| Path | Description |
|---|---|
| `config/crypto_params.json` | Shared ElGamal and DH parameters (generated once) |
| `users/<user>/elgamal_private.json` | Private key (chmod 600) |
| `users/<user>/elgamal_public.json` | Public key (shareable) |
| `users/<user>/vault.json` | AES-GCM encrypted and ElGamal-signed vault |
| `users/<user>/sessions/<id>.json` | Ephemeral DH import session state |
