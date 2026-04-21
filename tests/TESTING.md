# Testing Guide

This document explains how to run the test suite – both module-by-module and as a full end-to-end integration test.

---

## Prerequisites

Install the project's Python dependency:

```bash
pip install -r requirements.txt
```

All test files are in the `tests/` directory and use Python's built-in `unittest` framework, so no extra testing libraries are required.

---

## Running the Full Test Suite

From the repository root:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## Running Individual Module Tests

### shared – Crypto helpers and prime utilities

```bash
python -m unittest tests.test_shared -v
```

Tests:

| Test | What it validates |
|---|---|
| `test_sha256_bytes_known_value` | SHA-256 output matches reference |
| `test_sha256_int_is_big_endian` | Integer conversion is big-endian |
| `test_modular_inverse_basic` | Inverse of 3 mod 11 |
| `test_modular_inverse_larger` | Inverse for several values mod a prime |
| `test_known_primes` | Miller-Rabin accepts known primes |
| `test_known_composites` | Miller-Rabin rejects composites |
| `test_generate_safe_prime_structure` | p = 2q+1, both prime |
| `test_find_generator` | Generator is not a trivial element |

---

### elGamal – Module 1

```bash
python -m unittest tests.test_elgamal -v
```

Tests:

| Test | What it validates |
|---|---|
| `test_keygen_types` | Keygen returns correct dataclass types |
| `test_keygen_public_key_relation` | y = alpha^x mod p |
| `test_sign_and_verify_valid` | Valid signature verifies |
| `test_verify_wrong_message_fails` | Tampered message rejects |
| `test_verify_wrong_key_fails` | Wrong public key rejects |
| `test_verify_invalid_r_rejected` | r = 0 rejected |
| `test_shared_secret_matches` | DH shared secret is symmetric |
| `test_different_sessions_different_keys` | Ephemeral keys differ each session |

---

### vaultManager – Module 2

```bash
python -m unittest tests.test_vault_manager -v
```

Tests:

| Test | What it validates |
|---|---|
| `test_derive_data_key_length` | AES key is 32 bytes |
| `test_derive_data_key_deterministic` | Same password → same key |
| `test_derive_data_key_different_passwords` | Different passwords → different keys |
| `test_encrypt_decrypt_roundtrip` | AES-GCM round-trip |
| `test_decrypt_with_wrong_key_fails` | Wrong key raises exception |
| `test_each_encryption_uses_fresh_nonce` | Fresh nonce per encrypt call |

---

### auth – Module 3

```bash
python -m unittest tests.test_auth -v
```

Tests:

| Test | What it validates |
|---|---|
| `test_fresh_vault_is_valid` | Newly created vault passes verification |
| `test_vault_valid_after_add` | Vault re-signed after adding a credential |
| `test_tampered_ciphertext_fails` | Ciphertext modification detected |
| `test_tampered_nonce_fails` | Nonce modification detected |
| `test_tampered_tag_fails` | Tag modification detected |
| `test_tampered_signer_fails` | Signer field change detected |
| `test_invalid_vault_blocks_read` | Tampered vault blocks list_credentials |

---

### exporter – Module 4

```bash
python -m unittest tests.test_exporter -v
```

Tests:

| Test | What it validates |
|---|---|
| `test_basic_export_import` | Full DH transfer round-trip |
| `test_bob_vault_re_signed_after_import` | Bob's vault is signed with Bob's key |
| `test_tampered_package_payload_rejected` | In-transit tampering aborts import |
| `test_wrong_sender_rejected` | Mismatched sender aborts export |
| `test_session_state_cleaned_up_after_import` | Ephemeral state removed after import |

---

### End-to-End (E2E) Tests

```bash
python -m unittest tests.test_e2e -v
```

These tests exercise the full stack from `PasswordManagerApp` down through every module:

| Test | What it validates |
|---|---|
| `test_full_credential_lifecycle` | Add → retrieve → update → delete |
| `test_vault_invalid_after_tamper_blocks_all_reads` | Tamper blocks all reads |
| `test_full_export_import` | Multi-credential export and import |
| `test_export_import_uses_recipient_master_password` | Vault inaccessible with wrong password |
| `test_signatures_protect_against_mitm` | MITM tampering rejected |

---

## Legacy Tests

`tests/test_password_manager.py` contains the original monolithic tests.  They can be removed once the new suite provides equivalent coverage.
