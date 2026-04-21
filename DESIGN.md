# Design Notes

## Cryptographic Choices

- **AES-GCM** is used for vault and transfer payload encryption (`AES.new(key, AES.MODE_GCM)`).
- **SHA-256** is used for:
  - master password -> data key derivation
  - vault/payload digest prior to signing
  - Diffie-Hellman shared secret -> session key derivation
- **ElGamal signatures** are implemented from scratch:
  - key generation
  - signature generation `(r, s)`
  - verification equation
- **Diffie-Hellman key exchange** is implemented from scratch:
  - ephemeral private/public pair generation per export
  - shared secret computation

## Parameters and Key Lifecycle

- Shared parameters are generated once and stored in `config/crypto_params.json`.
- ElGamal long-lived key pairs are created once per user at initialization.
- DH keys are ephemeral and generated per export session.

## Vault Format

Vault JSON stores encrypted fields and signature metadata:

- `nonce`
- `ciphertext`
- `tag`
- `signer`
- `signature: { r, s }`

The signature is computed over encrypted fields + signer metadata, so any bit flip breaks verification.

## Export / Import Workflow

1. Sender and recipient create ephemeral DH key pairs.
2. Each DH public key is signed and verified with long-lived ElGamal keys.
3. Shared secret is derived and converted to a session AES key via SHA-256.
4. Sender decrypts local vault in memory, encrypts plaintext entries with session key, signs encrypted payload, and writes package.
5. Recipient verifies signature, derives same session key, decrypts payload, re-encrypts with recipient master password key, and re-signs with recipient key.

## Challenges / Trade-offs

- Implementing ElGamal and DH safely required parameter generation support. The code generates safe-prime groups with Miller-Rabin primality checks for demonstration purposes.
- Session state for recipient import is temporarily stored per transfer session to keep the export/import flow deterministic in a CLI environment.
