"""Hashing helpers shared across all modules."""

import hashlib


def sha256_bytes(payload: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *payload*."""
    return hashlib.sha256(payload).digest()


def sha256_int(payload: bytes) -> int:
    """Return the SHA-256 digest of *payload* as a big-endian integer."""
    return int.from_bytes(sha256_bytes(payload), "big")


def modular_inverse(value: int, modulus: int) -> int:
    """Return the modular multiplicative inverse of *value* mod *modulus*."""
    return pow(value, -1, modulus)
