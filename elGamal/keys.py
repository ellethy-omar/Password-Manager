"""ElGamal key dataclasses."""

from dataclasses import dataclass


@dataclass
class ElGamalPrivateKey:
    """Holds the ElGamal private key material *(p, alpha, x)*."""
    p: int       # large prime (group modulus)
    alpha: int   # primitive root modulo p
    x: int       # secret exponent


@dataclass
class ElGamalPublicKey:
    """Holds the ElGamal public key material *(p, alpha, y)*."""
    p: int       # large prime (group modulus)
    alpha: int   # primitive root modulo p
    y: int       # public value: y = alpha^x mod p
