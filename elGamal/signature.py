"""ElGamal digital signature: key generation, signing, and verification.

All three operations are implemented from scratch as required by the spec.
"""

import math
import secrets
from typing import Tuple

from elGamal.keys import ElGamalPrivateKey, ElGamalPublicKey
from shared.crypto_utils import modular_inverse


class ElGamalSignature:
    """From-scratch ElGamal signature scheme."""

    @staticmethod
    def keygen(p: int, alpha: int) -> Tuple[ElGamalPrivateKey, ElGamalPublicKey]:
        """Generate an ElGamal key pair for the group (p, alpha).

        *p* must be a large prime and *alpha* a primitive root modulo *p*.
        """
        x = secrets.randbelow(p - 3) + 2          # private exponent in [2, p-2]
        y = pow(alpha, x, p)                       # public value
        return (
            ElGamalPrivateKey(p=p, alpha=alpha, x=x),
            ElGamalPublicKey(p=p, alpha=alpha, y=y),
        )

    @staticmethod
    def sign(private_key: ElGamalPrivateKey, message_hash: int) -> Tuple[int, int]:
        """Sign an integer message hash and return the signature *(r, s)*.

        *k* is chosen freshly and uniformly at random for each signature
        (gcd(k, p-1) == 1 is required for the inverse to exist).
        """
        p = private_key.p
        while True:
            k = secrets.randbelow(p - 3) + 2
            if math.gcd(k, p - 1) != 1:
                # k must be coprime with p-1 so that k^{-1} mod (p-1) exists.
                continue
            r = pow(private_key.alpha, k, p)
            k_inv = modular_inverse(k, p - 1)
            s = ((message_hash - private_key.x * r) * k_inv) % (p - 1)
            if s != 0:
                return r, s

    @staticmethod
    def verify(
        public_key: ElGamalPublicKey,
        message_hash: int,
        signature: Tuple[int, int],
    ) -> bool:
        """Verify signature *(r, s)* against a public key and message hash.

        Returns True only when the signature is mathematically valid.
        """
        r, s = signature
        if not (1 <= r <= public_key.p - 1):
            return False
        if not (0 <= s <= public_key.p - 2):
            return False
        left = (
            pow(public_key.y, r, public_key.p)
            * pow(r, s, public_key.p)
        ) % public_key.p
        right = pow(public_key.alpha, message_hash, public_key.p)
        return left == right
