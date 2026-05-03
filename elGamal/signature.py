import math
import secrets
from typing import Tuple

from elGamal.keys import ElGamalPrivateKey, ElGamalPublicKey
from shared.crypto_utils import modular_inverse


class ElGamalSignature:

    @staticmethod
    def keygen(p: int, alpha: int) -> Tuple[ElGamalPrivateKey, ElGamalPublicKey]:
        x = secrets.randbelow(p - 3) + 2
        y = pow(alpha, x, p)
        return (
            ElGamalPrivateKey(p=p, alpha=alpha, x=x),
            ElGamalPublicKey(p=p, alpha=alpha, y=y),
        )

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
    def verify(
        public_key: ElGamalPublicKey,
        message_hash: int,
        signature: Tuple[int, int],
    ) -> bool:
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
