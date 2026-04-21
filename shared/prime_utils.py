"""Prime generation utilities shared by ElGamal and Diffie-Hellman modules."""

import secrets
from typing import Tuple


def is_probable_prime(value: int, rounds: int = 16) -> bool:
    """Miller-Rabin primality test.  Returns True when *value* is very likely prime."""
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
    """Generate a safe prime *p = 2q + 1* where both *p* and *q* are prime.

    Returns *(p, q)*.  *bits* controls the bit-length of *p*.
    """
    while True:
        # Set the second-highest bit to ensure the required bit-length and
        # the lowest bit to ensure q is odd.
        q = secrets.randbits(bits - 1)
        q |= (1 << (bits - 2)) | 1
        if not is_probable_prime(q):
            continue
        p = 2 * q + 1
        if is_probable_prime(p):
            return p, q


def find_generator_for_safe_prime(p: int, q: int) -> int:
    """Return a primitive root modulo the safe prime *p = 2q + 1*."""
    for g in range(2, p - 1):
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g
    raise RuntimeError("No generator found")
