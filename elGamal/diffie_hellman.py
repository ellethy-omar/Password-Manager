"""Diffie-Hellman key exchange, implemented from scratch.

Ephemeral DH key pairs are generated per export session.
"""

import secrets
from typing import Tuple


class DiffieHellman:
    """From-scratch Diffie-Hellman key exchange."""

    @staticmethod
    def generate_keypair(q: int, alpha: int) -> Tuple[int, int]:
        """Generate an ephemeral DH key pair *(private, public)* for group (q, alpha).

        Returns *(private_key, public_key)* where private_key is in [2, q-1]
        and public_key = alpha^private_key mod q.
        """
        private_key = secrets.randbelow(q - 2) + 2   # in [2, q-1]
        public_key = pow(alpha, private_key, q)
        return private_key, public_key

    @staticmethod
    def shared_secret(peer_public_key: int, own_private_key: int, q: int) -> int:
        """Compute the shared secret as peer_public_key^own_private_key mod q."""
        return pow(peer_public_key, own_private_key, q)
