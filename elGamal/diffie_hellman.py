import secrets
from typing import Tuple


class DiffieHellman:

    @staticmethod
    def generate_keypair(q: int, alpha: int) -> Tuple[int, int]:
        private_key = secrets.randbelow(q - 2) + 2
        public_key = pow(alpha, private_key, q)
        return private_key, public_key

    @staticmethod
    def shared_secret(peer_public_key: int, own_private_key: int, q: int) -> int:
        return pow(peer_public_key, own_private_key, q)
