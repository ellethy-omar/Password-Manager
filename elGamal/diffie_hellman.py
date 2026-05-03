import secrets
from typing import Tuple

# use secrets as random is a deterministic
# If someone can guess or recover the internal state, they can predict future “random” numbers.
# static method to be use class without initialize
import secrets


class DiffieHellman:

    @staticmethod
    def generate_DH_key_pair(q: int, alpha: int) -> Tuple[int, int]:
        # pick random x private less than q - 1
        DH_private_key = secrets.randbelow(q - 1)
        DH_public_key = pow(alpha, DH_private_key, q)
        return DH_private_key, DH_public_key

    @staticmethod
    def generate_shared_secret(
        own_private_key: int, other_device_public_key: int, q: int
    ) -> int:
        shared_secret = pow(other_device_public_key, own_private_key, q)
        return shared_secret
    
    @staticmethod
    def generate_keypair(q: int, alpha: int) -> Tuple[int, int]:
        private_key = secrets.randbelow(q - 2) + 2
        public_key = pow(alpha, private_key, q)
        return private_key, public_key

    @staticmethod
    def shared_secret(peer_public_key: int, own_private_key: int, q: int) -> int:
        return pow(peer_public_key, own_private_key, q)
