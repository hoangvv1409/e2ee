from os import urandom
from hashlib import sha256
from binascii import hexlify

from .prime_group import primes


class DiffieHellman:
    # Current minimum recommendation is 2048 bit (group 14)
    def __init__(self, group: int = 14) -> None:
        if group not in primes:
            raise ValueError("Unsupported Group")

        self.prime = primes[group]["prime"]
        self.generator = primes[group]["generator"]

        self.__private_key = int(hexlify(urandom(32)), base=16)

    def get_private_key(self) -> str:
        return hex(self.__private_key)[2:]

    def generate_public_key(self) -> str:
        public_key = pow(
            self.generator, self.__private_key, self.prime)

        return hex(public_key)[2:]

    def is_valid_public_key(self, key: int) -> bool:
        # check if the other public key is valid based on NIST SP800-56
        if 2 <= key and key <= self.prime - 2:
            if pow(key, (self.prime - 1) // 2, self.prime) == 1:
                return True

        return False

    def generate_shared_key(self, other_key_str: str) -> str:
        other_key = int(other_key_str, base=16)
        if not self.is_valid_public_key(other_key):
            raise ValueError("Invalid public key")

        shared_key = pow(other_key, self.__private_key, self.prime)

        return sha256(str(shared_key).encode()).hexdigest()
