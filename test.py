from enigma.diffie_hellman import DiffieHellman
from enigma.cipher import encrypt, decrypt

alice = DiffieHellman()
bob = DiffieHellman()

alice_private = alice.get_private_key()
alice_public = alice.generate_public_key()

bob_private = bob.get_private_key()
bob_public = bob.generate_public_key()

alice_shared = alice.generate_shared_key(bob_public)
bob_shared = bob.generate_shared_key(alice_public)
assert alice_shared == bob_shared

message = "Random message"
encrypted_message = encrypt(message, alice_shared)

print(encrypted_message)

decrypted_message = decrypt(encrypted_message, bob_shared)

print(decrypted_message)
