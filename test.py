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
print(f"Encrypting {message}")
encrypted_message = encrypt(message, alice_shared)

print(f"Origin message {message} encrypted as {encrypted_message}")

print(f"Decrypting: {encrypted_message}")
decrypted_message = decrypt(encrypted_message, bob_shared)

print(f"Result: {decrypted_message}")
