from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import os

# Generate parameters for Diffie-Hellman
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Alice generates her private key
alice_private_key = parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()

# Bob generates his private key
bob_private_key = parameters.generate_private_key()
bob_public_key = bob_private_key.public_key()

# Alice and Bob exchange public keys
# Alice computes the shared key using Bob's public key
alice_shared_key = alice_private_key.exchange(bob_public_key)

# Bob computes the shared key using Alice's public key
bob_shared_key = bob_private_key.exchange(alice_public_key)

# Ensure both shared keys are the same
assert alice_shared_key == bob_shared_key

# Optionally, derive a key from the shared key for encryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Derive a key using the shared key
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=os.urandom(16),
    iterations=100000,
    backend=default_backend()
)

key = kdf.derive(alice_shared_key)

print("Alice's Public Key:", alice_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
print("Bob's Public Key:", bob_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
print("Derived Shared Key:", key.hex())
