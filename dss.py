
import hashlib
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def generate_keys():
    private_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption() 
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def sign_message(private_key_pem, message):
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    message_hash = hashlib.sha256(message).digest()

    signature = private_key.sign(
        message_hash,
        algorithm=hashes.SHA256()  
    )
    
    return signature

def verify_signature(public_key_pem, message, signature):
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    message_hash = hashlib.sha256(message).digest()
    
    try:
        public_key.verify(signature, message_hash, algorithm=hashes.SHA256())
        return True
    except Exception as e:
        return False
if __name__ == "__main__":
    private_key, public_key = generate_keys()
    message = b"Hello, this is a test message."

    signature = sign_message(private_key, message)

    is_valid = verify_signature(public_key, message, signature)
    
    print("Signature valid:", is_valid)
