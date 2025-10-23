# crypto/key_manager.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(key_size: int = 2048):
    """
    Genera un par de claves RSA (private_key, public_key).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def private_key_to_pem(private_key, password: bytes = None) -> bytes:
    if password:
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    return pem

def public_key_to_pem(public_key) -> bytes:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def load_private_key_from_pem(pem_data: bytes, password: bytes = None):
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password
    )
    return private_key

def load_public_key_from_pem(pem_data: bytes):
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key