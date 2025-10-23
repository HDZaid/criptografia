# crypto/encryption_manager.py
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def encrypt_with_public(public_key, plaintext_bytes: bytes) -> bytes:
    """
    Cifra con la clave pública usando OAEP + SHA256.
    """
    ciphertext = public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_with_private(private_key, ciphertext: bytes) -> bytes:
    """
    Descifra con la clave privada usando OAEP + SHA256.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
