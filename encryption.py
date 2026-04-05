import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Generates a new random salt for key derivation.
def generate_salt() -> bytes:
    return os.urandom(16)


# Derives a secure encryption key from a master password and salt.
def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # Recommended value by OWASP as of 2023
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


# Encrypts a password using the derived key.
def encrypt_password(password_to_encrypt: str, key: bytes) -> bytes:
    f = Fernet(key)
    encrypted_password = f.encrypt(password_to_encrypt.encode())
    return encrypted_password


# Decrypts an encrypted password using the derived key.
def decrypt_password(encrypted_password: bytes, key: bytes) -> str:
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()
    return decrypted_password