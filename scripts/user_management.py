# user_management.py

import base64
import os
import bcrypt
import pyotp
from scripts.database import get_db_connection

# Deletes all users and their passwords from the database
def delete_all_users() -> None:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # This will also delete all associated credentials due to the ON DELETE CASCADE constraint
            cur.execute("DELETE FROM users;")
            conn.commit()
            print("All stored usernames and master passwords have been deleted.")
    finally:
        conn.close()

# Hashes the password
def hash_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pwd_bytes, salt)
    return hashed_password.decode('utf-8')

# Verifies a plain-text login attempt against a stored database hash
def check_password(password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a stored bcrypt hash.
    This function securely compares the user's input with the hash from the database.
    """
    # Encode both the plain-text password and the stored hash to bytes for bcrypt
    password_bytes = password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')

    # Use bcrypt's checkpw to prevent timing attacks
    return bcrypt.checkpw(password_bytes, hashed_password_bytes)

# Generates a random base32-encoded secret for use with TOTP authenticator apps.
# The secret is 20 bytes (160 bits) of randomness, encoded to a 32-character base32 string.
def generate_2fa_secret() -> str:
    """Returns a random 32-character base32 string suitable as a TOTP secret."""
    random_bytes = os.urandom(20)
    return base64.b32encode(random_bytes).decode('utf-8')

# Verifies a 6-digit TOTP code against the stored secret.
# pyotp checks the current time window plus one window on either side to account for clock drift.
def verify_2fa_code(secret: str, code: str) -> bool:
    """Returns True if the provided TOTP code is valid for the given secret."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

# Returns the otpauth:// provisioning URI used to generate a QR code.
# Authenticator apps (Google Authenticator, Authy, etc.) parse this URI when scanning.
def get_totp_uri(username: str, secret: str) -> str:
    """Returns the TOTP provisioning URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name="VaultLock")
