# user_management.py

import bcrypt
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