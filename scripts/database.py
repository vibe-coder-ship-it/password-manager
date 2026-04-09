import os
import psycopg2
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Connects to the PostgreSQL database
def get_db_connection():
    """Establishes and returns a connection to the database using DATABASE_URL."""
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        raise EnvironmentError("DATABASE_URL environment variable is not set.")
    parsed = urlparse(database_url)
    conn = psycopg2.connect(
        host=parsed.hostname,
        database=parsed.path.lstrip('/'),
        user=parsed.username,
        password=parsed.password,
        port=parsed.port
    )
    return conn

# Creates the database tables if they don't exist
def initialize_database():
    conn = get_db_connection()
    with conn.cursor() as cur:

        # Creates the table with the users registration/login data
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                master_password_hash VARCHAR(255) NOT NULL,
                encryption_salt VARCHAR(32) NOT NULL,
                two_factor_secret VARCHAR(32),
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Creates the table with the credentials stored by users.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                website VARCHAR(255) NOT NULL,
                username VARCHAR(255),
                email VARCHAR(255),
                encrypted_password BYTEA NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
        """)

        # This migration adds the email column to the credentials table if it doesn't exist,
        # ensuring old databases are updated without losing data.
        cur.execute("ALTER TABLE credentials ADD COLUMN IF NOT EXISTS email VARCHAR(255);")
        cur.execute("ALTER TABLE credentials ALTER COLUMN username DROP NOT NULL;")

        # Migrations to add 2FA columns to the users table for existing databases.
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_secret VARCHAR(32);")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT FALSE;")

    conn.commit()
    conn.close()
    print("Database initialized successfully.")

# Executes when the script is run directly.
if __name__ == "__main__":
    initialize_database()
