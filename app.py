import io
import os
import base64
import qrcode
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps

# Import our custom scripts for database, security, and password generation
from scripts.database import get_db_connection, initialize_database
from scripts.user_management import (
    hash_password, check_password,
    generate_2fa_secret, verify_2fa_code, get_totp_uri
)
from scripts.encryption import generate_salt, derive_key, encrypt_password, decrypt_password
from scripts.password_generator import generate_password as gen_pass

# Load environment variables from the .env file
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)
# Set the secret key for securely signing the session cookie
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Ensure database tables exist on every startup
try:
    initialize_database()
except Exception as e:
    print(f"Database initialization error: {e}")


# Decorator function to ensure a user is logged in before accessing certain routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user ID is present in the current session
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# The main dashboard route where users view their saved passwords
@app.route('/')
@login_required
def index():
    user_id = session['user_id']
    encryption_key = session.get('encryption_key')

    # If the session key is missing, force the user to log in again
    if not encryption_key:
        flash('Session key has expired. Please log in again.', 'danger')
        return redirect(url_for('logout'))

    # Get the search term from the URL query parameters
    search_query = request.args.get('q', '').strip()

    conn = get_db_connection()
    credentials = []
    two_factor_enabled = False
    try:
        with conn.cursor() as cur:
            # Fetch the user's 2FA status for the dashboard toggle
            cur.execute("SELECT two_factor_enabled FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            if row:
                two_factor_enabled = row[0] or False

            if search_query:
                # Use PostgreSQL's ILIKE for case-insensitive partial matching
                search_pattern = f"%{search_query}%"
                cur.execute(
                    """
                    SELECT id, website, username, encrypted_password, email
                    FROM credentials
                    WHERE user_id = %s
                    AND (website ILIKE %s OR username ILIKE %s OR email ILIKE %s)
                    ORDER BY website
                    """,
                    (user_id, search_pattern, search_pattern, search_pattern)
                )
            else:
                # Fetch all credentials for the currently logged-in user
                cur.execute(
                    "SELECT id, website, username, encrypted_password, email FROM credentials WHERE user_id = %s ORDER BY website",
                    (user_id,)
                )
            rows = cur.fetchall()

            # Loop through the results and decrypt each password
            for row in rows:
                try:
                    # Cast row[3] to bytes because psycopg2 returns BYTEA columns as memoryview objects
                    decrypted_pass = decrypt_password(bytes(row[3]), encryption_key.encode())
                    credentials.append({'id': row[0], 'website': row[1], 'username': row[2], 'password': decrypted_pass, 'email': row[4]})
                except Exception:
                    # If decryption fails, safely show an error message instead of crashing
                    credentials.append({'id': row[0], 'website': row[1], 'username': row[2], 'password': '*** DECRYPTION FAILED ***', 'email': row[4]})
    finally:
        conn.close()

    # Render the dashboard template and pass the decrypted credentials and search query to it
    return render_template('index.html', credentials=credentials, search_query=search_query, two_factor_enabled=two_factor_enabled)

# The registration route for new users
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Extract form data
        username = request.form['username']
        password = request.form['password']

        # Hash the master password for safe storage and generate a unique encryption salt
        hashed_pw = hash_password(password)
        encryption_salt = generate_salt()

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                # Check if the username is already taken
                cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                if cur.fetchone():
                    flash('Username already exists.', 'danger')
                    return redirect(url_for('register'))

                # Insert the new user into the database
                cur.execute(
                    "INSERT INTO users (username, master_password_hash, encryption_salt) VALUES (%s, %s, %s)",
                    (username, hashed_pw, encryption_salt.hex())
                )
                conn.commit()
                flash('Account created successfully. Please log in.', 'success')
                return redirect(url_for('login'))
        finally:
            conn.close()

    return render_template('register.html')

# The login route for existing users
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                # Retrieve the user's hash, salt, and 2FA status from the database
                cur.execute(
                    "SELECT id, master_password_hash, encryption_salt, two_factor_enabled, two_factor_secret FROM users WHERE username = %s",
                    (username,)
                )
                user = cur.fetchone()

                # Verify the password using bcrypt
                if user and check_password(password, user[1]):
                    stored_salt_hex = user[2]
                    try:
                        # The salt is stored as a hex string, so it must be converted back to bytes
                        salt_bytes = bytes.fromhex(stored_salt_hex)
                        key = derive_key(password, salt_bytes)
                        # The key is bytes; decode to a string for safe session storage
                        encryption_key = key.decode('utf-8')
                    except (ValueError, TypeError):
                        # This handles cases where the salt is missing or in an invalid format
                        flash("A security error occurred with your account. Please contact support.", "danger")
                        return redirect(url_for('login'))

                    two_factor_enabled = user[3] or False
                    two_factor_secret = user[4]

                    if two_factor_enabled and two_factor_secret:
                        # Store credentials temporarily in the session pending 2FA verification.
                        # The user is NOT fully logged in yet — user_id is absent until 2FA passes.
                        session.clear()
                        session['pre_2fa_user_id'] = user[0]
                        session['pre_2fa_encryption_key'] = encryption_key
                        return redirect(url_for('verify_2fa'))
                    else:
                        # No 2FA — log the user in directly
                        session.clear()
                        session['user_id'] = user[0]
                        session['encryption_key'] = encryption_key
                        return redirect(url_for('index'))
                else:
                    flash('Invalid username or password.', 'danger')
        finally:
            conn.close()

    return render_template('login.html')

# The logout route to clear the session securely
@app.route('/logout')
def logout():
    session.clear()  # Destroys the user_id and encryption_key from memory
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# GET: Display the 2FA setup page with a QR code.
# POST: Confirm the setup by verifying the user's first code, then save the secret.
@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user_id = session['user_id']

    if request.method == 'POST':
        secret = request.form.get('secret', '').strip()
        code = request.form.get('code', '').strip()

        if not secret or not code:
            flash('Missing secret or verification code.', 'danger')
            return redirect(url_for('setup_2fa'))

        if verify_2fa_code(secret, code):
            # Code is valid — persist the secret and enable 2FA for this user
            conn = get_db_connection()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE users SET two_factor_secret = %s, two_factor_enabled = TRUE WHERE id = %s",
                        (secret, user_id)
                    )
                    conn.commit()
            finally:
                conn.close()
            flash('Two-factor authentication has been enabled successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
            return redirect(url_for('setup_2fa'))

    # GET: generate a fresh secret and render the QR code page
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            username = row[0] if row else 'user'
    finally:
        conn.close()

    secret = generate_2fa_secret()
    totp_uri = get_totp_uri(username, secret)

    # Generate the QR code image and encode it as a base64 data URI for inline display
    qr_img = qrcode.make(totp_uri)
    buffer = io.BytesIO()
    qr_img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    qr_data_uri = f"data:image/png;base64,{qr_b64}"

    return render_template('setup_2fa.html', secret=secret, qr_data_uri=qr_data_uri)

# Disables 2FA for the logged-in user by clearing the stored secret.
@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET two_factor_secret = NULL, two_factor_enabled = FALSE WHERE id = %s",
                (user_id,)
            )
            conn.commit()
    finally:
        conn.close()
    flash('Two-factor authentication has been disabled.', 'success')
    return redirect(url_for('index'))

# GET: Show the 2FA code entry form during login.
# POST: Validate the submitted code and complete the login.
@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    # This route is only valid when a pre-2FA session exists
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        user_id = session['pre_2fa_user_id']

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT two_factor_secret FROM users WHERE id = %s", (user_id,))
                row = cur.fetchone()
                secret = row[0] if row else None
        finally:
            conn.close()

        if secret and verify_2fa_code(secret, code):
            # 2FA passed — promote the session to a fully authenticated state
            encryption_key = session.pop('pre_2fa_encryption_key')
            session.clear()
            session['user_id'] = user_id
            session['encryption_key'] = encryption_key
            return redirect(url_for('index'))
        else:
            flash('Invalid authentication code. Please try again.', 'danger')
            return redirect(url_for('verify_2fa'))

    return render_template('verify_2fa.html')

# Route to add a new website credential to the vault
@app.route('/add_credential', methods=['POST'])
@login_required
def add_credential():
    website = request.form['website']
    username = request.form.get('username', '')
    email = request.form.get('email', '')
    password = request.form['password']

    # Retrieve the user's active session key and encrypt the password
    encryption_key = session['encryption_key'].encode()
    encrypted_pw = encrypt_password(password, encryption_key)
    user_id = session['user_id']

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Save the encrypted credential to the database
            cur.execute(
                "INSERT INTO credentials (user_id, website, username, email, encrypted_password) VALUES (%s, %s, %s, %s, %s)",
                (user_id, website, username, email, encrypted_pw)
            )
            conn.commit()
            flash('Credential added successfully!', 'success')
    finally:
        conn.close()

    return redirect(url_for('index'))

# Route to edit an existing website credential
@app.route('/edit_credential/<int:credential_id>', methods=['POST'])
@login_required
def edit_credential(credential_id):
    website = request.form['website']
    username = request.form.get('username', '')
    email = request.form.get('email', '')
    password = request.form.get('password')

    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # If a new password is provided, encrypt it and update all fields
            if password:
                encryption_key = session['encryption_key'].encode()
                encrypted_pw = encrypt_password(password, encryption_key)
                cur.execute(
                    "UPDATE credentials SET website = %s, username = %s, email = %s, encrypted_password = %s WHERE id = %s AND user_id = %s",
                    (website, username, email, encrypted_pw, credential_id, user_id)
                )
            else:  # If no password is provided, update only the non-password fields
                cur.execute(
                    "UPDATE credentials SET website = %s, username = %s, email = %s WHERE id = %s AND user_id = %s",
                    (website, username, email, credential_id, user_id)
                )
            conn.commit()
            flash('Credential updated successfully!', 'success')
    finally:
        conn.close()
    return redirect(url_for('index'))

# Route to delete an existing credential from the vault
@app.route('/delete_credential/<int:credential_id>', methods=['POST'])
@login_required
def delete_credential(credential_id):
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Delete only if the credential matches both the ID and the current logged-in user
            cur.execute("DELETE FROM credentials WHERE id = %s AND user_id = %s", (credential_id, user_id))
            conn.commit()
            flash('Credential deleted successfully.', 'success')
    finally:
        conn.close()
    return redirect(url_for('index'))

# API route used by the frontend to dynamically generate strong passwords
@app.route('/api/generate-password', methods=['POST'])
@login_required
def api_generate_password():
    data = request.get_json() or {}
    length = int(data.get('length', 16))

    # Call our custom generation script based on the user's desired settings
    password = gen_pass(
        length=length,
        include_uppercase=data.get('include_uppercase', True),
        include_lowercase=data.get('include_lowercase', True),
        include_digits=data.get('include_digits', True),
        include_symbols=data.get('include_symbols', True)
    )
    return jsonify({'password': password})

# Starts the development server when the script is run directly
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
