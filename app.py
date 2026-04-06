import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps

# Import our custom scripts for database, security, and password generation
from scripts.database import get_db_connection, initialize_database
from scripts.user_management import hash_password, check_password
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
    try:
        with conn.cursor() as cur:
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
    return render_template('index.html', credentials=credentials, search_query=search_query)

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
                # Retrieve the user's hash and salt from the database
                cur.execute("SELECT id, master_password_hash, encryption_salt FROM users WHERE username = %s", (username,))
                user = cur.fetchone()
                
                # Verify the password using bcrypt
                if user and check_password(password, user[1]):
                    session.clear() # Clear any old session data
                    session['user_id'] = user[0] # Log the user in
                    
                    # Derive the encryption key from the user's password and stored salt
                    stored_salt_hex = user[2]
                    try:
                        # The salt is stored as a hex string, so it must be converted back to bytes
                        salt_bytes = bytes.fromhex(stored_salt_hex)
                        key = derive_key(password, salt_bytes)
                        # The key is bytes; decode to a string for safe session storage
                        session['encryption_key'] = key.decode('utf-8')
                    except (ValueError, TypeError):
                        # This handles cases where the salt is missing or in an invalid format
                        flash("A security error occurred with your account. Please contact support.", "danger")
                        return redirect(url_for('login'))
                    return redirect(url_for('index'))
                else:
                    flash('Invalid username or password.', 'danger')
        finally:
            conn.close()
            
    return render_template('login.html')

# The logout route to clear the session securely
@app.route('/logout')
def logout():
    session.clear() # Destroys the user_id and encryption_key from memory
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

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
            else: # If no password is provided, update only the non-password fields
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
