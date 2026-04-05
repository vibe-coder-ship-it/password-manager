# Password Manager Project Documentation

### March 20, 2026
This document tracks the setup and progress of the password manager web application.

## Phase 1: Project Initialization

### 1. Folder and File Structure

We created the core directory structure to keep our code organized and separated by concern.

-   `app.py`: The main entry point for our web application. It will run the Flask server.
-   `database.py`: Will contain all functions for interacting with the PostgreSQL database.
-   `encryption.py`: Will handle all security-critical functions like hashing and encryption.
-   `password_generator.py`: Will contain the logic for creating strong, random passwords.
-   `user_management.py`: Will handle user registration, login, and session management.
-   `templates/`: A dedicated folder where Flask will look for our HTML files (the user interface).
-   `static/`: A folder for static assets like CSS files (for styling) and images.

### 2. Virtual Environment (`venv`)

We created and activated a Python virtual environment using `python -m venv venv`.

-   **Purpose:** This creates an isolated "bubble" for our project. Any libraries we install (like Flask) are placed inside this bubble and won't affect other Python projects on the computer. This prevents version conflicts and keeps the project self-contained.

### 3. Dependency Management

To ensure the project is reproducible and all necessary libraries are tracked, we performed the following steps:

-   **Created `requirements.txt`:** A text file was generated to list all required Python libraries for the project, such as Flask, bcrypt, and psycopg2-binary.
-   **Installed Dependencies:** All libraries listed in the `requirements.txt` file were installed into the virtual environment using the command `pip install -r requirements.txt`.
-   **Upgraded Pip:** The Python package installer, `pip`, was upgraded to the latest version to ensure compatibility and access to the latest features.

## Phase 2: Database Setup

To create a persistent and robust database for our application, we are using PostgreSQL managed by Docker.

### 1. Docker Configuration

-   **Created `docker-compose.yml`:** A configuration file was created to define our PostgreSQL database service for Docker. This file specifies the database image, sets environment variables for the database name (`password_manager`), user, and password, and ensures data persistence.

### 2. Running the Database Server

-   **Launched the Container:** The database server was started as a background process (a container) by running the command `docker-compose up -d`. This brings our database online and makes it ready to accept connections.

### 3. Database Initialization

### March 21, 2026

-   **Schema Creation:** Successfully initialized the database schema by running the `database.py` script. After resolving initial port conflicts and ensuring the application connected to the correct port exposed by Docker, the script connected to the PostgreSQL container and created the `users` and `credentials` tables.

## Phase 3: Development and Tooling Notes

### March 22, 2026

### 1. AI Assistant Context Exclusion

- **Objective:** Prevent the `.env` file, which contains sensitive credentials, from being sent to the Gemini Code Assist extension.
- **Methods Tested:**
    - Created an `.aiexclude` file in the project root with `.env` listed.
    - Added `.env` to the Gemini context exclusion settings within VS Code.
- **Result:** The attempts to exclude the file failed during the active development session. The AI assistant was still able to read the contents of the `.env` file.
- **Reason:** The file had already been included in the AI's context for the session *before* the exclusion rules were applied. The context can be "sticky," and new rules may not apply retroactively within the same session.
- **Solution:** To ensure exclusion rules are respected, it's best to configure them *before* starting a session or to restart the VS Code window after adding the rule. This forces the extension to re-initialize its context from scratch, respecting the `.aiexclude` file from the beginning.

### 2. Password Generator Script (`password_generator.py`)

We developed a robust and flexible script to generate random passwords for users.

#### Key Features:

-   **Function Definition:** A single function, `generate_password`, was created. It accepts several parameters to customize the generated password:
    -   `length`: An integer to specify the password's length (defaults to 16).
    -   `include_uppercase`, `include_lowercase`, `include_digits`, `include_symbols`: Boolean flags (defaulting to `True`) that control which character sets are included in the password.

-   **Character Pool Construction:** The script dynamically builds a `character_pool` string. It checks each boolean `include_` flag and, if `True`, appends the corresponding character set (e.g., `string.ascii_uppercase`, `string.digits`) to the pool.

-   **Random Generation:** The core logic uses `random.choices(character_pool, k=length)` to select a random list of characters from the pool. The `"".join()` method is then used to concatenate this list into a final password string.

-   **Error Handling:** A safety check (`if not character_pool:`) was implemented. If no character types are selected, the function returns an empty string to prevent the application from crashing.

-   **Testability:** A standard `if __name__ == "__main__":` block was added. This allows the script to be run directly from the command line for testing and demonstration purposes without executing when it's imported as a module into other parts of the application.

- **Confirmation:** After restarting the VS Code window, a subsequent test confirmed that the AI assistant could no longer access the `.env` file. The exclusion rule is now working as intended.

### March 23, 2026

## Phase 4: Web Application Development (`app.py`)

### 1. Initial Application Setup

We began building the core web application using the Flask framework.

-   **Imports and Configuration:** We started by importing the necessary tools: `Flask` to build the app, `render_template` to show HTML pages, and `os` with `dotenv` to securely load our `SECRET_KEY` from the `.env` file. We also imported our custom `generate_password` function.

-   **Flask Initialization:** The Flask application was created (`app = Flask(__name__)`) and configured with the secret key. This key is crucial for securing user login sessions later on.

### 2. Creating the Homepage

-   **Homepage Route:** We defined the main homepage using the `@app.route('/')` decorator. This tells Flask that whenever a user visits the website's main address, it should run the `index()` function.

-   **HTML Template (`index.html`):** The `index()` function was written to display an HTML file. We created a new file, `templates/index.html`, which contains the basic HTML structure and a "Welcome" message. This file acts as the visual front-end for our homepage and includes the viewport meta tag, which is the first step in ensuring the site is mobile-friendly.

-   **Running the Server:** Finally, we added the `if __name__ == '__main__':` block. This allows us to run the application directly with the command `python app.py`, which starts a local development server. The `debug=True` setting makes development easier by automatically reloading the server on code changes.

-   **Testing and Verification:** To test the setup, we ran `python app.py` in the terminal. The server started successfully and provided a local URL (`http://127.0.0.1:5000`). Navigating to this URL in a web browser displayed the "Welcome" message from our `index.html` file, confirming that the application's core is working correctly.

### March 27, 2026

## Phase 5: User Registration

### 1. Secure Password Hashing (`user_management.py`)

Before handling user registration, we built the necessary security components. We created a new file, `scripts/user_management.py`, to contain functions for handling user passwords securely.

-   **Password Hashing:** We implemented a `hash_password` function using the `bcrypt` library. This function takes a user's plain-text password and converts it into a secure hash. It incorporates a "salt"—a random string—which ensures that even identical passwords result in unique hashes in the database. This is a critical security practice that prevents rainbow table attacks.

-   **Password Verification:** We also created a `check_password` function. This function takes a plain-text password (from a login attempt) and a stored hash from the database. It uses `bcrypt`'s secure comparison tool to verify if the password is correct without ever needing to decrypt the stored hash.

### 2. Registration Page and Logic

With the security functions in place, we built the user-facing registration feature.

-   **Registration Route:** In `app.py`, we added a new route, `@app.route('/register')`, that handles both `GET` and `POST` requests. A `GET` request simply displays the registration form, while a `POST` request processes the submitted data.

-   **Registration Form (`register.html`):** We created a new HTML template for the registration form. This form contains fields for a username and a master password and is configured to send the data back to our `/register` route.

-   **Form Processing Logic:** We implemented the logic within the `register` function in `app.py`. When a user submits the form:
    1.  The username and password are extracted from the request.
    2.  The password is run through our `hash_password` function.
    3.  The application connects to the database and checks if the username already exists.
    4.  If the username is unique, the new user's details (username and hashed password) are inserted into the `users` table, and the change is committed.
    5.  A `flash` message is used to provide feedback to the user (e.g., "Account successfully created" or "Username already exists").
    6.  The user is redirected back to the homepage.

### March 29, 2026

## Phase 6: Refactoring and Workflow Adjustments

### 1. Focused Script Development
- **Code Reset:** We temporarily eliminated the generated registration code from `app.py` and `user_management.py` to wipe the slate clean.
- **Workflow Change:** We decided to adopt a more focused workflow, building and completing one script entirely before moving on to the next, instead of constantly switching between `app.py` and `user_management.py`. This minimizes context switching and prevents confusion during development.

### March 30, 2026

## Phase 7: Debugging and AI Collaboration

- **Resolving Core Errors:** We spent time utilizing the Gemini Coding Partner Gem to tackle and debug several tricky `TypeError` and `ValueError` exceptions. A notable fix was handling how PostgreSQL returns binary data (`BYTEA`) as `memoryview` objects, which required casting to `bytes` before decryption.
- **Refining AI Interactions:** We also addressed and fixed some workflow and interaction issues with the Gemini Coding Assistant, improving how we manage context and prompt the AI for more accurate and helpful responses.

### March 31, 2026

## Phase 8: UI Enhancements and Security Clarifications

- **Dashboard UI Improvements:** We significantly improved the credential management interface. We split the combined "Username/Email" text box into two distinct fields and added a dedicated "Email" column to the dashboard table. This required updating the HTML template, the Flask routes, and adding a safe database migration to store the new email data.
- **Password Masking (Disguise):** For better over-the-shoulder visual security, we updated the UI to ensure that both newly generated passwords and saved credentials in the table are disguised as dots (`.....`) using the `type="password"` HTML attribute. We also tweaked the JavaScript so the "Copy" button seamlessly copies the hidden text without exposing it on the screen.
- **Security Architecture Review:** We reviewed the application's security model, specifically clarifying the difference between one-way *hashing* (correctly used for validating the master password) and two-way *encryption* (correctly used for the stored vault credentials). We confirmed the codebase accurately aligns with these security best practices.
