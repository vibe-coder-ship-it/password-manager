import random
import string

# Generates random password within a defined criteria
def generate_password(length=16, include_uppercase=True, include_lowercase=True, include_digits=True, include_symbols=True):
    character_pool = ""

    # Build the character pool based on the set criteria
    if include_uppercase:
        character_pool += string.ascii_uppercase
    if include_lowercase:
        character_pool += string.ascii_lowercase
    if include_digits:
        character_pool += string.digits
    if include_symbols:
        character_pool += string.punctuation

    # If the character pool is empty, return an empty string to avoid errors.
    if not character_pool:
        return ""

# Generates a password
    password = "".join(random.choices(character_pool, k=length))
    return password

# Executes when the script is run directly.
if __name__ == "__main__":
    new_password = generate_password()
    print(f"Generated Password: {new_password}")
