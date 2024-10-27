import bcrypt

# Function to hash a password
def hash_password(password: str) -> bytes:
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

# Function to verify a password
def check_password(password: str, hashed_password: bytes) -> bool:
    # Check if the given password matches the hashed password
    return bcrypt.checkpw(password.encode(), hashed_password)

# Example Usage
if __name__ == "__main__":
    # Original password
    original_password = "SuperSecretPassword123"
    
    # Hash the password
    hashed_pw = hash_password(original_password)
    print(f"Hashed Password: {hashed_pw}")

    # Verify the password
    password_match = check_password(original_password, hashed_pw)
    print("Password match:", password_match)
