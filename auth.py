#!/usr/bin/env python3

"""
auth.py
CST1510 Week 7 Lab: Secure Authentication System

This script provides a command-line interface for a secure authentication system. It includes user registration, login, and secure password handling using the bcrypt library.

This implementation also includes optional challenges:
1. Password strength checking.
2. User roles.
3. Account lockout after failed attempts.
4. Basic session token generation.
"""

import bcrypt
import os
import re  # Used for password strength (Challenge 1)
import time  # Used for account lockout (Challenge 3)
import secrets  # Used for session tokens (Challenge 4)

USER_DATA_FILE = "users.txt"

# Constants for Account Lockout (Challenge 3)
FAILED_LOGIN_LIMIT = 3
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes

# In-memory dictionary to track failed login attempts.
# Format: { 'username': (attempt_count, last_attempt_timestamp) }
# For persistence, this would be stored in a database or file.
failed_login_attempts = {}

# Core Security Functions (Steps 4 & 5)


def hash_password(plain_text_password):
    # We must encode the password into bytes for bcrypt.
    password_bytes = plain_text_password.encode('utf-8')

    # Generate a salt. This is automatically included in the hash.
    salt = bcrypt.gensalt()

    # Hash the password using the generated salt.
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)

    # Decode the hash back to a string for easy text file storage.
    return hashed_bytes.decode('utf-8')


def verify_password(plain_text_password, hashed_password):

    try:
        # We need to encode both inputs back into bytes.
        password_bytes = plain_text_password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')

        # bcrypt.checkpw handles extracting the salt and comparing.
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except ValueError:
        # This can happen if the hash format is invalid.
        print("Error: Invalid hash format encountered.")
        return False

# User Management Functions (Steps 7, 8, 9)


def user_exists(username):

    # First, check if the user file even exists.
    if not os.path.exists(USER_DATA_FILE):
        return False  # No file means no users.

    try:
        with open(USER_DATA_FILE, 'r') as f:
            for line in f:
                # Ensure the line is not empty before processing.
                if line.strip():
                    # Read the username, which is the first part.
                    # This is safe even if the line is malformed.
                    stored_username = line.split(',')[0]
                    if stored_username == username:
                        return True
    except FileNotFoundError:
        # This handles a rare case if the file is deleted mid-check.
        return False
    except Exception as e:
        # Log other potential errors, like file permissions.
        print(f"Error reading user file: {e}")

    # We finished the loop without finding the user.
    return False


def register_user(username, password, role="user"):

    # First, check if the username is already taken.
    if user_exists(username):
        print(f"Error: Username '{username}' already exists.")
        return False

    try:
        # Hash the password for secure storage.
        hashed_password = hash_password(password)

        # Our new file format includes the role (Challenge 2).
        # Format: username,hashed_password,role
        user_data_line = f"{username},{hashed_password},{role}\n"

        # 'a' mode appends to the file, or creates it if it doesn't exist.
        with open(USER_DATA_FILE, 'a') as f:
            f.write(user_data_line)

        print(
            f"Success: User '{username}' registered successfully as '{role}'.")
        return True
    except IOError as e:
        print(f"Error: Could not write to user file. {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during registration: {e}")
        return False


def _record_failed_login(username):
    current_time = time.time()

    if username not in failed_login_attempts:
        # This is the first failed attempt for this user.
        failed_login_attempts[username] = (1, current_time)
        count = 1
    else:
        # Increment the failed attempt count.
        count, last_attempt = failed_login_attempts[username]
        count += 1
        failed_login_attempts[username] = (count, current_time)

    print(
        f"Failed attempt {count} of {FAILED_LOGIN_LIMIT} for user '{username}'.")

    if count >= FAILED_LOGIN_LIMIT:
        print(f"Account for '{username}' is now LOCKED for 5 minutes.")


def login_user(username, password):

    # Challenge 3: Account Lockout Check
    if username in failed_login_attempts:
        count, last_attempt = failed_login_attempts[username]

        # Check if the user is currently locked out.
        if count >= FAILED_LOGIN_LIMIT:
            time_since_last_fail = time.time() - last_attempt

            if time_since_last_fail < LOCKOUT_DURATION_SECONDS:
                # The user is still within the lockout period.
                remaining = LOCKOUT_DURATION_SECONDS - time_since_last_fail
                print(
                    f"Error: Account is locked. Try again in {remaining // 60}m {remaining % 60:.0f}s.")
                return False
            else:
                # The lockout period has expired. Clear the attempts.
                print("Lockout period has expired. Resetting attempts.")
                del failed_login_attempts[username]

    # Handle the case where the user file doesn't exist.
    if not os.path.exists(USER_DATA_FILE):
        print("Error: No users are registered in the system.")
        return False

    try:
        with open(USER_DATA_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue  # Skip empty lines

                try:
                    # Unpack the line based on our format (Challenge 2)
                    stored_username, stored_hash, stored_role = line.split(
                        ',', 2)
                except ValueError:
                    # This catches lines that don't fit our format.
                    print(f"Warning: Skipping malformed line in user file.")
                    continue

                # We found the user, now check their password.
                if stored_username == username:
                    if verify_password(password, stored_hash):
                        # Password is correct. Success!
                        print(
                            f"\nSuccess: Welcome, {username}! (Role: {stored_role})")

                        # --- Challenge 4: Session Management ---
                        session_token = create_session(username)
                        print(f"Your new session token is: {session_token}")
                        # --- End Challenge 4 ---

                        # Reset any failed login attempts for this user.
                        if username in failed_login_attempts:
                            del failed_login_attempts[username]

                        return True
                    else:
                        # Username found, but password was wrong.
                        print("Error: Invalid password.")
                        # Record failure (Challenge 3)
                        _record_failed_login(username)
                        return False

            # We finished the loop without finding the username.
            print("Error: Username not found.")
            # We record this to prevent username fishing.
            _record_failed_login(username)  # Record failure (Challenge 3)
            return False

    except Exception as e:
        print(f"Error reading user file during login: {e}")
        return False

# Input Validation (Step 10)


def validate_username(username):

    if not (3 <= len(username) <= 20):
        return (False, "Username must be between 3 and 20 characters.")

    # .isalnum() checks if all characters are letters or numbers.
    if not username.isalnum():
        return (False, "Username must contain only letters and numbers.")

    return (True, "")


def validate_password(password):
    if not (6 <= len(password) <= 50):
        return (False, "Password must be between 6 and 50 characters.")

    if not re.search(r"[a-z]", password):
        return (False, "Password must contain at least one lowercase letter.")

    if not re.search(r"[A-Z]", password):
        return (False, "Password must contain at least one uppercase letter.")

    if not re.search(r"\d", password):
        return (False, "Password must contain at least one digit.")

    return (True, "")

# Optional Challenge Functions


def check_password_strength(password):

    score = 0

    # 1. Length
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1

    # 2. Character types
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1  # Has both cases
    if re.search(r"\d", password):
        score += 1  # Has digits
    if re.search(r"[!@#$%^&*(),.?:{}|<>]", password):
        score += 1  # Has special characters

    # 3. Final Rating
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"


def create_session(username):

    # Generates 16 random bytes, represented as 32 hex characters.
    token = secrets.token_hex(16)

    # In a real application, you would store this token.
    # For example: session_storage[token] = (username, time.time() + 3600)
    print(f"(Session created for {username}, expires in 1 hour)")
    return token

# Main Program Interface (Step 11)


def display_menu():
    """Displays the main menu options."""
    print("\n" + "="*50)
    print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print(" Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)


def main():

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue  # Go back to the main menu

            password = input("Enter a password: ").strip()

            # Validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            # Challenge 1: Show password strength
            strength = check_password_strength(password)
            print(f"Info: Password strength is '{strength}'.")
            if strength == "Weak":
                print("Warning: This password is weak and easy to guess.")

            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            # Challenge 2: Ask for Role
            role_input = input(
                "Enter role (admin, analyst) [default: user]: ").strip().lower()
            if role_input in ["admin", "analyst"]:
                role = role_input
            else:
                role = "user"

            # Register the user
            register_user(username, password, role)

        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            # Attempt login
            if login_user(username, password):
                print("\nYou are now logged in.")
                print("(In a real application, you would now access the main dashboard)")

                # Optional: Ask if they want to logout or exit
                input("\nPress Enter to 'logout' and return to main menu...")
            else:
                # Login function already prints error messages.
                # We can add a small delay to deter brute-force.
                time.sleep(1)

        elif choice == '3':
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break  # Exit the while True loop

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()
