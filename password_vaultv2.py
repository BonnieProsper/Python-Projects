"""
PASSWORD VAULT V2
==========================================================
A secure, logic-driven password manager implemented
entirely in Python without external libraries.

Features:
- Master password authentication and lockout
- Custom encryption/decryption (shift-based cipher)
- Add, view, delete, search, and export entries
- Password strength checker and generator
- Full audit logging
- Clean text-based user interface
==========================================================
"""

import os
import json
import random
import time
from getpass import getpass

VAULT_FILE = "vaultv2_data.json"
LOG_FILE = "vaultv2_audit.log"


# ------------------------------------------------------------------
# Encryption Logic
# ------------------------------------------------------------------

def generate_shift(master_password):
    """Derive a numeric shift value from the master password."""
    return sum(ord(ch) for ch in master_password) % 26


def encrypt_text(text, shift):
    """Encrypt text using a custom shift cipher."""
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        elif ch.isdigit():
            result.append(chr((ord(ch) - ord('0') + shift) % 10 + ord('0')))
        else:
            result.append(chr((ord(ch) + shift) % 126))
    return ''.join(result)


def decrypt_text(text, shift):
    """Decrypt text using the same custom cipher."""
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        elif ch.isdigit():
            result.append(chr((ord(ch) - ord('0') - shift) % 10 + ord('0')))
        else:
            result.append(chr((ord(ch) - shift) % 126))
    return ''.join(result)


# ------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------

def generate_password(length=12):
    """Generate a strong random password."""
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    symbols = "!@#$%^&*()-_=+[]{};:,.<>?"
    all_chars = letters + digits + symbols
    return ''.join(random.choice(all_chars) for _ in range(length))


def check_password_strength(password):
    """Evaluate password strength."""
    length = len(password)
    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(not ch.isalnum() for ch in password)

    score = sum([has_upper, has_lower, has_digit, has_symbol])
    if length >= 12 and score >= 3:
        return "Strong"
    elif length >= 8 and score >= 2:
        return "Moderate"
    return "Weak"


def log_action(action):
    """Log an event with a timestamp."""
    with open(LOG_FILE, "a") as log:
        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {action}\n")


# ------------------------------------------------------------------
# Main Vault Class
# ------------------------------------------------------------------

class PasswordVault:
    """Manages storage, encryption, and authentication."""

    def __init__(self):
        self.data = {}
        self.master_password = None
        self.shift = None
        self.load_vault()

    def load_vault(self):
        """Load existing vault or initialize a new one."""
        if not os.path.exists(VAULT_FILE):
            print("No vault found. Creating a new one...")
            self.setup_new_vault()
        else:
            with open(VAULT_FILE, "r") as f:
                self.data = json.load(f)

    def setup_new_vault(self):
        """Create a new vault and master password."""
        while True:
            master = getpass("Set a master password: ")
            confirm = getpass("Confirm master password: ")
            if master == confirm and len(master) >= 6:
                shift = generate_shift(master)
                encrypted_master = encrypt_text(master, shift)
                self.data = {"_master": encrypted_master, "entries": {}}
                self.save_vault()
                print("Vault created successfully.")
                log_action("Created new vault")
                break
            else:
                print("Passwords didn’t match or were too short. Try again.")

    def authenticate(self):
        """Authenticate user before allowing access."""
        attempts = 3
        while attempts > 0:
            entered = getpass("Enter master password: ")
            stored_encrypted = self.data.get("_master", "")
            shift = generate_shift(entered)
            decrypted = decrypt_text(stored_encrypted, shift)
            if entered == decrypted:
                self.master_password = entered
                self.shift = shift
                print("Access granted.\n")
                log_action("Vault unlocked")
                return True
            else:
                attempts -= 1
                print(f"Incorrect password. Attempts left: {attempts}")
        print("Too many failed attempts. Exiting.")
        log_action("Failed login attempt - locked out")
        exit()

    def save_vault(self):
        """Save the vault to disk."""
        with open(VAULT_FILE, "w") as f:
            json.dump(self.data, f, indent=4)

    # ---------------- Core Operations ----------------

    def add_entry(self):
        """Add a new credential."""
        service = input("Service name: ").strip()
        username = input("Username: ").strip()
        password = getpass("Password (leave blank to generate): ")
        if not password:
            password = generate_password()
            print(f"Generated password: {password}")

        strength = check_password_strength(password)
        print(f"Password strength: {strength}")

        encrypted_pw = encrypt_text(password, self.shift)
        self.data["entries"][service] = {
            "username": username,
            "password": encrypted_pw
        }
        self.save_vault()
        print(f"Added '{service}' successfully.\n")
        log_action(f"Added entry: {service}")

    def view_entry(self):
        """View a stored credential."""
        service = input("Service to view: ").strip()
        entry = self.data["entries"].get(service)
        if not entry:
            print("Service not found.\n")
            return
        decrypted_pw = decrypt_text(entry["password"], self.shift)
        print(f"\nService: {service}")
        print(f"Username: {entry['username']}")
        print(f"Password: {decrypted_pw}\n")
        log_action(f"Viewed entry: {service}")

    def delete_entry(self):
        """Delete a credential."""
        service = input("Service to delete: ").strip()
        if service in self.data["entries"]:
            del self.data["entries"][service]
            self.save_vault()
            print(f"Deleted '{service}'.\n")
            log_action(f"Deleted entry: {service}")
        else:
            print("Service not found.\n")

    def list_services(self):
        """List all stored services."""
        entries = self.data.get("entries", {})
        if not entries:
            print("Vault is empty.\n")
            return
        print("Stored services:")
        for s in entries:
            print(f" - {s}")
        print()
        log_action("Listed services")

    def search_service(self):
        """Search services by keyword."""
        keyword = input("Search keyword: ").strip().lower()
        matches = [s for s in self.data["entries"] if keyword in s.lower()]
        if matches:
            print("\nMatches:")
            for s in matches:
                print(f" - {s}")
        else:
            print("No matches found.\n")
        log_action(f"Searched for '{keyword}'")

    def export_vault(self):
        """Export decrypted credentials to a file."""
        filename = "vault_export.txt"
        with open(filename, "w") as f:
            for service, entry in self.data["entries"].items():
                decrypted_pw = decrypt_text(entry["password"], self.shift)
                f.write(f"Service: {service}\n")
                f.write(f"Username: {entry['username']}\n")
                f.write(f"Password: {decrypted_pw}\n")
                f.write("-" * 40 + "\n")
        print(f"Vault exported to '{filename}'.\n")
        log_action("Exported vault")


# ------------------------------------------------------------------
# Command-Line Interface
# ------------------------------------------------------------------

def main():
    vault = PasswordVault()
    vault.authenticate()

    while True:
        print("""
================ PASSWORD VAULT =================
1. Add new credential
2. View credential
3. Delete credential
4. List all services
5. Search service
6. Export vault
7. Generate password
8. Exit
===============================================
""")
        choice = input("Select an option: ").strip()

        if choice == "1":
            vault.add_entry()
        elif choice == "2":
            vault.view_entry()
        elif choice == "3":
            vault.delete_entry()
        elif choice == "4":
            vault.list_services()
        elif choice == "5":
            vault.search_service()
        elif choice == "6":
            vault.export_vault()
        elif choice == "7":
            print("Generated password:", generate_password())
        elif choice == "8":
            print("Goodbye.")
            log_action("Exited vault")
            break
        else:
            print("Invalid option.\n")


if __name__ == "__main__":
    main()
