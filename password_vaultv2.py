"""
==========================================================
 PASSWORD VAULT CLI (WITHOUT USING UNNEEDED LIBRARIES)
----------------------------------------------------------
 Stores and retrieves passwords using a custom cipher.
 Demonstrates logic, modular design, and file handling
 without external libraries.
==========================================================
"""

import os
import json
from getpass import getpass

VAULT_FILE = "vault_pure.json"

# ==========================================================
# Encryption Utilities
# ==========================================================
def generate_shift(master_password):
    """
    Generate a numeric shift value from the master password.
    The shift is derived from the sum of character codes.
    """
    return sum(ord(ch) for ch in master_password) % 26  # value 0–25

def encrypt_text(text, shift):
    """
    Encrypt a string using a simple ASCII shift cipher.
    """
    encrypted = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            encrypted.append(chr((ord(ch) - base + shift) % 26 + base))
        elif ch.isdigit():
            encrypted.append(chr((ord(ch) - ord('0') + shift) % 10 + ord('0')))
        else:
            # Shift symbols too, just to mix things up
            encrypted.append(chr((ord(ch) + shift) % 126))
    return ''.join(encrypted)


def decrypt_text(text, shift):
    """
    Reverse the custom cipher to retrieve the original text.
    """
    decrypted = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            decrypted.append(chr((ord(ch) - base - shift) % 26 + base))
        elif ch.isdigit():
            decrypted.append(chr((ord(ch) - ord('0') - shift) % 10 + ord('0')))
        else:
            decrypted.append(chr((ord(ch) - shift) % 126))
    return ''.join(decrypted)

# ==========================================================
# Core Vault Class
# ==========================================================
class PasswordVault:
    """Manages storage, encryption, and retrieval of credentials."""

    def __init__(self, master_password):
        self.master_password = master_password
        self.shift = generate_shift(master_password)
        self.data = self.load_vault()

    def load_vault(self):
        """Load vault data from disk or create a new one."""
        if not os.path.exists(VAULT_FILE):
            print("[*] Vault file not found. Creating a new one...")
            return {}
        try:
            with open(VAULT_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("[!] Vault file corrupted. Starting fresh.")
            return {}

    def save_vault(self):
        """Save vault data back to disk."""
        with open(VAULT_FILE, "w") as f:
            json.dump(self.data, f, indent=4)

    def add_entry(self, service, username, password):
        """Encrypt and store a new credential."""
        encrypted_pw = encrypt_text(password, self.shift)
        self.data[service] = {"username": username, "password": encrypted_pw}
        self.save_vault()
        print(f"[+] Added entry for '{service}' successfully.")

    def view_entry(self, service):
        """Decrypt and display a stored credential."""
        if service not in self.data:
            print("[!] Service not found.")
            return
        entry = self.data[service]
        decrypted_pw = decrypt_text(entry["password"], self.shift)
        print(f"\nService: {service}")
        print(f"Username: {entry['username']}")
        print(f"Password: {decrypted_pw}\n")

    def delete_entry(self, service):
        """Delete a credential by service name."""
        if service in self.data:
            del self.data[service]
            self.save_vault()
            print(f"[-] Deleted '{service}' from vault.")
        else:
            print("[!] No such service found.")

    def list_services(self):
        """Display all stored service names."""
        if not self.data:
            print("[!] Vault is empty.")
            return
        print("\nStored services:")
        for s in self.data:
            print(" -", s)
        print()

    def search_service(self, keyword):
        """Search vault for partial matches."""
        matches = [s for s in self.data if keyword.lower() in s.lower()]
        if matches:
            print("\nMatching services:")
            for s in matches:
                print(" -", s)
        else:
            print("[!] No matches found.")

# ==========================================================
# Password Strength Checker
# ==========================================================
def check_password_strength(password):
    """
    Evaluate the strength of a password.
    Returns 'Weak', 'Moderate', or 'Strong' based on rules.
    """
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
    else:
        return "Weak"

# ==========================================================
# CLI Interface
# ==========================================================
def main_menu(vault):
    """Interactive menu for user operations."""
    while True:
        print("""
==========================================================
 PASSWORD VAULT - MAIN MENU
==========================================================
1. Add new credential
2. View credential
3. Delete credential
4. List all services
5. Search service
6. Exit
==========================================================
""")
        choice = input("Select an option: ").strip()

        if choice == "1":
            service = input("Service name: ").strip()
            username = input("Username: ").strip()
            password = getpass("Password: ")
            strength = check_password_strength(password)
            print(f"[i] Password strength: {strength}")
            vault.add_entry(service, username, password)

        elif choice == "2":
            service = input("Service to view: ").strip()
            vault.view_entry(service)

        elif choice == "3":
            service = input("Service to delete: ").strip()
            vault.delete_entry(service)

        elif choice == "4":
            vault.list_services()

        elif choice == "5":
            keyword = input("Keyword to search: ").strip()
            vault.search_service(keyword)

        elif choice == "6":
            print("Goodbye!")
            break

        else:
            print("[!] Invalid choice. Try again.")

# ==========================================================
# Entry Point
# ==========================================================
if __name__ == "__main__":
    print("==========================================================")
    print("         Welcome to the Logic-Based Password Vault")
    print("==========================================================")

    master_pw = getpass("Enter master password: ")
    vault = PasswordVault(master_pw)
    main_menu(vault)
