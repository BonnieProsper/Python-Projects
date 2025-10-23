"""
==========================================================
 PASSWORD VAULT CLI
 Securely store, view, and manage encrypted credentials.
 Author: Bonnie (2025)
==========================================================
"""

import os
import json
from cryptography.fernet import Fernet
from getpass import getpass

VAULT_FILE = "vault.json"
KEY_FILE = "vault.key"


# ==========================================================
# Utility functions for key generation and encryption
# ==========================================================
def generate_key():
    """Generate a new encryption key and save it to KEY_FILE."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print("[+] New encryption key generated and saved.")
    return key


def load_key():
    """Load the encryption key from the KEY_FILE."""
    if not os.path.exists(KEY_FILE):
        print("[!] No key found. Generating new key...")
        return generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()


def encrypt_text(fernet, text):
    """Encrypt text using the Fernet instance."""
    return fernet.encrypt(text.encode()).decode()


def decrypt_text(fernet, token):
    """Decrypt text using the Fernet instance."""
    return fernet.decrypt(token.encode()).decode()


# ==========================================================
# Core Vault Class
# ==========================================================
class PasswordVault:
    """Handles secure storage, encryption, and retrieval of credentials."""

    def __init__(self, key):
        self.fernet = Fernet(key)
        self.data = self.load_vault()

    def load_vault(self):
        """Load existing vault data or create an empty one."""
        if not os.path.exists(VAULT_FILE):
            print("[*] Vault file not found, creating a new one...")
            return {}
        try:
            with open(VAULT_FILE, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            print("[!] Vault file corrupted. Starting fresh.")
            return {}

    def save_vault(self):
        """Save the encrypted vault data to disk."""
        with open(VAULT_FILE, "w") as file:
            json.dump(self.data, file, indent=4)

    def add_entry(self, service, username, password):
        """Add a new encrypted credential."""
        encrypted_pw = encrypt_text(self.fernet, password)
        self.data[service] = {"username": username, "password": encrypted_pw}
        self.save_vault()
        print(f"[+] Entry for '{service}' added successfully.")

    def view_entry(self, service):
        """View decrypted credentials for a service."""
        if service not in self.data:
            print("[!] No such service found.")
            return
        entry = self.data[service]
        decrypted_pw = decrypt_text(self.fernet, entry["password"])
        print(f"\nService: {service}")
        print(f"Username: {entry['username']}")
        print(f"Password: {decrypted_pw}\n")

    def delete_entry(self, service):
        """Delete a service entry."""
        if service in self.data:
            del self.data[service]
            self.save_vault()
            print(f"[-] Deleted entry for '{service}'.")
        else:
            print("[!] Service not found in vault.")

    def list_services(self):
        """List all stored services."""
        if not self.data:
            print("[!] Vault is empty.")
            return
        print("\nStored services:")
        for service in self.data:
            print(" -", service)
        print()

    def search_service(self, keyword):
        """Search for a service by name."""
        matches = [s for s in self.data if keyword.lower() in s.lower()]
        if matches:
            print("\nMatches found:")
            for s in matches:
                print(" -", s)
        else:
            print("[!] No matching services found.")


# ==========================================================
# CLI Interface
# ==========================================================
def main_menu(vault):
    """Main command-line interface loop."""
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
            keyword = input("Search keyword: ").strip()
            vault.search_service(keyword)

        elif choice == "6":
            print("Goodbye!")
            break
        else:
            print("[!] Invalid option. Try again.")


# ==========================================================
# Entry point
# ==========================================================
if __name__ == "__main__":
    print("==========================================================")
    print("      Welcome to the Secure CLI Password Vault")
    print("==========================================================")
    key = load_key()
    vault = PasswordVault(key)
    main_menu(vault)
