#!/usr/bin/env python3
"""
Password Vault TUI (pure Python, standard library only)
Author: Bonnie (2025)
Description:
  - PBKDF2-derived key (master password) used to encrypt data via XOR stream
  - JSON-backed vault with metadata, entries, history, and tags
  - Audit log, import/export, password generator, inactivity auto-lock
  - Simple text-based UI with arrow-key navigation and forms
"""

from __future__ import annotations
import os
import sys
import json
import time
import random
import base64
import hashlib
import getpass
from typing import Dict, Any, Optional, List, Tuple

# filenames (change if you like)
VAULT_FILE = "vault_tui_data.json"
AUDIT_FILE = "vault_tui_audit.log"
BACKUP_DIR = "vault_backups"

# security params
PBKDF2_ITER = 180_000  # number of iterations for key derivation
KEY_LENGTH = 32        # bytes

# inactivity auto-lock (seconds)
AUTO_LOCK_SECONDS = 300  # 5 minutes by default

# UI params
MENU_WIDTH = 60

# small wordlist for passphrase generation (kept short on purpose)
WORDLIST = [
    "river", "poppy", "tiger", "ember", "lunar", "atlas", "cinder", "sage",
    "quartz", "hollow", "orchid", "maple", "basil", "cobalt", "garnet", "cedar"
]


# ---------------------------
# Small portable getch utils
# ---------------------------
def _getch_unix() -> str:
    """Read a single key (Unix) including handling escape sequences for arrows."""
    import tty
    import termios
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == '\x1b':  # possible escape sequence
            ch2 = sys.stdin.read(1)
            if ch2 == '[':
                ch3 = sys.stdin.read(1)
                return '\x1b[' + ch3
            return ch + ch2
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _getch_windows() -> str:
    """Read a single key on Windows using msvcrt (returns readable strings)."""
    import msvcrt
    ch = msvcrt.getwch()
    if ch == '\x00' or ch == '\xe0':  # special key
        ch2 = msvcrt.getwch()
        # map common arrow keys to ANSI-like sequences
        codes = {'H': '\x1b[A', 'P': '\x1b[B', 'K': '\x1b[D', 'M': '\x1b[C'}
        return codes.get(ch2, ch2)
    return ch


if os.name == "nt":
    getch = _getch_windows
else:
    getch = _getch_unix


# ---------------------------
# Crypto / encoding utils
# ---------------------------
def _b64_encode(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def _b64_decode(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))


def derive_master_key(password: str, salt: bytes, iterations: int = PBKDF2_ITER) -> bytes:
    """
    Derive a key from the master password using PBKDF2-HMAC-SHA256.
    Returns bytes of length KEY_LENGTH.
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=KEY_LENGTH)


def xor_stream_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    XOR encrypt plaintext with key repeated as stream.
    Returns ciphertext bytes.
    """
    out = bytearray(len(plaintext))
    key_len = len(key)
    for i, b in enumerate(plaintext):
        out[i] = b ^ key[i % key_len]
    return bytes(out)


def encrypt_json_struct(data: Any, enc_key: bytes) -> str:
    """
    Serialize data to JSON bytes and encrypt with XOR stream,
    then return base64 string.
    """
    raw = json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    cipher = xor_stream_encrypt(raw, enc_key)
    return _b64_encode(cipher)


def decrypt_json_struct(b64cipher: str, enc_key: bytes) -> Any:
    """
    Decode base64, decrypt XOR stream, parse JSON and return object.
    """
    cipher = _b64_decode(b64cipher)
    raw = xor_stream_encrypt(cipher, enc_key)  # XOR is symmetric
    return json.loads(raw.decode('utf-8'))


# ---------------------------
# Vault handling
# ---------------------------

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _ensure_backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)


def audit_log(msg: str) -> None:
    """Append a timestamped message to the audit log."""
    ts = _now_iso()
    entry = f"{ts} - {msg}\n"
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(entry)


class Vault:
    """
    Top-level vault abstraction with on-disk persistence.
    Data layout (JSON):
    {
      "meta": {
         "salt": base64,
         "iterations": int,
         "version": 1
      },
      "verifier": base64,   # derived key verifier
      "data": base64         # encrypted JSON of entries (see below)
    }
    Encrypted entries JSON structure:
    {
      "entries": {
         "servicename": {
             "username": "...",
             "password": "...", (encrypted within the encrypted blob)
             "notes": "...",
             "tags": ["..."],
             "created": "...",
             "modified": "...",
             "history": [{"password": "...", "changed": "..."}]
         }, ...
      }
    }
    """
    def __init__(self, path: str = VAULT_FILE):
        self.path = path
        self._loaded = False
        self.meta: Dict[str, Any] = {}
        self.verifier: Optional[bytes] = None
        self._cipher_blob_b64: Optional[str] = None
        self._entries_cache: Dict[str, Any] = {}
        self._enc_key: Optional[bytes] = None  # encryption stream key for session
        self._salt: Optional[bytes] = None
        self._iterations: int = PBKDF2_ITER
        self.load_or_init()

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def load_or_init(self) -> None:
        """Load from disk if present; otherwise initialize an empty vault."""
        if not self.exists():
            # fresh vault
            self.meta = {
                "version": 1,
                "iterations": PBKDF2_ITER,
                "salt": _b64_encode(os.urandom(16))
            }
            self.verifier = None
            # empty encrypted payload for entries
            empty_blob = encrypt_json_struct({"entries": {}}, b'\x00' * KEY_LENGTH)
            self._cipher_blob_b64 = empty_blob
            self._save_disk()
            self._loaded = True
            return
        with open(self.path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        self.meta = doc.get("meta", {})
        self._cipher_blob_b64 = doc.get("data")
        verifier_b64 = doc.get("verifier")
        self.verifier = _b64_decode(verifier_b64) if verifier_b64 else None
        self._salt = _b64_decode(self.meta.get("salt"))
        self._iterations = int(self.meta.get("iterations", PBKDF2_ITER))
        self._loaded = True

    def _save_disk(self) -> None:
        """Persist meta, verifier and encrypted blob to disk."""
        doc = {
            "meta": self.meta,
            "verifier": _b64_encode(self.verifier) if self.verifier is not None else None,
            "data": self._cipher_blob_b64
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)

    def initialize_master(self, master_password: str) -> None:
        """
        Initialize or set the master password:
         - derive key from password+salt and store a verifier
         - derive an encryption key and re-encrypt entries (or initialize empty)
        """
        if self._salt is None:
            self._salt = os.urandom(16)
            self.meta["salt"] = _b64_encode(self._salt)
            self.meta["iterations"] = PBKDF2_ITER
        # derive a derived_key as verifier
        derived = derive_master_key(master_password, self._salt, iterations=self._iterations)
        self.verifier = derived  # store raw derived key as verifier (we encode to base64 on save)
        # derive encryption key for stream (use derived + constant info)
        self._enc_key = hashlib.sha256(derived + b"enc-stream").digest()
        # when creating new vault, re-encrypt existing entries (we have an initial empty blob)
        if not self._cipher_blob_b64:
            self._cipher_blob_b64 = encrypt_json_struct({"entries": {}}, self._enc_key)
        else:
            # decrypt using placeholder zero-key and re-encrypt with real key
            try:
                old_plain = decrypt_json_struct(self._cipher_blob_b64, b'\x00' * KEY_LENGTH)
            except Exception:
                old_plain = {"entries": {}}
            self._cipher_blob_b64 = encrypt_json_struct(old_plain, self._enc_key)
        self._save_disk()
        audit_log("Initialized master password")

    def verify_master(self, master_password: str) -> bool:
        """Verify entered master against stored verifier and set session keys if correct."""
        if self._salt is None:
            return False
        candidate = derive_master_key(master_password, self._salt, iterations=self._iterations)
        if self.verifier is None:
            # no verifier set: treat as initialization
            self.initialize_master(master_password)
            return True
        if hashlib.compare_digest(candidate, self.verifier):
            self._enc_key = hashlib.sha256(candidate + b"enc-stream").digest()
            # load entries into cache
            self._entries_cache = decrypt_json_struct(self._cipher_blob_b64, self._enc_key).get("entries", {})
            return True
        return False

    def _commit_entries(self) -> None:
        """Re-encrypt the entries cache and write to disk (assumes _enc_key set)."""
        if self._enc_key is None:
            raise RuntimeError("Encryption key not set; authenticate first")
        payload = {"entries": self._entries_cache}
        self._cipher_blob_b64 = encrypt_json_struct(payload, self._enc_key)
        self._save_disk()

    # ----- high-level operations -----

    def list_services(self) -> List[str]:
        return sorted(self._entries_cache.keys())

    def get_entry(self, service: str) -> Optional[Dict[str, Any]]:
        return self._entries_cache.get(service)

    def add_or_update_entry(self, service: str, username: str, password: str, notes: str = "", tags: Optional[List[str]] = None) -> None:
        now = _now_iso()
        tags = tags or []
        entry = self._entries_cache.get(service, {})
        # store previous password into history if changed
        if "password" in entry and entry["password"] != password:
            history = entry.setdefault("history", [])
            history.append({"password": entry["password"], "changed": entry.get("modified", now)})
        entry.update({
            "username": username,
            "password": password,
            "notes": notes,
            "tags": tags,
            "created": entry.get("created", now),
            "modified": now
        })
        self._entries_cache[service] = entry
        self._commit_entries()
        audit_log(f"Add/Update entry: {service}")

    def delete_entry(self, service: str) -> bool:
        if service in self._entries_cache:
            del self._entries_cache[service]
            self._commit_entries()
            audit_log(f"Deleted entry: {service}")
            return True
        return False

    def search_services(self, query: str) -> List[str]:
        q = query.lower()
        results = []
        for s, entry in self._entries_cache.items():
            if q in s.lower() or q in (entry.get("username","").lower()) or any(q in tag.lower() for tag in entry.get("tags", [])):
                results.append(s)
        return sorted(results)

    def export_decrypted(self, filepath: str) -> str:
        """Export decrypted data to a plaintext file (user-triggered). Returns path."""
        with open(filepath, "w", encoding="utf-8") as f:
            for s, e in sorted(self._entries_cache.items()):
                f.write(f"Service: {s}\n")
                f.write(f"Username: {e.get('username','')}\n")
                f.write(f"Password: {e.get('password','')}\n")
                f.write(f"Notes: {e.get('notes','')}\n")
                f.write(f"Tags: {', '.join(e.get('tags', []))}\n")
                f.write("-" * 40 + "\n")
        audit_log(f"Exported vault to {filepath}")
        return filepath

    def backup(self) -> str:
        """Write an encrypted backup copy of the vault file."""
        _ensure_backup_dir()
        ts = time.strftime("%Y%m%dT%H%M%S")
        dest = os.path.join(BACKUP_DIR, f"vault_backup_{ts}.json")
        with open(self.path, "rb") as src, open(dest, "wb") as dst:
            dst.write(src.read())
        audit_log(f"Created backup {dest}")
        return dest

    def import_backup(self, backup_path: str) -> bool:
        """Import an encrypted backup (overwrite). Returns True if successful."""
        if not os.path.exists(backup_path):
            return False
        with open(backup_path, "rb") as b, open(self.path, "wb") as dst:
            dst.write(b.read())
        self.load_or_init()
        audit_log(f"Imported backup {backup_path}")
        return True


# ---------------------------
# Password generator utilities
# ---------------------------

def generate_random_password(length: int = 16, use_symbols: bool = True) -> str:
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    symbols = "!@#$%^&*()-_=+[]{};:,.<>?"
    pool = letters + digits + (symbols if use_symbols else "")
    # ensure at least one of each important class
    pwd = [
        random.choice(letters),
        random.choice(digits),
    ]
    if use_symbols:
        pwd.append(random.choice(symbols))
    while len(pwd) < length:
        pwd.append(random.choice(pool))
    random.shuffle(pwd)
    return ''.join(pwd[:length])


def generate_passphrase(words: int = 4) -> str:
    return "-".join(random.choice(WORDLIST) for _ in range(words))


def rate_password_strength(password: str) -> str:
    return check_password_strength_light(password)


def check_password_strength_light(password: str) -> str:
    # lightweight rating used in TUI
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password) and any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1
    if score >= 4:
        return "Very strong"
    elif score == 3:
        return "Strong"
    elif score == 2:
        return "Moderate"
    return "Weak"


# ---------------------------
# Small helper UI functions
# ---------------------------

def clear_screen():
    # minimal cross-platform clear
    os.system('cls' if os.name == 'nt' else 'clear')


def center_text(s: str, width: int = MENU_WIDTH) -> str:
    s = s[:width]
    left = max((width - len(s)) // 2, 0)
    return " " * left + s


def prompt_input(prompt: str, allow_empty: bool = False) -> str:
    while True:
        val = input(prompt)
        if val or allow_empty:
            return val.strip()


def prompt_password(prompt: str = "Password: ") -> str:
    return getpass.getpass(prompt)


def confirm_prompt(prompt: str) -> bool:
    ans = input(f"{prompt} (y/n): ").lower().strip()
    return ans.startswith('y')


# ---------------------------
# Text-based UI
# ---------------------------

class TUI:
    """
    Minimal TUI with arrow keys or single-key commands.
    Presents a main menu, and lists entries with a selectable cursor.
    """

    def __init__(self, vault: Vault):
        self.vault = vault
        self.last_activity = time.time()
        self.locked = False

    def _touch(self):
        self.last_activity = time.time()

    def check_auto_lock(self) -> bool:
        """Return True if session should be locked due to inactivity."""
        if time.time() - self.last_activity > AUTO_LOCK_SECONDS:
            self.locked = True
            audit_log("Auto-locked due to inactivity")
            return True
        return False

    def _read_key(self) -> str:
        k = getch()
        # normalize common returns
        if k == '\r':
            return '\n'
        return k

    def run(self):
        # main loop
        while True:
            if self.check_auto_lock():
                # require re-auth
                print("\nSession locked due to inactivity. Please re-enter master password.")
                self.locked = True
                if not self._reauth():
                    print("Authentication failed. Exiting.")
                    return
            self.show_main_menu()
            # loop continues until exit

    def show_main_menu(self):
        clear_screen()
        print(center_text("Password Vault", MENU_WIDTH))
        print(center_text("(Use arrow keys or number keys)", MENU_WIDTH))
        print("\n")
        options = [
            "List services",
            "Add / Update service",
            "View service",
            "Delete service",
            "Search services",
            "Generate password",
            "Export vault (plaintext)",
            "Backup / Import",
            "Settings",
            "Exit"
        ]
        for i, opt in enumerate(options, start=1):
            print(f" {i}. {opt}")
        print("\nSelect (arrow keys/1-9): ", end='', flush=True)

        # read one key
        key = self._read_key()
        self._touch()

        # map arrows for convenience: up/down ignored here, simpler numeric mapping
        if key in ('1', '\x1b[A'):  # 1 or up arrow
            self.menu_list_services()
        elif key == '2':
            self.menu_add_service()
        elif key == '3':
            self.menu_view_service()
        elif key == '4':
            self.menu_delete_service()
        elif key == '5':
            self.menu_search_services()
        elif key == '6':
            self.menu_generate_password()
        elif key == '7':
            self.menu_export()
        elif key == '8':
            self.menu_backup_import()
        elif key == '9':
            self.menu_settings()
        elif key == '0' or key == '\x1b':  # exit on 0 or ESC
            if confirm_prompt("Are you sure you want to exit?"):
                audit_log("User exited")
                print("Goodbye.")
                sys.exit(0)
        else:
            # if key is newline (enter) show list
            if key == '\n':
                self.menu_list_services()

    # ---------- menus ----------
    def menu_list_services(self):
        services = self.vault.list_services()
        if not services:
            print("\nNo services stored yet. Press Enter to continue.")
            input()
            return
        idx = 0
        while True:
            clear_screen()
            print(center_text("Stored Services", MENU_WIDTH))
            print("-" * MENU_WIDTH)
            start = max(0, idx - 5)
            end = min(len(services), start + 12)
            for i in range(start, end):
                prefix = "-> " if i == idx else "   "
                print(f"{prefix}{services[i]}")
            print("\nUse Up/Down to navigate, Enter to view, 'q' to return.")
            k = self._read_key()
            self._touch()
            if k in ('\x1b[A', 'k'):  # up
                idx = (idx - 1) % len(services)
            elif k in ('\x1b[B', 'j'):  # down
                idx = (idx + 1) % len(services)
            elif k == '\n':
                self.show_service_detail(services[idx])
            elif k.lower() == 'q':
                return

    def menu_add_service(self):
        clear_screen()
        print(center_text("Add or Update Service", MENU_WIDTH))
        service = prompt_input("Service name: ")
        if not service:
            print("Service name required.")
            time.sleep(0.7)
            return
        username = prompt_input("Username: ", allow_empty=True)
        pwd = prompt_password("Password (leave blank to generate): ")
        if not pwd:
            cfg_len = int(prompt_input("Length for generated password (default 16): ", allow_empty=True) or 16)
            pwd = generate_random_password(cfg_len, use_symbols=True)
            print("Generated password:", pwd)
        notes = prompt_input("Notes (optional): ", allow_empty=True)
        tags_raw = prompt_input("Tags (comma separated, optional): ", allow_empty=True)
        tags = [t.strip() for t in tags_raw.split(",")] if tags_raw else []
        self.vault.add_or_update_entry(service, username, pwd, notes, tags)
        print("Done. Press Enter to continue.")
        input()

    def menu_view_service(self):
        service = prompt_input("Enter service to view (or blank to list): ", allow_empty=True)
        if not service:
            self.menu_list_services()
            return
        self.show_service_detail(service)

    def show_service_detail(self, service: str):
        entry = self.vault.get_entry(service)
        clear_screen()
        if not entry:
            print("Service not found.")
            input("Press Enter to continue.")
            return
        print(center_text(f"Service: {service}", MENU_WIDTH))
        print("-" * MENU_WIDTH)
        print(f"Username: {entry.get('username','')}")
        print(f"Password: {entry.get('password','')}")
        print(f"Tags: {', '.join(entry.get('tags',[]))}")
        print("Notes:")
        print(entry.get('notes','') or "(none)")
        print("\nHistory:")
        for h in entry.get("history", []):
            print(f" - {h.get('changed')}: {h.get('password')}")
        print("\nOptions: [c] copy password (not implemented), [e] edit, [b] back")
        k = input("Choose: ").lower().strip()
        if k == 'e':
            self.edit_entry(service, entry)
        # copy not implemented intentionally (clipboard libs are third-party / platform-specific)
        return

    def edit_entry(self, service: str, entry: Dict[str, Any]):
        clear_screen()
        print(center_text(f"Edit: {service}", MENU_WIDTH))
        username = prompt_input(f"Username [{entry.get('username','')}]: ", allow_empty=True) or entry.get("username","")
        pwd = prompt_password("Password (leave blank to keep current): ")
        if not pwd:
            pwd = entry.get("password","")
        notes = prompt_input(f"Notes (blank to keep): ", allow_empty=True) or entry.get("notes","")
        tags_raw = prompt_input("Tags (comma separated, leave blank to keep): ", allow_empty=True)
        tags = entry.get("tags", [])
        if tags_raw:
            tags = [t.strip() for t in tags_raw.split(",")]
        self.vault.add_or_update_entry(service, username, pwd, notes, tags)
        print("Updated. Press Enter to continue.")
        input()

    def menu_delete_service(self):
        service = prompt_input("Service to delete: ")
        if not service:
            return
        if not self.vault.get_entry(service):
            print("Service not found.")
            input("Press Enter to continue.")
            return
        if confirm_prompt(f"Delete '{service}' permanently?"):
            self.vault.delete_entry(service)
            print("Deleted.")
            input("Press Enter to continue.")

    def menu_search_services(self):
        q = prompt_input("Search query: ")
        results = self.vault.search_services(q)
        if not results:
            print("No matches.")
            input("Press Enter to continue.")
            return
        idx = 0
        while True:
            clear_screen()
            print(center_text(f"Search: {q}", MENU_WIDTH))
            for i, s in enumerate(results):
                prefix = "-> " if i == idx else "   "
                print(f"{prefix}{s}")
            print("\nUp/Down to select, Enter to view, q to return.")
            k = self._read_key()
            self._touch()
            if k in ('\x1b[A', 'k'):
                idx = (idx - 1) % len(results)
            elif k in ('\x1b[B', 'j'):
                idx = (idx + 1) % len(results)
            elif k == '\n':
                self.show_service_detail(results[idx])
            elif k.lower() == 'q':
                return

    def menu_generate_password(self):
        clear_screen()
        print(center_text("Password Generator", MENU_WIDTH))
        length = int(prompt_input("Length [16]: ", allow_empty=True) or 16)
        use_symbols = prompt_input("Include symbols? (y/n) [y]: ", allow_empty=True).lower().startswith('y') or True
        mode = prompt_input("Mode: [1] random, [2] passphrase (words) [1]: ", allow_empty=True) or "1"
        if mode == "2":
            words = int(prompt_input("Words in passphrase [4]: ", allow_empty=True) or 4)
            pwd = generate_passphrase(words)
        else:
            pwd = generate_random_password(length, use_symbols=use_symbols)
        print("\nGenerated password:")
        print(pwd)
        print("Strength:", rate_password_strength(pwd))
        input("\nPress Enter to continue.")

    def menu_export(self):
        clear_screen()
        print(center_text("Export Vault (plaintext)", MENU_WIDTH))
        if not confirm_prompt("Export vault to plaintext file? This will create an unencrypted file."):
            return
        default = f"vault_export_{time.strftime('%Y%m%dT%H%M%S')}.txt"
        path = prompt_input(f"Output path [{default}]: ", allow_empty=True) or default
        out = self.vault.export_decrypted(path)
        print(f"Exported to {out}")
        input("Press Enter to continue.")

    def menu_backup_import(self):
        clear_screen()
        print(center_text("Backup & Import", MENU_WIDTH))
        print("1. Create encrypted backup")
        print("2. Import encrypted backup")
        print("3. List backups")
        choice = prompt_input("Choice: ", allow_empty=True)
        if choice == "1":
            path = self.vault.backup()
            print("Backup created:", path)
            input("Press Enter to continue.")
        elif choice == "2":
            back = prompt_input("Path to backup to import: ")
            if self.vault.import_backup(back):
                print("Imported. NOTE: You may need to re-authenticate.")
            else:
                print("Import failed.")
            input("Press Enter to continue.")
        elif choice == "3":
            _ensure_backup_dir()
            items = sorted(os.listdir(BACKUP_DIR))
            for it in items:
                print(" -", it)
            input("Press Enter to continue.")

    def menu_settings(self):
        clear_screen()
        print(center_text("Settings", MENU_WIDTH))
        print(f"Auto-lock timeout (seconds): {AUTO_LOCK_SECONDS}")
        print("Not configurable at runtime in this demo. To change, edit the script.")
        input("Press Enter to continue.")

    def _reauth(self) -> bool:
        # re-prompt master password; allow 3 attempts
        attempts = 3
        while attempts > 0:
            pw = prompt_password("Master password: ")
            if self.vault.verify_master(pw):
                self.locked = False
                self._touch()
                return True
            else:
                attempts -= 1
                print("Incorrect password.")
        return False


# ---------------------------
# Entrypoint and flow
# ---------------------------

def main():
    random.seed()  # system seed
    vault = Vault(VAULT_FILE)
    # If no verifier: prompt user to set one
    if vault.verifier is None:
        print("Welcome — let's set up your master password.")
        while True:
            mpw = prompt_password("New master password (min 8 chars): ")
            if len(mpw) < 8:
                print("Password too short.")
                continue
            conf = prompt_password("Confirm master password: ")
            if mpw != conf:
                print("Passwords do not match.")
                continue
            vault.initialize_master(mpw)
            print("Master password set. Remember it — it cannot be recovered.")
            break
    # Otherwise authenticate
    else:
        attempts = 3
        ok = False
        while attempts > 0:
            mpw = prompt_password("Enter master password to unlock: ")
            if vault.verify_master(mpw):
                ok = True
                break
            attempts -= 1
            print("Incorrect. Attempts left:", attempts)
        if not ok:
            print("Failed to authenticate. Exiting.")
            audit_log("Failed initial authentication")
            sys.exit(1)
    # launch TUI
    tui = TUI(vault)
    audit_log("User session started")
    try:
        tui.run()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        audit_log("Interrupted by user")


if __name__ == "__main__":
    main()
