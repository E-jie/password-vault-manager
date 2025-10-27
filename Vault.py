import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
import os, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# File to store encrypted passwords
VAULT_FILE = "vault.bin"

# A constant salt to help protect the master password
SALT = b'my_fixed_salt_123'

# Soft purple theme background color
BG_COLOR = "#e6e0ff"


# This function converts the master password into a secure encryption key
def create_key(master_password):
    password_bytes = master_password.encode()  # Convert password to bytes

    # Key Derivation Function (PBKDF2) to make password stronger
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,              # Fernet needs 32 bytes
        salt=SALT,
        iterations=390000,     # Slows down password cracking attempts
        backend=default_backend()
    )

    # Convert the derived key to a valid Fernet key
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return Fernet(key)


# Load vault file if it exists
def load_vault():
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "rb") as file:
            return file.read()
    return b""


# Save data securely to vault file
def save_vault(data, fernet):
    encrypted = fernet.encrypt(data.encode())
    with open(VAULT_FILE, "wb") as file:
        file.write(encrypted)


class PasswordVault:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Vault")

        # Apply background color to the main window
        self.root.configure(bg=BG_COLOR)

        self.fernet = None
        self.vault = {}

        self.login_screen()


    # Remove all widgets from the screen to change views
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()


    # First screen: Login with master password
    def login_screen(self):
        self.clear_window()

        tk.Label(self.root, text="Enter Master Password:", bg=BG_COLOR).pack(pady=10)
        self.master_entry = tk.Entry(self.root, show="*")
        self.master_entry.pack(pady=5)

        tk.Button(self.root, text="Login", command=self.login, bg="#7b61ff", fg="white").pack(pady=10)


    # Check the master password entered
    def login(self):
        master_password = self.master_entry.get()
        self.fernet = create_key(master_password)

        encrypted_data = load_vault()
        if encrypted_data:
            try:
                decrypted = self.fernet.decrypt(encrypted_data).decode()
                for line in decrypted.split("\n"):
                    if line:
                        site, pw = line.split(":", 1)
                        self.vault[site] = pw
                self.main_screen()
            except:
                messagebox.showerror("Error", "Wrong master password!")
        else:
            messagebox.showinfo("New Vault", "Creating a new vault.")
            self.vault = {}
            self.main_screen()


    # Main menu screen after login
    def main_screen(self):
        self.clear_window()

        tk.Label(self.root, text="Password Vault", font=("Arial", 14, "bold"), bg=BG_COLOR).pack(pady=10)

        tk.Button(self.root, text="Add Entry", command=self.add_entry, bg="#7b61ff", fg="white").pack(pady=5)
        tk.Button(self.root, text="List Websites", command=self.list_entries, bg="#7b61ff", fg="white").pack(pady=5)
        tk.Button(self.root, text="Get Password", command=self.get_password, bg="#7b61ff", fg="white").pack(pady=5)
        tk.Button(self.root, text="Save & Exit", command=self.save_and_exit, bg="#7b61ff", fg="white").pack(pady=10)


    # Add a password entry
    def add_entry(self):
        site = simpledialog.askstring("Website", "Enter website:")
        password = simpledialog.askstring("Password", "Enter password:")
        if site and password:
            self.vault[site] = password
            messagebox.showinfo("Success", "Password saved!")


    # Show list of stored websites
    def list_entries(self):
        if self.vault:
            sites = "\n".join(self.vault.keys())
            messagebox.showinfo("Stored Websites", sites)
        else:
            messagebox.showinfo("Empty Vault", "No entries yet.")


    # View a stored password
    def get_password(self):
        site = simpledialog.askstring("Website", "Enter website name:")
        if site in self.vault:
            messagebox.showinfo("Password", self.vault[site])
        else:
            messagebox.showerror("Not Found", "Website not in vault")


    # Save vault when closing the app
    def save_and_exit(self):
        data = "\n".join(f"{s}:{p}" for s, p in self.vault.items())
        save_vault(data, self.fernet)
        self.root.destroy()


# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    root.configure(bg=BG_COLOR)  # ensure consistent background
    app = PasswordVault(root)
    root.mainloop()
