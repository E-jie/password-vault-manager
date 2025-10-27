

## 🔐 Password Vault (Local) — Group 12

This is a simple **Password Vault** built in Python.
It allows a user to save and retrieve passwords securely on their computer.

The vault is protected with a **Master Password**, so only the owner can access the stored passwords.


### ✅ Features

* Create a master password to secure your vault
* Add new password entries (e.g. Gmail, Facebook)
* View saved entries
* Passwords are **encrypted** before being stored
* Access is denied if the master password is wrong
* Copy a password to the clipboard


### 🛡 Security

This project uses the **Cryptography** library to keep passwords safe.

* AES encryption through **Fernet**
* Key is derived from the master password using PBKDF2
* Encrypted data is stored locally in a file

Only someone with the master password can decrypt the vault.


### 🖥 Requirements

Install the required libraries before running:

```
pip install -r requirements.txt
```


### ▶ How to Run

1. Download or clone this project
2. Open a terminal inside the project folder
3. Run the script:

```
python vault.py
```

4. Enter your master password to unlock the vault


### 📁 Files in this Project

| File               | Description                |
| ------------------ | -------------------------- |
| `vault.py`         | Main application program   |
| `vault.json`       | Encrypted password storage |
| `requirements.txt` | List of dependencies       |


### 👩🏽‍💻 Contributors

Group 12
Python Programming Class Project

### 📌 Reminder

Do not share your master password with anyone.
Losing the master password means **you cannot recover your saved passwords.**
