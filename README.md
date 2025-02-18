# Password Manager

A simple Password Manager built with Python's **CustomTkinter**, **hashlib**, and **cryptography** to securely store and manage your passwords.

## Features

- **Master Password Protection**:  
  Set a master password that is securely hashed using PBKDF2-HMAC SHA256, ensuring only authorized access to the app.

- **Secure Storage**:  
  Each password entry (formatted as `Name | Password`) is encrypted using Fernet symmetric encryption before being saved to file.

- **User-Friendly Interface**:  
  Built with CustomTkinter for an intuitive, modern UI.  
  Easily add, view, and delete password entries.

- **Persistent Data**:  
  All password entries are saved to a file and loaded on startup, ensuring your data is always available.

## Requirements

- Python 3.x
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
- `hashlib` (included in Python's standard library)
- [cryptography](https://cryptography.io/en/latest/) (for Fernet encryption)

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/paomfarv/Password-Manager.git
   cd Password-Manager
   ```

2. **Install Dependencies:**

   Use pip to install the required libraries:

   ```bash
   pip install customtkinter cryptography
   ```

## How to Run

Run the application using Python:

```bash
python PasswordManager.py
```

## Usage

1. **First-Time Setup:**
   - Launch the app and set your master password using the provided guide on the login screen.
  
2. **Login:**
   - Enter your master password and click **Submit** to access the password management interface.

3. **Manage Passwords:**
   - **Add** a new entry by typing in the `Name | Password` format.  
   - **View** your saved entries, which are automatically decrypted and displayed.  
   - **Delete** entries by clicking the corresponding delete button.

## Security

- **Master Password:**  
  The master password is securely hashed using PBKDF2-HMAC with SHA256 and a unique salt, protecting against brute-force and rainbow table attacks.

- **Password Encryption:**  
  Each password is encrypted with Fernet (symmetric encryption) before being stored, ensuring that even if the storage file is accessed, the passwords remain secure.

---

Feel free to contribute or open issues if you have any questions or suggestions!
