import customtkinter as ctk
import hashlib
import os
from cryptography.fernet import Fernet  # For encryption

ctk.set_appearance_mode("System")

# File paths
master_pw_file = "masterpass.dat"
passwords_file = "passwords.txt"
key_file = "encryption.key"  # File to store the encryption key

# -------------------------
# Encryption Key Management
# -------------------------
def generate_key():
    """Generates and saves an encryption key if not already present."""
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)

def load_key():
    """Loads the encryption key from file."""
    with open(key_file, 'rb') as f:
        return f.read()

# Generate key if necessary and create Fernet instance
generate_key()
fernet = Fernet(load_key())

# -------------------------
# Master Password Handling
# -------------------------
def encrypt(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed, salt

def save_master_pw():
    password = master_pw.get()
    if os.path.exists(master_pw_file):
        feedback.configure(text="Error: Master password already set!")
        return

    hashed, salt = encrypt(password)
    with open(master_pw_file, 'wb') as f:
        f.write(salt + hashed)
    feedback.configure(text="Master password set successfully!")

def login():
    input_pw = master_pw.get()
    if not os.path.exists(master_pw_file):
        feedback.configure(text="No master password found. Please set it first.")
        return
    try:
        with open(master_pw_file, 'rb') as f:
            stored_data = f.read()
            salt = stored_data[:16]
            stored_hash = stored_data[16:]
        input_hash, _ = encrypt(input_pw, salt)
        if input_hash == stored_hash:
            feedback.configure(text="Login Successful!")
            show_password_ui()  # Transition to password manager UI
        else:
            feedback.configure(text="Error: Incorrect Master Password")
    except Exception as e:
        feedback.configure(text=f"Error! {str(e)}")

# -------------------------
# Secure Password Management Functions
# -------------------------
def show_password_ui():
    """Sets up the password management UI after successful login."""
    for widget in first_page.winfo_children():
        widget.destroy()

    ctk.CTkLabel(master=first_page, text="Password Manager", font=("Copperplate Gothic Bold", 25), text_color="#00a6ff").pack(pady=20)

    global new_pw_entry
    new_pw_entry = ctk.CTkEntry(master=first_page, height=35, width=250, placeholder_text="Name | Password", font=("Helvetica", 12))
    new_pw_entry.pack(pady=20)

    ctk.CTkButton(master=first_page, text="Add", font=("Arial", 17, "bold"), width=80, command=add_password).pack(pady=10)

    global pw_scroll_frame
    pw_scroll_frame = ctk.CTkScrollableFrame(master=first_page, border_width=1, fg_color="black", height=200)
    pw_scroll_frame.pack(expand=True, fill="both", padx=30, pady=30)

    load_passwords()

def encrypt_password(password):
    """Encrypts a password using Fernet."""
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    """Decrypts an encrypted password using Fernet."""
    return fernet.decrypt(encrypted_password.encode()).decode()

def add_password():
    """Encrypts and adds a new password entry to file and UI."""
    pw_text = new_pw_entry.get().strip()
    if not pw_text:
        feedback.configure(text="Please enter a valid 'Name | Password' entry.")
        return

    # Ensure the proper format "Name | Password"
    if " | " not in pw_text:
        parts = pw_text.split()
        if len(parts) >= 2:
            pw_text = parts[0] + " | " + " ".join(parts[1:])
        else:
            feedback.configure(text="Invalid format. Use 'Name | Password'.")
            return

    name, password = pw_text.split(" | ", 1)
    encrypted_pw = encrypt_password(password)

    with open(passwords_file, 'a') as f:
        f.write(f"{name} | {encrypted_pw}\n")

    add_password_to_ui(name, encrypted_pw)
    new_pw_entry.delete(0, 'end')
    feedback.configure(text="Password added securely!")

def add_password_to_ui(name, encrypted_pw):
    """Displays a password entry in the UI after decryption."""
    decrypted_pw = decrypt_password(encrypted_pw)
    frame = ctk.CTkFrame(master=pw_scroll_frame, fg_color="transparent")
    frame.pack(fill="x", pady=5, padx=5)

    label = ctk.CTkLabel(master=frame, text=f"{name} | {decrypted_pw}", font=("Helvetica", 14))
    label.pack(side="left", padx=10)

    ctk.CTkButton(master=frame, text="Delete", font=("Arial", 12), width=60,
                  command=lambda: delete_password(name, encrypted_pw, frame)).pack(side="right", padx=10)

def delete_password(name, encrypted_pw, frame):
    """Removes a password entry from UI and file."""
    frame.destroy()
    if os.path.exists(passwords_file):
        with open(passwords_file, 'r') as f:
            lines = f.readlines()
        with open(passwords_file, 'w') as f:
            for line in lines:
                if line.strip() != f"{name} | {encrypted_pw}":
                    f.write(line)
    feedback.configure(text=f"Deleted entry: {name}")

def load_passwords():
    """Loads encrypted passwords from file and displays them."""
    if os.path.exists(passwords_file):
        with open(passwords_file, 'r') as f:
            lines = f.readlines()
        for line in lines:
            if " | " in line:
                name, encrypted_pw = line.strip().split(" | ", 1)
                add_password_to_ui(name, encrypted_pw)

# -------------------------
# UI Setup (Login / Set Master PW)
# -------------------------
app = ctk.CTk()
app.title("Password Manager")
app.geometry("400x500")

first_page = ctk.CTkFrame(master=app, border_width=1)
first_page.pack(expand=True, fill="both", padx=20, pady=20)

# Login Screen Header
ctk.CTkLabel(master=first_page, text="Password\nManager", font=("Copperplate Gothic Bold", 55), text_color="#00a6ff").pack(pady=20)

master_pw = ctk.CTkEntry(master=first_page, height=35, width=250, placeholder_text="Enter the Master Password", font=("Helvetica", 18), show="⁕")
master_pw.pack(pady=20)

ctk.CTkButton(master=first_page, text="Submit", font=("Arial", 20, "bold"), width=40, command=login).pack(pady=10)

# Guide label for first-time users
guide = ctk.CTkLabel(master=first_page, text="First time using? Set your Master Password below.", font=("Helvetica", 12))
guide.pack(pady=10)

ctk.CTkButton(master=first_page, text="Set Password", font=("Arial", 17, "bold"), width=40, command=save_master_pw).pack(pady=10)

feedback = ctk.CTkLabel(master=first_page, text="", font=("Helvetica", 15))
feedback.pack(pady=15)

app.mainloop()
