import customtkinter as ctk
import hashlib
import os

ctk.set_appearance_mode("System")

pw_file = None  # Global variable to store the file path

def encrypt(password, salt=None):
    if not salt:
        salt = os.urandom(16)  # Generate a random salt if not provided
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed, salt

def save_pw():
    global pw_file  # Make sure to use the global variable for the file path
    password = master_pw.get()
    hashed, salt = encrypt(password)  # Encrypt the password
    
    # Ask the user for the save location
    file_path = ctk.filedialog.asksaveasfilename(defaultextension=".dat", filetypes=[("Data Files", "*.dat*")])
    
    if file_path:
        pw_file = file_path  # Store the file path in the global variable
        with open(pw_file, 'wb') as f:  # Use the user-selected file path
            f.write(salt + hashed)  # Save the salt and hash to the file

def login():
    global pw_file  # Use the global pw_file variable
    input_pw = master_pw.get()
    
    if pw_file is None:
        feedback.configure(text="No password file found. Please set a password first.")
        return
    
    try:
        with open(pw_file, 'rb') as f:
            stored_data = f.read()  # Read the stored data
            salt = stored_data[:16]  # The first 16 bytes are the salt
            stored_hash = stored_data[16:]  # The rest is the hash
            
        # Encrypt the input password with the stored salt
        input_hash, _ = encrypt(input_pw, salt)
        
        if input_hash == stored_hash:
            feedback.configure(text="Login Successful!")
        else:
            feedback.configure(text="Error: Incorrect Password")
    except FileNotFoundError:
        feedback.configure(text="No saved password found. Please set a password first.")

app = ctk.CTk()
app.title("Password Manager")
app.geometry("400x500")

first_page = ctk.CTkFrame(master=app, border_width=1)
first_page.pack(expand=True, fill="both", padx=20, pady=20)

header = ctk.CTkLabel(master=first_page, text="Password\nManager", font=("Copperplate Gothic Bold", 55), text_color="#00a6ff")
header.pack(pady=20)

master_pw = ctk.CTkEntry(master=first_page, height=35, width=250, placeholder_text="Enter the Master Password", font=("Helvetica", 18), show="⁕")
master_pw.pack(pady=20)

login_btn = ctk.CTkButton(master=first_page, text="Submit", font=("Arial", 20, "bold"), width=40, command=login)
login_btn.pack()

guide = ctk.CTkLabel(master=first_page, text="Using for the first time? Click Below.")
guide.pack(pady=20)

set_btn = ctk.CTkButton(master=first_page, text="Set Password", font=("Arial", 17, "bold"), width=40, command=save_pw)
set_btn.pack()

feedback = ctk.CTkLabel(master=first_page, text="", font=("Copperplate Gothic Bold", 25))
feedback.pack(pady=15)

app.mainloop()
