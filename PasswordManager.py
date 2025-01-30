import customtkinter as ctk
import hashlib
import os

ctk.set_appearance_mode("System")

pw_file = "password.dat"

def encrypt(password, salt=None):
    if salt is None:
        salt = os.urandom(16) 
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed, salt

def save_pw():
    global pw_file
    password = master_pw.get()
    
    if os.path.exists(pw_file):
        feedback.configure(text="Error: Password already set! Use login.")
        return

    hashed, salt = encrypt(password)
    
    with open(pw_file, 'wb') as f:
        f.write(salt + hashed)
    
    feedback.configure(text="Password set successfully!")

def add_pw():
    global input_bar
    pw = input_bar.get()
    
    if " | " not in pw:
        pw = pw.replace(" "," | ")

    global stored_pw
    stored_pw = ctk.CTkLabel(master=frm_pw,text=pw,font=("System",30,"bold"))
    stored_pw.pack()

def delete():
    global stored_pw
    if stored_pw:
        stored_pw.destroy()

def clear():
    global frm_pw,input_bar
    for item in frm_pw.winfo_children():
        item.destroy()
    input_bar.delete(0, 'end')

def login():
    global pw_file
    input_pw = master_pw.get()

    if not os.path.exists(pw_file):
        feedback.configure(text="No password file found. Please set a password first.")
        return

    try:
        with open(pw_file, 'rb') as f:
            stored_data = f.read()
            salt = stored_data[:16]  
            stored_hash = stored_data[16:]

        input_hash, _ = encrypt(input_pw, salt)
        
        if input_hash == stored_hash:
            feedback.configure(text="Login Successful!")

            for widget in first_page.winfo_children():
                widget.destroy()
            global input_bar
            input_bar = ctk.CTkEntry(master=first_page,height=35, width=250, placeholder_text="Name | Password", font=("Helvetica", 12))
            input_bar.pack(pady=40)

            btn_frame = ctk.CTkFrame(master=first_page,fg_color="transparent")
            btn_frame.pack()

            add_btn = ctk.CTkButton(master=btn_frame, text="Add", font=("Arial", 17, "bold"), width=80, command=add_pw)
            add_btn.pack(side="left", padx=10)

            del_btn = ctk.CTkButton(master=btn_frame, text="Delete", font=("Arial", 17, "bold"), width=80, command=delete)
            del_btn.pack(side="left", padx=10)

            clear_btn = ctk.CTkButton(master=btn_frame, text="Clear", font=("Arial", 17, "bold"), width=80, command=clear)
            clear_btn.pack(side="left", padx=10)

            global frm_pw
            frm_pw = ctk.CTkScrollableFrame(master=first_page, border_width=1,fg_color="black")
            frm_pw.pack(expand=True, fill="both", padx=30, pady=30)

        else:
            feedback.configure(text="Error: Incorrect Password")
    except Exception as e:
        feedback.configure(text=f"Error! {str(e)}")

# UI Setup
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

feedback = ctk.CTkLabel(master=first_page, text="", font=("Helvetica", 15))
feedback.pack(pady=15)

app.mainloop()
