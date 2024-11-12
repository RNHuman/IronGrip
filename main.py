import base64
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import json
import time
import os
from cryptography.fernet import Fernet
import bcrypt

DATA_FILE = "passwords.dat"
HASH_FILE = "master.hash"
AUTO_LOCK_TIMEOUT = 300  # Lock after 5 minutes of inactivity (in seconds)


class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("400x300")

        self.tabs = {}
        self.last_active_time = time.time()

        self.master_password = None  # Store master password temporarily for encryption key derivation
        self.fernet = None  # Store Fernet instance for encryption/decryption

        # Main interface components
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=1, fill="both")

        save_button = tk.Button(self.root, text="Save Data", command=self.save_data)
        save_button.pack(side="bottom", pady=10)

        # Lock mechanism
        self.root.bind_all("<Any-KeyPress>", self.update_last_active_time)
        self.root.bind_all("<Any-ButtonPress>", self.update_last_active_time)
        self.check_auto_lock()

        # Set or verify master password
        if os.path.exists(HASH_FILE):
            self.authenticate_user()
        else:
            self.set_master_password()

    def update_last_active_time(self, event=None):
        self.last_active_time = time.time()

    def check_auto_lock(self):
        if time.time() - self.last_active_time > AUTO_LOCK_TIMEOUT:
            self.lock_manager()
        else:
            self.root.after(1000, self.check_auto_lock)  # Check every second

    def lock_manager(self):
        self.notebook.pack_forget()
        messagebox.showinfo("Locked", "Password Manager locked due to inactivity.")
        self.authenticate_user()

    def set_master_password(self):
        password = simpledialog.askstring("Set Master Password", "Enter a master password:", show="*")
        if password:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            with open(HASH_FILE, "wb") as f:
                f.write(hashed)
            self.master_password = password
            self.initialize_fernet()
            self.load_data()

    def authenticate_user(self):
        password = simpledialog.askstring("Master Password", "Enter your master password:", show="*")
        if password:
            with open(HASH_FILE, "rb") as f:
                hashed = f.read()
            if bcrypt.checkpw(password.encode(), hashed):
                self.master_password = password
                self.initialize_fernet()
                self.notebook.pack(expand=1, fill="both")
                self.load_data()
                self.last_active_time = time.time()
            else:
                messagebox.showerror("Error", "Incorrect master password.")
                self.authenticate_user()

    def initialize_fernet(self):
        # Derive key from master password
        salt = b'salt_'  # In production, use a better salt management strategy
        key = bcrypt.kdf(
            password=self.master_password.encode(),
            salt=salt,
            desired_key_bytes=32,
            rounds=100
        )
        self.fernet = Fernet(base64.urlsafe_b64encode(key))

    def add_tab(self):
        tab_name = simpledialog.askstring("Tab Name", "Enter new tab name:")
        if tab_name:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=tab_name)
            self.create_tab_content(frame, tab_name)
            self.tabs[tab_name] = frame

    def create_tab_content(self, frame, tab_name):
        email_label = tk.Label(frame, text="Email:")
        email_label.pack(pady=10)

        email_entry = tk.Entry(frame, width=30)
        email_entry.pack()

        password_label = tk.Label(frame, text="Password:")
        password_label.pack(pady=10)

        password_entry = tk.Entry(frame, width=30, show="*")
        password_entry.pack()

        toggle_btn = tk.Button(frame, text="Show",
                               command=lambda: self.toggle_password_visibility(password_entry, toggle_btn))
        toggle_btn.pack(pady=5)

        self.tabs[tab_name] = {
            'email': email_entry,
            'password': password_entry,
            'toggle_btn': toggle_btn
        }

    def toggle_password_visibility(self, password_entry, toggle_btn):
        if password_entry.cget('show') == "*":
            password_entry.config(show="")
            toggle_btn.config(text="Hide")
        else:
            password_entry.config(show="*")
            toggle_btn.config(text="Show")

    def save_data(self):
        tab_data = {}
        for tab_name, fields in self.tabs.items():
            email = fields['email'].get()
            password = fields['password'].get()
            tab_data[tab_name] = {'email': email, 'password': password}

        tab_data_json = json.dumps(tab_data)
        encrypted_data = self.fernet.encrypt(tab_data_json.encode())

        with open(DATA_FILE, "wb") as file:
            file.write(encrypted_data)

        messagebox.showinfo("Success", "Data saved and encrypted successfully!")

    def load_data(self):
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "rb") as file:
                encrypted_data = file.read()

            try:
                decrypted_data = self.fernet.decrypt(encrypted_data).decode()
                tab_data = json.loads(decrypted_data)

                for tab_name, data in tab_data.items():
                    frame = ttk.Frame(self.notebook)
                    self.notebook.add(frame, text=tab_name)
                    self.create_tab_content(frame, tab_name)
                    self.tabs[tab_name]['email'].insert(0, data['email'])
                    self.tabs[tab_name]['password'].insert(0, data['password'])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt data: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
