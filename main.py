import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import json
import os
from cryptography.fernet import Fernet

# Generate or load encryption key
KEY_FILE = "secret.key"
DATA_FILE = "passwords.dat"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

def decrypt_data(data, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data).decode()
    return decrypted

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("400x300")

        self.key = load_key()
        self.tabs = {}

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=1, fill="both")

        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        # Menu for managing tabs
        tab_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Manage Tabs", menu=tab_menu)
        tab_menu.add_command(label="Add Tab", command=self.add_tab)
        tab_menu.add_command(label="Rename Tab", command=self.rename_tab)
        tab_menu.add_command(label="Delete Tab", command=self.delete_tab)

        # Save button
        save_button = tk.Button(self.root, text="Save Data", command=self.save_data)
        save_button.pack(side="bottom", pady=10)

        # Load existing data
        self.load_data()

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

        # Button to toggle password visibility
        toggle_btn = tk.Button(frame, text="Show", command=lambda: self.toggle_password_visibility(password_entry, toggle_btn))
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

    def rename_tab(self):
        current_tab = self.notebook.select()
        if current_tab:
            current_tab_index = self.notebook.index(current_tab)
            old_name = self.notebook.tab(current_tab_index, 'text')

            new_name = simpledialog.askstring("Rename Tab", f"Enter new name for tab '{old_name}':")
            if new_name:
                self.notebook.tab(current_tab_index, text=new_name)
                self.tabs[new_name] = self.tabs.pop(old_name)

    def delete_tab(self):
        current_tab = self.notebook.select()
        if current_tab:
            current_tab_index = self.notebook.index(current_tab)
            tab_name = self.notebook.tab(current_tab_index, 'text')

            if messagebox.askyesno("Delete Tab", f"Are you sure you want to delete the tab '{tab_name}'?"):
                self.notebook.forget(current_tab_index)
                del self.tabs[tab_name]

    def save_data(self):
        tab_data = {}
        for tab_name, fields in self.tabs.items():
            email = fields['email'].get()
            password = fields['password'].get()
            tab_data[tab_name] = {'email': email, 'password': password}

        # Convert tab data to JSON and encrypt it
        tab_data_json = json.dumps(tab_data)
        encrypted_data = encrypt_data(tab_data_json, self.key)

        # Save encrypted data to file
        with open(DATA_FILE, "wb") as file:
            file.write(encrypted_data)

        messagebox.showinfo("Success", "Data saved and encrypted successfully!")

    def load_data(self):
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "rb") as file:
                encrypted_data = file.read()

            try:
                # Decrypt and load the data
                decrypted_data = decrypt_data(encrypted_data, self.key)
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
