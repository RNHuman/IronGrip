import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import json
import os

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("400x300")

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

        # Menu for file operations
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save", command=self.save_data)

        # Load existing data if available
        self.load_data()

    def add_tab(self, tab_name=None, email='', password=''):
        if not tab_name:
            tab_name = simpledialog.askstring("Tab Name", "Enter new tab name:")
        if tab_name:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=tab_name)
            self.create_tab_content(frame, tab_name, email, password)
            self.tabs[tab_name] = frame

    def create_tab_content(self, frame, tab_name, email='', password=''):
        email_label = tk.Label(frame, text="Email:")
        email_label.pack(pady=5)

        email_entry = tk.Entry(frame, width=30)
        email_entry.pack()
        email_entry.insert(0, email)

        password_label = tk.Label(frame, text="Password:")
        password_label.pack(pady=5)

        password_frame = tk.Frame(frame)
        password_frame.pack()

        password_entry = tk.Entry(password_frame, width=27, show="*")
        password_entry.pack(side='left')
        password_entry.insert(0, password)

        # Variable to track password visibility
        show_password = tk.BooleanVar(value=False)

        # Function to toggle password visibility
        def toggle_password():
            if show_password.get():
                password_entry.config(show="")
                toggle_btn.config(text="Hide Password")
                show_password.set(False)
            else:
                password_entry.config(show="*")
                toggle_btn.config(text="Show Password")
                show_password.set(True)

        toggle_btn = tk.Button(password_frame, text="Show Password", command=toggle_password)
        toggle_btn.pack(side='left', padx=5)

        self.tabs[tab_name] = {
            'email': email_entry,
            'password': password_entry
        }

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
        data = {}
        for tab_name, widgets in self.tabs.items():
            email = widgets['email'].get()
            password = widgets['password'].get()
            data[tab_name] = {'email': email, 'password': password}

        with open('password_data.json', 'w') as f:
            json.dump(data, f)
        messagebox.showinfo("Save Data", "Tabs and data have been saved successfully.")

    def load_data(self):
        if os.path.exists('password_data.json'):
            with open('password_data.json', 'r') as f:
                data = json.load(f)
            for tab_name, credentials in data.items():
                self.add_tab(tab_name, credentials.get('email', ''), credentials.get('password', ''))

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
