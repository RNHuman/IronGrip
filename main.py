import tkinter as tk
from tkinter import ttk, simpledialog, messagebox

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

        # Add a default tab
        self.add_tab()

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

        self.tabs[tab_name] = {'email': email_entry, 'password': password_entry}

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

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
