import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.fernet import Fernet
import bcrypt
import os

class PasswordManager:
    def __init__(self):
        self.key_file = "secret.key"
        self.password_file = "passwords.txt"
        self.master_password_file = "master.pass"
        self.key = self.load_or_generate_key()

    def load_or_generate_key(self):
        if not os.path.exists(self.key_file):
            self.generate_key()
        return self.load_key()

    def generate_key(self):
        key = Fernet.generate_key()
        with open(self.key_file, "wb") as key_file:
            key_file.write(key)

    def load_key(self):
        try:
            with open(self.key_file, "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            self.generate_key()
            return self.load_key()

    def encrypt_password(self, password):
        fernet = Fernet(self.key)
        return fernet.encrypt(password.encode())

    def decrypt_password(self, encrypted_password):
        fernet = Fernet(self.key)
        return fernet.decrypt(encrypted_password).decode()

    def add_password(self, service, password):
        encrypted_password = self.encrypt_password(password)
        with open(self.password_file, "a") as f:
            f.write(f"{service}:{encrypted_password.decode()}\n")

    def get_password(self, service):
        try:
            with open(self.password_file, "r") as f:
                for line in f:
                    stored_service, stored_password = line.strip().split(":")
                    if stored_service == service:
                        return self.decrypt_password(stored_password.encode())
            return None
        except FileNotFoundError:
            return None

    def change_key(self):
        old_key = self.key
        self.generate_key()
        new_key = self.key

        try:
            with open(self.password_file, "r") as f:
                lines = f.readlines()

            with open(self.password_file, "w") as f:
                for line in lines:
                    service, encrypted_password = line.strip().split(":")
                    decrypted_password = Fernet(old_key).decrypt(encrypted_password.encode()).decode()
                    new_encrypted_password = Fernet(new_key).encrypt(decrypted_password.encode()).decode()
                    f.write(f"{service}:{new_encrypted_password}\n")
        except FileNotFoundError:
            pass

    def delete_password(self, service):
        try:
            with open(self.password_file, "r") as f:
                lines = f.readlines()

            with open(self.password_file, "w") as f:
                for line in lines:
                    stored_service, stored_password = line.strip().split(":")
                    if stored_service != service:
                        f.write(line)
        except FileNotFoundError:
            pass

    def set_master_password(self, master_password):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(master_password.encode(), salt)
        with open(self.master_password_file, "wb") as f:
            f.write(hashed)

    def check_master_password(self, master_password):
        try:
            with open(self.master_password_file, "rb") as f:
                stored_hash = f.read()
                return bcrypt.checkpw(master_password.encode(), stored_hash)
        except FileNotFoundError:
            return False

class PasswordManagerGUI:
    def __init__(self, root):
        self.pm = PasswordManager()
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("400x300")

        # Show login screen first
        self.show_login_screen()

    def show_login_screen(self):
        self.clear_root()
        login_frame = ttk.Frame(self.root, padding="10 10 10 10")
        login_frame.grid(row=0, column=0, sticky="EW")

        self.master_password_label = ttk.Label(login_frame, text="Master Password:")
        self.master_password_label.grid(row=0, column=0, padx=5, pady=5, sticky="W")

        self.master_password_entry = ttk.Entry(login_frame, width=30, show="*")
        self.master_password_entry.grid(row=0, column=1, padx=5, pady=5, sticky="EW")

        self.login_button = ttk.Button(login_frame, text="Login", command=self.login)
        self.login_button.grid(row=1, column=1, padx=5, pady=5, sticky="E")

        if not os.path.exists(self.pm.master_password_file):
            self.master_password_label.config(text="Set Master Password:")
            self.login_button.config(text="Set Password", command=self.set_master_password)

    def login(self):
        master_password = self.master_password_entry.get()
        if self.pm.check_master_password(master_password):
            self.show_main_screen()
        else:
            messagebox.showwarning("Login Failed", "Incorrect master password!")

    def set_master_password(self):
        master_password = self.master_password_entry.get()
        if master_password:
            self.pm.set_master_password(master_password)
            messagebox.showinfo("Success", "Master password set successfully!")
            self.show_main_screen()
        else:
            messagebox.showwarning("Input Error", "Please enter a valid master password.")

    def show_main_screen(self):
        self.clear_root()

        # Configure style
        style = ttk.Style()
        style.configure("TLabel", font=("Helvetica", 12))
        style.configure("TButton", font=("Helvetica", 12))
        style.configure("TEntry", font=("Helvetica", 12))

        # Frame for service and password inputs
        input_frame = ttk.Frame(self.root, padding="10 10 10 10")
        input_frame.grid(row=0, column=0, sticky="EW")

        # Service label and entry
        self.service_label = ttk.Label(input_frame, text="Service:")
        self.service_label.grid(row=0, column=0, padx=5, pady=5, sticky="W")

        self.service_entry = ttk.Entry(input_frame, width=30)
        self.service_entry.grid(row=0, column=1, padx=5, pady=5, sticky="EW")

        # Password label and entry
        self.password_label = ttk.Label(input_frame, text="Password:")
        self.password_label.grid(row=1, column=0, padx=5, pady=5, sticky="W")

        self.password_entry = ttk.Entry(input_frame, width=30)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="EW")

        # Button Frame
        button_frame = ttk.Frame(self.root, padding="10 10 10 10")
        button_frame.grid(row=1, column=0, sticky="EW")

        # Add button
        self.add_button = ttk.Button(button_frame, text="Add Password", command=self.add_password)
        self.add_button.grid(row=0, column=0, padx=5, pady=5)

        # Get button
        self.get_button = ttk.Button(button_frame, text="Get Password", command=self.get_password)
        self.get_button.grid(row=0, column=1, padx=5, pady=5)

        # Change key button
        self.change_key_button = ttk.Button(button_frame, text="Change Key", command=self.change_key)
        self.change_key_button.grid(row=1, column=0, padx=5, pady=5)

        # Delete button
        self.delete_button = ttk.Button(button_frame, text="Delete Password", command=self.delete_password)
        self.delete_button.grid(row=1, column=1, padx=5, pady=5)

        # Menu Bar
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Change Key", command=self.change_key)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def add_password(self):
        service = self.service_entry.get()
        password = self.password_entry.get()
        if service and password:
            self.pm.add_password(service, password)
            messagebox.showinfo("Success", f"Password for {service} added successfully!")
            self.clear_entries()
        else:
            messagebox.showwarning("Input Error", "Please enter both service and password.")

    def get_password(self):
        service = self.service_entry.get()
        if service:
            password = self.pm.get_password(service)
            if password:
                messagebox.showinfo("Password Found", f"The password for {service} is {password}")
            else:
                messagebox.showwarning("Not Found", f"No password found for {service}.")
        else:
            messagebox.showwarning("Input Error", "Please enter a service name.")

    def change_key(self):
        self.pm.change_key()
        messagebox.showinfo("Success", "Secret key changed successfully!")

    def delete_password(self):
        service = self.service_entry.get()
        if service:
            self.pm.delete_password(service)
            messagebox.showinfo("Success", f"Password for {service} deleted successfully!")
            self.clear_entries()
        else:
            messagebox.showwarning("Input Error", "Please enter a service name.")

    def clear_entries(self):
        self.service_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_about(self):
        messagebox.showinfo("About", "Password Manager v2.0\nDeveloped by Daksh Thapar")

if __name__ == "__main__":
    root = tk.Tk()
    gui = PasswordManagerGUI(root)
    root.mainloop()
