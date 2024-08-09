import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import os

class PasswordManager:
    def __init__(self):
        self.key_file = "secret.key"
        self.password_file = "passwords.txt"
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

class PasswordManagerGUI:
    def __init__(self, root):
        self.pm = PasswordManager()
        self.root = root
        self.root.title("Password Manager")

        self.service_label = tk.Label(root, text="Service:")
        self.service_label.grid(row=0, column=0, padx=10, pady=10)

        self.service_entry = tk.Entry(root)
        self.service_entry.grid(row=0, column=1, padx=10, pady=10)

        self.password_label = tk.Label(root, text="Password:")
        self.password_label.grid(row=1, column=0, padx=10, pady=10)

        self.password_entry = tk.Entry(root)
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        self.add_button = tk.Button(root, text="Add Password", command=self.add_password)
        self.add_button.grid(row=2, column=0, padx=10, pady=10)

        self.get_button = tk.Button(root, text="Get Password", command=self.get_password)
        self.get_button.grid(row=2, column=1, padx=10, pady=10)

        self.change_key_button = tk.Button(root, text="Change Key", command=self.change_key)
        self.change_key_button.grid(row=3, column=0, padx=10, pady=10)

        self.delete_button = tk.Button(root, text="Delete Password", command=self.delete_password)
        self.delete_button.grid(row=3, column=1, padx=10, pady=10)

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

if __name__ == "__main__":
    root = tk.Tk()
    gui = PasswordManagerGUI(root)
    root.mainloop()
