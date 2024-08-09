import tkinter as tk
from tkinter import messagebox, ttk, font
from cryptography.fernet import Fernet, InvalidToken
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
        try:
            return fernet.decrypt(encrypted_password).decode()
        except InvalidToken:
            raise ValueError("Invalid key - unable to decrypt data. The key might have changed or the data is corrupted.")

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

    def get_all_services(self):
        try:
            with open(self.password_file, "r") as f:
                return [line.split(":")[0] for line in f.readlines()]
        except FileNotFoundError:
            return []

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
        self.root.geometry("500x450")

        self.custom_font = ("JetBrains Mono", 12)
        self.default_font = ("Helvetica", 12)

        self.show_login_screen()

    def show_login_screen(self):
        self.clear_root()
        login_frame = ttk.Frame(self.root, padding="10 10 10 10")
        login_frame.grid(row=0, column=0, sticky="EW")

        self.master_password_label = ttk.Label(login_frame, text="Master Password:", font=self.default_font)
        self.master_password_label.grid(row=0, column=0, padx=5, pady=5, sticky="W")

        self.master_password_entry = ttk.Entry(login_frame, width=30, show="*", font=self.default_font)
        self.master_password_entry.grid(row=0, column=1, padx=5, pady=5, sticky="EW")

        self.login_button = ttk.Button(login_frame, text="Login", command=self.login, style="Accent.TButton")
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
        style.configure("TLabel", font=self.custom_font)
        style.configure("TButton", font=self.custom_font)
        style.configure("TEntry", font=self.custom_font)

        # Frame for service and password inputs
        input_frame = ttk.Frame(self.root, padding="10 10 10 10")
        input_frame.grid(row=0, column=0, sticky="EW")

        # Service label and entry
        self.service_label = ttk.Label(input_frame, text="Service:", font=self.default_font)
        self.service_label.grid(row=0, column=0, padx=5, pady=5, sticky="W")

        self.service_entry = ttk.Entry(input_frame, width=30, font=self.default_font)
        self.service_entry.grid(row=0, column=1, padx=5, pady=5, sticky="EW")

        # Password label and entry
        self.password_label = ttk.Label(input_frame, text="Password:", font=self.default_font)
        self.password_label.grid(row=1, column=0, padx=5, pady=5, sticky="W")

        self.password_entry = ttk.Entry(input_frame, width=30, font=self.default_font)
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

        # Listbox Frame
        listbox_frame = ttk.Frame(self.root, padding="10 10 10 10")
        listbox_frame.grid(row=2, column=0, sticky="NSEW")

        self.service_listbox = tk.Listbox(listbox_frame, font=self.custom_font, height=10, activestyle="none")
        self.service_listbox.grid(row=0, column=0, sticky="NSEW")

        # Scrollbar for the Listbox
        scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical", command=self.service_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="NS")
        self.service_listbox.configure(yscrollcommand=scrollbar.set)

        # Populate the listbox with services
        self.update_service_listbox()

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

    def update_service_listbox(self):
        services = self.pm.get_all_services()
        self.service_listbox.delete(0, tk.END)
        for service in services:
            self.service_listbox.insert(tk.END, service)

    def add_password(self):
        service = self.service_entry.get()
        password = self.password_entry.get()
        if service and password:
            self.pm.add_password(service, password)
            messagebox.showinfo("Success", f"Password for {service} added successfully!")
            self.clear_entries()
            self.update_service_listbox()
        else:
            messagebox.showwarning("Input Error", "Please enter both service and password.")

    def get_password(self):
        selected_service = self.service_listbox.get(tk.ACTIVE)
        if selected_service:
            try:
                password = self.pm.get_password(selected_service)
                if password:
                    messagebox.showinfo("Password Found", f"The password for {selected_service} is {password}")
                else:
                    messagebox.showwarning("Not Found", f"No password found for {selected_service}.")
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showwarning("Input Error", "Please select a service.")

    def change_key(self):
        self.pm.change_key()
        messagebox.showinfo("Success", "Secret key changed successfully!")

    def delete_password(self):
        selected_service = self.service_listbox.get(tk.ACTIVE)
        if selected_service:
            self.pm.delete_password(selected_service)
            messagebox.showinfo("Success", f"Password for {selected_service} deleted successfully!")
            self.update_service_listbox()
        else:
            messagebox.showwarning("Input Error", "Please select a service.")

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
