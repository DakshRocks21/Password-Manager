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
