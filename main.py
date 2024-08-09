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
        print("A new encryption key has been generated and saved.")

    def load_key(self):
        try:
            with open(self.key_file, "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            print("Key file not found. Generating a new key...")
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
        print(f"Password for {service} added successfully!")

    def get_password(self, service):
        try:
            with open(self.password_file, "r") as f:
                for line in f:
                    stored_service, stored_password = line.strip().split(":")
                    if stored_service == service:
                        return self.decrypt_password(stored_password.encode())
            print(f"No password found for {service}.")
            return None
        except FileNotFoundError:
            print("Password file not found. No passwords stored yet.")
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

            print("Secret key changed and passwords re-encrypted successfully!")
        except FileNotFoundError:
            print("Password file not found. Cannot change key for non-existent passwords.")

    def delete_password(self, service):
        try:
            with open(self.password_file, "r") as f:
                lines = f.readlines()

            with open(self.password_file, "w") as f:
                found = False
                for line in lines:
                    stored_service, stored_password = line.strip().split(":")
                    if stored_service != service:
                        f.write(line)
                    else:
                        found = True
                if found:
                    print(f"Password for {service} deleted successfully.")
                else:
                    print(f"No password found for {service}.")

        except FileNotFoundError:
            print("Password file not found. No passwords stored yet.")

def main():
    pm = PasswordManager()

    while True:
        print("\nPassword Manager")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Change Secret Key")
        print("4. Delete Password")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            service = input("Enter the service name: ")
            password = input("Enter the password: ")
            pm.add_password(service, password)
        elif choice == '2':
            service = input("Enter the service name: ")
            password = pm.get_password(service)
            if password:
                print(f"The password for {service} is {password}")
        elif choice == '3':
            pm.change_key()
        elif choice == '4':
            service = input("Enter the service name: ")
            pm.delete_password(service)
        elif choice == '5':
            print("Exiting Password Manager. Goodbye!")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
