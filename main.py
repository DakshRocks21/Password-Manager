from cryptography.fernet import Fernet
import os

class PasswordManager:
    def __init__(self):
        self.key_file = "secret.key"
        self.password_file = "passwords.txt"
        if not os.path.exists(self.key_file):
            self.generate_key()
        self.key = self.load_key()

    def generate_key(self):
        key = Fernet.generate_key()
        with open(self.key_file, "wb") as key_file:
            key_file.write(key)
        self.key = key

    def load_key(self):
        return open(self.key_file, "rb").read()

    def encrypt_password(self, password):
        fernet = Fernet(self.key)
        encrypted_password = fernet.encrypt(password.encode())
        return encrypted_password

    def decrypt_password(self, encrypted_password):
        fernet = Fernet(self.key)
        decrypted_password = fernet.decrypt(encrypted_password).decode()
        return decrypted_password

    def add_password(self, service, password):
        encrypted_password = self.encrypt_password(password)
        with open(self.password_file, "a") as f:
            f.write(service + ":" + encrypted_password.decode() + "\n")

    def get_password(self, service):
        with open(self.password_file, "r") as f:
            for line in f.readlines():
                stored_service, stored_password = line.strip().split(":")
                if stored_service == service:
                    return self.decrypt_password(stored_password.encode())
        return None

    def change_key(self):
        old_key = self.key
        self.generate_key()
        new_key = self.key

        with open(self.password_file, "r") as f:
            lines = f.readlines()

        with open(self.password_file, "w") as f:
            for line in lines:
                service, encrypted_password = line.strip().split(":")
                decrypted_password = Fernet(old_key).decrypt(encrypted_password.encode()).decode()
                new_encrypted_password = Fernet(new_key).encrypt(decrypted_password.encode()).decode()
                f.write(service + ":" + new_encrypted_password + "\n")

def main():
    pm = PasswordManager()

    while True:
        print("\nPassword Manager")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Change Secret Key")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            service = input("Enter the service name: ")
            password = input("Enter the password: ")
            pm.add_password(service, password)
            print("Password added successfully!")
        elif choice == '2':
            service = input("Enter the service name: ")
            password = pm.get_password(service)
            if password:
                print(f"The password for {service} is {password}")
            else:
                print("Service not found!")
        elif choice == '3':
            pm.change_key()
            print("Secret key changed successfully!")
        elif choice == '4':
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
