from cryptography.fernet import Fernet
import os

def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_password(password, key):
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password

def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password

def add_password(service, password):
    key = load_key()
    encrypted_password = encrypt_password(password, key)
    with open("passwords.txt", "a") as f:
        f.write(service + ":" + encrypted_password.decode() + "\n")

def get_password(service):
    key = load_key()
    with open("passwords.txt", "r") as f:
        for line in f.readlines():
            stored_service, stored_password = line.strip().split(":")
            if stored_service == service:
                return decrypt_password(stored_password.encode(), key)
    return None

def main():
    if not os.path.exists("secret.key"):
        generate_key()

    while True:
        print("\nPassword Manager")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            service = input("Enter the service name: ")
            password = input("Enter the password: ")
            add_password(service, password)
            print("Password added successfully!")
        elif choice == '2':
            service = input("Enter the service name: ")
            password = get_password(service)
            if password:
                print(f"The password for {service} is {password}")
            else:
                print("Service not found!")
        elif choice == '3':
            break
        else:
            print("Invalid choice! Please try again.")

main()
