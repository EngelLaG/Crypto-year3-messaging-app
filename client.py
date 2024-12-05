import socket
import threading
import rsa
import json
import os  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import bcrypt

USER_FILE = "users.json"
RSA_KEY_SIZE = 2048


# AES encryption and decryption helper functions
def aes_encrypt(key, plaintext):
    iv = os.urandom(16) 
    cipher = Cipher(algorithms.AES(b64decode(key)), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return b64encode(iv + ciphertext).decode()


def aes_decrypt(key, ciphertext):
    decoded_data = b64decode(ciphertext)
    iv = decoded_data[:16]  
    encrypted_message = decoded_data[16:]
    cipher = Cipher(algorithms.AES(b64decode(key)), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(encrypted_message) + decryptor.finalize()
    return unpadder.update(padded_data) + unpadder.finalize()

def load_users():
    try:
        with open(USER_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)


def register_account(users):
    username = input("Enter new username: ")
    password = input("Enter new password: ")

    if username in users:
        print("Username already exists. Please try logging in.")
        return False

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    public_key, private_key = rsa.newkeys(RSA_KEY_SIZE)
    users[username] = {
        "password": hashed_password,
        "private_key": private_key.save_pkcs1().decode(),
        "public_key": public_key.save_pkcs1().decode(),
    }
    save_users(users)
    print("Registration successful!")
    return True


def authenticate(users):
    username = input("Enter username: ")
    password = input("Enter password: ")

    if username in users and bcrypt.checkpw(password.encode(), users[username]["password"].encode()):
        print("Login successful!")
        return username
    print("Invalid username or password.")
    return None


def receive_messages(sock, aes_key):
    while True:
        try:
            buffer = sock.recv(1024)
            if buffer:
                decrypted_message = aes_decrypt(aes_key, buffer.decode()).decode()
                print(decrypted_message)
            else:
                print("Server disconnected.")
                break
        except Exception as e:
            print(f"Error: {e}")
            break


def send_messages(sock, aes_key):
    while True:
        try:
            message = input()
            if message == "#exit":
                print("Disconnecting from server...")
                break
            encrypted_message = aes_encrypt(aes_key, message)
            sock.sendall(encrypted_message.encode())
        except Exception as e:
            print(f"Error: {e}")
            break


def main():
    users = load_users()

    print("1. Register")
    print("2. Login")
    option = input("Choose option: ")

    if option == "1":
        if not register_account(users):
            return
        print("Please login.")

    username = None
    while username is None:
        username = authenticate(users)

    private_key = rsa.PrivateKey.load_pkcs1(users[username]["private_key"].encode())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 1500))
    print("Connected to server.")

    public_key = rsa.PublicKey.load_pkcs1(users[username]["public_key"].encode())
    sock.sendall(public_key.save_pkcs1())

    encrypted_aes_key = sock.recv(1024)
    aes_key = rsa.decrypt(encrypted_aes_key, private_key).decode()

    sock.sendall(username.encode())

    receive_thread = threading.Thread(target=receive_messages, args=(sock, aes_key), daemon=True)
    receive_thread.start()

    send_messages(sock, aes_key)

    sock.close()


if __name__ == "__main__":
    main()
