import socket
import threading
import rsa
import json
import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

USER_FILE = "users.json"
RSA_KEY_SIZE = 2048

client_sockets = {}  # Dictionary to store client sockets with usernames
aes_keys = {}  # Store AES session keys for each client


# AES encryption and decryption helper functions
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)  # Initialization vector for AES
    cipher = Cipher(algorithms.AES(b64decode(key)), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return b64encode(iv + ciphertext).decode()


def aes_decrypt(key, ciphertext):
    decoded_data = b64decode(ciphertext)
    iv = decoded_data[:16]  # Extract initialization vector
    encrypted_message = decoded_data[16:]
    cipher = Cipher(algorithms.AES(b64decode(key)), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(encrypted_message) + decryptor.finalize()
    return unpadder.update(padded_data) + unpadder.finalize()


# Load or initialize user data
def load_users():
    try:
        with open(USER_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)


# Handles incoming messages from a specific client
def client_handler(client_socket, username):
    try:
        aes_key = aes_keys[username]
        while True:
            buffer = client_socket.recv(1024)
            if buffer:
                decrypted_message = aes_decrypt(aes_key, buffer.decode()).decode()
                print(f"{username} says: {decrypted_message}")

                for other_username, other_socket in client_sockets.items():
                    if other_username != username:
                        encrypted_message = aes_encrypt(aes_keys[other_username], f"{username}: {decrypted_message}")
                        other_socket.sendall(encrypted_message.encode())
            else:
                print(f"{username} disconnected.")
                break
    except Exception as e:
        print(f"Error: {e}")

    client_socket.close()
    del client_sockets[username]
    del aes_keys[username]


def main():
    users = load_users()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 1500))
    server_socket.listen(5)
    print("Listening for incoming connections...")

    while True:
        client_socket, _ = server_socket.accept()
        print("New client connected.")

        rsa_public_key = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))
        aes_key = b64encode(os.urandom(32)).decode()  # Generate AES-256 key
        encrypted_aes_key = rsa.encrypt(aes_key.encode(), rsa_public_key)

        client_socket.sendall(encrypted_aes_key)

        username = client_socket.recv(1024).decode()
        if username in users:
            aes_keys[username] = aes_key
            client_sockets[username] = client_socket
            print(f"User {username} connected!")
            threading.Thread(target=client_handler, args=(client_socket, username), daemon=True).start()
        else:
            client_socket.sendall("Invalid username".encode())
            client_socket.close()


if __name__ == "__main__":
    main()
