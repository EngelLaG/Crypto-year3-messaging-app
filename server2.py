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
CHAT_LOGS_DIR = "chat_logs"
DES_KEY_FILE = "des_key.txt"  # File to store the DES key
RSA_KEY_SIZE = 2048

client_sockets = {}  # Dictionary to store client sockets with usernames
aes_keys = {}  # Store AES session keys for each client
server_running = True  # Server status flag


# Save DES key for consistent encryption/decryption
def save_des_key(key):
    with open(DES_KEY_FILE, "w") as f:
        f.write(key)


# Load DES key or generate a new one
def load_des_key():
    if os.path.exists(DES_KEY_FILE):
        with open(DES_KEY_FILE, "r") as f:
            return f.read()
    else:
        key = b64encode(os.urandom(8)).decode()
        save_des_key(key)
        return key


DES_KEY = load_des_key()  # Load or generate DES key


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


# DES encryption and decryption for chat logs
def des_encrypt(key, plaintext):
    iv = os.urandom(8)  # Initialization vector for DES
    cipher = Cipher(algorithms.TripleDES(b64decode(key)), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return b64encode(iv + ciphertext).decode()


def des_decrypt(key, ciphertext):
    try:
        decoded_data = b64decode(ciphertext)
        iv = decoded_data[:8]  # Extract initialization vector
        encrypted_message = decoded_data[8:]
        cipher = Cipher(algorithms.TripleDES(b64decode(key)), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        padded_data = decryptor.update(encrypted_message) + decryptor.finalize()
        return unpadder.update(padded_data) + unpadder.finalize()
    except Exception as e:
        print(f"Error decrypting message: {e}")
        raise ValueError("Decryption failed due to padding issues or invalid ciphertext.")


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


# Ensure chat logs directory exists
def initialize_chat_logs():
    if not os.path.exists(CHAT_LOGS_DIR):
        os.makedirs(CHAT_LOGS_DIR)


# Get a unique filename for chat logs of two users
def get_chat_log_filename(user1, user2):
    sorted_users = "_".join(sorted([user1, user2]))
    return os.path.join(CHAT_LOGS_DIR, f"{sorted_users}.txt")


# Append a message to the encrypted chat log file
def save_chat_log(user1, user2, message):
    filename = get_chat_log_filename(user1, user2)
    encrypted_message = des_encrypt(DES_KEY, message)
    with open(filename, "a") as log_file:
        log_file.write(encrypted_message + "\n")


# Handles incoming messages from a specific client
def client_handler(client_socket, username):
    try:
        aes_key = aes_keys[username]
        while server_running:
            buffer = client_socket.recv(1024)
            if buffer:
                decrypted_message = aes_decrypt(aes_key, buffer.decode()).decode()
                print(f"{username} says: {decrypted_message}")

                for other_username, other_socket in client_sockets.items():
                    if other_username != username:
                        # Save chat log
                        save_chat_log(username, other_username, f"{username}: {decrypted_message}")

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


# Monitor for the "exit" or "ls" commands
def server_commands(server_socket):
    global server_running
    while True:
        command = input()
        if command.lower() == "exit":
            print("Shutting down server...")
            server_running = False
            server_socket.close()
            # Disconnect all clients
            for client_socket in client_sockets.values():
                client_socket.close()
            break
        elif command.lower() == "ls":
            print("\nChat Logs:")
            chat_logs = os.listdir(CHAT_LOGS_DIR)
            if chat_logs:
                for i, log in enumerate(chat_logs, 1):
                    print(f"{i}. {log}")
            else:
                print("No chat logs available.")
        elif command.startswith("open "):
            filename = command[5:].strip()
            filepath = os.path.join(CHAT_LOGS_DIR, filename)
            if os.path.exists(filepath):
                with open(filepath, "r") as log_file:
                    print(f"\nContents of {filename}:\n")
                    for line in log_file:
                        try:
                            decrypted_line = des_decrypt(DES_KEY, line.strip())
                            print(decrypted_line.decode())
                        except ValueError:
                            print("[ERROR] Could not decrypt line. Data may be corrupted.")
            else:
                print(f"Chat log {filename} not found.")
        else:
            print("Invalid command. Use 'ls' to list logs, 'open <filename>' to view a log, or 'exit' to shut down.")


def main():
    global server_running

    initialize_chat_logs()
    users = load_users()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 1500))
    server_socket.listen(5)
    print("Listening for incoming connections...")

    # Start server commands thread
    threading.Thread(target=server_commands, args=(server_socket,), daemon=True).start()

    while server_running:
        try:
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
        except OSError:
            break  # Exit the loop when the server socket is closed

    print("Server has shut down.")


if __name__ == "__main__":
    main()
