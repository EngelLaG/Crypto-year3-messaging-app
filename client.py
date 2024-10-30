import socket
import threading

key = 'K'  # Hard-coded key for XOR encryption

# Encrypts or decrypts text using XOR cipher
def xor_encrypt_decrypt(text, key):
    return ''.join(chr(ord(c) ^ ord(key)) for c in text)

# Thread function to receive messages from the server
def receive_messages(sock):
    while True:
        try:
            buffer = sock.recv(1024)
            if buffer:
                decrypted = xor_encrypt_decrypt(buffer.decode(), key)
                print(decrypted)
            else:
                print("Server disconnected.")
                break
        except Exception as e:
            print(f"Error: {e}")
            break

# Thread function to send messages to the server
def send_messages(sock):
    while True:
        try:
            message = input()
            if message == "#exit":
                encrypted = xor_encrypt_decrypt(message, key)
                sock.sendall(encrypted.encode())
                print("Disconnecting from server...")
                break
            encrypted = xor_encrypt_decrypt(message, key)
            sock.sendall(encrypted.encode())
        except Exception as e:
            print(f"Error: {e}")
            break

# Registers a new account by writing to a file
def register_account():
    username = input("Enter new username: ")
    password = input("Enter new password: ")

    encrypted_user = xor_encrypt_decrypt(username, key)
    encrypted_pass = xor_encrypt_decrypt(password, key)

    try:
        with open("accounts.txt", "r") as file:
            for line in file:
                stored_user, _ = line.strip().split(' ')
                if xor_encrypt_decrypt(stored_user, key) == username:
                    print("Username already exists. Please try logging in.")
                    return False
    except FileNotFoundError:
        pass

    with open("accounts.txt", "a") as file:
        file.write(f"{encrypted_user} {encrypted_pass}\n")
    return True

# Authenticates a user against entries in a file
def authenticate():
    username = input("Enter username: ")
    password = input("Enter password: ")

    encrypted_user = xor_encrypt_decrypt(username, key)
    encrypted_pass = xor_encrypt_decrypt(password, key)

    try:
        with open("accounts.txt", "r") as file:
            for line in file:
                stored_user, stored_pass = line.strip().split(' ')
                if stored_user == encrypted_user and stored_pass == encrypted_pass:
                    return True
    except FileNotFoundError:
        pass

    print("Invalid username or password.")
    return False

# Main function: sets up connection and threads
def main():
    option = input("1. Register\n2. Login\nChoose option: ")

    if option == "1":
        if not register_account():
            print("Registration failed.")
            return
        print("Registration successful. Please login.")

    if not authenticate():
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 1500))
    print("Connected to server! Type #exit to disconnect.")

    receive_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    receive_thread.start()

    send_messages(sock)

    sock.close()

if __name__ == "__main__":
    main()
