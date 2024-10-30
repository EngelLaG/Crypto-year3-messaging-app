import socket
import threading

key = 'K'  # Hard-coded key for XOR encryption

client_sockets = [None, None]  # List to store client sockets (2 Users)

# Encrypts or decrypts text using XOR cipher
def xor_encrypt_decrypt(text, key):
    return ''.join(chr(ord(c) ^ ord(key)) for c in text)

# Broadcasts messages from one client to another
def broadcast_message(message, sender_index):
    for i in range(2):
        if i != sender_index and client_sockets[i] is not None:
            encrypted = xor_encrypt_decrypt(message, key)
            client_sockets[i].sendall(encrypted.encode())

# Handles incoming messages from a specific client
def client_handler(client_socket, client_index):
    while True:
        try:
            buffer = client_socket.recv(1024)
            if buffer:
                decrypted = xor_encrypt_decrypt(buffer.decode(), key)
                print(f"Client {client_index + 1} says: {decrypted}")

                # Broadcast message to the other client
                broadcast_message(f"Client {client_index + 1} says: {decrypted}", client_index)
            else:
                print(f"Client {client_index + 1} disconnected.")
                break
        except Exception as e:
            print(f"Error: {e}")
            break

    client_socket.close()
    client_sockets[client_index] = None  # Reset client socket to its initial state

# Main function to set up the server
def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 1500))  # Bind to any available interface on port 1500
    server_socket.listen(2)  # Listen for up to 2 incoming connections
    print("Listening for incoming connections")

    client_count = 0
    while client_count < 2:
        client_socket, _ = server_socket.accept()
        client_sockets[client_count] = client_socket
        print(f"Client {client_count + 1} connected!")
        threading.Thread(target=client_handler, args=(client_socket, client_count), daemon=True).start()
        client_count += 1

    # Simple command interface for the server
    while True:
        input_command = input()
        if input_command == "exit":
            break

    # Close all client sockets
    for client_socket in client_sockets:
        if client_socket is not None:
            client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()
