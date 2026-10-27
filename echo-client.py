import socket


def echo_client():
    # Create a socket
    sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Specify server address and port
    server_address: str = '127.0.0.1'
    server_port: int = 12345

    try:
        # Establish a connection
        sock.connect((server_address, server_port))

        # Send and receive data
        message: str = "Hello, Server!"
        print(f"Sending: {message}")
        sock.sendall(message.encode())

        # Receive data from the server, specifying the buffer size
        response = sock.recv(1024)
        print(f"Recieved: {response.decode()}")

    finally:
        # Close the connection
        sock.close()


if __name__ == "__main__":
    echo_client()