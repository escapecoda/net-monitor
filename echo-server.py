import socket

def echo_server():
    # Create a socket with IPv4 and TCP
    server_sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket
    server_address: str = '127.0.0.1' # Localhost
    server_port: int = 12345
    server_sock.bind((server_address, server_port))

    # Listen for incoming connections
    server_sock.listen(5) # Argument is the backlog of connections allowed

    print("Servre is listening for incoming connections...")

    try:
        while True:
            # Accept connections
            client_sock, client_address = server_sock.accept()
            print(f"Connection from {client_address}")

            try:
                # Send and receive data
                message = client_sock.recv(1024)

                # Send a response back to the client
                response = "Message received"
                client_sock.sendall(response.encode())

            finally:
                # Close the client connection
                client_sock.close()
                print(f"Connection with {client_address} closed")

    except KeyboardInterrupt:
        print("Server is shutting down")

    finally:
        # Close server socket
        server_sock.close()
        print("Server socket closed")


if __name__ == "__main__":
    echo_server()