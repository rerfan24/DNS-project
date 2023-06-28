import socket


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '127.0.0.1'
    port = 12345

    client_socket.connect((host, port))

    while True:
        message = input('Enter a message to send to server: ')
        client_socket.send(message.encode())

        if message.lower() == 'end':
            break

        data = client_socket.recv(1024).decode()
        print('Received data from server:', data)

    client_socket.close()


if __name__ == '__main__':
    start_client()
