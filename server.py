import socket
import threading


def handle_client(client_socket, client_address):
    while True:
        data = client_socket.recv(1024).decode()
        if not data:
            break

        print('Received data from client {}: {}'.format(client_address, data))

        response = 'Message received: {}'.format(data)
        client_socket.send(response.encode())

    client_socket.close()
    print('Client {} disconnected'.format(client_address))


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '127.0.0.1'
    port = 12345

    server_socket.bind((host, port))

    server_socket.listen(5)

    print('Server listening on {}:{}'.format(host, port))

    while True:
        client_socket, client_address = server_socket.accept()
        print('Connected to client:', client_address)
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()


if __name__ == '__main__':
    start_server()
