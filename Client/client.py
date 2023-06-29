import socket
import os
import rsa
from utils import encrypt_message, decrypt_cipher


def start_client():
    logged_in = False
    username_register = ''
    username_login = ''

    pukey_server = rsa.PublicKey.load_pkcs1(open('../PublicKeys/pukey_server.pem', 'rb').read())

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '127.0.0.1'
    port = 12345

    client_socket.connect((host, port))
    print('Enter a message to send to server: ')
    message = input()
    client_socket.send(encrypt_message(message, pukey_server))
    # client_socket.send(message.encode())

    while True:
        if message.lower() == 'end':
            break

        data = client_socket.recv(1024).decode()

        # region Sign Up
        if data.startswith('Enter username for signup:') or data.startswith('Username already exists, try again:'):
            print(data, end='')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
            username_register = message

        elif data.startswith('Enter password for signup:') or data.startswith('Password does not match for signup, try again:'):
            print(data, end='')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))

        elif data.startswith('Confirm password for signup:'):
            print(data, end='')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))

        elif data.startswith('Send public key for signup:'):
            public_key, private_key = rsa.newkeys(512)
            client_socket.send(encrypt_message(public_key.save_pkcs1().decode(), pukey_server))
            print('Public key sent to server')
            
            if not os.path.exists('prkeys'):
                os.makedirs('prkeys')
            with open(f"prkeys/{username_register}.pem", "wb") as f:
                f.write(private_key.save_pkcs1())
            
            print('Enter a message to send to server: ')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region Login
        elif data.startswith('Enter username for login:') or data.startswith('Wrong username or password, try again:'):
            print(data, end='')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
            username_login = message
        elif data.startswith('Enter password for login:'):
            print(data, end='')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
        elif data.startswith('you logged in successfuly'):
            logged_in = True
            print(data)
            print('Enter a message to send to server: ')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        else:
            print(data)
            print('Enter a message to send to server: ')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))

    client_socket.close()


if __name__ == '__main__':
    # with open("client_config.py") as f:
    #     exec(f.read())

    start_client()
