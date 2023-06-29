import socket
import threading
import rsa
import sqlite3
import hashlib

from utils import encrypt_message, decrypt_cipher
from database_methods import *


def handle_client(client_socket, client_address):
    db = sqlite3.connect('server.db')
    db.execute("PRAGMA foreign_keys = ON")
    is_logged_in = False
    logged_in_user = ''
    
    private_key = rsa.PrivateKey.load_pkcs1(open('prkey_server.pem', 'rb').read())

    while True:
        data = decrypt_cipher(client_socket.recv(1024), private_key)
        if not data:
            break
        
        # region Sign Up
        if data == 'sign up':
            client_socket.send('Enter username for signup: '.encode())
            username = ''
            # TODO check username does not contain spaces
            while True:
                username = decrypt_cipher(client_socket.recv(1024), private_key)
                if check_user_exists(db, username):
                    client_socket.send('Username already exists, try again: '.encode())
                else:
                    break
            
            client_socket.send('Enter password for signup: '.encode())
            password = ''
            while True:
                password = decrypt_cipher(client_socket.recv(1024), private_key)
                client_socket.send('Confirm password for signup: '.encode())
                confirm = decrypt_cipher(client_socket.recv(1024), private_key)

                if password == confirm:
                    client_socket.send('Send public key for signup: '.encode())
                    break
                else:
                    client_socket.send('Password does not match for signup, try again: '.encode())

            user_public_key_string = decrypt_cipher(client_socket.recv(1024), private_key)
            user_public_key = rsa.PublicKey.load_pkcs1(user_public_key_string.encode())

            password = hashlib.sha256(password.encode()).hexdigest()

            insert_user(db, username, password, user_public_key, False, client_address[0], client_address[1])

            print(f'User {username} signed up')
        # endregion

        # region Login
        elif data == 'login':
            if not is_logged_in:
                client_socket.send('Enter username for login: '.encode())
                while True:
                    username = decrypt_cipher(client_socket.recv(1024), private_key)

                    client_socket.send('Enter password for login: '.encode())
                    password = decrypt_cipher(client_socket.recv(1024), private_key)
                    password = hashlib.sha256(password.encode()).hexdigest()

                    if check_user_password(db, username, password):
                        break
                    else:
                        client_socket.send('Wrong username or password, try again: '.encode())

            
                update_user_login_status(db, username, True)
                is_logged_in = True
                logged_in_user = username
                client_socket.send('you logged in successfuly'.encode())

                print(f'User {username} logged in')

            else:
                client_socket.send('You are already logged in'.encode())
                continue
        # endregion

        # region Logout
        elif data == 'logout':
            if is_logged_in:
                update_user_login_status(db, logged_in_user, False)
                client_socket.send('you logged out successfuly'.encode())
                print(f'User {logged_in_user} logged out')
                is_logged_in = False
                logged_in_user = ''
            else:
                client_socket.send('You are not logged in'.encode())

        # endregion

        else:
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
    with open("server_config.py") as f:
        exec(f.read())
    
    start_server()
