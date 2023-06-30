import socket
import threading
from random import random

import rsa
import sqlite3
import hashlib
from pyDH import DiffieHellman

import sympy

from utils import encrypt_message, decrypt_cipher, calculate_diff_key, generate_prime
from database_methods import *

from database_methods import check_user_password, insert_user, check_user_exists, update_user_login_status, \
    get_online_users, get_user_info_with_username

sockets = {}


def handle_client(client_socket, client_address):
    old_nonce = ''
    db = sqlite3.connect('server.db')
    db.execute("PRAGMA foreign_keys = ON")
    is_logged_in = False
    logged_in_user = ''

    private_key = rsa.PrivateKey.load_pkcs1(open('prkey_server.pem', 'rb').read())

    while True:
        data = decrypt_cipher(client_socket.recv(1024), private_key)
        print("data: ", data)
        if not data:
            break

        # TODO new code according to two threads in client
        command = data.split()[0]
        split_data = data.split()
        new_nonce = split_data[-1].strip()

        # region signup
        if command == 'signup':
            username = split_data[1].strip()
            password = split_data[2].strip()
            new_split = data.split("-----BEGIN RSA PUBLIC KEY-----")[0].strip()
            if username == 'exit()' or password == 'exit()':
                break
            if len(new_split.split()) < 3:
                client_socket.send('signup|Please enter both of username and password.'.encode())
            elif len(new_split.split()) > 3:
                client_socket.send('signup|Username and password cannot contain spaces!'.encode())
            elif check_user_exists(db, username):
                client_socket.send('signup|This username already exists.'.encode())
            else:
                user_public_key_string = data[data.find("-----BEGIN RSA PUBLIC KEY-----"):].strip()
                user_public_key = rsa.PublicKey.load_pkcs1(user_public_key_string.encode())

                password = hashlib.sha256(password.encode()).hexdigest()

                insert_user(db, username, password, user_public_key, False, client_address[0], client_address[1])

                client_socket.send(f'signup|Successfully, user {username} signed up'.encode())
                # print(f'signup|Successfully, user {username} signed up||{new_nonce}')
        # endregion

        # region login
        elif command == 'login':
            split_data = data.split()
            username = split_data[1].strip()
            password = split_data[2].strip()
            if username == 'exit()' or password == 'exit()':
                break
            if len(split_data) < 3:
                client_socket.send('login|Please enter both of username and password.'.encode())
            elif len(split_data) > 3:
                client_socket.send('login|Username and password cannot contain spaces!'.encode())
            elif logged_in_user:
                client_socket.send('login|You have already logged in!'.encode())
            else:
                password = hashlib.sha256(password.encode()).hexdigest()
                if check_user_password(db, username, password):
                    update_user_login_status(db, username, True, client_address[0], client_address[1])
                    is_logged_in = True
                    logged_in_user = username
                    client_socket.send(f'login|you logged in successfully as {username}'.encode())
                    sockets[username] = client_socket
                    print(f'User {username} logged in')
                else:
                    client_socket.send('login|Wrong username or password, try again!'.encode())
        # endregion

        # region logout
        elif command == 'logout':
            if len(split_data) > 1:
                client_socket.send('logout|You cannot enter anything after logout command'.encode())
                continue
            if is_logged_in:
                update_user_login_status(db, logged_in_user, False, client_address[0], client_address[1])
                client_socket.send('logout|you logged out successfully'.encode())
                print(f'User {logged_in_user} logged out')
                del sockets[logged_in_user]
                is_logged_in = False
                logged_in_user = ''
            else:
                client_socket.send('logout|You are not logged in'.encode())
                continue
        # endregion

        # region online-users
        elif command == 'online-users':
            if is_logged_in:
                online_users_list = get_online_users(db)
                if len(online_users_list) == 0:
                    client_socket.send('online-users|There are no online users'.encode())
                online_users_str = "online-users|These are the online users:\n"
                for i in online_users_list:
                    online_users_str += i + '\n'
                online_users_str = online_users_str[:-1]
                client_socket.send(online_users_str.encode())
            else:
                client_socket.send('online-users|Only logged in users can see other online users'.encode())
        # endregion

        # region private-connection
        elif command == 'private-connect':
            split_data = data.split()
            des_username = split_data[1]
            if is_logged_in:
                des_user = get_user_info_with_username(db, des_username)
                if des_user == -1:
                    client_socket.send('private-connect|This username does not exist.'.encode())
                else:
                    if des_user[3] == 1:
                        print("Creating DH!")
                        current_user = get_user_info_with_username(db, logged_in_user)

                        client_socket.send(f'private-connect|DH {des_username} public key: {des_user[2]}'.encode())

                        if current_user != -1:
                            sockets[des_username].send(f'private-connect|DH {logged_in_user} public key: {current_user[2]}'.encode())
                        
                    else:
                        client_socket.send('private-connect|This user is not online.'.encode())


            else:
                client_socket.send('private-connect|Only logged in users can connect to other users'.encode())
        # endregion

        # region forward-message
        elif command == 'forward':
            split_data = data.split()
            des_username = split_data[2]
            
            if is_logged_in:
                if split_data[3] == 'session':
                    if des_username in sockets:
                        sockets[des_username].send(f'forward|session {logged_in_user}: {data[data.rfind("session") + 8:]}'.encode())
                        client_socket.send(f'private-connect|You can now chat with {des_username}'.encode())
                    else:
                        client_socket.send('forward|This user is not online.'.encode())
                else:
                    client_socket.send('forward|Not implemented!'.encode())
            else:
                client_socket.send('forward|Only logged in users can send messages'.encode())

            # pubkey1 = decrypt_cipher(sockets[des_username].recv(1024), private_key)
            # pubkey2 = decrypt_cipher(client_socket.recv(1024), private_key)
        # endregion

        # region private-message
        elif command == 'send-private-message':
            if is_logged_in:
                source_username = logged_in_user
                des_username = data.split()[1]
                index = data.find('\"')
                if index == -1 or data.count('\"') != 2:
                    client_socket.send('send-private-message|Write the message in a correct format!'.encode())
                    continue
                index2 = data.find('\"', index + 1)
                encrypt_chat_message = data[index + 1:index2]

                if check_user_exists(db, des_username):
                    # TODO send message to the second user and also show
                    des_user = get_user_info_with_username(db, des_username)
                    if des_user[3] == 1:
                        client_socket.send('send-private-message|The message has been sent successfully.'.encode())
                        sockets[des_username].send(f'get-private-message|User:{logged_in_user} '
                                                   f'- message:{encrypt_chat_message}'.encode())
                    else:
                        client_socket.send('send-private-message|This user is not online.'.encode())
                        continue
                    # prime = generate_prime()
                    # base = random.randint(2, prime - 2)
                    # client_socket.send(str(prime).encode())
                    # client_socket.send(str(base).encode())
                else:
                    client_socket.send('send-private-message|This username does not exist, try again.'.encode())
                    continue

                y1_client = int(decrypt_cipher(client_socket.recv(1024), private_key))
            else:
                client_socket.send('send-private-message|You are not logged in'.encode())
        # endregion

        elif command == 'create-group':
            if is_logged_in:
                source_username = logged_in_user
                groupname = data.split()[1]

                # TODO check if the group name does already exist
                if check_user_exists(db, des_username):
                    # TODO send message to the group and also show
                    client_socket.send('send-group-message|This group already exists.'.encode())
                    continue
                    pass
                else:
                    # Create group
                    pass
                    continue

            else:
                client_socket.send('send-group-message|You are not logged in'.encode())

        elif command == 'send-group-message':
            if is_logged_in:
                source_username = logged_in_user
                des_username = data.split()[1]
                index = data.find('\"')
                if index == -1 or data.count('\"') != 2:
                    client_socket.send('send-group-message|Write the message in a correct format!'.encode())
                    continue
                message = data[index:-1]

                # TODO check if the group name does already exist
                if check_user_exists(db, des_username):
                    # TODO send message to the group and also show
                    pass
                else:
                    client_socket.send('send-group-message|This group already exists.'.encode())
                    pass
                    continue

            else:
                client_socket.send('send-group-message|You are not logged in'.encode())

        else:
            print('Received data from client {}: {}'.format(client_address, data))

            response = 'Message received: {}'.format(data)
            client_socket.send(response.encode())

        # TODO new code according to two threads in client
        # # region Send Message
        # elif data == 'send message':
        #     if is_logged_in:
        #         client_socket.send('Destination username: '.encode())
        #         while True:
        #             des_username = decrypt_cipher(client_socket.recv(1024), private_key)
        #
        #             if check_user_exists(db, des_username):
        #                 break
        #             else:
        #                 client_socket.send('This username does not exist, try again: '.encode())
        #
        #         client_socket.send('Write your message: '.encode())
        #         prime = generate_prime()
        #         base = random.randint(2, prime - 2)
        #         client_socket.send(str(prime).encode())
        #         client_socket.send(str(base).encode())
        #
        #         y1_client = int(decrypt_cipher(client_socket.recv(1024), private_key))
        #     else:
        #         client_socket.send('You are not logged in'.encode())
        # # endregion
        

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
