import socket
import threading
import random

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
groups = {}


def add_nonce(string, nonce):
    return str(string + '||' + nonce)


def handle_client(client_socket, client_address):
    old_nonce = ''
    db = sqlite3.connect('server.db')
    db.execute("PRAGMA foreign_keys = ON")
    is_logged_in = False
    logged_in_user = ''

    private_key = rsa.PrivateKey.load_pkcs1(open('prkey_server.pem', 'rb').read())

    while True:
        received_data = client_socket.recv(1024)
        data = decrypt_cipher(received_data, private_key)
        print("data: ", data)

        if not data:
            break

        # TODO new code according to two threads in client
        command = data.split('||')[0]
        print('command:', command)
        split_data = command.split()
        new_nonce = data.split('||')[-1].strip()
        print("nonce:", new_nonce)

        # region signup
        if command.split()[0] == 'signup':
            username = split_data[1].strip()
            password = split_data[2].strip()
            # new_split = data.split("-----BEGIN RSA PUBLIC KEY-----")[0].strip()
            if username == 'exit()' or password == 'exit()':
                break
            if len(split_data) < 3:
                client_socket.send(add_nonce('signup|Please enter both of username and password.', new_nonce).encode())
            elif len(split_data) > 3:
                client_socket.send(add_nonce('signup|Username and password cannot contain spaces!', new_nonce).encode())
            elif check_user_exists(db, username):
                client_socket.send(add_nonce('signup|This username already exists.', new_nonce).encode())
            else:
                user_public_key_string = data[data.find("-----BEGIN RSA PUBLIC KEY-----"):].strip()
                user_public_key = rsa.PublicKey.load_pkcs1(user_public_key_string.encode())

                password = hashlib.sha256(password.encode()).hexdigest()

                insert_user(db, username, password, user_public_key, False, client_address[0], client_address[1])

                client_socket.send(add_nonce(f'signup|Successfully, user {username} signed up', new_nonce).encode())
                # print(f'signup|Successfully, user {username} signed up||{new_nonce}')
        # endregion

        # region login
        elif command.split()[0] == 'login':
            split_data = command.split()
            username = split_data[1].strip()
            password = split_data[2].strip()
            if username == 'exit()' or password == 'exit()':
                break
            if len(split_data) < 3:
                client_socket.send(add_nonce('login|Please enter both of username and password.', new_nonce).encode())
            elif len(split_data) > 3:
                client_socket.send(add_nonce('login|Username and password cannot contain spaces!', new_nonce).encode())
            elif logged_in_user:
                client_socket.send(add_nonce('login|You have already logged in!', new_nonce).encode())
            else:
                password = hashlib.sha256(password.encode()).hexdigest()
                if check_user_password(db, username, password):
                    update_user_login_status(db, username, True, client_address[0], client_address[1])
                    is_logged_in = True
                    logged_in_user = username
                    client_socket.send(add_nonce(f'login|you logged in successfully as {username}', new_nonce).encode())
                    sockets[username] = client_socket
                    print(f'User {username} logged in')
                else:
                    client_socket.send(add_nonce('login|Wrong username or password, try again!', new_nonce).encode())
        # endregion

        # region logout
        elif command.split()[0] == 'logout':
            if len(split_data) > 1:
                client_socket.send(add_nonce('logout|You cannot enter anything after logout command', new_nonce).encode())
                continue
            if is_logged_in:
                update_user_login_status(db, logged_in_user, False, client_address[0], client_address[1])
                client_socket.send(add_nonce('logout|you logged out successfully', new_nonce).encode())
                print(f'User {logged_in_user} logged out')
                del sockets[logged_in_user]
                is_logged_in = False
                logged_in_user = ''
            else:
                client_socket.send(add_nonce('logout|You are not logged in', new_nonce).encode())
                continue
        # endregion

        # region online-users
        elif command.split()[0] == 'online-users':
            if is_logged_in:
                online_users_list = get_online_users(db)
                if len(online_users_list) == 0:
                    client_socket.send(add_nonce('online-users|There are no online users', new_nonce).encode())
                online_users_str = "online-users|These are the online users:\n"
                for i in online_users_list:
                    online_users_str += i + '\n'
                online_users_str = online_users_str[:-1]
                client_socket.send(add_nonce(online_users_str, new_nonce).encode())
            else:
                client_socket.send(add_nonce('online-users|Only logged in users can see other online users', new_nonce).encode())
        # endregion

        # region private-connection
        elif command.split()[0] == 'private-connect':
            split_data = data.split()
            des_username = split_data[1]
            if is_logged_in:
                des_user = get_user_info_with_username(db, des_username)
                if des_user == -1:
                    client_socket.send(add_nonce('private-connect|This username does not exist.', new_nonce).encode())
                else:
                    if des_user[3] == 1:
                        print("Creating DH!")
                        current_user = get_user_info_with_username(db, logged_in_user)
                        prime = generate_prime()
                        base = random.randint(2, prime - 2)
                        # client_socket.send()
                        # client_socket.send()

                        client_socket.send(add_nonce(f'private-connect|DH {des_username} public key: {des_user[2]}'
                                                               , new_nonce).encode())

                        if current_user != -1:
                            sockets[des_username].send(
                                add_nonce(f'private-connect|DH {logged_in_user} public key: {current_user[2]}'
                                    , new_nonce).encode())

                    else:
                        client_socket.send(add_nonce('private-connect|This user is not online.', new_nonce).encode())


            else:
                client_socket.send(add_nonce('private-connect|Only logged in users can connect to other users', new_nonce).encode())
        # endregion

        # region forward-message
        elif command == 'forward':
            split_data = data.split()
            des_username = split_data[2]

            if is_logged_in:
                if split_data[3] == 'session':
                    if des_username in sockets:
                        try:
                            sockets[des_username].send(f"forward|session {logged_in_user}: ".encode() + b'$$$$' + received_data.split(b'$$$$')[1])
                        except IndexError:
                            client_socket.send(f'private-connect|Format of the message is incorrect.'.encode())
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
        elif command == 'send-private-message': # "send-private-message " + des_username + "encrypted_message.decode()"
            # send-private-message m "$@!#%B%FQRFE"
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
                    des_user = get_user_info_with_username(db, des_username)
                    if des_user != -1 and des_user[3] == 1:
                        client_socket.send(f'send-private-message|User:{des_username} message:{encrypt_chat_message}'.encode())
                        sockets[des_username].send(f'get-private-message|User:{logged_in_user} message:{encrypt_chat_message}'.encode())
                    else:
                        client_socket.send('send-private-message|This user is not online.'.encode())
                        continue
                else:
                    client_socket.send('send-private-message|This username does not exist, try again.'.encode())
                    continue
            else:
                client_socket.send('send-private-message|You are not logged in'.encode())
        # endregion

        # region create-group
        elif command == 'create-group':
            if is_logged_in:
                group_name = data.split()[1]
                if group_name in groups:
                    client_socket.send('create-group|This group already exists.'.encode())
                    continue
                else:
                    members = [logged_in_user]
                    flag = 0
                    online_users_list = get_online_users(db)
                    if len(data.split()) > 2:
                        for mem in data.split()[2:]:
                            if check_user_exists(db, mem) and mem in online_users_list:
                                members.append(mem)
                            else:
                                flag = 1
                                break
                        if flag == 1:
                            client_socket.send('create-group|All the users should be online!'.encode())
                        else:
                            groups[group_name] = members
                            # TODO add to db
                            client_socket.send('create-group|Group has been created successfully!'.encode())
                    else:
                        client_socket.send('create-group|A group has to contain at least two members!'.encode())
            else:
                client_socket.send('create-message|You are not logged in.'.encode())
        # endregion

        # region add-member
        elif command == 'add-member':  # add-member group_name username1 username2 ...
            if is_logged_in:
                group_name = data.split()[1]
                if group_name not in groups:
                    client_socket.send('add-member|This group does not exist.'.encode())
                    continue
                else:
                    members = groups[group_name].copy()
                    if members[0] == logged_in_user:
                        flag = 0
                        online_users_list = get_online_users(db)
                        if len(data.split()) > 2:
                            for mem in data.split()[2:]:
                                if check_user_exists(db, mem) and mem in online_users_list:
                                    members.append(mem)
                                else:
                                    flag = 1
                                    break
                            if flag == 1:
                                client_socket.send('add-member|All the users should be online!'.encode())
                            else:
                                groups[group_name] = members
                                # TODO add to db
                                client_socket.send('add-member|The members added successfully.'.encode())
                        else:
                            client_socket.send('add-member|You have to add at least one member!'.encode())
                    else:
                        client_socket.send('add-member|You have to be admin to add members.'.encode())
            else:
                client_socket.send('add-member|You are not logged in.'.encode())
        # endregion

        # region send group message
        elif command == 'send-group-message':  # send-group-message group-name "message"
            if is_logged_in:
                source_username = logged_in_user
                des_username = data.split()[1]
                index = data.find('\"')
                if index == -1 or data.count('\"') != 2:
                    client_socket.send('send-group-message|Write the message in a correct format!'.encode())
                    continue
                message = data[index + 1:-1]

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
        # endregion

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
