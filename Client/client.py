import socket
import os
import sqlite3
import threading
from random import random

import rsa
from utils import encrypt_message, decrypt_cipher, calculate_key, gen_nonce
from database_methods import get_user_messages, get_all_private_messages, get_group_message


logged_in = False
username_register = ''
username_login = ''
public_key = ''
private_key = ''
pukey_server = rsa.PublicKey.load_pkcs1(open('../PublicKeys/pukey_server.pem', 'rb').read())
last_nonce = ''

db = sqlite3.connect('client.db')
db.execute("PRAGMA foreign_keys = ON")


def merge_client():
    logged_in = False
    username_register = ''
    username_login = ''

    pukey_server = rsa.PublicKey.load_pkcs1(open('../PublicKeys/pukey_server.pem', 'rb').read())

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '127.0.0.1'
    port = 12345

    client_socket.connect((host, port))
    print('Enter a message to send to the server: ')
    message = input()
    client_socket.send(encrypt_message(message, pukey_server))
    # client_socket.send(message.encode())

    while True:
        if message.lower() == 'end':
            break

        data = client_socket.recv(1024).decode()

        # region Sign Up
        if data.startswith('Enter username for signup:') or data.startswith('Username already exists, try again:') or \
                data.startswith('Username cannot contain spaces, try again:'):
            print(data, end='')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
            username_register = message

        elif data.startswith('Enter password for signup:') or data.startswith(
                'Password does not match for signup, try again:'):
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
        elif data.startswith('you logged in successfully'):
            logged_in = True
            print(data)
            print('Enter a message to send to server: ')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region online users
        elif data.startswith('There are no online users') or data.startswith('These are the online users'):
            print(data)
            print('Enter a message to send to server: ')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region Send message
        elif data.startswith('Destination username:') or data.startswith('This username does not exist, try again:'):
            print(data, end='')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
        elif data.startswith('Write your message:'):
            prime = int(client_socket.recv(1024).decode())
            base = int(client_socket.recv(1024).decode())
            X = random.randint(2, prime - 2)

            Y = calculate_key(base, X, prime)

            # TODO: use long term key instead of pubkey server
            client_socket.send(encrypt_message(str(Y), pukey_server))
            shared_key = int(client_socket.recv(1024).decode())

            print(data, end='')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        else:
            print(data)
            print('Enter a message to send to server: ')
            message = input()
            client_socket.send(encrypt_message(message, pukey_server))
            if message == 'sign up' or message == 'login':
                print('If you wanted to abort, type "exit()"')

    client_socket.close()


def get_client(client_socket):
    while True:
        global last_nonce
        data = client_socket.recv(1024).decode()

        # if last_nonce != data.split("||")[1]:
        #     print("The message is not secure. Invalid nonce!")
        #     continue

        if data.startswith('signup'):
            mess = data[data.find("|") + 1:]
            if mess.startswith("Successfully"):  # Successfully, user {username} signed up
                print("salaaaaaaaaam")
                username_register = mess.split()[2]
                if not os.path.exists('../PublicKeys'):
                    os.makedirs('../PublicKeys')
                with open(f"../PublicKeys/{username_register}.pem", "wb") as f:
                    f.write(public_key.save_pkcs1())

                if not os.path.exists('prkeys'):
                    os.makedirs('prkeys')
                with open(f"prkeys/{username_register}.pem", "wb") as f:
                    f.write(private_key.save_pkcs1())
                print(mess)
            else:
                print(mess)

        elif data.startswith('login'):
            mess = data[data.find("|"):]
            splitted_data = data.split()
            if mess.startswith('you logged in successfully'):
                print(mess)
                # successfully logged in as username
                logged_in = True
                username_login = splitted_data[-1]
            else:
                print(data[1:])
        elif data.startswith('logout'):
            mess = data[data.find("|"):]
            print(mess)
        elif data.startswith('online-users'):
            mess = data[data.find("|"):]
            print(data)
        elif data.startswith('send-private-message'):
            # TODO
            splitted_data = data.split()
            mess = data[data.find("|"):]
            if mess.startswith('This user is not online'):
                pass
            elif mess.startswith('This username does not exist'):
                pass
            else:
                pass
        elif data.startswith('create-group'):
            # TODO
            mess = data[data.find("|"):]
        elif data.startswith('send-group-message'):
            # TODO
            splitted_data = data.split()
            mess = data[data.find("|"):]


def send_client(client_socket):
    global logged_in, public_key, private_key
    while True:
        message = input()
        # nonce = gen_nonce()
        if message.lower() == 'end':
            break

        if message.startswith("signup"):  # signup username password pubkey nonce
            # TODO add public key to message and then send it
            public_key, private_key = rsa.newkeys(512)
            pubkey_str = public_key.save_pkcs1().decode()
            # new_message = message + " " + pubkey_str + " " + nonce
            new_message = message + " " + pubkey_str
            client_socket.send(encrypt_message(new_message, pukey_server))
        elif message.startswith("login"):
            if logged_in:
                print("You have already Logged in.")
            else:
                client_socket.send(encrypt_message(message, pukey_server))
        elif message == "logout":
            pass
        elif message.startswith("online-users"):
            client_socket.send(encrypt_message(message, pukey_server))
        elif message.startswith('send-private-message'):  # send-private-message username "message"
            splitted_message = message.split()
            des_username = splitted_message[1]
            index = message.find('\"')
            plain_message = message[index:-1]
            client_socket.send(encrypt_message(message, pukey_server))
        elif message.startswith('create-group'):  # create-group group-name
            # TODO
            pass
        elif message.startswith('send-group-message'):  # send-group-message group-name "message"
            splitted_message = message.split()
            des_groupname = splitted_message[1]
            index = message.find('\"')
            plain_message = message[index:-1]
            client_socket.send(encrypt_message(message, pukey_server))
        elif message.startswith("get-user-messages"):  # get-message username
            temp_username = message.split()[1]
            if logged_in:
                # TODO check temp_username `exist
                get_user_messages(db, username_login, temp_username)
            else:
                print("You are not logged in!")
            # TODO show messages from temp_username from client db
            pass

        elif message == "get-all-private-messages":
            # TODO show all the messages from client db
            if logged_in:
                get_all_private_messages(db, username_login)
            else:
                print("You are not logged in!")
            pass

        elif message == "get-all-private-messages":
            # TODO show all the messages from client db
            if logged_in:
                get_all_private_messages(db, username_login)
            else:
                print("You are not logged in!")
            pass

        else:
            print("Invalid command!")


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '127.0.0.1'
    port = 12345

    client_socket.connect((host, port))
    # merge_client()

    # TODO new code
    get_thread = threading.Thread(target=get_client, args=(client_socket,))
    get_thread.start()

    send_thread = threading.Thread(target=send_client, args=(client_socket,))
    send_thread.start()
    # TODO new code


if __name__ == '__main__':
    with open("client_config.py") as f:
        exec(f.read())

    start_client()
