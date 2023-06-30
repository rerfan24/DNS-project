import socket
import os
import sqlite3
import threading
from random import random
import pyDH

import rsa
from utils import *
from database_methods import get_user_messages, get_all_private_messages, get_group_message

from Client.utils import encrypt_message, decrypt_cipher, encrypt_message_byte

logged_in = False
dh_self = None
username_register = ''
username_login = ''
public_key = ''
private_key = ''
pukey_server = rsa.PublicKey.load_pkcs1(open('../PublicKeys/pukey_server.pem', 'rb').read())
last_nonce = ''

sessions = {}

db = sqlite3.connect('client.db')
db.execute("PRAGMA foreign_keys = ON")


def get_client(client_socket):
    while True:
        global logged_in, last_nonce, username_login, private_key, dh_self
        data = client_socket.recv(1024).decode()

        # if last_nonce != data.split("||")[1]:
        #     print("The message is not secure. Invalid nonce!")
        #     continue

        # region Sign Up
        if data.startswith('signup'):
            mess = data[data.find("|") + 1:]
            if mess.startswith("Successfully"):  # Successfully, user {username} signed up
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
        # endregion

        # region Login
        elif data.startswith('login'):
            mess = data[data.find("|") + 1:]
            splitted_data = data.split()
            if mess.startswith('you logged in successfully'):
                print(mess)
                # successfully logged in as username
                logged_in = True
                username_login = splitted_data[-1]
            else:
                print(mess)
        # endregion

        # region logout        
        elif data.startswith('logout'):
            mess = data[data.find("|") + 1:]
            if mess.startswith('you logged out successfully'):
                logged_in = False
            print(mess)
        # endregion

        # region online users
        elif data.startswith('online-users'):
            mess = data[data.find("|") + 1:]
            print(mess)
        # endregion

        # region private-connection
        elif data.startswith('private-connect'):
            mess = data[data.find("|") + 1:]
            if mess.startswith('This username does not exist'):
                print(mess)
            elif mess.startswith('This user is not online'):
                print(mess)
            elif mess.startswith('You can now chat'):
                print(mess)
            else:
                if mess.startswith("DH"):  # DH {des_username} public key: {des_user[2]}
                    public_key_destination_string = mess.split("public key: ")[1].strip()
                    public_key_destination = rsa.PublicKey.load_pkcs1(public_key_destination_string.encode())

                    dh_self = pyDH.DiffieHellman(5)
                    dh_self_pubkey = dh_self.gen_public_key()

                    encrypted_key = encrypt_message(str(dh_self_pubkey), public_key_destination)
                    print("encrypted_key: ", encrypted_key)
                    # print("type encrypted_key.decode(): ", type(encrypted_key.decode()))
                    client_socket.send(
                        encrypt_message_byte(b'forward to ' + mess.split()[1].encode() + b' session ' + encrypted_key,
                                             pukey_server))
                    # TODO  

        # endregion

        # region forward
        elif data.startswith(
                'forward'):  # forward|session {logged_in_user}: {data[data.rfind("session") + 8:]}'.encode()
            mess = data[data.find("|") + 1:]
            pr_key = rsa.PrivateKey.load_pkcs1(open(f"prkeys/{username_login}.pem", "rb").read())
            if mess.startswith("session"):
                decrypt_end_user_diffie = decrypt_cipher(mess[mess.find(':') + 2:], pr_key)
                d1_sharedkey = dh_self.gen_shared_key(int(decrypt_end_user_diffie))
                print(f"{username_login}: ", d1_sharedkey)
                sessions[mess.split()[1]] = d1_sharedkey
            else:
                print(mess)
        # endregion

        # region send message
        elif data.startswith('send-private-message'):
            mess = data[data.find("|") + 1:]
            if mess.startswith('This user is not online'):
                print(mess)
            elif mess.startswith('This username does not exist'):
                print(mess)
            else:
                print(mess)
        # endregion

        # region send message
        elif data.startswith('get-private-message'):  # f'get-private-message|User:{logged_in_user} - message:{
            # encrypt_chat_message}'
            index = data.find(":")
            index2 = data.find(':', index + 1)
            username_des = data[index + 1:].split()[0].strip()
            encrypted_message = data[index2 + 1:]
            decrypted_message = decrypt_cipher(encrypted_message, sessions[username_des])
            print(f"Message from {username_des}: {decrypted_message}")
        # endregion

        # region create group
        elif data.startswith('create-group'):
            # TODO
            mess = data[data.find("|"):]
        # endregion

        elif data.startswith('send-group-message'):
            # TODO
            splitted_data = data.split()
            mess = data[data.find("|"):]


def send_client(client_socket):
    global logged_in, public_key, private_key, des_username
    while True:
        message = input()
        # nonce = gen_nonce()
        if message.lower() == 'end':
            break

        # region Sign Up
        if message.startswith("signup"):  # signup username password pubkey nonce
            public_key, private_key = rsa.newkeys(512)
            pubkey_str = public_key.save_pkcs1().decode()
            # new_message = message + " " + pubkey_str + " " + nonce
            new_message = message + " " + pubkey_str
            client_socket.send(encrypt_message(new_message, pukey_server))
        # endregion

        # region Login
        elif message.startswith("login"):
            if logged_in:
                print("You have already Logged in.")
            else:
                client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region logout
        elif message == "logout":
            client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region online-users
        elif message.startswith("online-users"):
            client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region connect-to-another-user
        elif message.startswith('private-connect'):  # private-connect username
            if logged_in == False:
                print("You are not logged in!")
            else:
                splitted_message = message.split()
                des_username = splitted_message[1]
                client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region private message
        elif message.startswith('send-private-message'):  # send-private-message username "message"
            splitted_message = message.split()
            des_username = splitted_message[1]
            index = message.find('\"')
            index2 = message.find('\"', index + 1)
            plain_message = message[index + 1:index2]
            if des_username in sessions:
                encrypted_message = encrypt_message(plain_message, sessions[des_username])
                concat_message = "send-private-message " + des_username + ' \"' + encrypted_message + '\"'
                client_socket.send(encrypt_message(concat_message, pukey_server))
            else:
                print(f"You are not connected to {des_username}")
        # endregion

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
