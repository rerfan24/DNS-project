import socket
import os
import sqlite3
import threading
from random import random
import pyDH

import rsa

from utils import *
from database_methods import *
from client_config import *

logged_in = False
X = 0
q = 0
username_register = ''
username_login = ''
public_key = ''
private_key = ''
pukey_server = rsa.PublicKey.load_pkcs1(open('../PublicKeys/pukey_server.pem', 'rb').read())
last_nonce = ''

sessions = {}

def get_client(client_socket):
    db: sqlite3.Connection
    while True:
        global logged_in, last_nonce, username_login, private_key, dh_self, sessions, q, X
        received_data = client_socket.recv(1024)
        data = ''
        dollar_index = received_data.find(b'$$$$')
        if dollar_index == -1:
            data = received_data.decode()
        else:
            data = received_data.split(b'$$$$')[0].decode()

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
                initialize_db(username_login)
                db = sqlite3.connect(f'client-{username_login}.db')
                db.execute('''PRAGMA foreign_keys = ON''')
            else:
                print(mess)
        # endregion

        # region logout        
        elif data.startswith('logout'):
            mess = data[data.find("|") + 1:]
            if mess.startswith('you logged out successfully'):
                sessions = {}
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
                if mess.startswith("DH"):  # DH {des_username} prime: {str(prime)} alpha: {str(base)} public key: {des_user[2]}
                    public_key_destination_string = mess.split("public key: ")[1].strip()
                    public_key_destination = rsa.PublicKey.load_pkcs1(public_key_destination_string.encode())
                    prime_number = int(mess.split("prime: ")[1].split(" alpha: ")[0])
                    base_number = int(mess.split("alpha: ")[1].split(" public key: ")[0])
                    q = prime_number

                    X = int(random() * prime_number)
                    Y = int(calculate_key(base_number, X, prime_number))
                    print("Y: ", Y)

                    encrypted_key = encrypt_message(str(Y), public_key_destination)
                    print("encrypted_key: ", encrypted_key)


                    # dh_self = pyDH.DiffieHellman(5)
                    # dh_self_pubkey = dh_self.gen_public_key()
                    # encrypted_key = encrypt_message(str(dh_self_pubkey), public_key_destination)
                    # print("encrypted_key: ", encrypted_key)

                    # print("type encrypted_key.decode(): ", type(encrypted_key.decode()))
                    client_socket.send(
                        encrypt_message('forward to ' + mess.split()[1] + ' session ',pukey_server) + b'$$$$' + encrypted_key)
                    # TODO  

        # endregion

        # region forward
        elif data.startswith(
                'forward'):  # (f"forward|session {logged_in_user}: ".encode() + b'$$$$' + received_data.split(b'$$$$')[1].strip())
            mess = data[data.find("|") + 1:]
            pr_key = rsa.PrivateKey.load_pkcs1(open(f"prkeys/{username_login}.pem", "rb").read())
            if mess.startswith("session"):
                print("session")
                Y_destination = int(decrypt_cipher(received_data.split(b'$$$$')[1], pr_key))
                d_sharedkey = calculate_key(Y_destination, X, q)
                
                # d1_sharedkey = dh_self.gen_shared_key(int(decrypt_end_user_diffie))s
                print(f"{username_login}: ", d_sharedkey)
                sessions[mess.split()[1][:-1]] = d_sharedkey
            else:
                print(mess)
        # endregion

        # region send message
        elif data.startswith('send-private-message'): # send-private-message|User:{des_username} message:{encrypt_chat_message}
            mess = data[data.find("|") + 1:]
            if mess.startswith('User'):
                print("Message has been sent successfully.")
                sender = username_login
                receiver = mess.split()[0].split(":")[1]
                encrypt_chat_message = mess.split()[1].split(":")[1]
                if receiver in sessions:
                    plain_message = decrypt_cipher_symmetric(encrypt_chat_message, int(sessions[receiver]))
                    insert_private_messages(db, sender, receiver, plain_message)
                else:
                    print(f"You are not connected to {receiver}!")
            else:
                print(mess)
        # endregion

        # region get message
        elif data.startswith('get-private-message'):  # get-private-message|User:{logged_in_user} message:{encrypt_chat_message}
            mess = data[data.find("|") + 1:]
            if mess.startswith('User'):
                sender = mess.split()[0].split(":")[1]
                receiver = username_login
                encrypt_chat_message = mess.split()[1].split(":")[1]
                if sender in sessions:
                    plain_message = decrypt_cipher_symmetric(encrypt_chat_message, int(sessions[sender]))
                    insert_private_messages(db, sender, receiver, plain_message)
                    print(f'{sender} sent: {plain_message}')
                else:
                    print(f"You are not connected to {sender}!")
            else:
                print(mess)
        # endregion

        # region create group
        elif data.startswith('create-group'):
            mess = data[data.find("|") + 1:]
            if mess.startswith("Group has been created successfully"):
                print(mess)
            else:
                print(mess)
        # endregion

        # region create group
        elif data.startswith('add-member'):
            mess = data[data.find("|") + 1:]
            print(mess)
        # endregion

        # region send a group message
        elif data.startswith('send-group-message'):
            # TODO
            splitted_data = data.split()
            mess = data[data.find("|") + 1:]
        # endregion


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
        elif message.startswith("login"): # login username password 
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
            if not logged_in:
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
                integer_key = int(sessions[des_username])
                print(integer_key)
                encrypted_message = encrypt_message_symmetric(plain_message, integer_key)
                concat_message = "send-private-message " + des_username + ' \"' + encrypted_message.decode() + '\"'
                client_socket.send(encrypt_message(concat_message, pukey_server))
            else:
                print(f"You are not connected to {des_username}")
        # endregion

        # region private message
        elif message.startswith('create-group'):  # create-group group_name username1 username2 ...
            if not logged_in:
                print("You are not logged in!")
            else:
                client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region get all private messages
        elif message.startswith('add-member'):  # add-member group_name username1 username2 ...
            if not logged_in:
                print("You are not logged in!")
            else:
                client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region send group message
        elif message.startswith('send-group-message'):  # send-group-message group-name "message"
            splitted_message = message.split()
            des_groupname = splitted_message[1]
            index = message.find('\"')
            plain_message = message[index + 1:-1]
            client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region get group messages
        elif message.startswith('get-group-messages'):  # get-group-messages group-name
            if not logged_in:
                print("You are not logged in!")
            else:
                client_socket.send(encrypt_message(message, pukey_server))
        # endregion

        # region get user messages
        elif message.startswith("get-user-messages"):  # get-message username
            temp_username = message.split()[1]
            if logged_in:
                # TODO check temp_username `exist
                get_user_messages(db, username_login, temp_username)
            else:
                print("You are not logged in!")
            # TODO show messages from temp_username from client db
            pass
        # endregion

        # region get all private messages
        elif message == "get-all-private-messages":
            # TODO show all the messages from client db
            if logged_in:
                get_all_private_messages(db, username_login)
            else:
                print("You are not logged in!")
            pass
        # endregion

        else:
            print("Invalid command!")


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '127.0.0.1'
    port = 12345

    client_socket.connect((host, port))

    get_thread = threading.Thread(target=get_client, args=(client_socket,))
    get_thread.start()

    send_thread = threading.Thread(target=send_client, args=(client_socket,))
    send_thread.start()


if __name__ == '__main__':
    # with open("client_config.py") as f:
    #     exec(f.read())

    start_client()
