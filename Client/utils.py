import hashlib
import os
import socket
import string
from random import random
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import rsa
from cryptography.fernet import Fernet

def encrypt_message_symmetric(message, key):
    key = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    key = key.rjust(32, b'\x00')
    key = base64.urlsafe_b64encode(key)
    
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_cipher_symmetric(encrypted_message, key): 
    key = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    key = key.rjust(32, b'\x00')
    key = base64.urlsafe_b64encode(key)

    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

def encrypt_private_key(private_key, password, salt):
    # Generate a derived key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password)

    # Create a Fernet object with the derived key
    f = Fernet(key)

    # Encrypt the private key
    encrypted_private_key = f.encrypt(private_key.encode())

    return encrypted_private_key


def decrypt_private_key(encrypted_private_key, password, salt):
    # Generate a derived key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password)

    # Create a Fernet object with the derived key
    f = Fernet(key)

    # Decrypt the private key
    decrypted_private_key = f.decrypt(encrypted_private_key)

    return decrypted_private_key.decode()

def random_string(size: int) -> str:
    characters = string.ascii_letters
    characters += string.digits
    characters += string.punctuation
    characters = characters.replace("|", '')
    return ''.join(random.choices(characters, k=64))


def encrypt_message(message: str, public_key: rsa.PublicKey):
    n = 53
    chunks = [message[i:i + n] for i in range(0, len(message), n)]
    chunks_cipher = [rsa.encrypt(i.encode(), public_key) for i in chunks]
    cipher = b''
    for chunk_cipher in chunks_cipher:
        cipher += chunk_cipher
    return cipher

def encrypt_message_byte(message: bytes, public_key: rsa.PublicKey):
    n = 53
    chunks = [message[i:i + n] for i in range(0, len(message), n)]
    chunks_cipher = [rsa.encrypt(i, public_key) for i in chunks]
    cipher = b''
    for chunk_cipher in chunks_cipher:
        cipher += chunk_cipher
    return cipher


def decrypt_cipher(cipher: bytes, private_key: rsa.PrivateKey) -> str:
    n = 64
    chunks = [cipher[i:i + n] for i in range(0, len(cipher), n)]
    chunks_plain = [rsa.decrypt(i, private_key).decode() for i in chunks]
    plain = ''.join(chunks_plain)
    return plain


def calculate_key(base: int, exponent: int, modulus: int):
    return (base ** exponent) % modulus


def gen_nonce() -> str:
    return hashlib.sha256(random_string(64).encode()).hexdigest()
