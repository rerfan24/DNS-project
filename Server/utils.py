import os
import rsa
import socket

import sympy


def encrypt_message(message: str, public_key: rsa.PublicKey):
    n = 53
    chunks = [message[i:i + n] for i in range(0, len(message), n)]
    chunks_cipher = [rsa.encrypt(i.encode(), public_key) for i in chunks]
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


def calculate_diff_key(base, exponent, modulus):
    return pow(base, exponent, modulus)


def generate_prime():
    prime = sympy.randprime(100, 1000)
    while not sympy.isprime(prime):
        prime = sympy.randprime(100, 1000)
    return prime





import hashlib
import os
import string
import random

import rsa
import socket


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


def calculate_key(base, exponent, modulus):
    return (base ** exponent) % modulus


def gen_nonce() -> str:
    return hashlib.sha256(random_string(64).encode()).hexdigest()


def enc_nonce_sign(message, receiver_public_key, nonce, sender_private_key):
    enc_nonce = encrypt_message(message + '||' + nonce, receiver_public_key)
    sign = rsa.sign(message.encode(), sender_private_key, 'SHA-256')
    return enc_nonce + b'----------' + sign


def check_sign(message: str, signature: bytes, public_key: rsa.PublicKey):
    try:
        rsa.verify(message.encode(), signature, public_key)
        return True
    except Exception as e:
        return e


def check_integrity_and_freshness(data, receiver_private_key, last_nonce, sender_public_key):

    # freshness
    enc_nonce, sign = data.split(b'----------')[0], data.split(b'----------')[1]
    enc_nonce_dec = decrypt_cipher(enc_nonce, receiver_private_key)
    obtained_msg, obtained_nonce = enc_nonce_dec.split('||')[0], enc_nonce_dec.split('||')[1]
    freshness_check = last_nonce == obtained_nonce

    # Integrity
    integrity_check = check_sign(obtained_msg, sign, sender_public_key)

    if freshness_check and integrity_check:
        return 1
    if freshness_check and not integrity_check:
        return 0
    if not freshness_check and integrity_check:
        return -1
    else:
        return -2


def add_nonce(message, nonce):
    return message + '||' + nonce
