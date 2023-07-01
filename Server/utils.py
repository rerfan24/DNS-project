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
    cipher_message = cipher.split(b'$$$$')[0] 
    n = 64
    chunks = [cipher_message[i:i + n] for i in range(0, len(cipher_message), n)]
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