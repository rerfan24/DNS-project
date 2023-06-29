import os
import rsa
import socket

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