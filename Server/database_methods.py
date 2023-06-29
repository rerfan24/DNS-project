import sqlite3
import rsa

def check_user_exists(db: sqlite3.Connection, username: str) -> bool:
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM users WHERE username = ?
    ''', (username,))
    return cursor.fetchone() is not None

def insert_user(db: sqlite3.Connection, username: str, password: str, public_key: rsa.PublicKey, is_online: bool = False):
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO users(username, password, public_key, is_online)
        VALUES(?, ?, ?, ?)
    ''', (username, password, public_key.save_pkcs1().decode(), is_online))
    db.commit()