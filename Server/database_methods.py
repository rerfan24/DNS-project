import sqlite3
import rsa

def check_user_exists(db: sqlite3.Connection, username: str) -> bool:
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM users WHERE username = ?
    ''', (username,))
    return cursor.fetchone() is not None

def check_user_password(db: sqlite3.Connection, username: str, password: str) -> bool:
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM users WHERE username = ? AND password = ?
    ''', (username, password))
    return cursor.fetchone() is not None

def insert_user(db: sqlite3.Connection, username: str, password: str, public_key: rsa.PublicKey, is_online: bool, 
                host: str, port: int):
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO users(username, password, public_key, is_online, host, port)
        VALUES(?, ?, ?, ?, ?, ?)
    ''', (username, password, public_key.save_pkcs1().decode(), is_online, host, port))
    db.commit()

def update_user_login_status(db: sqlite3.Connection, username: str, is_online: bool):
    cursor = db.cursor()
    cursor.execute('''
        UPDATE users SET is_online = ? WHERE username = ?
    ''', (is_online, username))
    db.commit()