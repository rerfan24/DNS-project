import sqlite3
import os
import rsa

def get_messages(db: sqlite3.Connection, person1: str, person2: str):
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
    ''', (person1, person2, person2, person1))
    return cursor.fetchall()

def insert_messages(db: sqlite3.Connection, sender: str, receiver: str, message: str):
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO messages(sender, receiver, message)
        VALUES(?, ?, ?)
    ''', (sender, receiver, message))
    db.commit()