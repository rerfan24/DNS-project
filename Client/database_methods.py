import sqlite3
import os
import rsa


def get_user_messages(db: sqlite3.Connection, person1: str, person2: str):
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
    ''', (person1, person2, person2, person1))
    return cursor.fetchall()


def get_all_private_messages(db: sqlite3.Connection, person1: str):
    cursor = db.cursor()
    cursor.execute('''
            SELECT * FROM messages WHERE sender = ? OR receiver = ?
        ''', (person1, person1))
    return cursor.fetchall()


def insert_private_messages(db: sqlite3.Connection, sender: str, receiver: str, message: str):
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO messages(sender, receiver, message)
        VALUES(?, ?, ?)
    ''', (sender, receiver, message))
    db.commit()


def get_group_message(db: sqlite3.Connection, group_name: str):
    cursor = db.cursor()
    cursor.execute('''
            SELECT * FROM groups_messages WHERE group_name = ?
        ''', (group_name,))
    return cursor.fetchall()


def insert_group_messages(db: sqlite3.Connection, group_name: str, sender: str, message: str):
    cursor = db.cursor()
    cursor.execute('''
            INSERT INTO groups_messages(group_name, sender, message)
            VALUES(?, ?, ?)
        ''', (group_name, sender, message))
    db.commit()
