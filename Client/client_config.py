import rsa
import os
import sqlite3

db = sqlite3.connect('client.db')
db.execute('PRAGMA foreign_keys = ON')
cursor = db.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        message TEXT NOT NULL
    );
''')


cursor.execute('''
    CREATE TABLE IF NOT EXISTS groups_info(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_name TEXT NOT NULL,
        usernames TEXT NOT NULL,
        admins TEXT NOT NULL
    );
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS groups_messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_name TEXT NOT NULL,
        sender TEXT NOT NULL,
        message TEXT NOT NULL
    );
''')

db.commit()

# if os.path.exists("pukey_client.pem") and os.path.exists("prkey_client.pem"):
#     exit()

# public_key, private_key = rsa.newkeys(512)

# with open(f"pukey_client.pem", "wb") as f:
#     f.write(public_key.save_pkcs1())

# with open(f"prkey_client.pem", "wb") as f:
#     f.write(private_key.save_pkcs1())