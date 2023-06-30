import sqlite3
import os
import rsa

db = sqlite3.connect('server.db')
db.execute('PRAGMA foreign_keys = ON')
cursor = db.cursor()


cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        public_key TEXT NOT NULL,
        is_online INTEGER NOT NULL DEFAULT 0,
        host TEXT,
        port INTEGER
    );
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS groups(
        name TEXT PRIMARY KEY,
        admins TEXT NOT NULL,
        usernames TEXT NOT NULL,
        session_key TEXT NOT NULL,
        online_users TEXT,
        hosts TEXT,
        ports TEXT
    );
    
''')

db.commit()

public_key, private_key = rsa.newkeys(512)

if not os.path.exists('../PublicKeys'):
    os.mkdir('../PublicKeys')
with open('../PublicKeys/pukey_server.pem', mode='wb') as public_key_file:
    public_key_file.write(public_key.save_pkcs1())

with open('prkey_server.pem', mode='wb') as private_key_file:
    private_key_file.write(private_key.save_pkcs1())

# # get public key as string
# public_key_string = public_key.save_pkcs1().decode()

# # insert public key into database
# cursor.execute('''
#     INSERT INTO users(username, password, public_key)
#     VALUES(?, ?, ?)
# ''', ('server', 'server', public_key_string))
