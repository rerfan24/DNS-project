import sqlite3
import rsa


def get_user_info_with_username(db: sqlite3.Connection, username:str):
    cursor = db.cursor()
    cursor.execute('''
       SELECT * FROM users WHERE name = ? 
    ''', (username,))
    if cursor.fetchone() is None:
        return -1
    return cursor.fetchone()


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


def get_online_users(db: sqlite3.Connection):
    cursor = db.cursor()
    cursor.execute('''
            SELECT * FROM users WHERE is_online = ?
        ''', (1,))
    rows = cursor.fetchall()
    usernames = [i[0] for i in rows]

    return usernames


def insert_group(db: sqlite3.Connection, name: str, admin: str, session_key: str, online_users: str, hosts: str, ports: str):
    cursor = db.cursor()
    cursor.execute('''
           INSERT INTO groups(name, admins, usernames, session_key, online_users, hosts, ports)
           VALUES(?, ?, ?, ?, ?, ?)
       ''', ({name}, f'{admin},', f'{admin},', session_key, f'{online_users},', f'{hosts},', f'{ports},'))
    db.commit()


def get_group_info_with_name(db: sqlite3.Connection, name:str):
    cursor = db.cursor()
    cursor.execute('''
       SELECT * FROM groups WHERE name = ? 
    ''', (name,))
    if cursor.fetchone() is None:
        return -1
    return cursor.fetchone()


def add_user_to_group(db: sqlite3.Connection, group_name: str, new_user: str, new_session_key: str,  new_host: str, new_port: str):

    group_info = get_group_info_with_name(db, group_name)
    last_usernames = group_info[2]
    last_onlines = group_info[4]
    last_hosts = group_info[5]
    last_ports = group_info[6]

    cursor = db.cursor()

    cursor.execute('''
            UPDATE groups SET session_key = ?, usernames = ?, online_users = ?, hosts = ?, ports = ? WHERE name = ?
        ''', (new_session_key, f'{last_usernames}{new_user},', f'{last_onlines}{new_user}',
                   f'{last_hosts}{new_host}', f'{last_ports}{new_port},', group_name))
    db.commit()


def remove_user_from_group(db: sqlite3.Connection, group_name: str, username: str, new_session_key: str):
    user_info = get_user_info_with_username(db, username)
    group_info = get_group_info_with_name(db, group_name)

    group_users = group_info[2].replace(username, '')
    group_onlines = group_info[4].replace(username, '')
    group_hosts = group_info[5].replace(user_info[4], '')
    group_ports = group_info[6].replace(user_info[5], '')

    cursor = db.cursor()

    cursor.execute('''
                UPDATE groups SET session_key = ?, usernames = ?, online_users = ?, hosts = ?, ports = ? WHERE name = ?
            ''', (new_session_key, group_users, group_onlines,
                  group_hosts, group_ports, group_name))

    db.commit()
