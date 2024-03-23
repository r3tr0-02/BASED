'''
import socket
import threading

HOST = '127.0.0.1'
PORT = 9090

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))

server.listen()

clients = []
nicknames = []

def broadcast(message):
    for client in clients:
        client.send(message)

def handle(client):
    while True:
        try:
            message = client.recv(1024)
            print(f"{nicknames[clients.index(client)]} says {message}")
            broadcast(message)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()

            nickname = nicknames[index]
            nicknames.remove(nickname)

            break

def receive():
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}!")

        client.send("NICK".encode('utf-8'))
        nickname = client.recv(1024)

        nicknames.append(nickname)

        clients.append(client)

        print(f"Nickname of the client is {nickname}")
        broadcast(f"{nickname} connected to the server!\n".encode('utf-8'))
        client.send("Connected to the server".encode('utf-8'))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

print("Server is running!")
receive()
'''

# `TODO : switch hashlib to argon2 properly
# `TODO : start initial encryption between server-client in handling login/register inputs

import socket
import threading
import sqlite3
import hashlib
import secrets

from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHAKE128
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from kyber import Kyber1024

HOST = '127.0.0.1'
PORT = 9090

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))

server.listen()

clients = []
nicknames = []

# Create SQLite database and connect
conn = sqlite3.connect('chat_users.db')
cursor = conn.cursor()

# Create table to store usernames, hashed passwords, and salts
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        salt TEXT
    )
''')
conn.commit()

def banner():
    print('''
                                                                      

$$$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$$\ $$$$$$$\         $$$$$$\                                                    
$$  __$$\ $$  __$$\ $$  __$$\ $$  _____|$$  __$$\       $$  __$$\                                                   
$$ |  $$ |$$ /  $$ |$$ /  \__|$$ |      $$ |  $$ |      $$ /  \__| $$$$$$\   $$$$$$\ $$\    $$\  $$$$$$\   $$$$$$\  
$$$$$$$\ |$$$$$$$$ |\$$$$$$\  $$$$$\    $$ |  $$ |      \$$$$$$\  $$  __$$\ $$  __$$\\$$\  $$  |$$  __$$\ $$  __$$\ 
$$  __$$\ $$  __$$ | \____$$\ $$  __|   $$ |  $$ |       \____$$\ $$$$$$$$ |$$ |  \__|\$$\$$  / $$$$$$$$ |$$ |  \__|
$$ |  $$ |$$ |  $$ |$$\   $$ |$$ |      $$ |  $$ |      $$\   $$ |$$   ____|$$ |       \$$$  /  $$   ____|$$ |      
$$$$$$$  |$$ |  $$ |\$$$$$$  |$$$$$$$$\ $$$$$$$  |      \$$$$$$  |\$$$$$$$\ $$ |        \$  /   \$$$$$$$\ $$ |      
\_______/ \__|  \__| \______/ \________|\_______/        \______/  \_______|\__|         \_/     \_______|\__|      
                                                                                                                    
                                                                                                                    
                                                                                                                    
''')

def server_keygen():
    # Gen server-side keypair
    server_key = ECC.generate(curve='ed25519')

    # set keypair to session
    server_key_public = server_key.public_key()
    server_key_private = server_key

    # export server keypair
    print("\n\nVERSION vx.x - Unauthorized Access is Prohibited.")
    print("\nserver_keygen() >>>")

    # export server private key
    with open("server_key_private.pem", "wt") as f:
        
        data = server_key.export_key(format='PEM',
                                    protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                    prot_params={'iteration_count':131072})
        f.write(data)
        f.close()
        
    # export server public key
    with open("server_key_public.pem", "wt") as f:
        server_key_public = server_key.public_key().export_key(format='PEM')
        f.write(data)
        f.close()

def server_PQ_keygen():
    server_pq_key_public, server_pq_key_private = Kyber1024.keygen()

    return server_pq_key_public, server_pq_key_private

def read_server_private_key():
    with open("server_key_private.pem", "rt") as f:
        data = f.read()
        server_key_private = ECC.import_key(data)

    return server_key_private

def read_server_public_key():
    with open("server_key_public.pem", "rt") as f:
        data = f.read()
        server_key_public = ECC.import_key(data)

    return server_key_public

def kdf(x):
    return SHAKE128.new(x).read(32)

def generate_salt():
    return secrets.token_hex(16)

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def broadcast(message):
    for client in clients:
        client.send(message)

def handle(client):
    while True:
        try:
            message = client.recv(1024)
            
            # ! remove logging in server - based
            #print(f"{nicknames[clients.index(client)]} says {message}")
            broadcast(message)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()

            nickname = nicknames[index]
            nicknames.remove(nickname)

            break

def receive():
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}!")

        # Ask for login or register
        
        # ! remove send message to client
        #client.send("LOGIN_OR_REGISTER".encode('utf-8'))
        login_or_register = client.recv(1024).decode('utf-8')

        if login_or_register.lower() == 'login':

            # ! remove send message to client
            #client.send("LOGIN".encode('utf-8'))

            # ? before receive, perform ecdh here?
            server_key_public = read_server_public_key()
            server_key_private = read_server_private_key()

            # import user_key_public from user
            user_key_public = ECC.import_key(client.recv(1024).decode('utf-8'))

            # export server_key_public as PEM send to user
            client.send(str(server_key_public.export_key(format='PEM')).encode('utf-8'))

            # perform ecdh on server-client
            session_key = key_agreement(static_priv=server_key_private,
                                        static_pub=user_key_public,
                                        kdf=kdf)

            #print(session_key)

            login_data = client.recv(1024)
            iv = client.recv(1024)

            cipher = AES.new(session_key, AES.MODE_CBC, iv)
            login_data = unpad(cipher.decrypt(login_data), AES.block_size)

            login_data = login_data.decode('utf-8').split()

            try:
                username = login_data[0]
                password = login_data[1]
            except IndexError:
                pass
            else:
                # Retrieve salt for the user
                cursor.execute('SELECT salt FROM users WHERE username = ?', (username,))
                salt_data = cursor.fetchone()

                if salt_data:
                    salt = salt_data[0]
                    hashed_password = hash_password(password, salt)

                    # Verify login credentials
                    cursor.execute('SELECT username, password FROM users WHERE username = ? AND password = ?', (username, hashed_password))
                    user_data = cursor.fetchone()

                    if user_data:
                        client.send("LOGIN_SUCCESS".encode('utf-8'))

                        # Set the username as the nickname
                        nicknames.append(username)

                        clients.append(client)

                        print(f"Nickname of the client is {username}")
                        broadcast(f"{username} connected to the server!\n".encode('utf-8'))
                        client.send("Connected to the server".encode('utf-8'))

                        thread = threading.Thread(target=handle, args=(client,))
                        thread.start()
                    else:
                        client.send("LOGIN_FAILED".encode('utf-8'))

                else:
                    client.send("LOGIN_FAILED".encode('utf-8'))

        elif login_or_register.lower() == 'register':
            # ! remove send message to client
            #client.send("REGISTER".encode('utf-8'))
            register_data = client.recv(1024).decode('utf-8').split()

            try:
                username = register_data[0]
                password = register_data[1]
            except IndexError:
                pass
            else:
                # Generate salt
                salt = generate_salt()

                # Hash password
                hashed_password = hash_password(password, salt)

                # Insert new user into the database
                cursor.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', (username, hashed_password, salt))
                conn.commit()

                client.send("REGISTER_SUCCESS".encode('utf-8'))
        else:
            client.send("INVALID_OPTION".encode('utf-8'))

banner()
server_keygen()
server_PQ_keygen()
print("\nServer is running!")
receive()
