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
# // TODO : start initial encryption between server-client in handling login/register inputs
# // TODO : start initial encryption between server-client in handling register
# // TODO : storing user keys into db on register
# // TODO : retrieve user keys from db on login 
# // TODO : maybe except handling on register dupe users?
# // TODO : except handling on exit (init ecdh-decrypt)
# TODO : start calc pqxdh sk - send all keys for client in clients in session?, then update?
# // TODO : clean up encryption method in separate funct

### These libs are used for basic funct - network and threading
import base64
import time
import socket
import threading

### These libs are used for username, password and salt handling and storing
import sqlite3
import hashlib
import secrets

### These libs are used for conv. symm / asymm op.
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHAKE128
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

### These libs are used for Post-Quantum op.
from kyber import Kyber1024
from pqc.sign import dilithium5

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
    );
''')
conn.commit()

# Create table to store all user keys and sigs
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        user_id INTEGER PRIMARY KEY,
        id_key_public TEXT, id_key_private TEXT,
        pqid_pkey TEXT, pqid_skey TEXT,
        spk_key_public TEXT, spk_key_private TEXT,
        sig_spk TEXT,
        pqspk_pkey TEXT, pqspk_skey TEXT,
        sig_pqspk TEXT,
        opk_key_public TEXT, opk_key_private TEXT,
        pqopk_pkey TEXT, pqopk_skey TEXT,
        sig_pqopk TEXT
    );
''')
conn.commit()

# * This function is to display server's message banner
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

# * This function is to generate an ECC ed25519 keypair for server
# ? server keypairs are stored locally in .pem files
# ! server keypairs are not encrypted with passphrase
# ? server keypairs are re-generated each runtime 
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

# * This function is to generate a Kyber-1024 keypair for server
# ! This function is not used anymore as of test v1.3 Alpha
# ? server keypairs are stored in memory
# ? server keypairs are re-generated each runtime 
# // def server_PQ_keygen():
# //    server_pq_key_public, server_pq_key_private = Kyber1024.keygen()
# //    return server_pq_key_public, server_pq_key_private

# * This function is to get server private key from .pem file
def read_server_private_key():
    with open("server_key_private.pem", "rt") as f:
        data = f.read()
        server_key_private = ECC.import_key(data)

    return server_key_private

# * This function is to get server public key from .pem file
def read_server_public_key():
    with open("server_key_public.pem", "rt") as f:
        data = f.read()
        server_key_public = ECC.import_key(data)

    return server_key_public

# * This function is for Key Derivation Function for ECDH op.
def kdf(x):
    return SHAKE128.new(x).read(32)

# * This function is to perform initial ECDH KEP on server-client
# ? This function will return a shared session key
def init_ecdh(client):
    # read server keypair for op.
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
    
    return session_key

# * This function is to perform initial decryption of user data
# ? This function will return decrypted user data
def init_decrypt(client, session_key):
    # receive ct of login data from user and iv used during enc
    login_data = client.recv(1024)
    iv = client.recv(1024)

    # init AES and attempt to decrypt ct using session_key
    # decrypted ct will be unpad to return to pt
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    login_data = unpad(cipher.decrypt(login_data), AES.block_size)

    return login_data

# * This function is to store user keys into database
# ? No return for this function
def store_keys(client, username):
    cursor.execute('SELECT id from users WHERE username = ?;', (username,))
    user_id = cursor.fetchone()
    user_id = user_id[0]

    id_key_public = client.recv(1024).decode('utf-8')
    id_key_private = client.recv(1024).decode('utf-8')

    #print("ok 1")
    
    pqid_pkey = client.recv(30720).decode('utf-8')
    pqid_skey = client.recv(30720).decode('utf-8')

    #print("ok 2")

    spk_key_public = client.recv(1024).decode('utf-8')
    spk_key_private = client.recv(1024).decode('utf-8')

    #print("ok 3")

    sig_spk = client.recv(20480).decode('utf-8')

    #print("ok 4")

    pqspk_pkey = client.recv(30720).decode('utf-8')
    pqspk_skey = client.recv(30720).decode('utf-8')

    #print("ok 5")

    sig_pqspk = client.recv(20480).decode('utf-8')

    #print("ok 6")

    opk_key_public = client.recv(1024).decode('utf-8')
    opk_key_private = client.recv(1024).decode('utf-8')

    #print("ok 7")

    pqopk_pkey = client.recv(30720).decode('utf-8')
    pqopk_skey = client.recv(30720).decode('utf-8')

    #print("ok 8")

    sig_pqopk = client.recv(20480).decode('utf-8')

    #print("ok 9")
    #print("ok in recv keys")

    # Insert new keys into the database
    # ? may need a better way of key mgmt...
    cursor.execute('''INSERT INTO keys (
                        user_id,
                        id_key_public, id_key_private,
                        pqid_pkey, pqid_skey,
                        spk_key_public, spk_key_private,
                        sig_spk,
                        pqspk_pkey, pqspk_skey,
                        sig_pqspk,
                        opk_key_public, opk_key_private,
                        pqopk_pkey, pqopk_skey,
                        sig_pqopk) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);''', (
                        user_id,
                        id_key_public, id_key_private,
                        pqid_pkey, pqid_skey,
                        spk_key_public, spk_key_private,
                        sig_spk,
                        pqspk_pkey, pqspk_skey,
                        sig_pqspk,
                        opk_key_public, opk_key_private,
                        pqopk_pkey, pqopk_skey,
                        sig_pqopk))
    conn.commit()

# * This function is to retrieve user keys from database after successful login
# ? This function will send all keys to client
def retrieve_keys(client, user_id):
    cursor.execute('SELECT * FROM keys WHERE user_id = ?;', (user_id,))
    keys = cursor.fetchone()

    client.send(keys[1].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[2].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[3].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[4].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[5].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[6].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[8].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[9].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[11].encode('utf-8'))
    client.send(keys[12].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[13].encode('utf-8'))
    client.send(keys[14].encode('utf-8'))

# * This function is to generate a random 16-byte salt for pass hash
def generate_salt():
    return secrets.token_hex(16)

# * This function is to generate a SHA-256 hash from password input and hash
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

# * This function is to send message to all clients conn to server
def broadcast(message):
    for client in clients:
        client.send(message)

# * This function is to try invoke broadcast funct.
# ! if a client exits, server will close conn. with client
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

# * This function is to accept incoming conn from client
# * and handle login or register of client
# ? if success login, handle funct will be invoked
# ! else of fail login or register, server will return err msg
def receive():
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}!")

        # Ask for login or register
        login_or_register = client.recv(1024).decode('utf-8')

        # login option
        if login_or_register.lower() == 'login':
            try:
                # initial KEP and decryption on login data
                session_key = init_ecdh(client)
                login_data = init_decrypt(client, session_key)

                login_data = login_data.decode('utf-8').split()
                username = login_data[0]
                password = login_data[1]
            except IndexError:
                pass
            except ValueError:  # ? for except handle ecdh
                pass
            else:
                # ! prevent same acc login twice
                if username in nicknames:
                    client.send("LOGIN_DUPE".encode('utf-8'))
                
                # else account has not log in yet, proceed login
                else:
                    # Retrieve salt for the user
                    cursor.execute('SELECT salt FROM users WHERE username = ?;', (username,))
                    salt_data = cursor.fetchone()

                    if salt_data:
                        salt = salt_data[0]
                        hashed_password = hash_password(password, salt)

                        # Verify login credentials
                        cursor.execute('SELECT id, username, password FROM users WHERE username = ? AND password = ?;', (username, hashed_password))
                        user_data = cursor.fetchone()

                        if user_data:
                            client.send("LOGIN_SUCCESS".encode('utf-8'))

                            # ? Send all user keys from db to client
                            retrieve_keys(client, user_data[0])

                            # Set the username as the nickname
                            nicknames.append(username)

                            clients.append(client)

                            print(nicknames)

                            print(f"Nickname of the client is {username}")
                            broadcast(f"{username} connected to the server!\n".encode('utf-8'))
                            client.send("Connected to the server".encode('utf-8'))

                            thread = threading.Thread(target=handle, args=(client,))
                            thread.start()
                        else:
                            client.send("LOGIN_FAILED".encode('utf-8'))

                    else:
                        client.send("LOGIN_FAILED".encode('utf-8'))

        # register option
        elif login_or_register.lower() == 'register':
            try:
                session_key = init_ecdh(client)
                register_data = init_decrypt(client, session_key)

                register_data = register_data.decode('utf-8').split()
                username = register_data[0]
                password = register_data[1]
            except IndexError:
                pass
            except ValueError:  # ? for except handle ecdh
                pass
            else:
                # ! check if there are attempt on insert duplicate username
                cursor.execute('SELECT id FROM users WHERE username = ?;', (username, ))
                
                # ? if username exist, abort register
                if len(cursor.fetchall()) == 1:
                    client.send("REGISTER_FAIL".encode('utf-8'))
                
                # ? else cont register with username
                else:
                    # Generate salt
                    salt = generate_salt()

                    # Hash password
                    hashed_password = hash_password(password, salt)

                    # Insert new user into the database
                    cursor.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?);', (username, hashed_password, salt))
                    conn.commit()

                    client.send("REGISTER_SUCCESS".encode('utf-8'))

                    # ? Insert keys from client to db
                    store_keys(client, username)

        else:
            client.send("INVALID_OPTION".encode('utf-8'))

banner()
server_keygen()
print("\nServer is running!")
receive()