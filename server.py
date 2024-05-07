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
# TODO : look into resetting opk, spk as defined in paper ; replenish from client
# // TODO : look into resetting pq_ct, ep_key after fetch
# // TODO : clean up encryption method in separate funct

### These libs are used for basic funct - network and threading
from base64 import b64encode, b64decode
import json
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
from Crypto.Util.Padding import unpad, pad

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
        sig_pqopk TEXT,
        ep_key_public TEXT,
        pq_ct TEXT
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

# * This function is to perform initial encryption of server response
# ? This function will return encrypted server response
def init_encrypt(client, session_key, data):
    cipher = AES.new(session_key, AES.MODE_CBC)
    data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))

    json_k = ['iv', 'data']
    json_v = [b64encode(x).decode('utf-8') for x in (cipher.iv, data)]
    json_ct = json.dumps(dict(zip(json_k, json_v)))
    client.send(json_ct.encode('utf-8'))

# * This function is to perform initial decryption of user data
# ? This function will return decrypted user data
def init_decrypt(client, session_key):
    try:
        # receive ct of login data from user and iv used during enc
        login_data = client.recv(20480).decode('utf-8')

        b64 = json.loads(login_data)
        json_k = [ 'iv', 'data' ]
        json_v = {k:b64decode(b64[k]) for k in json_k}
        

        # init AES and attempt to decrypt ct using session_key
        # decrypted ct will be unpad to return to pt
        cipher = AES.new(session_key, AES.MODE_CBC, json_v['iv'])
        login_data = unpad(cipher.decrypt(json_v['data']), AES.block_size)

        return login_data
        
    except Exception as e:
        pass

# * This function is to store user keys into database
# ? No return for this function
def store_keys(client, username):
    cursor.execute('SELECT id from users WHERE username = ?;', (username,))
    user_id = cursor.fetchone()
    user_id = user_id[0]

    id_key_public = client.recv(1024).decode('utf-8')
    id_key_private = client.recv(1024).decode('utf-8')
    
    pqid_pkey = client.recv(30720).decode('utf-8')
    pqid_skey = client.recv(30720).decode('utf-8')

    spk_key_public = client.recv(1024).decode('utf-8')
    spk_key_private = client.recv(1024).decode('utf-8')

    sig_spk = client.recv(20480).decode('utf-8')

    pqspk_pkey = client.recv(30720).decode('utf-8')
    pqspk_skey = client.recv(30720).decode('utf-8')

    sig_pqspk = client.recv(20480).decode('utf-8')

    opk_key_public = client.recv(1024).decode('utf-8')
    opk_key_private = client.recv(1024).decode('utf-8')

    pqopk_pkey = client.recv(30720).decode('utf-8')
    pqopk_skey = client.recv(30720).decode('utf-8')

    sig_pqopk = client.recv(20480).decode('utf-8')

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
# ? This function will send all keys belonging to client
def resp_init_pqxdh(client, user_id):
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
    client.send(keys[7].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[8].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[9].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[10].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[11].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[12].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[13].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[14].encode('utf-8'))
    time.sleep(0.05)
    client.send(keys[15].encode('utf-8'))

# * This function is to retrieve all pubkeys, sigs of users in server session,
# ! --
# ? This function send all keys and sigs of corresponding clients to client
def resp_calc_pqxdh(client, session_key, nicknames, username):

    askUser = init_decrypt(client, session_key)
    askUser = askUser.decode()

    # Look for corresp. user in db
    cursor.execute('SELECT id FROM users WHERE username = ?;', (askUser, ))
    user_id = cursor.fetchone()

    # if user exists, proceed to either ENC or DEC
    if user_id:
        user_id = user_id[0]

        # if corresp. user is not logged in, perform ENC
        if askUser not in nicknames:
            init_encrypt(client, session_key, "ENC")

            cursor.execute('''SELECT id_key_public, pqid_pkey, spk_key_public, sig_spk,
                    pqspk_pkey, sig_pqspk, opk_key_public, pqopk_pkey, sig_pqopk
                    FROM keys WHERE user_id = ?;''', (user_id, ))
            keys = cursor.fetchone()

            client.send(keys[0].encode('utf-8'))
            time.sleep(0.05)
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
            client.send(keys[7].encode('utf-8'))
            time.sleep(0.05)
            client.send(keys[8].encode('utf-8'))

            ct_a = client.recv(30720).decode('utf-8')
            ep_key_public = client.recv(1024).decode('utf-8')

            cursor.execute('''SELECT id FROM users WHERE username = ?''', (username, ))
            user_id = cursor.fetchone()
            user_id = user_id[0]

            cursor.execute('UPDATE keys SET ep_key_public = ?, pq_ct = ? WHERE user_id = ?;', (ep_key_public, ct_a, user_id, ))
            conn.commit()

            return True
        
        # else if corresp. user is logged in, perform DEC
        else:
            init_encrypt(client, session_key, "DEC")

            cursor.execute('''SELECT id_key_public, pqid_pkey, spk_key_public, sig_spk,
                    pqspk_pkey, sig_pqspk, opk_key_public, pqopk_pkey, sig_pqopk, ep_key_public, pq_ct
                    FROM keys WHERE user_id = ?''', (user_id, ))
            keys = cursor.fetchone()

            client.send(keys[0].encode('utf-8'))
            time.sleep(0.05)
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
            client.send(keys[7].encode('utf-8'))
            time.sleep(0.05)
            client.send(keys[8].encode('utf-8'))
            time.sleep(0.05)
            client.send(keys[9].encode('utf-8'))
            time.sleep(0.05)
            client.send(keys[10].encode('utf-8'))
            time.sleep(0.05)
            client.send(keys[10].encode('utf-8'))

            cursor.execute('UPDATE keys SET ep_key_public = ?, pq_ct = ? WHERE user_id = ?;', ("", "", user_id, ))
            conn.commit()

            return True
    
    # if corresp. user not exist in db, return no user
    else:
        init_encrypt(client, session_key, "NO USER")
        return False

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
            message = client.recv(30720)

            #print(message)
            
            # ? remove client from server list on exit
            # ! might need to revise method since user can malice type "LOG_OUT" lole
            if message.decode('utf-8') == "LOG_OUT":
                raise ConnectionError
            else:
                broadcast(message)

        except ConnectionError:
            index = clients.index(client)
            nickname = nicknames[index]

            print(f"{nickname} has logged out or exited the session!")
            broadcast(f"{nickname} has logged out or exited the session!".encode('utf-8'))

            clients.remove(client)
            nicknames.remove(nickname)

            client.close()
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
        try:
            login_or_register = client.recv(1024).decode('utf-8')

        except:         # ? catch except if client exit on login/register
            pass

        else:
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
                        init_encrypt(client, session_key, "LOGIN_DUPE")
                    
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
                                init_encrypt(client, session_key, "LOGIN_SUCCESS")

                                # ? Send all user keys from db to client - init_pqxdh()
                                resp_init_pqxdh(client, user_data[0])

                                # Set the username as the nickname
                                nicknames.append(username)
                                clients.append(client)

                                # ? Send corresponder keys from db to client - askUserMsg() -> calc_pqxdh()
                                # ! input valid here - loop if NO USER
                                askUser_bool = resp_calc_pqxdh(client, session_key, nicknames, username)
                                if not askUser_bool:
                                    while not askUser_bool:
                                        askUser_bool = resp_calc_pqxdh(client, session_key, nicknames, username)

                                print(f"Nickname of the client is {username}")
                                broadcast(f"{username} connected to the server!\n".encode('utf-8'))
                                client.send("Connected to the server".encode('utf-8'))

                                thread = threading.Thread(target=handle, args=(client,))
                                thread.start()
                            else:
                                init_encrypt(client, session_key, "LOGIN_FAILED")

                        else:
                            init_encrypt(client, session_key, "LOGIN_FAILED")

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
                        init_encrypt(client, session_key, "REGISTER_FAIL")
                    
                    # ? else cont register with username
                    else:
                        # Generate salt
                        salt = generate_salt()

                        # Hash password
                        hashed_password = hash_password(password, salt)

                        # Insert new user into the database
                        cursor.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?);', (username, hashed_password, salt))
                        conn.commit()

                        init_encrypt(client, session_key, "REGISTER_SUCCESS")

                        # ? Insert keys from client to db
                        store_keys(client, username)

            else:
                client.send("INVALID_OPTION".encode('utf-8'))

banner()
server_keygen()
print("\nServer is running!")
receive()