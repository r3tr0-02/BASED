'''
import socket
import threading
import tkinter as tk
import tkinter.scrolledtext
from tkinter import simpledialog

HOST = '127.0.0.1'
PORT = 9090

class Client:

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        msg = tk.Tk()
        msg.withdraw()

        self.nickname = simpledialog.askstring("Nickname", "Please choose a nickname", parent=msg)

        self.gui_done = False
        self.running = True

        gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive)

        gui_thread.start()
        receive_thread.start()

    def gui_loop(self):
        self.win = tk.Tk()
        self.win.configure(bg="lightgreen")

        self.chat_label = tk.Label(self.win, text="Chat:", bg="lightgreen")
        self.chat_label.config(font=("Arial", 12))
        self.chat_label.pack(padx=20, pady=5)

        self.text_area = tk.scrolledtext.ScrolledText(self.win)
        self.text_area.pack(padx=20, pady=5)
        self.text_area.config(state='disabled')
        
        self.msg_label = tk.Label(self.win, text="Message:", bg="lightgreen")
        self.msg_label.config(font=("Arial", 12))
        self.msg_label.pack(padx=20, pady=5)

        self.input_area = tk.Text(self.win, height=3)
        self.input_area.pack(padx=20, pady=5)

        self.send_button = tk.Button(self.win, text="Send", command=self.write)
        self.send_button.config(font=("Arial", 12))
        self.send_button.pack(padx=20, pady=5)

        self.gui_done = True

        self.win.protocol("WM_DELETE_WINDOW", self.stop)

        self.win.mainloop()

    def write(self):
        message = f"{self.nickname}: {self.input_area.get('1.0', 'end')}"
        self.sock.send(message.encode('utf-8'))
        self.input_area.delete('1.0', 'end')

    def stop(self):
        self.running = False
        self.win.destroy()
        self.sock.close()
        exit(0)

    def receive(self):
        while self.running:
            try:
                message = self.sock.recv(1024).decode('utf-8')
                if message == 'NICK':
                    self.sock.send(self.nickname.encode('utf-8'))
                else:
                    if self.gui_done:
                        self.text_area.config(state='normal')
                        self.text_area.insert('end', message)
                        self.text_area.yview('end')
                        self.text_area.config(state='disabled')
            except ConnectionAbortedError:
                break
            except:
                print("Error")
                self.sock.close()
                break

client = Client(HOST, PORT)
'''

# // TODO : add GUI for login or register
# // TODO : add GUI for username & password 
# TODO : hide password entries
# // TODO : start init. encrypt on login on conn
# // TODO : start init. encrypt on register on conn
# // TODO : polish retry login after fail - some uncaught exception / logic err
# // TODO : clean up encryption method in separate funct
# TODO : start init. pqxdh key gen
# TODO : start calc pqxdh sk - get current clients in session, then update SK each time?
# TODO : research on how to do clients > 2 ?
# TODO : research on what happen if client exit?
# // TODO : except handling on exit (init ecdh-encrypt)
# // TODO : polish login-retrieve key (encrypt curve skeys)
# // TODO : how to encrypt and handle priv keys in db? 
# ! TODO : polish clean exit - threading err

### These libs are used for basic funct - network and threading
from base64 import b64encode, b64decode
import json
import time
import socket
import threading

### These libs are used for GUI generation
import tkinter as tk
import tkinter.scrolledtext
from tkinter import simpledialog
from tkinter import messagebox

### These libs are used for conv. symm / asymm op.
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHAKE128, SHA512
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Signature import eddsa

### These libs are used for Post-Quantum op.
from kyber import Kyber1024
from pqc.sign import dilithium5

HOST = '127.0.0.1'
PORT = 9090

class Client:

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        self.user_keygen()
        self.login_or_register_gui()

    # * This function is to generate an ECC ed25519 keypair for client
    # ? client keypairs are all stored in memory
    # ? client keypairs are always generated each time invoked
    def user_keygen(self):

        # Gen user-side keypair
        user_key = ECC.generate(curve='ed25519')

        # set keypair to session
        self.user_key_public = user_key.public_key()
        self.user_key_private = user_key

    # * This function is for Key Derivation Function for ECDH op.
    def kdf(self, x):
        return SHAKE128.new(x).read(32)

    # * This function is to perform initial ECDH KEP on client-server
    # ? This function will return a shared session key
    def init_ecdh(self):
        
        # export user_key_public as PEM and send to server
        self.sock.send(str(self.user_key_public.export_key(format='PEM')).encode('utf-8'))

        # import server_key_public from server
        server_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))

        # perform ecdh on client-server
        session_key = key_agreement(static_priv=self.user_key_private,
                                        static_pub=server_key_public,
                                        kdf=self.kdf)
        return session_key

    # * This function is to perform initial encryption of user data
    # ? This function will return decrypted user data
    def init_encrypt(self, session_key, data):
        cipher = AES.new(session_key, AES.MODE_CBC)
        data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))

        self.sock.send(data)
        self.sock.send(cipher.iv)

    # * This function is to perform initial PQXDH key generation and 
    # * management on client-server
    # ? If login, retrieve user keys from server and set session with keys
    # ? If register, generate and upload keys and sigs to server
    def init_pqxdh(self, state, pwd):

        # if login, retrieve all keys belong to user
        # ? decrypt all privkeys with kdf(pwd)
        if state == "login":
            id_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))
            json_key = self.sock.recv(1024).decode('utf-8')
            json_key = json.loads(json_key)
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
            id_key_private = unpad(cipher.decrypt(b64decode(json_key['id_key_private'])), AES.block_size)
            id_key_private = ECC.import_key(id_key_private.decode('utf-8'))

            pqid_pkey = self.sock.recv(30720).decode('utf-8')
            pqid_pkey = b64decode(pqid_pkey)

            json_key = self.sock.recv(30720).decode('utf-8')
            json_key = json.loads(json_key)
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
            pqid_skey = unpad(cipher.decrypt(b64decode(json_key['pqid_skey'])), AES.block_size)

            spk_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))
            json_key = self.sock.recv(1024).decode('utf-8')
            json_key = json.loads(json_key)
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
            spk_key_private = unpad(cipher.decrypt(b64decode(json_key['spk_key_private'])), AES.block_size)
            spk_key_private = ECC.import_key(spk_key_private.decode('utf-8'))

            pqspk_pkey = self.sock.recv(30720).decode('utf-8')
            pqspk_pkey = b64decode(pqspk_pkey)

            json_key = self.sock.recv(30720).decode('utf-8')
            json_key = json.loads(json_key)
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
            pqspk_skey = unpad(cipher.decrypt(b64decode(json_key['pqspk_skey'])), AES.block_size)

            opk_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))
            json_key = self.sock.recv(1024).decode('utf-8')
            json_key = json.loads(json_key)
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
            opk_key_private = unpad(cipher.decrypt(b64decode(json_key['opk_key_private'])), AES.block_size)
            opk_key_private = ECC.import_key(opk_key_private.decode('utf-8'))

            pqopk_pkey = self.sock.recv(30720).decode('utf-8')
            pqopk_pkey = b64decode(pqopk_pkey) 

            json_key = self.sock.recv(30720).decode('utf-8')
            json_key = json.loads(json_key)
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
            pqopk_skey = unpad(cipher.decrypt(b64decode(json_key['pqopk_skey'])), AES.block_size)

        # if register first time, publish all keys to server
        # ! may not be best way to do but encrypt all privkeys 
        # ! with kdf(pwd) and AES
        elif state == "register":
            signer = eddsa.new(self.user_key_private, 'rfc8032')

            # Generate keys for init PQXDH
            id_key_public = self.user_key_public.export_key(format='PEM')
            id_key_private = self.user_key_private.export_key(format='PEM')
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC)
            id_key_private = cipher.encrypt(pad(id_key_private.encode('utf-8'), AES.block_size))
            id_key_private = json.dumps(
                {
                    'iv': b64encode(cipher.iv).decode('utf-8'),
                    'id_key_private': b64encode(id_key_private).decode('utf-8')
                }
            )

            pqid_pkey, pqid_skey = dilithium5.keypair()

            pqid_pkey = b64encode(pqid_pkey).decode('utf-8')
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC)
            pqid_skey = cipher.encrypt(pad(pqid_skey, AES.block_size))
            pqid_skey = json.dumps(
                {
                    'iv': b64encode(cipher.iv).decode('utf-8'),
                    'pqid_skey': b64encode(pqid_skey).decode('utf-8')
                }
            )

            spk_key = ECC.generate(curve='ed25519')
            spk_key_public = spk_key.public_key().export_key(format='PEM')
            spk_key_private = spk_key.export_key(format='PEM')
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC)
            spk_key_private = cipher.encrypt(pad(spk_key_private.encode('utf-8'), AES.block_size))
            spk_key_private = json.dumps(
                {
                    'iv': b64encode(cipher.iv).decode('utf-8'),
                    'spk_key_private': b64encode(spk_key_private).decode('utf-8')
                }
            )

            sig_spk = signer.sign(SHA512.new(spk_key.public_key().export_key(format='DER')))
            sig_spk = b64encode(sig_spk).decode('utf-8')

            pqspk_pkey, pqspk_skey = Kyber1024.keygen()

            sig_pqspk = signer.sign(SHA512.new(pqspk_pkey))
            sig_pqspk = b64encode(sig_pqspk).decode('utf-8')

            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC)
            pqspk_skey = cipher.encrypt(pad(pqspk_skey, AES.block_size))
            pqspk_pkey = b64encode(pqspk_pkey).decode('utf-8')
            pqspk_skey = json.dumps(
                {
                    'iv': b64encode(cipher.iv).decode('utf-8'),
                    'pqspk_skey': b64encode(pqspk_skey).decode('utf-8')
                }
            )

            opk_key = ECC.generate(curve='ed25519')
            opk_key_public = opk_key.public_key().export_key(format='PEM')
            opk_key_private = opk_key.export_key(format='PEM')
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC)
            opk_key_private = cipher.encrypt(pad(opk_key_private.encode('utf-8'), AES.block_size))
            opk_key_private = json.dumps(
                {
                    'iv': b64encode(cipher.iv).decode('utf-8'),
                    'opk_key_private': b64encode(opk_key_private).decode('utf-8')
                }
            )

            pqopk_pkey, pqopk_skey = Kyber1024.keygen()

            sig_pqopk = signer.sign(SHA512.new(pqopk_pkey))
            sig_pqopk = b64encode(sig_pqopk).decode('utf-8')

            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC)
            pqopk_skey = cipher.encrypt(pad(pqopk_skey, AES.block_size))
            pqopk_pkey = b64encode(pqopk_pkey).decode('utf-8')
            pqopk_skey = json.dumps(
                {
                    'iv': b64encode(cipher.iv).decode('utf-8'),
                    'pqopk_skey': b64encode(pqopk_skey).decode('utf-8')
                }
            )

            # Publish keys to server
            # ! may need to work out better way to send keys...
            self.sock.send(id_key_public.encode('utf-8'))
            self.sock.send(id_key_private.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqid_pkey.encode('utf-8'))
            self.sock.send(pqid_skey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(spk_key_public.encode('utf-8'))
            self.sock.send(spk_key_private.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(str(sig_spk).encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqspk_pkey.encode('utf-8'))
            self.sock.send(pqspk_skey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(str(sig_pqspk).encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(opk_key_public.encode('utf-8'))
            self.sock.send(opk_key_private.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqopk_pkey.encode('utf-8'))
            self.sock.send(pqopk_skey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(str(sig_pqopk).encode('utf-8'))
            time.sleep(0.05)

    def calc_pqxdh():
        pass



    # * This function is to ask users whether to login or register
    def login_or_register_gui(self):
        self.login_or_register_win = tk.Tk()
        self.login_or_register_win.title("Login/Register")
        self.login_or_register_win.configure(bg="lightgreen")

        width = 600
        height = 400
        screenwidth = self.login_or_register_win.winfo_screenwidth()
        screenheight = self.login_or_register_win.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        self.login_or_register_win.geometry(alignstr)

        self.logo_label = tk.Label(self.login_or_register_win, text="BASED", background="white")
        self.logo_label.config(font=("Arial", 56))
        self.logo_label.pack(padx=100, pady=50)

        self.login_button = tk.Button(self.login_or_register_win, text="Login", command=self.login_gui)
        self.login_button.config(font=("Arial", 12))
        self.login_button.pack(padx=20, pady=10)

        self.register_button = tk.Button(self.login_or_register_win, text="Register", command=self.register_gui)
        self.register_button.config(font=("Arial", 12))
        self.register_button.pack(padx=20, pady=10)

        self.login_or_register_win.protocol("WM_DELETE_WINDOW", self.stop_login_register)

        self.login_or_register_win.mainloop()

    # * This function is to ask users for username and password for login
    def login_gui(self):
        self.login_or_register_win.destroy()
        self.sock.send("login".encode('utf-8'))

        self.login_win = tk.Tk()
        self.login_win.title("Login")
        self.login_win.configure(bg="lightgreen")

        width = 600
        height = 400
        screenwidth = self.login_win.winfo_screenwidth()
        screenheight = self.login_win.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        self.login_win.geometry(alignstr)

        self.username_label = tk.Label(self.login_win, text="Username : ", bg="lightgreen")
        self.username_label.config(font=("Arial", 12))
        self.username_label.pack(padx=20, pady=5)

        self.username_input = tk.Text(self.login_win, height=3)
        self.username_input.pack(padx=20, pady=5)

        self.password_label = tk.Label(self.login_win, text="Password :", bg="lightgreen")
        self.password_label.config(font=("Arial", 12))
        self.password_label.pack(padx=20, pady=5)

        self.password_input = tk.Text(self.login_win, height=3)
        self.password_input.pack(padx=20, pady=5)

        self.send_button = tk.Button(self.login_win, text="Login", command=self.login)
        self.send_button.config(font=("Arial", 12))
        self.send_button.pack(padx=20, pady=5)

        self.login_win.protocol("WM_DELETE_WINDOW", self.stop_login)

        self.login_win.mainloop()

        #login_thread = threading.Thread(target=self.login)
        #login_thread.start()

    # * This function is to ask users for username, password and confirm
    # * password for register
    def register_gui(self):
        self.login_or_register_win.destroy()
        self.sock.send("register".encode('utf-8'))

        self.register_win = tk.Tk()
        self.register_win.title("Register")
        self.register_win.configure(bg="lightgreen")

        width = 600
        height = 400
        screenwidth = self.register_win.winfo_screenwidth()
        screenheight = self.register_win.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        self.register_win.geometry(alignstr)

        self.username_label = tk.Label(self.register_win, text="Username : ", bg="lightgreen")
        self.username_label.config(font=("Arial", 12))
        self.username_label.pack(padx=20, pady=5)

        self.username_input = tk.Text(self.register_win, height=3)
        self.username_input.pack(padx=20, pady=5)

        self.password_label = tk.Label(self.register_win, text="Password :", bg="lightgreen")
        self.password_label.config(font=("Arial", 12))
        self.password_label.pack(padx=20, pady=5)

        self.password_input = tk.Text(self.register_win, height=3)
        self.password_input.pack(padx=20, pady=5)

        self.confirm_password_label = tk.Label(self.register_win, text="Confirm Password :", bg="lightgreen")
        self.confirm_password_label.config(font=("Arial", 12))
        self.confirm_password_label.pack(padx=20, pady=5)

        self.confirm_password_input = tk.Text(self.register_win, height=3)
        self.confirm_password_input.pack(padx=20, pady=5)

        self.send_button = tk.Button(self.register_win, text="Register", command=self.register)
        self.send_button.config(font=("Arial", 12))
        self.send_button.pack(padx=20, pady=5)

        self.register_win.protocol("WM_DELETE_WINDOW", self.stop_register)

        self.register_win.mainloop()

        #register_thread = threading.Thread(target=self.register)
        #register_thread.start()

    # * This function is to get input from login_gui funct and send to
    # * server for verification
    # ? After login, this function will goto message_gui
    # ! If login fail, this function will goto login_or_register_gui
    def login(self):
        self.username = self.username_input.get('1.0', 'end-1c')
        self.password = self.password_input.get('1.0', 'end-1c')

        # ! input might get sanitized here

        login_data = f"{self.username} {self.password}"

        # initial KEP and encryption on login data
        # ? encrypted data will be sent on encrypt()
        session_key = self.init_ecdh()
        self.init_encrypt(session_key, login_data)

        # Wait for server response
        login_response = self.sock.recv(1024).decode('utf-8')

        # if login success, goto message_gui
        if login_response == "LOGIN_SUCCESS":
            self.login_win.destroy()

            self.init_pqxdh("login", self.password)

            self.nickname = self.username
            self.gui_done = False
            self.running = True

            gui_thread = threading.Thread(target=self.message_gui)
            receive_thread = threading.Thread(target=self.receive)

            gui_thread.start()
            receive_thread.start()

            gui_thread.join()
            receive_thread.join()

        # if login dupe, abort login
        elif login_response == "LOGIN_DUPE":
            messagebox.showerror(title="Error", message="Your account has been logged in by another client!")

            # ! for some reason, retry after login will result in conn drop
            # ? temp solution is to close the current conn and re-init the conn
            self.sock.close()

            self.login_win.destroy()

            self.__init__(HOST, PORT)

        # if login fail, go back to login_or_register
        else:
            messagebox.showerror(title="Error", message="Your username and/or password is incorrect!")

            # ! for some reason, retry after login will result in conn drop
            # ? temp solution is to close the current conn and re-init the conn
            self.sock.close()

            self.login_win.destroy()

            self.__init__(HOST, PORT)

    # * This function is to get input from register_gui funct and send to
    # * server for verification
    # ? After register, this function will goto login_or_register_gui
    # ! If register fail, this function will either display err msg
    # ! or goto login_or_register_gui
    def register(self):
        self.username = self.username_input.get('1.0', 'end-1c')
        self.password = self.password_input.get('1.0', 'end-1c')
        self.confirm_password = self.confirm_password_input.get('1.0', 'end-1c')

        # ! input might get sanitized here

        if self.password == self.confirm_password and (len(self.password) != 0 and len(self.confirm_password) != 0):
            register_data = f"{self.username} {self.password}"
            
            # initial KEP and encryption on login data
            # ? encrypted data will be sent on encrypt()
            session_key = self.init_ecdh()
            self.init_encrypt(session_key, register_data)

            # Wait for server response
            register_response = self.sock.recv(1024).decode('utf-8')
            if register_response == "REGISTER_SUCCESS":
                self.init_pqxdh(state="register", pwd=self.password)
                messagebox.showinfo(title="Info", message="Registration complete. Please log in using your username and password.")
                
                # ! same handle case as login, close and re-init conn after exit win
                self.sock.close()
                self.register_win.destroy()
                self.__init__(HOST, PORT)
            else:
                tk.messagebox.showerror(title="Error", message="Registration Failed!")

                # ! same handle case as login, close and re-init conn after exit win
                self.sock.close()
                self.register_win.destroy()
                self.__init__(HOST, PORT)
        else:
            tk.messagebox.showerror(title="Error", message="Please double confirm your password!")
            self.password_input.delete('1.0', 'end')
            self.confirm_password_input.delete('1.0', 'end')

    # * This function is to get input from user message and display message
    # * from other users
    def message_gui(self):
        self.win = tk.Tk()
        #self.win.configure()
        self.win.title("Message")
        self.win.configure(bg="lightgreen")

        width = 600
        height = 575
        screenwidth = self.win.winfo_screenwidth()
        screenheight = self.win.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        self.win.geometry(alignstr)

        self.chat_label = tk.Label(self.win, text="Chat:", bg="lightgreen")
        self.chat_label.config(font=("Arial", 12))
        self.chat_label.pack(padx=20, pady=5)

        self.text_area = tk.scrolledtext.ScrolledText(self.win)
        self.text_area.pack(padx=20, pady=5)
        self.text_area.config(state='disabled')
        
        self.msg_label = tk.Label(self.win, text="Message:", bg="lightgreen")
        self.msg_label.config(font=("Arial", 12))
        self.msg_label.pack(padx=20, pady=5)

        self.input_area = tk.Text(self.win, height=3)
        self.input_area.pack(padx=20, pady=5)

        self.send_button = tk.Button(self.win, text="Send", command=self.write)
        self.send_button.config(font=("Arial", 12))
        self.send_button.pack(padx=20, pady=5)

        self.gui_done = True

        self.win.protocol("WM_DELETE_WINDOW", self.stop)

        self.win.mainloop()

    # * This function is to send message from user to server for it to be 
    # * broadcasted to other users
    def write(self):
        message = f"{self.nickname}: {self.input_area.get('1.0', 'end')}"

        # ! encrypt here
        self.sock.send(message.encode('utf-8'))
        self.input_area.delete('1.0', 'end')

    # `* All stop funct below is to handle event where a window is closed
    # ? might be a better way to do this...
    def stop_login_register(self):
        self.running = False
        self.login_or_register_win.destroy()
        self.sock.close()
        exit(0)

    def stop_login(self):
        self.running = False
        self.login_win.destroy()
        self.sock.close()
        exit(0)

    def stop_register(self):
        self.running = False
        self.register_win.destroy()
        self.sock.close()
        exit(0)

    def stop(self):
        self.running = False
        self.win.destroy()
        self.sock.close()
        exit(0)

    # * This function is to receive message from server and display it in 
    # * message_gui
    # ! If conn is aborted OR error in message handling, the program will
    # ! terminate conn and exit
    def receive(self):
        while self.running:
            try:
                # ! decrypt here
                message = self.sock.recv(1024).decode('utf-8')
                if message == 'NICK':
                    self.sock.send(self.nickname.encode('utf-8'))
                else:
                    if self.gui_done:
                        self.text_area.config(state='normal')
                        self.text_area.insert('end', message)
                        self.text_area.yview('end')
                        self.text_area.config(state='disabled')
            except ConnectionAbortedError:
                break
            except:
                print("Error")
                self.sock.close()
                break

client = Client(HOST, PORT)
