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

        self.nickname = simpledialog.asksctring("Nickname", "Please choose a nickname", parent=msg)

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
# // TODO : start init. pqxdh key gen
# TODO : start calc pqxdh sk - get current clients in session, then update SK each time?
# TODO : research on how to do clients > 2 ?
    # // TODO : resort to askMsguser? 
# TODO : research on what happen if client exit
    # // TODO : fix memleak on exit - gui_thread, recv_thread
# // TODO : polish on message exit - both client shut
# // TODO : look into pqid sign-verify on both ends
# // TODO : except handling on exit (init ecdh-encrypt)
# // TODO : polish login-retrieve key (encrypt curve skeys)
# // TODO : how to encrypt and handle priv keys in db? 
# // ! TODO : polish clean exit - threading err

### These libs are used for basic funct - network and threading
from base64 import b64encode, b64decode
import json
import time
import socket
import threading
import os

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

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
        except ConnectionRefusedError:
            messagebox.showinfo(title="Info", message="BASED Server is not up and running! It may be down and you may check later.")
        else:
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
        self.session_key = key_agreement(static_priv=self.user_key_private,
                                        static_pub=server_key_public,
                                        kdf=self.kdf)

    # * This function is to perform initial encryption of user data
    # ? This function will return encrypted user data
    def init_encrypt(self, data):
        cipher = AES.new(self.session_key, AES.MODE_CBC)
        data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))

        json_k = ['iv', 'data']
        json_v = [b64encode(x).decode('utf-8') for x in (cipher.iv, data)]
        json_ct = json.dumps(dict(zip(json_k, json_v)))
        self.sock.send(json_ct.encode('utf-8'))

    # * This function is to perform message encryption using AEAD scheme
    # * - This function will also perform message signing with Dilithium
    # ? This function will return encrypted message data
    def init_encrypt_aead(self, secret_key, data):

        # sign message upon receive msg
        msg_sig = self.sign_msg(self.pqid_skey, data)

        cipher = AES.new(secret_key, AES.MODE_EAX)
        cipher.update(self.header)
        ct, tag = cipher.encrypt_and_digest(data.encode('utf-8'))

        # zip every elem in json format 
        json_k = ['nonce', 'header', 'ct', 'tag', 'msg_sig']
        json_v = [b64encode(x).decode('utf-8') for x in (cipher.nonce, self.header, ct, tag, msg_sig)]
        json_ct = json.dumps(dict(zip(json_k, json_v)))

        return json_ct

    # * This function is to perform message decryption using AEAD scheme
    # * - This function will also perform message verification
    # ? This function will return the decrypted message 
    # ? along with message verification indication 
    def init_decrypt_aead(self, secret_key, data):
        try:
            b64 = json.loads(data)
            json_k = [ 'nonce', 'header', 'ct', 'tag', 'msg_sig' ]
            json_v = {k:b64decode(b64[k]) for k in json_k}

            cipher = AES.new(secret_key, AES.MODE_EAX, nonce=json_v['nonce'])
            cipher.update(json_v['header'])
            pt = cipher.decrypt_and_verify(json_v['ct'], json_v['tag'])
            pt = pt.decode('utf-8')

            msg_verify = self.verify_msg(pt, json_v['msg_sig'])

            # concat verification indication with message
            return pt + msg_verify

        except Exception as e:      # ? decryption failed - pt from server on client disconn.
            #print(e)
            return data

    # * This function is to perform message signing
    # ? This function will return msg_sig called to init_encrypt_aead()
    def sign_msg(self, pqid_skey, data):
        return dilithium5.sign(SHA512.new(data.encode('utf-8')).digest(), pqid_skey)

    # * This function is to perform message verification
    # ? This function will return str OK on successful verify
    # ? or str NOT OK on failed verify
    def verify_msg(self, pt, msg_sig):

        # verify message using own pqid_pkey
        try:
            dilithium5.verify(msg_sig, SHA512.new(pt.encode('utf-8')).digest(), self.pqid_pkey)
            return " - OK"
        except ValueError:

            # if raise except, msg from corresp. ; try verify using corresp. pqid_pkey
            try:
                dilithium5.verify(msg_sig, SHA512.new(pt.encode('utf-8')).digest(), self.corresp_pqid_pkey)
                return " - OK"
            except ValueError:      # ! if somehow fails to verify, return not ok
                return " - NOT OK"

    # * This function is to perform initial decryption of server response
    # ? This function will return decrypted server response
    def init_decrypt(self):
        try:
            data = self.sock.recv(20480).decode('utf-8')

            b64 = json.loads(data)
            json_k = [ 'iv', 'data' ]
            json_v = {k:b64decode(b64[k]) for k in json_k}

            cipher = AES.new(self.session_key, AES.MODE_CBC, json_v['iv'])
            data = unpad(cipher.decrypt(json_v['data']), AES.block_size)

            return data.decode('utf-8')

        except Exception as e:
            pass

    # * This function is to perform initial PQXDH key generation and 
    # * management on client-server
    # ? If login, retrieve user keys from server and set session with own keys
    # ? If register, generate and upload keys and sigs to server
    def init_pqxdh(self, state, pwd):

        # if login, retrieve all keys belong to user
        # ? decrypt all privkeys with kdf(pwd)
        if state == "login":
            self.id_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))
            json_key = self.sock.recv(1024).decode('utf-8')
            json_key = json.loads(json_key)
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
            self.id_key_private = unpad(cipher.decrypt(b64decode(json_key['id_key_private'])), AES.block_size)
            self.id_key_private = ECC.import_key(self.id_key_private.decode('utf-8'))

            self.pqid_pkey = self.sock.recv(30720).decode('utf-8')
            self.pqid_pkey = b64decode(self.pqid_pkey)

            json_key = self.sock.recv(30720).decode('utf-8')
            json_key = json.loads(json_key)
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
            self.pqid_skey = unpad(cipher.decrypt(b64decode(json_key['pqid_skey'])), AES.block_size)

            self.spk_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))
            json_key = self.sock.recv(1024).decode('utf-8')
            json_key = json.loads(json_key)
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
            self.spk_key_private = unpad(cipher.decrypt(b64decode(json_key['spk_key_private'])), AES.block_size)
            self.spk_key_private = ECC.import_key(self.spk_key_private.decode('utf-8'))

            self.sig_spk = self.sock.recv(20480).decode('utf-8')
            self.sig_spk = b64decode(self.sig_spk)

            self.pqspk_pkey = self.sock.recv(30720).decode('utf-8')
            self.pqspk_pkey = b64decode(self.pqspk_pkey)

            json_key = self.sock.recv(30720).decode('utf-8')
            json_key = json.loads(json_key)
            cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
            self.pqspk_skey = unpad(cipher.decrypt(b64decode(json_key['pqspk_skey'])), AES.block_size)

            self.sig_pqspk = self.sock.recv(20480).decode('utf-8')
            self.sig_pqspk = b64decode(self.sig_pqspk)

            self.opk_key_public = self.sock.recv(1024).decode('utf-8')
            if "NULL" not in self.opk_key_public:
                self.opk_key_public = ECC.import_key(self.opk_key_public)
            else:
                self.opk_key_public = None

            json_key = self.sock.recv(1024).decode('utf-8')
            if "NULL" not in json_key:
                json_key = json.loads(json_key)
                cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
                self.opk_key_private = unpad(cipher.decrypt(b64decode(json_key['opk_key_private'])), AES.block_size)
                self.opk_key_private = ECC.import_key(self.opk_key_private.decode('utf-8'))
            else:
                self.opk_key_private = None

            self.pqopk_pkey = self.sock.recv(30720).decode('utf-8')
            if "NULL" not in self.pqopk_pkey:
                self.pqopk_pkey = b64decode(self.pqopk_pkey)
            else:
                self.pqopk_pkey = None 

            json_key = self.sock.recv(30720).decode('utf-8')
            if "NULL" not in json_key:
                json_key = json.loads(json_key)
                cipher = AES.new(self.kdf(pwd.encode('utf-8')), AES.MODE_CBC, b64decode(json_key['iv']))
                self.pqopk_skey = unpad(cipher.decrypt(b64decode(json_key['pqopk_skey'])), AES.block_size)
            else:
                self.pqopk_skey = None

            self.sig_pqopk = self.sock.recv(20480).decode('utf-8')
            if "NULL" not in self.sig_pqopk:
                self.sig_pqopk = b64decode(self.sig_pqopk)
            else:
                self.sig_pqopk = None

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
            time.sleep(0.05)
            self.sock.send(id_key_private.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqid_pkey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqid_skey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(spk_key_public.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(spk_key_private.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(str(sig_spk).encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqspk_pkey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqspk_skey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(str(sig_pqspk).encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(opk_key_public.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(opk_key_private.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqopk_pkey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqopk_skey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(str(sig_pqopk).encode('utf-8'))

    def update_pqxdh(self, pwd):
        if (self.opk_key_public is None and
            self.opk_key_private is None and
            self.sig_pqopk is None and
            self.pqopk_pkey is None and
            self.pqopk_skey is None):
            
            self.init_encrypt("UPD")

            signer = eddsa.new(self.id_key_private, 'rfc8032')

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

            self.sock.send(opk_key_public.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(opk_key_private.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqopk_pkey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(pqopk_skey.encode('utf-8'))
            time.sleep(0.05)
            self.sock.send(str(sig_pqopk).encode('utf-8'))
        else:
            self.init_encrypt("NO UPD")

    # * This function is to perform retrieve PQXDH keys from corresponding users 
    # * and perform calculation of secret key from both keypairs
    # ! ---
    # ? Get corresp. user keys, sigs
    # ? and perf. ENC or DEC
    def calc_pqxdh(self):
        askUser = self.username_input.get('1.0', 'end-1c')

        # ! input valid here
        if len(askUser) == 0:
            messagebox.showerror(title="Error", message="User cannot be empty!")

        elif askUser == self.nickname:
            messagebox.showerror(title="Error", message="You cannot message yourself (for now)!")

        else:
            askUser = f'{askUser}'

            self.init_encrypt(askUser)

            # Get pqxdh mode from server resp.
            pqxdh_mode = self.init_decrypt()

            # if corresp. user is not logged in, perform ENC
            if pqxdh_mode == "ENC":
                id_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))

                self.corresp_pqid_pkey = self.sock.recv(30720).decode('utf-8')
                self.corresp_pqid_pkey = b64decode(self.corresp_pqid_pkey)

                spk_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))

                sig_spk = self.sock.recv(20480).decode('utf-8')
                sig_spk = b64decode(sig_spk)

                pqspk_pkey = self.sock.recv(30720).decode('utf-8')
                pqspk_pkey = b64decode(pqspk_pkey)

                sig_pqspk = self.sock.recv(20480).decode('utf-8')
                sig_pqspk = b64decode(sig_pqspk)

                opk_key_public = self.sock.recv(1024).decode('utf-8')
                
                if "NULL" not in opk_key_public:
                    opk_key_public = ECC.import_key(opk_key_public)
                else:
                    opk_key_public = None

                pqopk_pkey = self.sock.recv(30720).decode('utf-8')
                if "NULL" not in pqopk_pkey:
                    pqopk_pkey = b64decode(pqopk_pkey)
                else:
                    pqopk_pkey = None

                sig_pqopk = self.sock.recv(20480).decode('utf-8')
                if "NULL" not in sig_pqopk:
                    sig_pqopk = b64decode(sig_pqopk)
                else:
                    sig_pqopk = None

                # verify keys sent from server
                verifier = eddsa.new(id_key_public, 'rfc8032')

                try:
                    verifier.verify(SHA512.new(spk_key_public.export_key(format='DER')), sig_spk)
                    verifier.verify(SHA512.new(pqspk_pkey), sig_pqspk)
                    
                    if sig_pqopk is not None and pqopk_pkey is not None:
                        verifier.verify(SHA512.new(pqopk_pkey), sig_pqopk)
                    
                except ValueError:
                    pass

                else:
                    ep_key = ECC.generate(curve='ed25519')
                    self.ep_key_public = ep_key.public_key()
                    self.ep_key_private = ep_key

                    if pqopk_pkey is not None:
                        ct_a, ss_a = Kyber1024.enc(pqopk_pkey)
                        print("using pqopk") 
                    else:
                        ct_a, ss_a = Kyber1024.enc(pqspk_pkey)
                        print("using pqspk")

                    dh_1 = key_agreement(static_priv=self.id_key_private, static_pub=spk_key_public, kdf=self.kdf)
                    dh_2 = key_agreement(static_priv=self.ep_key_private, static_pub=id_key_public, kdf=self.kdf)
                    dh_3 = key_agreement(static_priv=self.ep_key_private, static_pub=spk_key_public, kdf=self.kdf)

                    if opk_key_public is not None:
                        dh_4 = key_agreement(static_priv=self.ep_key_private, static_pub=opk_key_public, kdf=self.kdf)
                        self.secret_key = self.kdf(dh_1 + dh_2 + dh_3 + dh_4 + ss_a)

                    else:
                        dh_4 = ""
                        self.secret_key = self.kdf(dh_1 + dh_2 + dh_3 + ss_a)

                    # ! need to del all dh, ss vals

                    ss_a = b''
                    dh_1 = ""
                    dh_2 = ""
                    dh_3 = ""
                    dh_4 = ""

                    self.header = self.id_key_public.export_key(format='DER')

                    # upload ct and ep_key_public to server
                    # ? to be fetched by corresp. , performing DEC
                    ct_a = b64encode(ct_a).decode('utf-8')
                    self.sock.send(ct_a.encode('utf-8'))
                    time.sleep(0.05)

                    self.ep_key_public = ep_key.public_key().export_key(format='PEM')
                    self.sock.send(self.ep_key_public.encode('utf-8'))

                    # start message after successful set secret_key
                    try:
                        self.ask_userMsg_win.destroy()
                        gui_thread = threading.Thread(target=self.message_gui)
                        receive_thread = threading.Thread(target=self.receive)

                        gui_thread.daemon = True
                        receive_thread.daemon = True

                        gui_thread.start()
                        receive_thread.start()

                        gui_thread.join()
                        receive_thread.join()

                    except Exception as e:
                        print(e)
                        pass

            elif pqxdh_mode == "DEC":
                id_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))

                self.corresp_pqid_pkey = self.sock.recv(30720).decode('utf-8')
                self.corresp_pqid_pkey = b64decode(self.corresp_pqid_pkey)

                spk_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))

                sig_spk = self.sock.recv(20480).decode('utf-8')
                sig_spk = b64decode(sig_spk)

                pqspk_pkey = self.sock.recv(30720).decode('utf-8')
                pqspk_pkey = b64decode(pqspk_pkey)

                sig_pqspk = self.sock.recv(20480).decode('utf-8')
                sig_pqspk = b64decode(sig_pqspk)

                opk_key_public = self.sock.recv(1024).decode('utf-8')
                
                if "NULL" not in opk_key_public:
                    opk_key_public = ECC.import_key(opk_key_public)
                else:
                    opk_key_public = None

                pqopk_pkey = self.sock.recv(30720).decode('utf-8')
                if "NULL" not in pqopk_pkey:
                    pqopk_pkey = b64decode(pqopk_pkey)
                else:
                    pqopk_pkey = None

                sig_pqopk = self.sock.recv(20480).decode('utf-8')
                if "NULL" not in sig_pqopk:
                    sig_pqopk = b64decode(sig_pqopk)
                else:
                    sig_pqopk = None

                ep_key_public = ECC.import_key(self.sock.recv(1024).decode('utf-8'))

                ct_a = self.sock.recv(30720).decode('utf-8')
                ct_a = b64decode(ct_a)

                # verify keys sent from server
                verifier = eddsa.new(id_key_public, 'rfc8032')

                try:
                    verifier.verify(SHA512.new(spk_key_public.export_key(format='DER')), sig_spk)
                    verifier.verify(SHA512.new(pqspk_pkey), sig_pqspk)

                    if sig_pqopk is not None and pqopk_pkey is not None:
                        verifier.verify(SHA512.new(pqopk_pkey), sig_pqopk)
                    
                except ValueError:
                    pass
                
                else:
                    ep_key = ECC.generate(curve='ed25519')
                    self.ep_key_public = ep_key.public_key()
                    self.ep_key_private = ep_key

                    if self.pqopk_skey is not None:
                        pt = Kyber1024.dec(ct_a, self.pqopk_skey)
                        print("using pqopk")
                    else:
                        pt = Kyber1024.dec(ct_a, self.pqspk_skey)
                        print("using pqspk")

                    dh_1 = key_agreement(static_priv=self.spk_key_private, static_pub=id_key_public, kdf=self.kdf)
                    dh_2 = key_agreement(static_priv=self.id_key_private, static_pub=ep_key_public, kdf=self.kdf)
                    dh_3 = key_agreement(static_priv=self.spk_key_private, static_pub=ep_key_public, kdf=self.kdf)

                    if self.opk_key_private is not None:
                        dh_4 = key_agreement(static_priv=self.opk_key_private, static_pub=ep_key_public, kdf=self.kdf)
                        self.secret_key = self.kdf(dh_1 + dh_2 + dh_3 + dh_4 + pt)
                    else:
                        dh_4 = ""
                        self.secret_key = self.kdf(dh_1 + dh_2 + dh_3 + pt)

                    # ! need to del all dh, ss vals
                    pt = b''
                    dh_1 = ""
                    dh_2 = ""
                    dh_3 = ""
                    dh_4 = ""

                    self.header = self.id_key_public.export_key(format='DER')

                    # start message after successful set secret_key
                    try:
                        self.ask_userMsg_win.destroy()
                        gui_thread = threading.Thread(target=self.message_gui)
                        receive_thread = threading.Thread(target=self.receive)

                        gui_thread.daemon = True
                        receive_thread.daemon = True

                        gui_thread.start()
                        receive_thread.start()

                        gui_thread.join()
                        receive_thread.join()

                    except Exception as e:
                        print(e)
                        pass
            else:
                messagebox.showerror(title="Error", message="No user found!")

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

        logo_label = tk.Label(self.login_or_register_win, text="BASED", background="white")
        logo_label.config(font=("Arial", 56))
        logo_label.pack(padx=100, pady=50)

        login_button = tk.Button(self.login_or_register_win, text="Login", command=self.login_gui)
        login_button.config(font=("Arial", 12))
        login_button.pack(padx=20, pady=10)

        register_button = tk.Button(self.login_or_register_win, text="Register", command=self.register_gui)
        register_button.config(font=("Arial", 12))
        register_button.pack(padx=20, pady=10)

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

        username_label = tk.Label(self.login_win, text="Username : ", bg="lightgreen")
        username_label.config(font=("Arial", 12))
        username_label.pack(padx=20, pady=5)

        self.username_input = tk.Text(self.login_win, height=3)
        self.username_input.pack(padx=20, pady=5)

        password_label = tk.Label(self.login_win, text="Password :", bg="lightgreen")
        password_label.config(font=("Arial", 12))
        password_label.pack(padx=20, pady=5)

        self.password_input = tk.Text(self.login_win, height=3)
        self.password_input.pack(padx=20, pady=5)

        send_button = tk.Button(self.login_win, text="Login", command=self.login)
        send_button.config(font=("Arial", 12))
        send_button.pack(padx=20, pady=5)

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

        username_label = tk.Label(self.register_win, text="Username : ", bg="lightgreen")
        username_label.config(font=("Arial", 12))
        username_label.pack(padx=20, pady=5)

        self.username_input = tk.Text(self.register_win, height=3)
        self.username_input.pack(padx=20, pady=5)

        password_label = tk.Label(self.register_win, text="Password :", bg="lightgreen")
        password_label.config(font=("Arial", 12))
        password_label.pack(padx=20, pady=5)

        self.password_input = tk.Text(self.register_win, height=3)
        self.password_input.pack(padx=20, pady=5)

        confirm_password_label = tk.Label(self.register_win, text="Confirm Password :", bg="lightgreen")
        confirm_password_label.config(font=("Arial", 12))
        confirm_password_label.pack(padx=20, pady=5)

        self.confirm_password_input = tk.Text(self.register_win, height=3)
        self.confirm_password_input.pack(padx=20, pady=5)

        send_button = tk.Button(self.register_win, text="Register", command=self.register)
        send_button.config(font=("Arial", 12))
        send_button.pack(padx=20, pady=5)

        self.register_win.protocol("WM_DELETE_WINDOW", self.stop_register)

        self.register_win.mainloop()

        #register_thread = threading.Thread(target=self.register)
        #register_thread.start()

    # * This function is to ask users for the corresponding user to exchange
    # * message with
    # ? The first user to initiate will be perf. pqxdh's enc
    # ? While the other user will accept the initiate and perf. pqxdh's dec
    # ! May need to revise meth. - cannot message yourself
    def ask_userMsg_gui(self):
        #self.sock.send("login".encode('utf-8'))

        self.ask_userMsg_win = tk.Tk()
        self.ask_userMsg_win.title("Set Message Receiver")
        self.ask_userMsg_win.configure(bg="lightgreen")

        width = 600
        height = 400
        screenwidth = self.ask_userMsg_win.winfo_screenwidth()
        screenheight = self.ask_userMsg_win.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        self.ask_userMsg_win.geometry(alignstr)

        username_label = tk.Label(self.ask_userMsg_win, text="Username to message to : ", bg="lightgreen")
        username_label.config(font=("Arial", 12))
        username_label.pack(padx=20, pady=5)

        self.username_input = tk.Text(self.ask_userMsg_win, height=3)
        self.username_input.pack(padx=20, pady=5)

        send_button = tk.Button(self.ask_userMsg_win, text="Exchange Message", command=self.calc_pqxdh)
        send_button.config(font=("Arial", 12))
        send_button.pack(padx=20, pady=5)

        self.ask_userMsg_win.protocol("WM_DELETE_WINDOW", self.stop_askuserMsg)

        self.ask_userMsg_win.mainloop()

    # * This function is to get input from login_gui funct and send to
    # * server for verification
    # ? After login, this function will goto message_gui
    # ! If login fail, this function will goto login_or_register_gui
    def login(self):
        username = self.username_input.get('1.0', 'end-1c')
        password = self.password_input.get('1.0', 'end-1c')

        # ! input might get sanitized here
        if len(username) == 0 or len(password) == 0:
            messagebox.showerror(title="Error", message="Username / Password cannot be empty!")
        else:
            login_data = f"{username} {password}"

            # initial KEP and encryption on login data
            # ? encrypted data will be sent on encrypt()
            self.init_ecdh()
            self.init_encrypt(login_data)

            # Wait for server response
            login_response = self.init_decrypt()

            # if login success, goto message_gui
            if login_response == "LOGIN_SUCCESS":
                self.login_win.destroy()

                self.init_pqxdh("login", password)
                self.update_pqxdh(password)

                self.nickname = username
                self.gui_done = False
                self.running = True

                self.ask_userMsg_gui()

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
        username = self.username_input.get('1.0', 'end-1c')
        password = self.password_input.get('1.0', 'end-1c')
        confirm_password = self.confirm_password_input.get('1.0', 'end-1c')

        # ! input might get sanitized here
        if len(username) == 0 or len(password) == 0 or len(confirm_password) == 0:
            messagebox.showerror(title="Error", message="Username / Password cannot be empty!")

        else:
            if password == confirm_password and (len(password) != 0 and len(confirm_password) != 0):
                register_data = f"{username} {password}"
                
                # initial KEP and encryption on login data
                # ? encrypted data will be sent on encrypt()
                self.init_ecdh()
                self.init_encrypt(register_data)

                # Wait for server response
                register_response = self.init_decrypt()

                if register_response == "REGISTER_SUCCESS":
                    self.init_pqxdh(state="register", pwd=password)
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
        #self.ask_userMsg_win.destroy()
        self.win = tk.Tk()
        self.win.title("Message")
        self.win.configure(bg="lightgreen")

        width = 600
        height = 575
        screenwidth = self.win.winfo_screenwidth()
        screenheight = self.win.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        self.win.geometry(alignstr)

        chat_label = tk.Label(self.win, text="Chat:", bg="lightgreen")
        chat_label.config(font=("Arial", 12))
        chat_label.pack(padx=20, pady=5)

        self.text_area = tk.scrolledtext.ScrolledText(self.win)
        self.text_area.pack(padx=20, pady=5)
        self.text_area.config(state='disabled')
        
        msg_label = tk.Label(self.win, text="Message:", bg="lightgreen")
        msg_label.config(font=("Arial", 12))
        msg_label.pack(padx=20, pady=5)

        self.input_area = tk.Text(self.win, height=3)
        self.input_area.pack(padx=20, pady=5)

        send_button = tk.Button(self.win, text="Send", command=self.write)
        send_button.config(font=("Arial", 12))
        send_button.pack(padx=20, pady=5)

        self.gui_done = True

        self.win.protocol("WM_DELETE_WINDOW", self.stop)

        self.win.mainloop()

    # * This function is to send message from user to server for it to be 
    # * broadcasted to other users
    def write(self):
        message = self.input_area.get('1.0', 'end-1c')

        # ! input valid here
        if len(message) == 0:
            messagebox.showerror(title="Error", message="Message cannot be empty!")

        else:
            message = f"{self.nickname}: {message}"

            # attempt pqxdh_encrypt_aead here
            message = self.init_encrypt_aead(self.secret_key, message)

            self.sock.send(message.encode('utf-8'))
            self.input_area.delete('1.0', 'end')

    # `* All stop funct below is to handle event where a window is closed
    # ? might be a better way to do this...
    def stop_login_register(self):
        self.running = False
        self.login_or_register_win.destroy()
        self.sock.close()
        os._exit(0)

    def stop_login(self):
        self.running = False
        self.login_win.destroy()
        self.sock.close()
        os._exit(0)

    def stop_register(self):
        self.running = False
        self.register_win.destroy()
        self.sock.close()
        os._exit(0)

    def stop_askuserMsg(self):
        self.running = False
        self.ask_userMsg_win.destroy()
        self.sock.close()
        os._exit(0)

    def stop(self):
        self.running = False
        self.sock.send("LOG_OUT".encode('utf-8'))
        self.win.destroy()
        self.sock.close()
        os._exit(0)

    # * This function is to receive message from server and display it in 
    # * message_gui
    # ! If conn is aborted OR error in message handling, the program will
    # ! terminate conn and exit
    def receive(self):
        while self.running:
            try:
                # decrypt here
                message = self.sock.recv(30720).decode('utf-8')

                try:
                    # attempt pqxdh_aead_decrypt here
                    message = self.init_decrypt_aead(self.secret_key, message)
                except Exception as e:
                    print(e)
                    pass

                if self.gui_done:
                    self.text_area.config(state='normal')
                    self.text_area.insert('end', message + "\n")
                    self.text_area.yview('end')
                    self.text_area.config(state='disabled')
                
            except ConnectionAbortedError:
                break

            # // ! need to look into why two clients crash here - 
            # bug fixed - return type of init_enc_aead was none ; set to str
            except Exception as e:
                print(e)
                print("Error")
                self.stop()
                break

client = Client(HOST, PORT)