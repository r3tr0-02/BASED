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

# `TODO : add GUI for login or register
# `TODO : add GUI for username & password 

import socket
import threading
import tkinter as tk
import tkinter.scrolledtext
from tkinter import simpledialog
from tkinter import messagebox

HOST = '127.0.0.1'
PORT = 9090

class Client:

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        self.login_or_register_gui()

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

    # * This function is to ask users for username, password and confirm
    # * password for register
    def register_gui(self):
        self.login_or_register_win.destroy()
        self.sock.send("register".encode('utf-8'))

        self.register_win = tk.Tk()
        self.register_win.title("Login")
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

        self.confirm_password_label = tk.Label(self.register_win, text="Password :", bg="lightgreen")
        self.confirm_password_label.config(font=("Arial", 12))
        self.confirm_password_label.pack(padx=20, pady=5)

        self.confirm_password_input = tk.Text(self.register_win, height=3)
        self.confirm_password_input.pack(padx=20, pady=5)

        self.send_button = tk.Button(self.register_win, text="Login", command=self.register)
        self.send_button.config(font=("Arial", 12))
        self.send_button.pack(padx=20, pady=5)

        self.register_win.protocol("WM_DELETE_WINDOW", self.stop_register)

        self.register_win.mainloop()

    # * This function is to get input from login_gui funct and send to
    # * server for verification
    # ? After login, this function will goto message_gui
    # ! If login fail, this function will goto login_or_register_gui
    def login(self):
        self.username = self.username_input.get('1.0', 'end-1c')
        self.password = self.password_input.get('1.0', 'end-1c')

        # ! input might get sanitized here

        login_data = f"{self.username} {self.password}"
        self.sock.send(login_data.encode('utf-8'))

        # Wait for server response
        login_response = self.sock.recv(1024).decode('utf-8')

        if login_response == "LOGIN_SUCCESS":
            self.login_win.destroy()

            self.nickname = self.username
            self.gui_done = False
            self.running = True

            gui_thread = threading.Thread(target=self.message_gui)
            receive_thread = threading.Thread(target=self.receive)

            gui_thread.start()
            receive_thread.start()
        else:
            messagebox.showerror(title="Error", message="Your username and/or password is incorrect!")
            self.login_win.destroy()

            self.login_or_register_gui()

    # * This function is to get input from register_gui funct and send to
    # * server for verification
    # ? After register, this function will goto login_or_register_gui
    # ! If login fail, this function will goto login_or_register_gui
    def register(self):
        self.username = self.username_input.get('1.0', 'end-1c')
        self.password = self.password_input.get('1.0', 'end-1c')
        self.confirm_password = self.confirm_password_input.get('1.0', 'end-1c')

        if self.password == self.confirm_password:
            register_data = f"{self.username} {self.password}"
            self.sock.send(register_data.encode('utf-8'))

            # Wait for server response
            register_response = self.sock.recv(1024).decode('utf-8')
            if register_response == "REGISTER_SUCCESS":
                messagebox.showinfo(title="Info", message="Registration complete. Please log in using your username and password.")
                self.register_win.destroy()
            else:
                tk.messagebox.showerror(title="Error", message="Registration Failed!")
                self.register_win.destroy()

                self.login_or_register_gui()
        else:
            tk.messagebox.showerror(title="Error", message="Please double confirm your password!")
            self.register_win.destroy()

            self.login_or_register_gui()

    # * This function is to get input from user message and display message
    # * from other users
    def message_gui(self):
        self.win = tk.Tk()
        self.login_win.title("Message")
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
