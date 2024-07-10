
BASED
=====

[Project Link](https://github.com/r3tr0-02/BASED)

A Client-Server messaging application build using Python GUI and Socket Programming while implementing Hybrid Post-Quantum Encryption and KEP.

  

What is this project?
=====================

This project was created to partially fulfill the requirements for the Bachelor of Computer Science (Cyber Security) (Hons.), College of Computing and Informatics, `[redacted]`.

_With the advancement of Quantum Computing, there has been a new theoretical threat rising sometime in the future where they could potentially break current conventional encryption scheme; both asymmetric and symmetric with Shor's and Grover's Algorithm, once Quantum Computers become more available to the public._

_Current mitigation on this threat is to encapsulate current cryptographic scheme with a Post-Quantum or Quantum-Resistant mechanism. Any attacks on data confidentiality especially Store-Now-Decrypt-Later now must break through another layer of encryption that is theoretically resistant towards attacks from Quantum Computers._

A proof-of-concept is to build a bare instant messaging platform where two parties can communicate in one session; with the mitigation implemented. Oversimplifying, the users will perform a Key Exchange Protocol, in which in it has a layer of Key Encapsulation Mechanism. The output is a secret key that both mutually share and can be used for encrypting subsequent messages in the session. Additionally, all messages are digitally signed on send and verified on receive using a Digital Signature Algorithm.

For more detailed information on how this PoC works (because you are a crypto nerd or you are just bored), refer [here](https://github.com/r3tr0-02/BASED/tree/main?tab=readme-ov-file#-how-does-the-crypto-thingy-works-here-)

  

How this project was built?
===========================

This project was build using pure Python implementation, with GUI from Tkinter lib and Networking from Socket lib.

Cryptography modules used are listed below:

*   Symmetric Encryption (both CBC and AEAD scheme) : `Pycryptodome v 3.20.0` - AES
    
*   Asymmetric PKI and KEP : `Pycryptodome v 3.20.0` - ECC, ECDH
    
*   Hash funct and Key Deriv. funct : `Pycryptodome v 3.20.0` - SHA512, SHAKE128
    
*   Password hashing and salting : `hashlib` and `secrets`
    
*   Conventional Digital Signature : `Pycryptodome v 3.20.0` - EdDSA
    
*   Post-Quantum KEM : `kyber-py v 0.2.2` - Kyber1024
    
*   Post-Quantum Digital Signature : `pypqc v 0.0.6.2` - dilithium5
    

  

What are inside this project?
=============================

There are 2 parts:

*   `server.py` : Server-side application, to serve clients and relay messages between clients
    
*   `testGui.py` : Client-side application, for users to exchange message to another user.
    

  

How do I run this project?
==========================

First, make sure to set the `HOST="..."` on both server and client are the same. Put `127.0.0.1` host it locally or your Internal IP address (use `cmd -> ipconfig` to get the IP) to host it in your LAN. As for now, hosting on the Internet is not possible, yet. Then, there are two ways to run the project:

1.  Thru compiler
    -------------
    
    *   (Pre-requisite) You have to install all of the libraries above before running. **Make sure to add \--nodeps option when installing py-kyber.** This is because it will downgrade pycryptodome version.

	```
	pip install pycryptodome
	pip install kyber-py --no-deps
	pip install pypqc
	...
	verify version with pip list
	```

    *   Download both the files and open the directory of the project / Clone this repo locally.

    *   Open Windows Terminal / CMD and run `python ./server.py`. **Make sure to not run it in any Python .venv - like in VSC.** For some reason, the server cannot work properly.
    
    *   Open another Terminal / CMD with the same directory and run `python ./testGui.py`.
      

2.  Thru compiled `.exe`
    ------------------------
    
    Note that the IP used in the compiled code is `127.0.0.1`.
    
    *   Download the latest release binaries.
        
    *   Click the `server.exe` to start the server.
        
    *   Click the `testGui.exe` to start a client.
        

  

What this app looks like?
=========================

Normal Operations
-----------------

Upon starting the server, it will display a banner message and a notification that it is ready to accept incoming client's connection.

![server_init](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_init.png?raw=true)  

Upon starting the client, it will display an initial page with two options, either to register an account or login.

![client_init](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_init.png?raw=true)  

New users can go on to register a new account by clicking register. A register page will appear.

![client_register](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_register.png?raw=true)  

A pop-up will notify user on successful account registration.

![client_register_success](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_register_success.png?raw=true)  

Users can login to their account by clicking the login button. A login page will appear.

![client_login](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_login.png?raw=true)  

On successful account login, user will be asked who they want to message to. This works like a private chat (user-to-user).

![set_message_recv](https://github.com/r3tr0-02/BASED/blob/main/Assets/set_message_recv.png?raw=true)  

On successful setting correspondent user, chat session is started and users can start to send and receive message.

![client_message](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_message.png?raw=true)  

Once the correspondent user logged in and set their correspondence as the first user, both users can send and receive message.

_Note that in picture below, the client on the left is "test123" and the client on the right is "asdasd"_

On successful verification of message, a string ("- OK") will be appended to the end of message.

![client_message_send_recvOK](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_message_send_recvOK.png?raw=true)  

For the server side, it will display which user successfully logged in and in session.

![server_client_login](https://github.com/r3tr0-02/BASED/blob/main/Assets/server_client_login.png?raw=true)  

When clients close the message window, it will also log out the client on the server side.

![server_client_logout](https://github.com/r3tr0-02/BASED/blob/main/Assets/server_client_logout.png?raw=true)  

Abnormal operations : Input validations and Exception Handlings
---------------------------------------------------------------

### Client init.

If the client is started but failed to connect to a server (because the server is not started or is being set with wrong IP), a pop-up window will notify user that the server is unreachable, then will exit the application.

![client_init_fail](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_init_fail.png?raw=true)  

### Register

If a user tries to register an existing account on database, or the registration process failed, a pop-up window will notify user that the registration process failed.

This is to prevent identity fraud on the platform - every user must have distinct username.

![client_register_fail](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_register_fail.png?raw=true)  

Similarly, if a user tries to register an account but the password is not same as confirm password field, a pop-up window will notify user to double-confirm their password.

![client_register_fail_notconfirmpass](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_register_fail_notconfirmpass.png?raw=true)  

If a user tries to register an account but one of the entries are empty, a pop-up window will notify user to double-confirm their inputs.

![client_register_fail_noinput](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_register_fail_noinput.png?raw=true)  

### Login

If a user tries to login to an account that has been in the server's session, a pop-up window will notify user that the login process failed.

This is because one client is set uniquely to one credential / account on login.

![client_login_fail_dupe](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_login_fail_dupe.png?raw=true)  

Similarly, if a user tries to login to an account but one of the entries are empty, a pop-up window will notify user to double-confirm their inputs.

![client_login_fail_noinput](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_login_fail_noinput.png?raw=true)  

### Set Message Receiver / Correspondence

If a user tries to set their message receiver to a non-existent account, a pop-up window will notify user that no user is found.

![set_message_recv_fail_nouser](https://github.com/r3tr0-02/BASED/blob/main/Assets/set_message_recv_fail_nouser.png?raw=true)  

If the input is empty, a pop-up window will notify user to double-confirm their inputs.

![set_message_recv_fail_noinput](https://github.com/r3tr0-02/BASED/blob/main/Assets/set_message_recv_fail_noinput.png?raw=true)  

If a user tries to set their correspondence receiver to themselves, a pop-up window will notify user that this action is not permissible.

Theoretically, this action could break the application (Also, the server will not allow a second instance of the same account to message the same account.)

![set_message_recv_fail_selfset](https://github.com/r3tr0-02/BASED/blob/main/Assets/set_message_recv_fail_selfset.png?raw=true)

### Message

If a user tries to send an empty message, a pop-up window will notify user that message cannot be empty.

![client_message_fail_noinput](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_message_fail_noinput.png?raw=true)  

In a more unlikely scenario, if a message from correspondent user cannot be verified (due to a bad signature or attempt on message manipulation by a threat actor), message will be appended with a "- NOT OK" to denote that the message should not be trusted because it cannot be verified.

_Note that in picture below, the client on the left is "test123" and the client on the right is "asdasd"_

![client_message_fail_noverify](https://github.com/r3tr0-02/BASED/blob/main/Assets/client_message_fail_noverify.png?raw=true)  

How does the crypto thingy works here?...
=========================================

The thesis of this project can be read here :

  

References
==========

[E. Kret and R. Schmidt, “The PQXDH Key Agreement Protocol,” _Signal Protocol Documentation_](https://signal.org/docs/specifications/pqxdh/pqxdh.pdf)  

LICENSE
=======

License of this project are in LICENSE file, using GPL v2.0. `You are free to use the source code in this repository ONLY for educational purposes, only.`

Cryptography Notice
-------------------

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted. See [http://www.wassenaar.org/](http://www.wassenaar.org/) for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing cryptographic functions with asymmetric algorithms. The form and manner of this distribution makes it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export Administration Regulations, Section 740.13) for both object code and source code.

  

DISCLAIMER
==========

This project, while aiming to provide a proof-of-concept on mitigation towards threats by Quantum Computer; **must not be used in any real-world environment.** (see under this [README](https://github.com/GiacomoPope/kyber-py/blob/main/README.md))

This project, while aiming to provide data confidentiality and privacy to users; **must not be misused for any malice acts according to any countries' laws.**
