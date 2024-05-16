<h1> BASED </h1>
<p>
A Client-Server messaging application build using Python GUI and Socket Programming while implementing Hybrid Post-Quantum Encryption and KEP.</p>
<br>

<h1> What is this project? </h1>
<p>
This project was created to partially fulfill the requirements for the Bachelor of Computer Science (Cyber Security) (Hons.), College of Computing and Informatics, <code>[redacted]</code>. </p>
<p><i>
With the advancement of Quantum Computing, there has been a new theoretical threat rising sometime in the future where they could potentially break current conventional encryption scheme; both asymmetric and symmetric with Shor's and Grover's Algorithm, once Quantum Computers become more available to the public.</i></p>
<p><i>Current mitigation on this threat is to encapsulate current cryptographic scheme with a Post-Quantum or Quantum-Resistant mechanism. Any attacks on data confidentiality especially Store-Now-Decrypt-Later now must break through another layer of encryption that is theoretically resistant towards attacks from Quantum Computers.</i></p>
<p>A proof-of-concept is to build a bare instant messaging platform where two parties can communicate in one session; with the mitigation implemented. Oversimplifying, the users will perform a Key Exchange Protocol, in which in it has a layer of Key Encapsulation Mechanism. The output is a secret key that both mutually share and can be used for encrypting subsequent messages in the session. Additionally, all messages are digitally signed on send and verified on receive using a Digital Signature Algorithm.</p>
<p>For more detailed information on how this PoC works (because you are a crypto nerd or you are just bored), refer <a href="https://github.com/r3tr0-02/BASED/tree/main?tab=readme-ov-file#-how-does-the-crypto-thingy-works-here-">here</a></p>
<br>

<h1> How this project was built?</h1>
<p>This project was build using pure Python implementation, with GUI from Tkinter lib and Networking from Socket lib. </p>
<p>Cryptography modules used are listed below:</p>
<ul>
    <li><p>Symmetric Encryption (both CBC and AEAD scheme) : <code>Pycryptodome v 3.20.0</code> - AES</p></li>
    <li><p>Asymmetric PKI and KEP : <code>Pycryptodome v 3.20.0</code> - ECC, ECDH</p></li>
    <li><p>Hash funct and Key Deriv. funct : <code>Pycryptodome v 3.20.0</code> - SHA512, SHAKE128</p></li>
    <li><p>Password hashing and salting : <code>hashlib</code> and <code>secrets</code></p></li>
    <li><p>Conventional Digital Signature : <code>Pycryptodome v 3.20.0</code> - EdDSA</p></li>
    <li><p>Post-Quantum KEM : <code>kyber-py v 0.2.2</code> - Kyber1024</p></li>
    <li><p>Post-Quantum Digital Signature : <code>pypqc v 0.0.6.2</code> - dilithium5</p></li>
</ul>
<br>

<h1> What are inside this project?</h1>
<p>There are 2 parts:</p>
<ul>
    <li><p><code>server.py</code> : Server-side application, to serve clients and relay messages between clients</p></li>
    <li><p><code>testGui.py</code> : Client-side application, for users to exchange message to another user.</p></li>
</ul>
<br>
<h1> How do I run this project? </h1>
<p>First, make sure to set the <code>HOST="..."</code> on both server and client are the same. Put <code>127.0.0.1</code> host it locally or your Internal IP address (use <code>cmd -> ipconfig</code> to get the IP) to host it in your LAN.
As for now, hosting on the Internet is not possible, yet.
Then, there are two ways to run the project:</p>
<ol>
    <h2><li>Thru compiler</li></h2>
    <ul>
        <li><p>(Pre-requisite) You have to install all of the libraries above before running. <b>Make sure to add <u>--nodeps</u> option when installing py-kyber.</b> This is because it will downgrade pycryptodome version.</p></li>
        <br>
    </ul>

        pip install pycryptodome
        pip install kyber-py --no-deps
        pip install pypqc
        ...
        verify version with pip list

<ul>
        <li><p>Download both the files and open the directory of the project / Clone this repo locally.</p></li>
        <li><p>Open Windows Terminal / CMD and run <code>python ./server.py</code>. <b>Make sure to not run it in any Python .venv - like in VSC.</b> For some reason, the server cannot work properly.</p></li>
        <li><p>Open another Terminal / CMD with the same directory and run <code>python ./testGui.py</code>.</p></li>
    </ul><br>
    <h2><li>Thru compiled <code>.exe</code></li></h2>
        <ul>
            <li><p>Do the same setup as server above. (in future I will maybe package the server as exe)</p></li>
            <li><p>Click the <code>testGui.exe</code> to start a client. (Note that if the IP is changed, the client needs to be rebuild again, since it's hardcoded.)</p></li>
        </ul>
</ol>
<br>
<h1> What this app looks like? </h1>
    <h2>Normal Operations</h2>
    <p>Upon starting the server, it will display a banner message and a notification that it is ready to accept incoming client's connection.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/server_init.png" alt="server_init">
	<br>
	<p>Upon starting the client, it will display an initial page with two options, either to register an account or login.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_init.png" alt="client_init">
	<br>
	<p>New users can go on to register a new account by clicking register. A register page will appear.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_register.png" alt="client_register">
	<br>
	<p>A pop-up will notify user on successful account registration.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_register_success.png" alt="client_register_success">
	<br>
	<p>Users can login to their account by clicking the login button. A login page will appear.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_login.png" alt="client_login">
	<br>
	<p>On successful account login, user will be asked who they want to message to. This works like a private chat (user-to-user).</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/set_message_recv.png" alt="set_message_recv">
	<br>
	<p>On successful setting correspondent user, chat session is started and users can start to send and receive message.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_message.png" alt="client_message">
	<br>
	<p>Once the correspondent user logged in and set their correspondence as the first user, both users can send and receive message.</p>
	<p><i>Note that in picture below, the client on the left is "test123" and the client on the right is "asdasd"</i></p>
	<p>On successful verification of message, a string ("- OK") will be appended to the end of message.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_message_send_recvOK.png" alt="client_message_send_recvOK">
	<br>
	<p>For the server side, it will display which user successfully logged in and in session.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/server_client_login.png" alt="server_client_login">
	<br>
	<p>When clients close the message window, it will also log out the client on the server side.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/server_client_logout.png" alt="server_client_logout">
	<br>
	<h2>Abnormal operations : Input validations and Exception Handlings</h2>
	<h3>Client init.</h3>
	<p>If the client is started but failed to connect to a server (because the server is not started or is being set with wrong IP), a pop-up window will notify user that the server is unreachable, then will exit the application.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_init_fail.png" alt="client_init_fail">
	<br>
	<h3>Register</h3>
	<p>If a user tries to register an existing account on database, or the registration process failed, a pop-up window will notify user that the registration process failed.</p>
	<p>This is to prevent identity fraud on the platform - every user must have distinct username.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_register_fail.png" alt="client_register_fail">
	<br>
	<p>Similarly, if a user tries to register an account but the password is not same as confirm password field, a pop-up window will notify user to double-confirm their password.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_register_fail_notconfirmpass.png" alt="client_register_fail_notconfirmpass">
	<br>
	<p>If a user tries to register an account but one of the entries are empty, a pop-up window will notify user to double-confirm their inputs.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_register_fail_noinput.png" alt="client_register_fail_noinput">
	<br>
	<h3>Login</h3>
	<p>If a user tries to login to an account that has been in the server's session, a pop-up window will notify user that the login process failed.</p>
	<p>This is because one client is set uniquely to one credential / account on login.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_login_fail_dupe.png" alt="client_login_fail_dupe">
	<br>
	<p>Similarly, if a user tries to login to an account but one of the entries are empty, a pop-up window will notify user to double-confirm their inputs.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_login_fail_noinput.png" alt="client_login_fail_noinput">
	<br>
	<h3>Set Message Receiver / Correspondence</h3>
	<p>If a user tries to set their message receiver to a non-existent account, a pop-up window will notify user that no user is found.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/set_message_recv_fail_nouser.png" alt="set_message_recv_fail_nouser">
	<br>
	<p>If the input is empty, a pop-up window will notify user to double-confirm their inputs.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/set_message_recv_fail_noinput.png" alt="set_message_recv_fail_noinput">
	<br>
	<p>If a user tries to set their correspondence receiver to themselves, a pop-up window will notify user that this action is not permissible.</p>
	<p>Theoretically, this action could break the application (Also, the server will not allow a second instance of the same account to message the same account.)
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/set_message_recv_fail_selfset.png" alt="set_message_recv_fail_selfset">
	<h3>Message</h3>
	<p>If a user tries to send an empty message, a pop-up window will notify user that message cannot be empty.</p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_message_fail_noinput.png" alt="client_message_fail_noinput">
	<br>
	<p>In a more unlikely scenario, if a message from correspondent user cannot be verified (due to a bad signature or attempt on message manipulation by a threat actor), message will be appended with a "- NOT OK" to denote that the message should not be trusted because it cannot be verified.</p>
	<p><i>Note that in picture below, the client on the left is "test123" and the client on the right is "asdasd"</i></p>
	<img src="https://github.com/r3tr0-02/BASED/blob/main/Assets/client_message_fail_noverify.png" alt="client_message_fail_noverify">
	<br>
<h1 id="detail"> How does the crypto thingy works here?... </h1>
	
<br>
<h1>References</h1>
    <p>later here...</p>
<br>
<h1> LICENSE </h1>
    <p>License of this project are in LICENSE file, using GPL v2.0. <code>You are free to use the source code in this repository ONLY for educational purposes, only.</code></p>
    <h2>Cryptography Notice</h2>
    <p>This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted. See <a href="http://www.wassenaar.org/">http://www.wassenaar.org/</a> for more information.</p>

<p>The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing cryptographic functions with asymmetric algorithms. The form and manner of this distribution makes it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export Administration Regulations, Section 740.13) for both object code and source code.</p>
<br>

<h1> DISCLAIMER </h1>
    <p> This project, while aiming to provide a proof-of-concept on mitigation towards threats by Quantum Computer; <b>must not be used in any real-world environment. </b>(see under this <a href="https://github.com/GiacomoPope/kyber-py/blob/main/README.md">README</a>)</p>
    <p>This project, while aiming to provide data confidentiality and privacy to users; <b>must not be misused for any malice acts according to any countries' laws.</b></p>
<br>
