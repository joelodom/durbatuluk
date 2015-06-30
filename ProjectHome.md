# Overview #

Durbatulûk is a command and control system for controlling a number of distributed clients.  The clients, which may be behind firewalls, check with a command server for new commands from their commander.  The commander need not be the command server, but the commander must be capable of posting commands to the command server.  All commands are encrypted and digitally signed so that only the commander may issue commands and so that the commands are kept secret from nosy bystanders who may have access to the command server.

'<img width='100%' src='http://durbatuluk.googlecode.com/svn/images/diagram.png'>'<br>
<br>
In the diagram above, which represents a sample scenario, the commander is controlling a number of clients on different networks.  The commander posts a command to the command server, and the clients check the command server for a new command at some interval.  The clients may be personal computers that the commander is administering, the clients may be embedded systems or hardware controllers, or the clients may be any other kind of system capable of running Durbatulûk.<br>
<br>
The current implementation of Durbatulûk is written in C++ using the same code base for commanders and clients.  Our implementation is currently only tested on Linux, but we have coded the implementation in standard C++11 so that future implementations may be ported to different platforms.  We employ Google Protocol Buffers for efficient message packing and for saving state to files between runs of our binary.  OpenSSL library functions are used for cryptography.  cURL library functions are used for communication with the command server.<br>
<br>
We currently have a <a href='http://durbatuluk-server.appspot.com/'>demonstration command server</a> running on Google App Engine.  Users of Durbatulûk are free to use our server for testing purposes, though we encourage production users to establish a server of their own so that they are not dependent on our server.  Our test server allows Durbatulûk commanders to post commands that remain available for clients to download for a five-minute period, after which they roll off the server.  Because of the efficiency of Google App Engine, many commands may be posted on our server simultaneously by different commanders and for different clients.<br>
<br>
To get started, see GettingStarted.