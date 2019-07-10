# Scapy-socket
this module is written in python and it allows you to make a socket with given source and destination addresses and ports and spoof the source IP while using a socket API.

Usage:

Suppose a server is running on IP 192.168.1.100 and is listening for TCP connection on port 5555.
Assuming this server is an echo server and you want to spoof your IP address to 192.168.1.200 this will be the usage of this module to send and recive "Hello World!":

import scapy_socket as ss

s = ss.socket('192.168.1.100', '192.168.1.137', 8070)
s.handshake()
s.send('Hello World!')
print s.recv()
s.fin()

Output:

Hello World!
