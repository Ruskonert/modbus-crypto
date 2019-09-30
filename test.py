import socket
import os
import struct
import packet
import time
from diffiehellman.diffiehellman import DiffieHellman

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 501))

data = 'CRYT'.encode('utf-8')

dh = DiffieHellman()
dh.generate_public_key()

# Generate user
ep = packet.EncryptionPacket(None, s)
ep._user = dh

# Handshake
s.send(data + struct.pack(">B", 0x00))

time.sleep(0.3)

# receiving initialize public key
data = s.recv(2048)
ep.recv_public_data(data[6:])
time.sleep(0.3)

# send the public key
ep.init_encryption_data(False, 1)

time.sleep(0.3)

ep.send_complete_public_data()

# receive the message (Received the public key is successful, just receive :D)
s.recv(1024)
print("Successful handshake established")
print("shared key -> {}".format(ep._user.shared_key))
