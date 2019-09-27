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
dh.generate_private_key()
dh.generate_public_key()

# Generate user
ep = packet.EncryptionPacket(None, s)
ep._user = dh

# Handshake
s.send(data + struct.pack(">B", 0x00))

time.sleep(0.5)

# receiving initialize public key
data = s.recv(2048)
ep.recv_public_data(data[2:])
time.sleep(0.5)

# send the public key
ep.init_encryption_data(False, 1)
ep.recv_public_data(data[2:])

# receive the message
s.recv(1024)

