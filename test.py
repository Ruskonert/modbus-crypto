import socket
import os
import struct
import packet
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

# receiving initialize public key
data = s.recv(2048)
ep.recv_public_data(data[2:])
