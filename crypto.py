import struct
import hashlib
from packet import EncryptionPacket

def encrypt(shared_key, timestamp, length, modbus_data):
    # magic string + packet_length + hash length
    header = EncryptionPacket.PACKET_MAGIC_CODE + struct.pack(">L", length) + struct.pack(">B", 32)

    m = hashlib.sha256()
    m.update(str(timestamp).encode('utf-8'))
    

    bytes.fromhex("0x" + "{:06x}".format(length))
    key = str(shared_key)



    for i in range(0, len(key), 2):
        part = int(key[i, i+2], base=16)


def decrypt(shared_key, data):
    pass