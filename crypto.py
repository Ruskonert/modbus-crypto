import struct
import hashlib

def encrypt(shared_key, timestamp, length, modbus_data):
    # magic string + packet_length + hash length
    header = bytearray(struct.pack('>BBBB', 0x43, 0x52, 0x59, 0x54)) + struct.pack(">B", 2) + struct.pack(">L", length) + struct.pack(">B", timestamp)
    #m = hashlib.sha256()
    #m.update(str(timestamp).encode('utf-8'))

    key = str(shared_key)

    result = bytearray()
    for i in range(0, len(modbus_data)):
        select = i % len(key)
        part_key = int(key[select:select+2], base=16)
        result += bytes(modbus_data[i] ^ part_key)
    return header + result

def decrypt(shared_key, data):
    key = str(shared_key)
    result = bytearray()
    data = data[10:]
    for i in range(0, len(data)):
        select = i % len(key)
        part_key = int(key[select:select+2], base=16)
        result += bytes(data[i] ^ part_key)
    return result