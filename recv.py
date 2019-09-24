import socket, struct, json

from ctypes import cdll, c_char

class KeyElement:
    lib = cdll.LoadLibrary("modbus-crypto.so")
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
    
    def decrypt(key, iv, data):
        self.key = None

target_addr = None
target_port = None


with open('target.json', 'r', 'utf-8') as f:
    json_data = f.read()
    data = json.loads(json_data)
    target_addr = data['addr']
    target_port = data['port']
    f.close()

target_so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
target_so.settimeout(5.0)
target_so.connect((target_addr, target_port))

print("Connected device: [{}:{}]".format(target_addr, target_port))

so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
so.bind(('0.0.0.0', 502))
so.listen(1)
print("Listening others for encrypt ...")
conn, addr = so.accept()
print("Connected other device!")

while True:
    message = conn.recv()
    if set(message[0:4]) != set(struct.pack(">BBBB", 0x63, 0x72, 0x79, 0x70)):
        print("Received message, But It's not invalid header")
    else:
        # It needs to separate the message header
        message = message[4:]
        if set(message[0:4]) == set(struct.pack(">BBBB", 0,0,0,0)):
            so.close()
            print("Received disconnection signal -> \x00\x00\x00\x00")
            break
        char_array = c_char * len(message)
        print("Received encryption data -> {}".format(message))
        dec_data = lib.decrypt(char_array.from_bytes(message), len(message))
        print("Dencrypted data -> {}".format(dec_data))
        target_so.send(dec_data)
    
target_so.close()