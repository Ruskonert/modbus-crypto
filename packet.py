import socket
import struct
import threading
import time
import os
import crypto
import hashlib

from diffiehellman.diffiehellman import DiffieHellman

class EncryptionPacket:
    PACKET_MAGIC_CODE = struct.pack('>BBBB', 0x43, 0x52, 0x59, 0x54)
    FUNCTION_INITIALIZE_HANDSHAKE = 0x00
    FUNCTION_SECURE_COMMUNICATION = 0x02

    def __init__(self, device, other):
        self.device = device
        self.other = other
        self._user = None

    def generate_key(self):
        self._user = DiffieHellman()
        self._user.generate_public_key()

    def send_complete_public_data(self):
        data = bytearray(EncryptionPacket.PACKET_MAGIC_CODE) + struct.pack(">BB", EncryptionPacket.FUNCTION_INITIALIZE_HANDSHAKE, 0x55)
        self.other.send(data)

    def recv_public_data(self, data):
        hash_length = data[0]
        hash_value = data[1:hash_length+1]
        hash_str = str()
        for i in range(0, len(hash_value)):
            hash_str += '{:02x}'.format(int(hex(hash_value[i]), 16))
        print("Digest: {}".format(hash_str))
        public_key_data = data[hash_length+1:]
        public_key = str()
        for i in range(0, len(public_key_data)):
            public_key += '{:02X}'.format(int(hex(public_key_data[i]), 16))

        m = hashlib.sha256()
        m.update(public_key.encode('utf-8'))
        other_hash_value = m.hexdigest()

        print("Calculated digest: {}".format(other_hash_value))

        # the public key is not matched
        if hash_str != other_hash_value:
            return -1

        # Convert str to big-integer
        received_public_key = int(public_key)
        self._user.generate_shared_secret(received_public_key)
        print("Shared key: {}".format(self._user.shared_key))
        return 0



    def init_encryption_data(self, generated=True, mode=0):
        if generated:
            self.generate_key()
        if self.other is None:
            raise ConnectionError("You need to connect the other deivce!")
        else:
            print("Initializing encryption handshake ...", end='')
            key = str(self._user.public_key)
            key_array = bytearray()
            for i in range(0, len(key), 2):
                hex_number = key[i:i+2]
                hex_number = '0x' + str(hex_number)
                key_array += struct.pack(">B", int(hex_number, base=16))
    
            print("Generated public key -> len=[{}]".format(len(key_array)))
            print("Sending the public key ...")

            m = hashlib.sha256()
            m.update(key.encode('utf-8'))
            result_hash = m.hexdigest()
            result_hash_array = bytearray()
            for i in range(0, len(result_hash), 2):
                hex_number = result_hash[i:i+2]
                hex_number = '0x' + str(hex_number)
                result_hash_array += struct.pack(">B", int(hex_number, base=16))
            fih = struct.pack(">B", EncryptionPacket.FUNCTION_INITIALIZE_HANDSHAKE)
            hash_str_length = struct.pack(">B", len(result_hash_array))
            self.other.send(EncryptionPacket.PACKET_MAGIC_CODE + fih + struct.pack(">B", mode) + hash_str_length + result_hash_array + key_array)
            if mode == 0:
                print("Awaiting the received public key ...")

class PacketMiddler:
    def __init__(self):
        self._recv = None
        self._target = None
        self._ref = None
        self._other = None
        self._enc = None
        self._recv_thread = None
        self._communi = 0

    def connect(self, listening_addr = None, listening_port=502):
        print("Conneting the PLC device[{}:{}] that will be send the encryption data ...".format(self._ref[0], self._ref[1]))
        self._target.settimeout(5.0)
        self._target.connect(self._ref)
        print("Connected the PLC deivce [{}:{}]".format(self._ref[0], self._ref[1]))

        self._recv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if listening_addr is None:
            listening_addr = socket.gethostbyname(socket.gethostname())

        self._recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._recv.bind((listening_addr, listening_port))

        self._recv.listen(1)
        
        print("Listening this device[{}:{}] that will be received plain data ...".format(listening_addr, listening_port))
        self._other = self._recv.accept()
        print("Connected other to this device [{}:{}]".format(self._other[1][0],self._other[1][1]))
        self._other = self._other[0]


    def set_plc_target(self, target_addr, port = 502):
        self._target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._ref = (target_addr, port)

    @staticmethod
    def print_packet_data(packet_data, separate=16):
        for i in range(0, len(packet_data)):
            if i % separate == 0:
                print()
                print('{:08X}: '.format(i), end='')
            print('{:02X} '.format(packet_data[i]), end='')

    @staticmethod
    def _recv_packet_data(pm, plc_device, other_device):
        if plc_device is None:
            raise ConnectionError("Not connected the sending device!")

        if other_device is None:
            raise ConnectionError("Not connected the PLC device!")

        while True:
            start = time.time()
            packet_data = other_device.recv(2048)
            print("\nOther device send the plain data: {} byte(s) ".format(len(packet_data)), end='')
            PacketMiddler.print_packet_data(packet_data)
            print()

            if set(packet_data[0:4]) != set(EncryptionPacket.PACKET_MAGIC_CODE):
                print("INVALID PACKET DATA! Maybe the other device was not following packet format.")
                send_packet_data = bytearray(EncryptionPacket.PACKET_MAGIC_CODE) + struct.pack('>BB',0xff, 0xff)
                print("Retriving the respond data: {} byte(s)".format(len(send_packet_data)))
                print()
                other_device.send(send_packet_data)
            else:
                # if the function code is null
                if len(packet_data) == 4:
                    print("Function code is null, Connection Reset")
                    send_packet_data = bytearray(EncryptionPacket.PACKET_MAGIC_CODE) + struct.pack('>BB',0x00, 0x03)
                    print("Retriving the respond data: {} byte(s)".format(len(send_packet_data)))
                    print()
                    other_device.send(send_packet_data)
                    end = time.time()
                    print("Time elapsed:", end - start)
                    other_device.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                    other_device.close()
                    plc_device.close()
                    break

                else:
                    # function name print
                    function_name = 'Unknown'
                    if packet_data[4] == EncryptionPacket.FUNCTION_INITIALIZE_HANDSHAKE:
                        function_name = "Initialize handshake"
                    elif packet_data[4]== EncryptionPacket.FUNCTION_SECURE_COMMUNICATION:
                        function_name = "Secure communiation"
                    print("Function: {} [0x{:02X}]".format(function_name, packet_data[4]))

                    if packet_data[4] == EncryptionPacket.FUNCTION_SECURE_COMMUNICATION:
                        if pm._communi < 2:
                            print("~~~Error~~~ Handshake is not established, You need to connect first!")
                            PacketMiddler.force_disconnect(plc_device, other_device)
                            break
                        else:
                            data = packet_data[5:]
                            print("Received encrypted data: ")
                            PacketMiddler.print_packet_data(data)
                            print()
                            dec_data = crypto.decrypt(pm._enc._user.shared_key, data)
                            #if timestamp != pm._communi:
                            #    print("~~~Error~~~ Checksum verification failed. It looks like a replay attack was attempted.")
                            if dec_data:
                                if dec_data is None:
                                    print("~~~Error~~~ Failed to decrypt encrypted data. Is it correct encryption? ")
                                else:
                                    print("Retriving decrypted data: ")
                                    PacketMiddler.print_packet_data(dec_data)
                                    print()
                                    plc_device.send(dec_data)
                                    pm._communi = pm._communi + 1
                                    recv_data = plc_device.recv(1024)
                                    other_device.send(recv_data)
                                    



                    elif packet_data[4] == EncryptionPacket.FUNCTION_INITIALIZE_HANDSHAKE:
                        # Handshake established, But not yet sending the public key
                        if pm._communi == 0:
                            enc = EncryptionPacket(plc_device, other_device)
                            pm._enc = enc
                            # Send the initialize public key
                            enc.init_encryption_data()
                            pm._communi = pm._communi + 1
                        elif pm._communi == 1:
                            # Receive the public key
                            data = packet_data[5:]
                            # Invalid mode!
                            if data[0] == 0:
                                PacketMiddler.force_disconnect(plc_device, other_device)
                                break
                            else:
                                result = enc.recv_public_data(data[1:])
                                print("Received public key!")
                            if result == -1:
                                print("~~~Error~~~ INVALID KEY! The hexdigest is not matched")
                                PacketMiddler.force_disconnect(plc_device, other_device)
                                break
                            pm._communi = pm._communi + 1
                        else:
                            data = packet_data[5:]
                            if data[0] == 0x55:
                                print("Successful handshake established")
                                pm._enc.send_complete_public_data()

    @staticmethod
    def force_disconnect(plc_device, other_device):
        print("Handshake failed! Not match the function code or data invalid, Connection Reset")
        send_packet_data = bytearray(EncryptionPacket.PACKET_MAGIC_CODE) + struct.pack('>BB',0xee, 0xee)
        print("Retriving the respond data: {} byte(s)".format(len(send_packet_data)))
        print()
        other_device.send(send_packet_data)
        other_device.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        other_device.close()
        if plc_device is not None:
            plc_device.close() 


    def start_middle(self):
        if self._other is None:
            raise ConnectionError("Not connected the sending device!")
        if self._recv is None:
            raise ConnectionError("Not connected the PLC device!")
        self._recv_thread = threading.Thread(target=PacketMiddler._recv_packet_data, args=(self, self._recv, self._other))
        self._recv_thread.start()
        print("Started the packet data worker")
        while True:
            if not self._recv_thread.isAlive():
                break