import socket
import struct
import threading

class EncryptionPacket:
    PACKET_MAGIC_CODE = struct.pack('>BBBB', 0x43, 0x52, 0x59, 0x54)
    FUNCTION_INITIALIZE_HANDSHAKE = 0x00
    FUNCTION_INITIALIZE_VECTOR = 0x01
    FUNCTION_SECURE_COMMUNICATION = 0x02

    def __init__(self, device, other):
        self.device = device
        self.other = other

class PacketMiddler:
    def __init__(self):
        self._recv = None
        self._target = None
        self._ref = None
        self._other = None
        self._recv_thread = None
        self._communi = 0

    def connect(self, listening_addr = None, listening_port=502):
        print("Connecting the PLC device that will be send the encryption data ...")
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
    def _recv_packet_data(plc_device, other_device):
        if plc_device is None:
            raise ConnectionError("Not connected the sending device!")
        if other_device is None:
            raise ConnectionError("Not connected the PLC device!")
        while True:
            packet_data = other_device.recv(2048)
            print("\nOther device send the plain data: {} byte(s) ".format(len(packet_data)), end='')
            PacketMiddler.print_packet_data(packet_data)
            print()

            if set(packet_data[0:4]) != set(EncryptionPacket.PACKET_MAGIC_CODE):
                print("INVALID PACKET DATA! Maybe the other device was not following packet format.")
                send_packet_data = struct.pack('>BBBBBB', 0x43, 0x52, 0x59, 0x54, 0xff, 0xff)
                print("Retriving the respond data: {} byte(s)".format(len(send_packet_data)))
                print()
                other_device.send(send_packet_data)
                # If you need to disconnect when received wrong data
                # other_device.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            else:
                if packet_data[5] == EncryptionPacket.FUNCTION_INITIALIZE_HANDSHAKE:
                    

    def start_middle(self):
        if self._other is None:
            raise ConnectionError("Not connected the sending device!")
        if self._recv is None:
            raise ConnectionError("Not connected the PLC device!")
        self._recv_thread = threading.Thread(target=PacketMiddler._recv_packet_data, args=(self._recv, self._other))
        self._recv_thread.start()
        print("Started constantly the packet data received worker.")
    
pm = PacketMiddler()
pm.set_plc_target('10.211.55.3', 502)
pm.connect(listening_addr='0.0.0.0', listening_port=4444)
pm.start_middle()