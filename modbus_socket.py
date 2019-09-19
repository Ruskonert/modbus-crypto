import struct
import socket
import os
import sys
import random

class Function:
    class Read:
        Coli = 0x01
        Input_Register = 0x04
        Holding_Register = 0x03
        Discrete_Inputs= 0x02
    class Write:
        Single_Coil = 0x05
        Multiple_Coils = 0x0F
        Single_Register = 0x06
        Multiple_Registers = 0x10

class PacketElement:
    def __init__(self, data, length):
        self.data = data
        self.length = length

    @staticmethod
    def get_string_pack(data):
        if isinstance(data, int):
            if data > 0 and data <= 0xFFFF:
                return 'H'
            elif data > 0xFFFF:
                return 'I'
            else:
                return 'B'
        else:
            return 's'

    @staticmethod
    def get_length_pack(length):
        if length == 1:
            return 'B'
        if length == 2:
            return 'H'
        if length == 4:
            return 'I'
        else:
            return 'L'
    
    def create(self):
        if isinstance(self.data, int):
            return struct.pack('{}{}'.format('>', PacketElement.get_length_pack(self.length)), self.data)
        elif isinstance(self.data, str):
            return self.data.encode('utf-8')

class ModbusClient:
    def __init__(self, socket_base):
        self.transaction_id = PacketElement(0x01, 2)

        # The modbus protocol id, It always constantly 0x00 on TCP
        self.protocol_id = PacketElement(0x00, 2)

        # TCP Port always 0x01
        self.unit_id = PacketElement(0x01, 1)

        # The function code, The default is Read Coli (0x01)
        self.function_code = PacketElement(0x01, 1)
        self._socket_base = socket_base

        self._reference = None
        self._count = None

        self._data_count = 0

    def apply_function(self, fcode):
        self.function_code = PacketElement(fcode, 1)

    # reference Number (Slave id)
    def set_slave_id(self, id):
        self._reference = bytearray(struct.pack('>H', id))

    def set_rw_count(self, count):
        self._count = bytearray(struct.pack('>H', count))
        self._data_count = count

    def get_modbus_header(self):
        # Generate packet header, but others need to calcuate length.
        tdata = bytearray(self.transaction_id.create())
        tdata += bytearray(self.protocol_id.create())

        # unit id
        unit_id = bytearray(self.unit_id.create())

        # function code
        function_code = bytearray(self.function_code.create())
        
        # reference Number (Slave id)
        reference = self._reference
        
        # data (Bit count, it means how many read to bits?)
        data = self._count

        multi_write_mode = False

        if self.function_code.data == 0x0f:
            multi_write_mode = True
            byte_value_length = int(self._data_count / 5)
            if byte_value_length == 0:
                byte_value_length = 1
            byte_count = struct.pack('>B', byte_value_length)

            register_data = bytearray()
            for _ in range(0, byte_value_length):
                random_byte = bytes.fromhex(hex(random.randrange(0, 65535)).replace('0x', ''))
                register_data += bytearray(random_byte)
            print("\t"*2 + "~~~~~~~Random Value Exploit~~~~~~~")

        elif self.function_code.data == 0x10:
            multi_write_mode = True
            # it needs to write some data.
            byte_count = bytearray(struct.pack('>B', self._data_count*2))
            # randomness value, 2 bytes equal 1 register value (there is 120 register value)
            register_data = bytearray(bytes.fromhex('1234567890abcdefaabbccddeeff1a1b1c1d1e1f'*12))[0:self._data_count*4]
            print()
        
        if multi_write_mode:
            pdata = unit_id + function_code + reference + data + byte_count + register_data
        else:
            # Combines data without header.
            pdata = unit_id + function_code + reference + data

        # Calucates the length.
        length = bytearray(PacketElement(len(pdata), 2).create())

        # Append length (2 bytes)
        tdata += length

        # Append packet data
        tdata += pdata
        return tdata

    def _next_trans_id(self):
        if self.transaction_id.data > 0xFFFF:
            self.transaction_id.data = 0
        else:
            self.transaction_id.data = self.transaction_id.data + 1
          
    def send(self, packet=None):
        if packet is None:
            packet = self.get_modbus_header()
        self._socket_base.send(packet)
        self._next_trans_id()