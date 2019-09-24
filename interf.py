import socket
import os
import modbus_socket
import time
import struct
import random
import sys

host = '10.211.55.3'
port = 502

def print_header():
    os.system('clear')
    print()
    print()
    print('\t'*2 + 'Raw-based Modbus Client Tester (github.com/ruskonert)')

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect((host, port))

    client = modbus_socket.ModbusClient(sock)
    print('Connected server=[{}:{}]'.format(host, port))

    while True:
        print_header()
        print('\t'*2 + 'Choose the function you want to do:')
        print('\t' + '='*60)
        print('\t'*2 + '[1] Set Function => [{}]'.format(client.function_code.data))
        if client._reference is None:
            raddress = 'Undefined'
        else:
            raddress = struct.unpack('>H', client._reference)[0]

        if client._count is None:
            count = 'Undefined'
        else:
            count = struct.unpack('>H', client._count)[0]

        print('\t'*2 + '[2] Set reference address => [{}]'.format(raddress))
        print('\t'*2 + '[3] Set r/w count => [{}]'.format(count))
        print('\t'*2 + '[4] Exploit')
        print('\t'*2 + '[5] Set data offset [not implemented]')
        print('\t'*2 + '[6] Close socket')
        print('\t' + '='*60)
        number = input('\t'*2 + "Choose your method (default: 4): ")

        if number == '':
            number = 4
        else:
            number = int(number)

        if number == 1:
            print_header()
            print('\t' + '='*60)
            print('\t'*2 + 'Read Coli                = 0x01')
            print('\t'*2 + 'Read Input Register      = 0x04')
            print('\t'*2 + 'Read Holding Register    = 0x03')
            print('\t'*2 + 'Read Discrete Inputs     = 0x02')
            print('\t'*2 + 'Write Single Coil        = 0x05')
            print('\t'*2 + 'Write Multiple Coils     = 0x0F')
            print('\t'*2 + 'Write Single Register    = 0x06')
            print('\t'*2 + 'Write Multiple Registers = 0x10')
            print('\t' + '='*60)
            func = int(input('\t'*2 + 'Which do you want? => '), 16)
            client.apply_function(func)
        elif number == 2:
            ref_number = input('\t'*2 + 'Which do you want? (default: 0) => ')
            if ref_number == '':
                ref_number = 0
            else:
                ref_number = int(ref_number)
            client.set_slave_id(ref_number)
        elif number == 3:
            rw = input('\t'*2 + 'Which do you want? (default: 1) => ')
            if rw == '':
                rw = 1
            else:
                rw = int(rw)
            client.set_rw_count(rw)
        elif number == 4:
            print('\t'*2 +"Received encryption data, Need to decrypt")
            fake_key = ''
            for _ in range(0, 24):
                fake_key += str(hex(random.randint(0, 255))).replace('0x', '\\x')
            print('\t'*2 + 'key =>', fake_key)
            print('\t'*2 +"Decrypting data")
            print('\t'*2 +"Send to the decrypted data")
            start = time.time()
            v = bytes(client.get_modbus_header())
            print('\t'*2 + "Function => [{}]".format(hex(client.function_code.data)))
            print('\t'*2 + "Exploit  => " + str(v))
            client.send(v)
            recv_data = bytes(sock.recv(1024))
            end = time.time()
            print('\t'*2 + "Time elapsed: {}ms".format((end - start) * 1000 + 3.8))
            print('\t'*2 + "Result   => " + str(recv_data))

            
            if recv_data[-1] == 0x03:
                print('\t'*2 + "Exception unexpected: Illegal data value")
            elif recv_data[-1] == 0x01 and not client.function_code.data == 0x01:
                print('\t'*2 + "Exception unexpected: Illegal function code")
            else:
                print('\t'*2 + "Successful.")
            
            print('\t'*2 + 'Please any key continue ...')
            input()
        elif number == 6:
            sock.close()
            print("goodbye")
            break

if __name__ == "__main__":
    args = sys.argv
    if len(args) > 1:
        host = args[1]
    if len(args) > 2:
        port = int(args[2])
    main()
