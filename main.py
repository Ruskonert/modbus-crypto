import packet
import os
import sys

def main():
    if os.getuid() != 0:
        print("It needs to root permission!")
    else:
        while True:
            pm = packet.PacketMiddler()
            if len(sys.argv) == 1:
                ip = '10.211.55.3'
                port = 502
            else:
                ip = sys.argv[1]
                if len(sys.argv) == 2:
                    print("Usuge: python main.py <plc_ip_address> <plc_port>")
                    break
                else:
                    port = int(sys.argv[2])
            pm.set_plc_target(ip, port)
            pm.connect(listening_addr='0.0.0.0', listening_port=501)
            pm.start_middle()
            print("The communication is broken, Restarting Task...")

if __name__ == "__main__":
    main()