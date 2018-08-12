# open PCAP, extract data per packet, write ( append) data to new file
import binascii
from scapy.all import *
from scapy.utils import *


packets = rdpcap('/home/bob/projects/Wishkah_09_07_2016.pcapng')
Pcount = 0
port = 0
f = open('/home/bob/projects/Wishkah17','w+')
for packet in packets:
    if packet.haslayer(UDP):
        Pcount = Pcount + 1
        port = packet.sport
        if port == 10636:
            x = packet.load[9:]
            print hexdump(x)
            f.write(x)




    print (Pcount, port)

f.close()
