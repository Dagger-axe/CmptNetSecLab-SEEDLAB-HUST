#!/usr/bin/python3
from scapy.all import *

SRC  = "10.0.2.6"
DST  = "10.0.2.7"
PORT = 23

def spoof(pkt):
    old_tcp = pkt[TCP]
    old_ip  = pkt[IP]

    #############################################
    ip  =  IP( src   = ?? , 
               dst   = ??
             )
    tcp = TCP( sport = ?? , 
               dport = ?? , 
               seq   = ?? ,
               flags = "R"
             ) 
    #############################################

    pkt = ip/tcp
    send(pkt,verbose=0)
    print("Spoofed Packet: {} --> {}".format(ip.src, ip.dst))

f = 'tcp and src host {} and dst host {} and dst port {}'.format(SRC, DST, PORT)
sniff(filter=f, prn=spoof)

