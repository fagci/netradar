#!/usr/bin/env python3

from netifaces import gateways
from socket import gethostbyaddr

from scapy.layers.l2 import arping

def scan(ip):
    print(ip)
    answered, unanswered = arping(ip+'/24', verbose=False, inter=0.1)
    for i in answered:
        ip, mac = i[1].psrc, i[1].hwsrc
        try:
            host, *_ = gethostbyaddr(ip)
        except:
            host = ''
        print(ip, mac, host)

scan(gateways()[2][0][0])
