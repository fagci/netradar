#!/usr/bin/env python3

from fcntl import ioctl
from socket import (
    AF_INET,
    AF_PACKET,
    SOCK_DGRAM,
    SOCK_RAW,
    gethostbyaddr,
    htons,
    inet_aton,
    inet_ntoa,
    socket,
)
from struct import pack, unpack
from sys import argv
from threading import Thread
from time import sleep, time
from ipaddress import IPv4Network

TIMEOUT = 2

if len(argv) < 2:
    print(f'Usage: {argv[0]} <interface>')
    exit(255)

iface = argv[1]

s = socket(AF_PACKET, SOCK_RAW, htons(0x0806))
s.settimeout(0.25)
s.bind((iface, 0))


targets = {}

def ifipmaski(iface):
    with socket(AF_INET, SOCK_DGRAM) as so:
        ifacep = pack('256s', iface.encode('utf_8'))
        return (
            ioctl(so.fileno(), 0x8915, ifacep)[20:24],
            ioctl(so.fileno(), 0x891b, ifacep)[20:24]
        )

ipsi, ipsmask = ifipmaski(iface)
macs = s.getsockname()[4]
macd = b'\xff\xff\xff\xff\xff\xff'

def scan(ipd):
    ipdi = inet_aton(ipd)

    eth = pack('!6s6sH', macd, macs, 0x0806)
    arp = pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, macs, ipsi, macd, ipdi)
    packet = eth + arp
    s.send(packet)
    targets[ipdi] = time() + TIMEOUT

def recv():
    te = time() + TIMEOUT * 2
    while time() < te:
        try:
            packet, _ = s.recvfrom(2048)
        except:
            continue
        # eth = unpack('!6s6s2s', packet[0:14])
        arp = unpack('2s2s1s1s2s6s4s6s4s', packet[14:42])
        macd = '%x:%x:%x:%x:%x:%x' % unpack('BBBBBB', arp[5])
        ipdi = arp[6]
        timeout = targets.get(ipdi)
        if timeout and time() <= timeout:
            ipd = inet_ntoa(ipdi)
            try:
                host, *_ = gethostbyaddr(ipd)
            except:
                host = ''
            print(ipd, macd, host)

def scan_range():
    ips = inet_ntoa(ipsi)
    ipsp = ips.split('.')
    ipsp[3] = '0'
    n = '.'.join(ipsp)
    net = IPv4Network(f'{n}/{inet_ntoa(ipsmask)}', False)
    for ip in net:
        scan(str(ip))
        sleep(0.01)

rt = Thread(target=recv)
st = Thread(target=scan_range)

rt.start()
st.start()

rt.join()
