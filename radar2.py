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



class ARPScan(socket):
    def __init__(self, iface):
        super().__init__(AF_PACKET, SOCK_RAW, htons(0x0806))
        self.iface = iface
        self.settimeout(0.25)
        self.bind((iface, 0))
        self.targets = {}
        self.ipsi, self.ipsmask = self.ifipmaski()
        self.macs = self.getsockname()[4]
        self.macd = b'\xff\xff\xff\xff\xff\xff'

    def ifipmaski(self):
        with socket(AF_INET, SOCK_DGRAM) as so:
            ifacep = pack('256s', self.iface.encode('utf_8'))
            return (
                ioctl(so.fileno(), 0x8915, ifacep)[20:24],
                ioctl(so.fileno(), 0x891b, ifacep)[20:24]
            )


    def ping(self, ip):
        ipdi = inet_aton(ip)

        eth = pack('!6s6sH', self.macd, self.macs, 0x0806)
        arp = pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, self.macs, self.ipsi, self.macd, ipdi)
        packet = eth + arp
        self.send(packet)
        self.targets[ipdi] = time() + TIMEOUT

    def recv(self):
        te = time() + TIMEOUT
        while time() < te:
            try:
                packet, _ = self.recvfrom(2048)
            except:
                continue
            # eth = unpack('!6s6s2s', packet[0:14])
            arp = unpack('2s2s1s1s2s6s4s6s4s', packet[14:42])
            macd = '%x:%x:%x:%x:%x:%x' % unpack('BBBBBB', arp[5])
            ipdi = arp[6]
            timeout = self.targets.get(ipdi)
            if timeout and time() <= timeout:
                ipd = inet_ntoa(ipdi)
                try:
                    host, *_ = gethostbyaddr(ipd)
                except:
                    host = ''
                print(ipd, macd, host)

    def scan_range(self):
        ips = inet_ntoa(self.ipsi)
        ipsp = ips.split('.')
        ipsp[3] = '0'
        net = '.'.join(ipsp)
        mask = inet_ntoa(self.ipsmask)
        for ip in IPv4Network(f'{net}/{mask}', False):
            self.ping(str(ip))
            sleep(0.01)

    def scan(self):
        rt = Thread(target=self.recv)
        st = Thread(target=self.scan_range)

        rt.start()
        st.start()

        rt.join()

if __name__ == '__main__':
    if len(argv) < 2:
        print(f'Usage: {argv[0]} <interface>')
        exit(255)

    scanner = ARPScan(argv[1])
    scanner.scan()
