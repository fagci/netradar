#!/usr/bin/env python3

from ipaddress import IPv4Network
from socket import (
    AF_PACKET,
    SOCK_RAW,
    gethostbyaddr,
    htons,
    inet_aton,
    inet_ntoa,
    socket,
)
from struct import unpack
from sys import argv
from threading import Thread
from time import sleep, time

from utils import ETH_P_ARP, arp, iface_ip, iface_netmask

TIMEOUT = 2

class ARPScan(socket):
    def __init__(self, iface):
        super().__init__(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))
        self.iface = iface
        self.settimeout(0.5)
        self.bind((iface, 0))
        self.targets = {}
        self.iface_ip = iface_ip(iface)
        self.iface_netmask = iface_netmask(iface)

        self.ipsi = inet_aton(self.iface_ip)
        self.ipsmask = inet_aton(self.iface_netmask)

        self.macs = self.getsockname()[4]
        self.macd = b'\xff\xff\xff\xff\xff\xff'


    def scan(self):
        rt = Thread(target=self.recv)
        st = Thread(target=self.scan_range)

        rt.start()
        st.start()

        rt.join()


    def scan_range(self):
        ips = inet_ntoa(self.ipsi)
        ipsp = ips.split('.')
        ipsp[3] = '0'
        net = '.'.join(ipsp)
        mask = inet_ntoa(self.ipsmask)
        for ip in IPv4Network(f'{net}/{mask}', False):
            self.ping(str(ip))
            sleep(0.01)


    def ping(self, ip):
        ipdi = inet_aton(ip)

        packet = arp(self.macs, self.ipsi, self.macd, ipdi)
        self.send(packet)

        self.time_end = self.targets[ipdi] = time() + TIMEOUT


    def recv(self):
        self.time_end = time() + TIMEOUT
        while time() < self.time_end:
            try:
                packet, _ = self.recvfrom(2048)
            except:
                continue
            # eth = unpack('!6s6s2s', packet[0:14])
            arp = unpack('2s2s1s1s2s6s4s6s4s', packet[14:42])
            mac_src, ip_src = arp[5:7]
            mac = '%x:%x:%x:%x:%x:%x' % unpack('BBBBBB', mac_src)
            timeout = self.targets.get(ip_src)
            if timeout and time() <= timeout:
                self.targets[ip_src] = 0
                ip = inet_ntoa(ip_src)
                try:
                    host, *_ = gethostbyaddr(ip)
                except:
                    host = ''
                print(ip, mac, host)

if __name__ == '__main__':
    if len(argv) < 2:
        print(f'Usage: {argv[0]} <interface>')
        exit(255)

    scanner = ARPScan(argv[1])
    scanner.scan()
