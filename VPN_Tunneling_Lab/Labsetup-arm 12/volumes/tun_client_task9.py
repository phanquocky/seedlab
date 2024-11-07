#!/usr/bin/env python3

import fcntl
import struct
import os
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

SERVER_IP = "10.9.0.11"
SERVER_PORT = 9090

# Create the tun interface
tap = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'ky%d', IFF_TAP | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tap, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))


os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while True:
    # Get a packet from the tun interface
    packet = os.read(tap, 2048)
    if packet:
        pkt = Ether(packet)
        FAKE_MAC = "00:00:00:00:00:01"

        if ARP in pkt and pkt[ARP].op == 1:
            arp = pkt[ARP]
            newEther = Ether(src=FAKE_MAC, dst=pkt.src)
            newArp = ARP(op=2, hwsrc=FAKE_MAC, psrc=arp.pdst, hwdst=pkt.src, pdst=arp.psrc)
            newPkt = newEther/newArp
            os.write(tap, bytes(newPkt))