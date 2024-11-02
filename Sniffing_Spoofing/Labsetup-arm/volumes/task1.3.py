from scapy.all import *
import time

count = 1
while count < 100 :
    a = IP() # create an IP header
    a.dst = '10.9.0.5' # set the destination IP address
    a.ttl = count # set the TTL value
    b = ICMP() # create an ICMP header
    p = a/b # combine the IP and ICMP headers
    send(p) # send the packet

    count = count + 1
    time.sleep(1) # wait for 1 second