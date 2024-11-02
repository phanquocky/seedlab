from scapy.all import *

a = IP() # create an IP header
a.dst = '10.9.0.5' # set the destination IP address
b = ICMP() # create an ICMP header
p = a/b # combine the IP and ICMP headers
send(p) # send the packet