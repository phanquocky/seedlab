from scapy.all import *

def print_pkt(pkt):
    pkt.show()

# "br-0a3772abc032" is the name of the bridge interface
# to get the name of the bridge interface, run the following command: ifconfig
# prn=print_pkt is used to print the packets
# function print_pkt is executed when a packet is captured

combined_filter = (
    "icmp or "
    "(tcp and src host 192.168.1.1 and dst port 23) or "
    "(net 128.230.0.0/16)"
)

sniff(iface="br-0a3772abc032",filter=combined_filter, prn=print_pkt)
