from scapy.all import *

def print_pkt(pkt):
    pkt.show()

# "br-0a3772abc032" is the name of the bridge interface
# to get the name of the bridge interface, run the following command: ifconfig
# prn=print_pkt is used to print the packets
# function print_pkt is executed when a packet is captured

combined_filter = (
    "tcp"
)

sniff(iface="br-b4db7f32bb2e",filter=combined_filter, prn=print_pkt)
