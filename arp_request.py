from scapy.all import *

udst=raw_input("input ip")

p=sr1(ARP(op=ARP.who_has, pdst=udst)

p.show()