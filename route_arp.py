from scapy.all import *

p = sr1(IP(dst="8.8.8.8",ttl=0)/ICMP()/"wtf")

pkt=sr1(ARP(op=ARP.who_has , pdst=p.src))

pkt.show()