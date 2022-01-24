#!/usr/bin/env python3


import socket
from colorama import init, Fore
from threading import Thread, Lock
from queue import Queue
import argparse

# Initializing Colors:
############################
init()
GREEN = Fore.GREEN
RED =  Fore.RED
YELLOW =  Fore.YELLOW
RESET = Fore.RESET
BLUE = Fore.BLUE
GRAY = Fore.LIGHTBLACK_EX
CYAN = Fore.CYAN
############################

# A dictionary that will contain all the common ports and their
protocols = {1 : "tcpmux", 5 : "rje", 7 : "echo", 9 : "discard", 11 : "systat", 13 : "daytime", 17 : "qotd", 18 : "msp", 19 : "chargen", 20 : "ftp-data", 21 : "ftp", 22 : "ssh", 23 : "telnet", 25 : "smtp", 37 : "time", 39 : "rlp", 42 : "nameserver", 43 : "nicname", 49 : "tacacs", 50 : "re-mail-ck", 53 : "domain", 63 : "whois++", 67 : "bootps", 68 : "bootpc", 69 : "tftp", 70 : "gopher", 71 : "netrjs-1", 72 : "netrjs-2", 73 : "netrjs-3", 73 : "netrjs-4", 79 : "finger", 80 : "http", 88 : "kerberos", 95 : "supdup", 101 : "hostname", 102 : "iso-tsap", 105 : "csnet-ns", 107 : "rtelnet", 109 : "pop2", 110 : "pop3", 111 : "sunrpc", 113 : "auth", 115 : "sftp", 117 : "uucp-path", 119 : "nntp", 123 : "ntp", 137 : "netbios-ns", 138 : "netbios-dgm", 139 : "netbios-ssn", 143 : "imap", 161 : "snmp", 162 : "snmptrap", 163 : "cmip-man", 164 : "cmip-agent", 174 : "mailq", 177 : "xdmcp", 178 : "nextstep", 179 : "bgp", 191 : "prospero", 194 : "irc", 199 : "smux", 201 : "at-rtmp", 202 : "at-nbp", 204 : "at-echo", 206 : "at-zis", 209 : "qmtp", 210 : "z39.50", 213 : "ipx", 220 : "imap3", 245 : "link", 347 : "fatserv", 363 : "rsvp_tunnel", 369 : "rpc2portmap", 370 : "codaauth2", 372 : "ulistproc", 389 : "ldap", 427 : "svrloc", 434 : "mobileip-agent", 435 : "mobilip-mn", 443 : "https", 444 : "snpp", 445 : "microsoft-ds", 464 : "kpasswd", 468 : "photuris", 487 : "saft", 488 : "gss-http", 496 : "pim-rp-disc", 500 : "isakmp", 535 : "iiop", 538 : "gdomap", 546 : "dhcpv6-client", 547 : "dhcpv6-server", 554 : "rtsp", 563 : "nntps", 565 : "whoami", 587 : "submission", 610 : "npmp-local", 611 : "npmp-gui", 612 : "hmmp-ind", 631 : "ipp", 636 : "ldaps", 674 : "acap", 694 : "ha-cluster", 749 : "kerberos-adm", 750 : "kerberos-iv", 765 : "webster", 767 : "phonebook", 873 : "rsync", 992 : "telnets", 993 : "imaps", 994 : "ircs", 995 : "pop3s" }
## Ports that  do not respond to banner grabbing.
no_enum_ports = [389, 445,  139]
explicit_ports = list()

class PortScanner():
	def __init__(self, ip, ports, threads=200, verbose=False):
		self.ip = ip
		self.threads = threads
		self.verbose = verbose
		self.ports = ports
		## Creating variables
		self.q = Queue() # This will hold the ports
		self.qPorts = Queue()
		self.print_lock = Lock()
		self.Banners = dict()
		self.open_ports = list()
		self.closed = True

	def extractBanner(self, port):
		s = socket.socket()
		if port in no_enum_ports:
			print(f"[{RED}-{RESET}] Port {RED}{port}{RESET} : {CYAN}{protocols[port]}{RESET} : Unable to grab banner. :(")
			return
		try:
			s.connect((self.ip, port))
			if port == 80 or port == 443 or port == 8080:
				req = "GET / HTTP/1.1 \r\n"
				s.send(req.encode())
				banner = s.recv(1024).decode()
				banner = banner[banner.find("Server"):]
				banner =  banner[:banner.find("\n")].split(': ')[1]
				banner = f"[{GREEN}+{RESET}] Port {GREEN}{port}{RESET} : {CYAN}{protocols[port]}{RESET} : " + banner
			else:
				banner = s.recv(1024).decode()
				if banner == "":
					banner = f"[{RED}-{RESET}] Port {port} : No Banner Found! :("
				else:
					banner = f"[{GREEN}+{RESET}] Port {GREEN}{port}{RESET} : {CYAN}{protocols[port]}{RESET} : " + banner.strip()
			with self.print_lock:
				print(banner)
		except  KeyboardInterrupt:
			pass
		except:
			print(f"[{RED}-{RESET}] Port {port} : Unable to grab banner. :(")

		s.close()
	def getBanners(self):
		while True:
			port = self.qPorts.get()
			self.extractBanner(port)
			self.qPorts.task_done()

	def threadBanners(self):
		for th in range(self.threads):
			th = Thread(target=self.getBanners)
			th.daemon = True
			th.start()
		
		for port in self.open_ports:
			self.qPorts.put(port)
		
		self.qPorts.join()

	def isOpen(self, port):
		addr = (self.ip, port)
		s = socket.socket()
		ret = False
		with self.print_lock:
			print(f"[{YELLOW}*{RESET}] Current Port : {BLUE}{port}{RESET}", end='\r')
		try:
			s.connect(addr)
		except:
			
			with self.print_lock:
				if self.verbose or port in explicit_ports:
					print(f"[{RED}-{RESET}] PORT {port} is {RED}closed{RESET}!" + " " * 10)
				pass
		else:
			with self.print_lock:
				service = ""
				try:
					service = protocols[port]
				except:
					service = "- UNIDENTIFIED -"
				print(f"[{GREEN}+{RESET}] PORT {port} is {GREEN}open{RESET}! Service running :  {CYAN}{service}{RESET}")
				self.open_ports.append(port)
				scanner.closed = False
				ret = True
		finally:
			s.close()
		return ret
	def scanWorker(self):
		while True:
			try:
				worker =  self.q.get()
				self.isOpen(worker)
				self.q.task_done()
			except KeyboardInterrupt:
				exit(1)
			except:
				pass
	def init(self):
		for thread in range(self.threads):
			thread = Thread(target=self.scanWorker)
			thread.daemon = True
			thread.start()
		
		for worker in self.ports:
			self.q.put(worker)

		self.q.join()
class Args():
	def __init__(self):
		self.parser = argparse.ArgumentParser(description="FLASHSCAN - A Multithreaded Port Scanner")
		self.parser.add_argument("host", help="Host to scan.")
		self.parser.add_argument("--ports", "-p", dest="ports", default="1-65535", help="Port range to scan, default is 1-65535 (all ports)")
		self.parser.add_argument("--threads", "-t", default=200,  type=int, help="Number of threads that will be used.")
		self.parser.add_argument("--no-ping", "-n",  dest="checkping", help="Scan for ports without actually testing if the host is up or not.")
		self.parser.add_argument("--verbose", "-v", help="Verbose output.", action="store_true")
		self.parser.add_argument("--detailed", "-d", help="Detailed output. Displaying more information about each service", action="store_true")
	def get_args(self):
		return self.parser.parse_args()

def getBanner():
	return f"""
{YELLOW}           ,/{RESET}  
{YELLOW}         ,'/{RESET}     {RED}_____ _           _     {YELLOW}____{RESET}
{YELLOW}       ,' /{RESET}     {RED}|  ___| | __ _ ___| |__ {YELLOW}/ ___|  ___ __ _ _ __{RESET}
{YELLOW}     ,'  /_____,{RESET}{RED}| |_  | |/ _` / __| '_ \\{YELLOW} ___ \\ / __/ _` | '_ \\{RESET}
{YELLOW}   .'____    ,' {RESET}{RED}|  _| | | (_| \\__ \\ | |{YELLOW} |___) | (_| (_| | | | |{RESET}
{YELLOW}        /  ,'{RESET}   {RED}|_|   |_|\\__,_|___/_| |_|{YELLOW}____/ \\___\\__,_|_| |_|{RESET}
{YELLOW}       / ,'{RESET}                           A Python3 based Multithreaded Port Scanner
{YELLOW}      /,'{RESET}                             by @{YELLOW}The{RED}Flash{GRAY}2K.{RESET}
{YELLOW}     /'{RESET}
=================================================="""


def checkHostStatus(ip):
	## Limiting these import to this function
	import platform
	import  subprocess
	import os

	os_ver = platform.system().lower()

	param = '-n' if os_ver == "windows" else 'c'
	cmd = 'ping' if  os_ver == "windows" else '/bin/ping'
	command = [cmd, param, '1', ip]

	import tempfile
	dir = tempfile.gettempdir()
	delim = '\\' if  os_ver == "windows" else '/'
	fileName  = dir + delim + "ping.out"

	file = open(fileName, 'w')
	x = subprocess.call(command, stdout=file, 
    stderr=subprocess.STDOUT)

	file.close()

	if x != 0:
		return False
	## Checking if file contains data:
	err = "Destination host unreachable"
	reader = open(fileName, 'r')
	data = reader.read()
	reader.close()
	## Deleting file;
	os.remove(fileName)
	if err in data:
		return False
	return  True
def setPorts(ports):
	tLen = 1
	if "-" in ports:
		start_port, end_port = port_range.split("-")
		start_port, end_port = int(start_port), int(end_port)

		ports = [ p for p in range(start_port, end_port  + 1)]
		tLen = end_port - start_port

	elif "," in ports:
		ports = ports.split(",")
		# Converting  the list to intt:
		for i in range(len(ports)):
			ports[i] = int(ports[i])
			explicit_ports.append(ports[i])
		tLen = len(ports)
	else:
		ports = [int(ports)]

	return ports, tLen

if __name__ == "__main__":
	
	print(getBanner())

	ArgHandler = Args()
	args = ArgHandler.get_args()

	host = args.host
	port_range = args.ports
	threads = args.threads
	verbose = args.verbose
	detailed = args.detailed
	checkPing = args.checkping

	ports, 	tPorts = setPorts(port_range)

	## Checking if host is up:
	if not checkHostStatus(host):
		print(f"[{RED}-{RESET}] {host} seems to be down. Maybe the ICMP Packet sending failed. Try again using this script or just simply add -n/--no-ping flag")
		exit()


	scanner = PortScanner(host, threads=threads, ports=ports)
	scanner.init()

	if scanner.closed:
		for port in scanner.ports:
			print(f"[{RED}-{RESET}] PORT {port} is {RED}closed{RESET}!" + " " * 10)

	print("=" * 50)
	if detailed and  not scanner.closed:
		print(f"[{BLUE}*{RESET}] Port Scan Finished successfully")
		print(f"[{YELLOW}&{RESET}] Grabbing Banners for all the open ports....")
		print("=" * 50)
		scanner.threadBanners()
		print("=" * 50)
	
	print(f"[{GREEN}+{RESET}] Scan of {YELLOW}{tPorts}{RESET} ports done!")
