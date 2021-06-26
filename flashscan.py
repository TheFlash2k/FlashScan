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
############################

class PortScanner():
	def __init__(self, ip, ports, threads=200, verbose=False):
		self.ip = ip
		self.threads = threads
		self.verbose = verbose
		self.ports = ports
		## Creating variables
		self.q = Queue() # This will hold the ports
		self.print_lock = Lock()
		self.Banners = dict()
		self.open_ports = list()
		self.closed = True

	def extractBanner(self, port):
		s = socket.socket()
		try:
			s.connect((self.ip, port))
			if port == 80 or port == 443 or port == 8080:
				req = "GET / HTTP/1.1 \r\n"
				s.send(req.encode())
				banner = s.recv(1024).decode()
				banner = banner[banner.find("Server"):]
				banner =  banner[:banner.find("\n")].split(': ')[1]
				banner = f"[{GREEN}+{RESET}] Port {port} : " + banner
			else:
				banner = s.recv(1024).decode()
				if banner == "":
					banner = f"[{RED}-{RESET}] Port {port} : No Banner Found! :("
				else:
					banner = f"[{GREEN}+{RESET}] Port {port} : " + banner.strip()
			with self.print_lock:
				print(banner)
		except  KeyboardInterrupt:
			pass
		except:
			print(f"[{RED}-{RESET}] Port {port} : Unable to grab banner. :(")

		s.close()

	def getBanners(self):
		for port in self.open_ports:
			self.extractBanner(port)

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
				if self.verbose:
					print(f"[{RED}-{RESET}] PORT {port} is {RED}closed{RESET}!" + " " * 10)
				pass
		else:
			with self.print_lock:
				self.open_ports.append(port)
				scanner.closed = False
				print(f"[{GREEN}+{RESET}] PORT {port} is {GREEN}open{RESET}!" + " " * 10)
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
		self.parser.add_argument("--detailed", "-d", help="Detailed output. Displaying more information about each service. Also enumerate for directories (if any webserver found)", action="store_true")
		self.parser.add_argument("--wordlist", "-w", help="Provide a wordlist for directory enumeration. Should be used along with -d flag.")
	def get_args(self):
		return self.parser.parse_args()

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

		ports = [ p for p in range(start_port, end_port)]
		tLen = end_port - start_port

	elif "," in ports:
		ports = ports.split(",")
		# Converting  the list to intt:
		for i in range(len(ports)):
			ports[i] = int(ports[i])
		tLen = len(ports)
	else:
		ports = [int(ports)]

	return ports, tLen

if __name__ == "__main__":
	
	ArgHandler = Args()
	args = ArgHandler.get_args()

	host = args.host
	port_range = args.ports
	threads = args.threads
	verbose = args.verbose
	detailed = args.detailed
	wordlist = args.wordlist
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
		scanner.getBanners()
		print("=" * 50)
	
	print(f"[{GREEN}+{RESET}] Scan of {YELLOW}{tPorts}{RESET} ports done!")
