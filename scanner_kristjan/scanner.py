import os
import sys
import socket
import argparse
from datetime import datetime


# Skv. verkefnalýsingu þá er þetta "python grind að skanna sem virkar til að skanna eina IP tölu með „connection scan“, þ.e. fullt 3-way handshake" - eok4

class SimpleScanner():

	def __init__(self):
		pass

	def scan(self, hostname, lowport, highport):

		serverIP  = socket.gethostbyname(hostname)

		print("-" * 60)
		print("Please wait, scanning host '%s', IP %s" % (hostname, serverIP))
		print("-" * 60)

		t1 = datetime.now()

		try:
			total = highport-lowport
			current = 0
			open = 0
			closed_or_filtered = 0
			for port in range(lowport,highport+1):
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(1)
				result = sock.connect_ex((serverIP, port))
				sock.close()
				if result == 0:
					open += 1
					print("Port %s - Open" % (port))
				else:
					closed_or_filtered += 1

		except KeyboardInterrupt:
			print("You pressed Ctrl+C")
			sys.exit()
		except socket.gaierror:
			print('Hostname could not be resolved. Exiting')
			sys.exit()
		except socket.error:
			print("Couldn't connect to server")
			sys.exit()

		t2 = datetime.now()
		total =  t2 - t1
		print('Scanning Completed in:  %s' % total)
		print('    Open:               %d' % open)
		print('    Closed or filtered: %d' % closed_or_filtered)


#
# Parse some arguments
#
parser = argparse.ArgumentParser('Scanner')
parser.add_argument('host', help="The host")
parser.add_argument('lowport', help="The low port")
parser.add_argument('highport', help="The high port")
parser.add_argument('-v', '--verbose', help="Verbose output", action="store_true")
args = parser.parse_args()

host = args.host
lowport = int(args.lowport)
highport = int(args.highport)

scanner = SimpleScanner()
scanner.scan(host, lowport, highport)
