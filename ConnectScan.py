import os
import sys
import socket
import argparse
from datetime import datetime

import numpy as np
from numpy.random import shuffle

class ConnectScan():

	well_known_port_descriptions = None
	failed_hostnames = 0

	def __init__(self):
		"""Initialize data"""
		self.failed_hostnames = 0
		self.read_port_descriptions()


	def read_port_descriptions(self):
		"""Read port descriptions from a local file"""
		# File contents retrieved from https://github.com/maraisr/ports-list/blob/master/tcp.csv
		self.well_known_port_descriptions = np.loadtxt("well_known_port_description.csv", delimiter=';', dtype=str)


	def connect_scan(self, hostname, lowport, highport, shuffle_ports, closed_and_filtered):
		"""
		Performs connect scan on host

		hostname -- host to be scanned
		lowport -- lowest port number to be scanned
		highport -- highest port number to be scanned
		shuffle_ports -- 1 if ports should be shuffled
		shuffle_hosts -- 1 if hosts should be shuffled
		host_discovery -- 1 if host discovery should be performed
		closed_and_filtered -- 1 if details of ports scanned should be printed
		"""
		try:
    	# Takes in hostname or ip-address, returns ip-address
			serverIP = socket.gethostbyname(hostname)
		except socket.gaierror:
			self.failed_hostnames += 1
			print("Hostname '%s' could not be resolved. Trying next hostname if there is one." % (hostname))
			return
		
    # shuffle the ports if prompted
		ports = np.arange(lowport, highport+1)
		if shuffle_ports:
			shuffle(ports)

		print("-" * 90)
		if hostname != serverIP:
			print("Please wait, performing connect scan on host '%s', IP %s" % (hostname, serverIP))
		else:
			print("Please wait, performing connect scan on IP %s" % serverIP)
		print("-" * 90)

		t1 = datetime.now()

		try:
			open = 0
			closed_or_filtered = 0

			# Try all the ports in the given range
			for port in ports:

        # Get the port description
				port_description = self.well_known_port_descriptions[port,1]

				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(1)

        # Scanner can differentiate between open, closed and blocked ports.
				result = sock.connect_ex((serverIP, port))
				sock.close()
				if result == 0:
					open += 1
					print("Port, %s - Open               (%s)" % (port, port_description))
				else:
					closed_or_filtered += 1
					if closed_and_filtered:
						print("Port, %s - Closed or Filtered (%s)" % (port, self.well_known_port_descriptions[port,1]))

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
		total_time =  t2 - t1
		print('Scanning Completed in:    %s' % total_time)
		print('Scanned a total of %d ports.' % len(ports))
		print('    Open:                 %d' % open)
		print('    Closed or filtered:   %d' % closed_or_filtered)