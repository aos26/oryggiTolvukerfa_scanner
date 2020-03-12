import os
import sys
import socket
import argparse
from datetime import datetime

import subprocess 
import ipaddress

import numpy as np
from numpy.random import shuffle

from ConnectScan import ConnectScan
from SynScan import SynScan


def extract_hosts(host):
	"""
	Return a list of IP addresses generated from host if host was a CIDR notation, otherwise unchanged

	Parameters:
	host -- host of dtype str
	"""
	
	try:
		# try to extract netrange from the user input
		hosts = ipaddress.ip_network(host).hosts()
		IPs = []
		for h in hosts:
			IPs.append(str(h))
	except ValueError:
		# host should be a single hostname (url with '/')
		return host

	return IPs

def ping_host(address):
	"""Return True if address responded to ping, False otherwise"""

	res = subprocess.call(['ping', '-c', '3', address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
	if res == 0: 
		print('Ping to address %s - OK' % address)
		return True
	else:
		print('Ping to address %s - Failed or no response' % address)
		return False


def perform_host_discovery(hosts):
	"""Return list where inactive hosts have been removed"""
	active_hosts = []
	print('Running host discovery for {} ports.'.format(len(hosts)))
	for host in hosts:
		if ping_host(host):
			active_hosts.append(host)
	return active_hosts


def scan_multiple_hosts(hosts, lowport, highport, 
						shuffle_ports, shuffle_hosts, 
						host_discovery, closed_and_filtered, type_of_scan):
	"""
	Prints information on scan for user and calls on scan type based on parameters

	Parameters:
	hosts -- list of hosts to be scanned
	lowport -- lowest port number to be scanned
	highport -- highest port number to be scanned
	shuffle_ports -- 1 if ports should be shuffled
	shuffle_hosts -- 1 if hosts should be shuffled
	host_discovery -- 1 if host discovery should be performed
	closed_and_filtered -- 1 if details of ports scanned should be printed
	type_of_scan -- Type of scan to be performed (0 for connect scan, 1 for syn scan)
	"""
	IPs = []
	for host in hosts:
		# Iterate through the hosts and change netranges to lists
		if '/' in host:
			extracted_IPs = extract_hosts(host)
			if type(extracted_IPs) != str:
				# Remove netrange from the list of hosts
				hosts.remove(host)
				IPs.append(extracted_IPs)
	
	# Append the extracted IPs to the hosts
	for ips in IPs:
		hosts = hosts + ips

	if host_discovery == 1:
		print("-" * 90)
		print('Performing "host discovery" to reduce the set of IP ranges.')
		print("-" * 90)
		hosts = perform_host_discovery(hosts)

	if shuffle_ports == 1: # The scanner will be responsible for shuffling the ports
		print('Starting scan on ports {} to {} in a randomized order.'.format(lowport, highport))
	else:
		print('Starting scan on ports {} to {}.'.format(lowport, highport))

	if shuffle_hosts == 1: # shuffle the hosts if prompted 
		shuffle(hosts)
		print('The scanner will scan the hosts in a randomized order.')

	if closed_and_filtered == 1: # The scanner will be responsible for printing these details
		print('The scanner will print details about closed and filtered ports.')


	if type_of_scan == 0:
		# Perform connect scan
		scanner = ConnectScan()
		# loop through the hosts and scan each of them
		for host in hosts:
			scanner.connect_scan(host, lowport, highport, shuffle_ports==1, closed_and_filtered==1)

	else:
		# Perform SYN scan
		scanner = SynScan()
		# TODO: loop through the hosts and scan each of them
		for host in hosts:
			scanner.syn_scan(host, lowport, highport, shuffle_ports, closed_and_filtered)

	print("-" * 90)
	print("-" * 90)
	print('Scanned a total of %d hosts, out of which %d failed and the rest were successful.' % (len(hosts), scanner.failed_hostnames))
	print("-" * 90)

"""
Input:
1.	Can specify 1 or more IP addresses (including CIDR) or hostnames.
	Can specify IP addresses from a file (line by line).
2.	Can specify the range of ports that should be scanned, default 1-1023
3.	Can specify type of scan that should be used (Connect (full TCP handshake) or SYN). 
4.	Can specify if should do "host discovery" first to analyze living IP addresses, or scan straight away
5.	Can specify if port order should be shuffled.
6.	Can specify if host order should be shuffled.
7.	Can specify if output should show closed and filtered ports.

Output: 
1.	Notwork that was scanned.
2.	Type of scan that was used.
3.	Total number of ports that was scanned and breakdown into open, closed, filtered.
4. 	All open ports as well as the name of the service if it is a 'well known port'.
4.	Shows closed and filtered ports depending on input parameter.
"""
parser = argparse.ArgumentParser('Scanner', fromfile_prefix_chars='@')
# parser.add_argument('host', help="The host") # hostname


parser.add_argument('-ho','--hosts', 
	nargs='+',
	help="One or multiple hostnames or IP addresses to scan. To read the list from a file, prefix the filename with '@'.", 
	required=True)


parser.add_argument('-lo', '--lowport', help="The low port", type=int, default=1, required=False)
parser.add_argument('-hi', '--highport', help="The high port", type=int, default=1023, required=False)
parser.add_argument('-sp', '--shuffleports', help="1 to scan ports in a random order, 0 otherwise", type=int, default=0, required=False)
parser.add_argument('-sh', '--shufflehosts', help="1 to scan hosts in a random order, 0 otherwise", type=int, default=0, required=False)
parser.add_argument('-ts', '--typeofscan', help="0 for connect scan, 1 for SYN scan", type=int, default=0, required=False)
parser.add_argument('-hd', '--hostdiscovery', help="1 to perform host discovery first, 0 otherwise", type=int, default=0, required=False)
parser.add_argument('-cf', '--closedandfiltered', help="1 to show closed and filtered ports, 0 otherwise", type=int, default=0, required=False)

# Parse the arguments and retrieve their values
args = parser.parse_args()
hosts = args.hosts
lowport = args.lowport
highport = args.highport
shuffleports = args.shuffleports
shufflehosts = args.shufflehosts
typeofscan = args.typeofscan
hostdiscovery = args.hostdiscovery
closedandfiltered = args.closedandfiltered

# Run a function that determines what to do
scan_multiple_hosts(hosts, lowport, highport, 
					shuffleports, shufflehosts, 
					hostdiscovery, closedandfiltered, typeofscan)

