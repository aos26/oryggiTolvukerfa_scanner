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


# Param: host of dtype str.
# Tries to generate a range of useable hosts in a network from the string host, hoping that it is a CIDR notation.
# Returns: a list of IP addresses generated from host if host was a CIDR notation,
# 				 host unchanged otherwise.
def extract_hosts(host):
	try:
		# try to extract netrange from the user input
		hosts = ipaddress.ip_network(host).hosts()
		IPs = []
		for h in hosts:
			IPs.append(str(h))
	except ValueError:
		# should be a single hostname (url with '/')
		return host

	return IPs

def ping_host(address):
	
	res = subprocess.call(['ping', '-c', '3', address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
	if res == 0: 
		print('Ping to address %s - OK' % address)
		return True
	else:
		print('Ping to address %s - Failed or no response' % address)
		return False


# Removes inactive hosts
def perform_host_discovery(hosts):
	active_hosts = []
	print('Running host discovery for {} ports.'.format(len(hosts)))
	for host in hosts:
		if ping_host(host):
			active_hosts.append(host)
	return active_hosts


def scan_multiple_hosts(hosts, lowport, highport, 
																shuffle_ports, shuffle_hosts, 
																host_discovery, closed_and_filtered, type_of_scan):
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
		print('Starting connect scan on ports {} to {} in a randomized order.'.format(lowport, highport))
	else:
		print('Starting connect scan on ports {} to {}.'.format(lowport, highport))

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

	# else:
		# Perform SYN scan
		# scanner = SynScan()
		# TODO: loop through the hosts and scan each of them
		# for host in hosts:
		# 	scanner.syn_scan(host, lowport, highport, shuffle_ports, closed_and_filtered)

	print("-" * 90)
	print("-" * 90)
	print('Scanned a total of %d hosts, out of which %d failed and the rest were successful.' % (len(hosts), scanner.failed_hostnames))
	print("-" * 90)

#####
# Input:
# 1.	Can specify 1 or more IP addresses (netrange or CIDR) or hostnames.
# 		Can specify IP addresses from a file (line by line).
# 2.	Can specify the range of ports that should be scanned, default 1-1023
# 3.	Can specify type of scan that should be used (Connect (full) or SYN). 
# 		TODO: Implement SYN scan.
# 4.	Can specify if should do "host discovery" first to analyze living IP addresses, or scan straight away
# 5.	Can specify if port order should be shuffled.
# 6.	Can specify if host order should be shuffled.
#	7.	Can specify if output should show closed and filtered ports.
# 
# Output: 
# 1.	Netsvið sem var skannað og tegund skanns.
# 2.	Total number of ports that was scanned and breakdown into open, closed, filtered
#			TODO: Break down closed and filtered?
# 3. 	Öll opin port. Ef um er að ræða „well known port“ þá skilar skanninn einnig nafn líklegrar þjónustu.
# 4.	Sýna lokuð og blokkuð port eftir fyrirmælum notanda.
#			TODO: Break down closed and filtered?

parser = argparse.ArgumentParser('Scanner', fromfile_prefix_chars='@')
# parser.add_argument('host', help="The host") # hostname


# How to take a list as an argument
# parser.add_argument('-l','--list', nargs='+', help='<Required> Set flag', required=True)
# Use like:
# python arg.py -l 1234 2345 3456 4567
parser.add_argument('-ho','--hosts', 
										nargs='+',
										help="One or multiple hostnames or IP addresses to scan. To read the list from a file, prefix the filename with '@'.", 
										required=True)


parser.add_argument('-lo', '--lowport', help="The low port", type=int, default=1, required=False)
parser.add_argument('-hi', '--highport', help="The high port", type=int, default=1023, required=False)
parser.add_argument('-sp', '--shuffleports', help="1 to scan ports in a random order, 0 otherwise", type=int, default=0, required=False)
parser.add_argument('-sh', '--shufflehosts', help="1 to scan hosts in a random order, 0 otherwise", type=int, default=0, required=False)
parser.add_argument('-ts', '--typeofscan', help="0 for connect scan, 1 for SYN scan", type=int, default=1, required=False)
parser.add_argument('-hd', '--hostdiscovery', help="1 to perform host discovery first, 0 otherwise", type=int, default=0, required=False)
parser.add_argument('-cf', '--closedandfiltered', help="1 to show closed and filtered ports, 0 otherwise", type=int, default=0, required=False)


# Verbose output implies that more details will be printed, e.g.
#   'The program provides additional details as to what the computer 
#   is doing and what drivers and software it is loading during startup.'
parser.add_argument('-v', '--verbose', help="Verbose output", action="store_true")

# Parse the arguments
args = parser.parse_args()

# TODO: Validate and Sanitize the input?
hosts = args.hosts
lowport = args.lowport
highport = args.highport
shuffleports = args.shuffleports
shufflehosts = args.shufflehosts
typeofscan = args.typeofscan
hostdiscovery = args.hostdiscovery
closedandfiltered = args.closedandfiltered


scan_multiple_hosts(hosts, lowport, highport, 
									shuffleports, shufflehosts, 
									hostdiscovery, closedandfiltered, typeofscan)

