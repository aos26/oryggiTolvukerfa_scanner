import ipaddress

# Just to play around with ipaddresses and network ranges

cidr = 'scanme.nmap.org/a'
print(cidr)
if '/' in cidr:
  try:
    hosts = ipaddress.ip_network(cidr).hosts()
  except ValueError:
    print('Value Error')
    # should be a single host name
    hosts = [cidr]
else:
  # should just be a single hostname or ip address (i.e. not a range)
  hosts = [cidr]


i = 0
for x in hosts:
  print(x)  
  i+=1

print('printed', i)


