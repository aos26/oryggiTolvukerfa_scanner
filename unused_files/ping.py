import subprocess 
  
# Just to play around with host discovery (pinging)

for ping in range(150,160): 
    address = "45.33.32." + str(ping) 
    res = subprocess.call(['ping', '-c', '3', address]) 
    if res == 0: 
        print( "ping to", address, "OK") 
    elif res == 2: 
        print("no response from", address) 
    else: 
        print("ping to", address, "failed!")