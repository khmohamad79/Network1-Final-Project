from port_scaners import *
from os import system
#import msvcrt
import time

	
target = input('Target IP or Hostname: ')
target = socket.gethostbyname(target)
print("Target IP: " + target)

host = get_host_ip()
print("Host IP: " + host)


ports = []
mode = 0
delay = 0

while True:
	portmode = input("""
	
Select The Port Mode: 
	1. Single Port
	2. Mutiple Port
	3. Range
	""")
	try:
		if portmode == "1":
			input_port = int(input("\n\tEnter The Port Number(1-65535): "))
			if input_port<=0 or input_port>65535:
				raise Exception("Unvalid Port Number.")
			ports.append(input_port)
		elif portmode == "2":
			input_port = input("\n\tEnter The Ports Seperated by Slash Sign (/) (1-65535): ")
			for x in input_port.split('/'):
				if int(x)<=0 or int(x)>65535:
					raise Exception("Unvalid Port Number.")
				else:
					ports.append(int(x))
		elif portmode == "3":
			range_start = int(input("\n\tEnter Starting Port(1-65535): "))
			if range_start<=0 or range_start>65535:
				raise Exception("Unvalid Port Number.")
			range_end = int(input("\tEnter Last Port(1-65535): "))
			if range_end<=0 or range_end>65535:
				raise Exception("Unvalid Port Number.")
			if range_end<range_start:
				raise Exception("Last Port Should be greater than Starting Port.") 
			ports = list(range(range_start, range_end+1))
		else:
			raise Exception("Unvalid Mode Number.")
	except Exception as e:
		if len(e.args)>0 :
			print(e.args[0])
		else:
			print("Unvalid Input.")
		#msvcrt.getch()
		continue
	break

while True:
	scanmode = input("""

Select Scan Type:
	1.Connect Scan
	2.ACK Scan
	3.SYN Scan
	4.FIN Scan
	5.Windows Scan
	""") 
	try:
		if scanmode == "1":
			mode = connect_scan
		elif scanmode == "2":
			mode = ack_scan
		elif scanmode == "3":
			mode = syn_scan
		elif scanmode == "4":
			mode = fin_scan
		elif scanmode == "5":
			mode = windows_scan
		else:
			raise Exception("Unvalid Scan Type Number.")
		#Alternate Mode Assinging
	except Exception as e:
		if len(e.args)>0 :
			print(e.args[0])
		else:
			print("Unvalid Scan Type Input.")
		#msvcrt.getch()
		continue
	break

while True:
	try:
		delay = int(input("\nEnter Delay(ms): "))
		if delay < 0:
			raise Exception()
	except:
		print("Wrong Input.")
		continue
	break

for port in ports:
	print(mode(host, target, port))
	time.sleep(delay/1000)
	
"""
n=0
for port in ports:
	if mode == 1:
		#sys(cls)
		print("Connect-Scan for Host()
		print(host)
		print("):\n")
		res = connect_scan(host, target, port, delay)
		if res:
			print("\tPort " + str(port) + " : Open")
		else:
			n++

	elif mode == 2:
		#sys(cls)
		print("ACK-Scan for Host()
		print(host)
		print("):\n")
		res = ack_scan(host, target, port, delay)
		if res=="filtred":
			print("\tPort " + str(port) + " : Filtered")
		elif res=="unfiltered":
			print("\tPort " + str(port) + " : Unfiltered")
			
	elif mode == 3:
		#sys(cls)
		print("SYN-Scan for Host()
		print(host)
		print("):\n")
		res = syn_scan(host, target, port, delay)
		if res=="open":
			print("\tPort " + str(port) + " : Open")
		elif res=="filtered":
			print("\tPort " + str(port) + " : Filtered")
		elif res=="closed":
			n++
			
	elif mode == 4:
		#sys(cls)
		print("FIN-Scan for Host()
		print(host)
		print("):\n")
		res = fin_scan(host, target, port, delay)
		if res=="open/filtered":
			print("\tPort " + str(port) + " : Open|Filtered")
		elif res=="closed":
			n++

	elif mode == 5:
		#sys(cls)
		print("Window-Scan for Host()
		print(host)
		print("):\n")
		res = windows_scan(host, target, port, delay)
		if res=="open":
			print("\tPort " + str(port) + " : Open")
		elif res=="closed":
			n++
		
if n>0:
	print( str(n) + " Ports are Closed")

"""

